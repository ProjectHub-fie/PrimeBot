/**
 * Auth middleware for the dashboard.
 *
 * The session (created by express-session) holds the Discord OAuth2 tokens
 * and the cached user object. This module attaches `req.user` and exposes
 * `requireAuth` / `requireGuildAdmin` guards.
 */

const discord = require('./discord');
const pages = require('./render/pages');
const L = require('./render/layout');
const dashboardDb = require('./db');
const betaManager = require('../utils/betaManager');
const botRoles = require('../utils/botRoles');
const constants = require('./constants');

// Users holding a developer/owner bot role (utils/botRoles.js, bot_roles table
// on COMMUNITY_DATABASE_URL) bypass the dashboard's beta + upcoming feature
// gates so they can exercise locked features for testing. Degrades to false on
// any DB error so a role-DB outage never widens access.
async function canBypassFeatureGates(req) {
    const userId = req.user && req.user.id;
    if (!userId) return false;
    try {
        return await botRoles.canBypassFeatureGates(userId);
    } catch (err) {
        console.error('[AUTH] canBypassFeatureGates error:', err.message);
        return false;
    }
}

// Idle auto-logout window (server-side safety net). Single source of truth in
// dashboard/constants.js (SESSION_IDLE_TIMEOUT_MS env, default 30 minutes).
const IDLE_TIMEOUT_MS = constants.SESSION_IDLE_TIMEOUT_MS;
// Neon compute optimization: the server-side idle deadline is only persisted
// when at least this much time has elapsed since the previous persistence. This
// turns "update last activity on every request" into "update at most once per
// interval" (default 10 minutes). The exact value is derived from the deadline
// itself, so no extra session field / DB column is needed.
const REFRESH_INTERVAL_MS = constants.SESSION_ACTIVITY_REFRESH_INTERVAL_MS;

// When was the session's idle deadline last persisted to the session store?
// Derived from the current deadline: idleExpiresAt = lastRefresh + IDLE_TIMEOUT_MS.
// A missing/non-numeric deadline (legacy or debug session) returns 0.
function lastActivityAt(req) {
    if (!req.session) return 0;
    const exp = req.session.idleExpiresAt;
    if (typeof exp !== 'number' || !Number.isFinite(exp)) return 0;
    return exp - IDLE_TIMEOUT_MS;
}

// Refresh the session's idle deadline to "now + IDLE_TIMEOUT_MS" — but ONLY
// when the minimum refresh interval has elapsed since the last persistence.
// Called on every successful authenticated request (see requireAuth) and by
// the /api/session/heartbeat activity-sync endpoint. When the throttle holds,
// the session object is left untouched, so express-session's store.set() is
// skipped entirely → ZERO writes to Neon for the vast majority of requests.
//
// Writing the deadline onto the session (rather than just touching resave)
// makes the timeout survive serverless instance churn: the deadline lives in
// the Postgres-backed session row, not in process memory. Once the interval
// elapses the deadline is rolled forward to a full idle window again.
function touchIdleDeadline(req) {
    if (!req.session) return false;
    const now = Date.now();
    if (now - lastActivityAt(req) < REFRESH_INTERVAL_MS) return false;
    req.session.idleExpiresAt = now + IDLE_TIMEOUT_MS;
    return true;
}

// Returns true if the session's idle deadline has lapsed. A session without a
// deadline (e.g. created before this feature shipped, or a debug session) is
// treated as not-yet-idle so we don't surprise-logout legacy sessions.
function isIdleExpired(req) {
    if (!req.session) return false;
    const exp = req.session.idleExpiresAt;
    if (!exp || typeof exp !== 'number') return false;
    return Date.now() >= exp;
}

// Destroy the session and send the user back to the login page with an
// idle_timeout reason. HTML requests redirect; JSON requests get 401 so the
// SPA-style fetch callers (api()) can react. Mirrors requireAuth's 401 path.
function expireForIdle(req, res) {
    req.session.destroy(() => {});
    if (req.accepts('html')) {
        return res.redirect('/login?error=idle_timeout');
    }
    return res.status(401).json({ error: 'Your session expired due to inactivity. Please log in again.', reason: 'idle_timeout' });
}

function requireAuth(req, res, next) {
    if (req.session && req.session.user) {
        // Idle safety net: if the heartbeat deadline lapsed (tab was hidden/
        // closed longer than the idle window), end the session now instead of
        // serving the request. The client also enforces this on visibility
        // change, but the server check covers throttled/closed tabs.
        if (isIdleExpired(req)) {
            return expireForIdle(req, res);
        }
        // Activity refreshes the idle deadline so the session stays alive while
        // the user is genuinely using the dashboard (page navigations, API
        // calls). The write is throttled to once per REFRESH_INTERVAL_MS — when
        // the deadline is still fresh the session object is left untouched, so
        // express-session skips store.set() (zero Postgres writes). The boolean
        // is recorded for the activity-sync endpoint to report.
        req.idleDeadlineRefreshed = touchIdleDeadline(req);
        req.user = req.session.user;
        return next();
    }
    if (req.accepts('html')) {
        return res.redirect('/login');
    }
    return res.status(401).json({ error: 'Not authenticated' });
}

// Read-only variant of requireAuth: authenticates and enforces the idle expiry
// (destroying dead sessions) but NEVER extends the idle deadline. Used by the
// GET /api/session/heartbeat accessor so a mere status sync (clock drift, tab
// return, multi-tab resync) can never grant the browser extra time — the POST
// activity sync is the only endpoint that may roll the deadline forward.
function requireAuthReadonly(req, res, next) {
    if (req.session && req.session.user) {
        if (isIdleExpired(req)) {
            return expireForIdle(req, res);
        }
        req.user = req.session.user;
        return next();
    }
    if (req.accepts('html')) {
        return res.redirect('/login');
    }
    return res.status(401).json({ error: 'Not authenticated' });
}

/**
 * Guard that loads the requested guild and verifies the logged-in user has
 * management rights over it (and the bot is a member). Attaches `req.guild`
 * on success.
 *
 * Strategy: pull the user's guild list from Discord (cached briefly in the
 * session) and check the permissions bitfield. Then confirm the bot is in the
 * guild via a bot-token REST call.
 */
async function requireGuildAdmin(req, res, next) {
    try {
        const guildId = req.params.guildId;
        if (!/^\d{17,20}$/.test(guildId)) {
            return res.status(400).json({ error: 'Invalid guild ID' });
        }

        const accessToken = req.session && req.session.accessToken;
        if (!accessToken) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        // Refresh the user's guild list if missing or stale (>10 min old).
        let guilds = req.session.guilds;
        const fetchedAt = req.session.guildsFetchedAt || 0;
        if (!Array.isArray(guilds) || Date.now() - fetchedAt > 10 * 60 * 1000) {
            guilds = await discord.getUserGuilds(accessToken);
            req.session.guilds = guilds;
            req.session.guildsFetchedAt = Date.now();
        }

        const userGuild = guilds.find(g => g.id === guildId);
        if (!userGuild || !discord.canManageGuild(userGuild.permissions)) {
            return res.status(403).json({ error: 'You do not have permission to manage this server.' });
        }

        // Confirm the bot is present in the guild. This uses the BOT token
        // (process.env.DISCORD_TOKEN), NOT the user's OAuth token, so a 401 here
        // means the bot token is missing/invalid — NOT that the user's session
        // expired. Destroying the session on a bot-token 401 would log the user
        // out for an unrelated reason, so we handle it separately below.
        let botGuild;
        try {
            botGuild = await discord.getBotGuild(guildId);
        } catch (err) {
            if (err.status === 401) {
                console.error('[AUTH] getBotGuild returned 401 — DISCORD_TOKEN is missing or invalid. Set DASHBOARD_BOT_TOKEN/DISCORD_TOKEN on Vercel.');
                return res.status(503).json({
                    error: 'PrimeBot is not reachable (bot token not configured). Ask an admin to set DISCORD_TOKEN on the dashboard deployment.',
                    reason: 'bot_token_unauthorized',
                });
            }
            if (err.status === 403 || err.status === 404) {
                return res.status(404).json({ error: 'PrimeBot is not in this server. Invite it first.' });
            }
            throw err;
        }

        req.guild = {
            id: botGuild.id,
            name: botGuild.name,
            icon: botGuild.icon,
            owner_id: botGuild.owner_id,
            approximate_member_count: botGuild.approximate_member_count,
            userIsOwner: userGuild.owner,
        };
        // Stash the caller's raw guild permissions on the session so the Event
        // Management guards can tell an administrator from an event-manager
        // without another Discord round-trip.
        req.session.userGuildPermissions = userGuild.permissions;
        next();
    } catch (err) {
        console.error('[AUTH] requireGuildAdmin error:', err.message);
        // A 401 reaching here can only come from the user's OAuth access token
        // (getUserGuilds). That genuinely means the session expired — refresh it.
        if (err.status === 401) {
            req.session.destroy(() => {});
            if (req.accepts('html')) return res.redirect('/login');
            return res.status(401).json({ error: 'Session expired. Please log in again.' });
        }
        return res.status(500).json({ error: 'Failed to verify guild access.' });
    }
}

/**
 * Build the guard for a guild settings page.
 *
 * Verifies guild-management access and bot presence, then attaches what the
 * page renders: `req.guild._channels` / `_roles` / `_config` plus the beta and
 * upcoming flags. Pages declare the config they need — a tab like /prefix
 * renders one field, and loading every feature's settings slice for it meant
 * ~18 queries across every feature pool (plus the Anti-Nuke extras) on a
 * request that can be killed by the host's function timeout before it finishes
 * (the browser reports ERR_CONNECTION_ABORTED). `selectors: false` skips the
 * channel/role lookups for pages with no <select>; `antiNukeExtras` loads the
 * lockdown/incident/permission context only where the Anti-Nuke console needs
 * it. `betaGates` loads the beta/upcoming flags — only pages that render a
 * beta or "Coming Soon" overlay consult them.
 *
 * The JSON variant (requireGuildAdmin) is unchanged and still used by all
 * /api/* routes.
 */
function guildPage({ config = null, selectors = true, antiNukeExtras = false, betaGates = false } = {}) {
    return async function guildPageGuard(req, res, next) {
        try {
            const guildId = req.params.guildId;
            if (!/^\d{17,20}$/.test(guildId)) {
                return res.status(404).type('html').send(pages.notFoundPage({ user: req.session && req.session.user }));
            }

            const accessToken = req.session && req.session.accessToken;
            if (!accessToken) {
                return res.redirect('/login');
            }

            let guilds = req.session.guilds;
            const fetchedAt = req.session.guildsFetchedAt || 0;
            if (!Array.isArray(guilds) || Date.now() - fetchedAt > 10 * 60 * 1000) {
                guilds = await discord.getUserGuilds(accessToken);
                req.session.guilds = guilds;
                req.session.guildsFetchedAt = Date.now();
            }

            const userGuild = guilds.find(g => g.id === guildId);
            if (!userGuild || !discord.canManageGuild(userGuild.permissions)) {
                const body = `<div class="card"><div class="alert alert-error">You do not have permission to manage this server.</div><p><a href="/">← Back to servers</a></p></div>`;
                return res.status(403).type('html').send(L.render({ title: 'PrimeBot · Access denied', body, user: req.session && req.session.user }));
            }

            // These are independent of each other, so they run in ONE parallel
            // batch: bot presence, the optional channel/role lookups, the config
            // slices this page renders, and the beta/bypass flags.
            const [botGuild, channels, roles, configData, betaAccess, bypassGates] = await Promise.all([
                discord.getBotGuild(guildId).then(g => ({ guild: g })).catch(err => ({ err })),
                selectors
                    ? discord.getGuildChannels(guildId)
                        .then(cs => cs.map(c => ({ id: c.id, name: c.name })))
                        .catch(err => { console.error('[AUTH] getGuildChannels failed:', err.message); return []; })
                    : Promise.resolve([]),
                // Only show roles the bot can actually assign (below its highest
                // role, not integration-managed) so reaction-role / leveling
                // selectors never offer a role that fails with a 50007 error.
                selectors
                    ? discord.getGuildRoles(guildId, { excludeUnassignable: true })
                        .then(rs => rs.map(r => ({ id: r.id, name: r.name, position: r.position })))
                        .catch(err => { console.error('[AUTH] getGuildRoles failed:', err.message); return []; })
                    : Promise.resolve([]),
                dashboardDb.getGuildConfig(guildId, { only: config }).catch(err => {
                    console.error('[AUTH] getGuildConfig failed:', err.message);
                    return { server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [] };
                }),
                betaGates ? betaManager.canAccess(guildId).catch(() => false) : Promise.resolve(false),
                betaGates ? canBypassFeatureGates(req).catch(() => false) : Promise.resolve(false),
            ]);

            if (botGuild.err) {
                const err = botGuild.err;
                if (err.status === 401) {
                    const body = `<div class="card"><div class="alert alert-error">PrimeBot is not reachable (bot token not configured). Ask an admin to set DISCORD_TOKEN on the dashboard deployment.</div><p><a href="/">← Back to servers</a></p></div>`;
                    return res.status(503).type('html').send(L.render({ title: 'PrimeBot · Unreachable', body, user: req.session && req.session.user }));
                }
                if (err.status === 403 || err.status === 404) {
                    const cid = process.env.DISCORD_CLIENT_ID || '';
                    const invite = `https://discord.com/oauth2/authorize?client_id=${cid}&permissions=8&integration_type=0&scope=bot%20applications.commands`;
                    const body = `<div class="card"><div class="alert alert-warn">PrimeBot is not in this server.</div><p>To configure PrimeBot here, add it to your server first.</p><p style="margin-top:16px"><a class="btn btn-primary" href="${invite}" target="_blank" rel="noopener">Invite PrimeBot</a></p><p style="margin-top:12px"><a href="/">← Back to servers</a></p></div>`;
                    return res.status(404).type('html').send(L.render({ title: 'PrimeBot · Not in server', body, user: req.session && req.session.user }));
                }
                throw err;
            }

            const bg = botGuild.guild;
            req.guild = {
                id: bg.id,
                name: bg.name,
                icon: bg.icon,
                owner_id: bg.owner_id,
                approximate_member_count: bg.approximate_member_count,
                userIsOwner: userGuild.owner,
            };
            req.guild._channels = channels;
            req.guild._roles = roles;
            req.guild._config = configData;

            // Anti-Nuke page extras: lockdown status, the bot's permission report
            // (for the honest "missing permissions" warning), the incident
            // summary and the setup progress. Each degrades gracefully.
            if (antiNukeExtras) {
                try {
                    const { validatePermissionsFromBitfield } = require('../utils/antiNukeContainment');
                    const { computeProgress } = require('../utils/antiNukeSetup');
                    const [lockdown, summary, botPerms] = await Promise.all([
                        dashboardDb.getAntiNukeLockdown(req.guild.id).catch(() => ({ active: false })),
                        dashboardDb.getAntiNukeIncidentSummary(req.guild.id).catch(() => ({ total: 0, byAction: [] })),
                        discord.computeBotPermissions(req.guild.id, process.env.DISCORD_CLIENT_ID).catch(() => null),
                    ]);
                    const antiNukeCfg = configData.antiNuke || {};
                    const method = antiNukeCfg.setupMethod || null;
                    req.guild._config.antiNukeLockdown = lockdown;
                    req.guild._config.antiNukeSummary = summary;
                    req.guild._config.antiNukePermissions = validatePermissionsFromBitfield(botPerms);
                    req.guild._config.antiNukeSetup = {
                        method,
                        status: antiNukeCfg.setupStatus || 'not_started',
                        // The raw step map so the manual wizard can resume at the
                        // right section (the computed `progress` alone cannot
                        // restore which sections are already complete).
                        state: antiNukeCfg.setupState || {},
                        progress: computeProgress(method || 'automatic', antiNukeCfg.setupState || {}),
                    };
                } catch (err) {
                    console.error('[AUTH] anti-nuke extras failed:', err.message);
                }
                // Anti-Nuke access context (owner-controlled hierarchy).
                try {
                    await attachAntiNukeAccess(req);
                } catch (err) {
                    console.error('[AUTH] attachAntiNukeAccess failed:', err.message);
                    req.guild._antiNukeAccess = { ok: false, reason: 'error' };
                }
            }

            // Beta access flag (allowed && enabled) — developer/owner-role users
            // bypass the gate entirely (they can exercise beta features anywhere).
            // Degrades to false on any DB error so non-beta servers stay locked.
            // Only loaded for pages that render a beta/upcoming overlay; every
            // other page gets `false`, which it never reads.
            req.guild._beta = betaAccess || bypassGates;
            // Upcoming-gate bypass (same privileged roles). eventsPage skips the
            // "Coming Soon" overlay when this is set.
            req.guild._bypassUpcoming = bypassGates;
            next();
        } catch (err) {
            console.error('[AUTH] requireGuildAdminPage error:', err.message);
            if (err.status === 401) {
                req.session.destroy(() => {});
                return res.redirect('/login');
            }
            const body = `<div class="card"><div class="alert alert-error">Failed to verify guild access.</div><p><a href="/">← Back to servers</a></p></div>`;
            return res.status(500).type('html').send(L.render({ title: 'PrimeBot · Error', body, user: req.session && req.session.user }));
        }
    };
}

// Full-config guard (channels + roles + every config slice + all extras).
// Kept for callers that have not been narrowed to the data they render.
const requireGuildAdminPage = guildPage({ antiNukeExtras: true, betaGates: true });

/**
 * Guard for beta-only guild features (e.g. Events). Verifies the guild has beta
 * access (allowed && enabled). Must run AFTER requireGuildAdmin so req.guild is
 * set. Returns 403 JSON for API routes; for page routes use the locked render.
 */
async function requireBeta(req, res, next) {
    try {
        const [allowed, bypass] = await Promise.all([
            betaManager.canAccess(req.guild.id).catch(() => false),
            canBypassFeatureGates(req).catch(() => false),
        ]);
        if (!allowed && !bypass) {
            return res.status(403).json({ error: 'This feature is in beta and not enabled for this server.', reason: 'beta_required' });
        }
        next();
    } catch (err) {
        console.error('[AUTH] requireBeta error:', err.message);
        return res.status(403).json({ error: 'Beta access could not be verified.', reason: 'beta_required' });
    }
}

/**
 * Guard for "upcoming" (not-yet-released) features (e.g. Events, Tickets).
 * Upcoming features are disabled for ALL servers — the dashboard renders a "Coming Soon"
 * overlay and the write endpoints return 403 so the feature can't be used via
 * API either. Upcoming takes priority over beta. Must run AFTER requireGuildAdmin.
 */
async function requireUpcoming(req, res, next) {
    // Developer/owner-role users bypass the upcoming gate so they can exercise
    // unreleased features. Everyone else still gets 403.
    const bypass = await canBypassFeatureGates(req).catch(() => false);
    if (bypass) return next();
    return res.status(403).json({ error: 'This feature is coming soon and is not available yet.', reason: 'upcoming' });
}

/**
 * Anti-Nuke owner-controlled access gate (API routes). Must run AFTER
 * requireAuth + requireGuildAdmin so req.user and req.guild (Discord-derived,
 * incl. `owner_id`) are set. The ACTUAL guild owner always passes; every other
 * user needs the requested bot-defined permission. Results are stashed on
 * `req.antiNukeAuth` so handlers re-check at action time instead of trusting
 * the frontend.
 *
 * Anti-Nuke stays unreleased: because the tab/feature does not ship to the
 * public yet, the bot-defined hierarchy is the *only* path in (the Discord
 * Administrator/Manage Guild check on its own still answers 403).
 */
function requireAntiNukePermission(requiredPermission, opts = {}) {
    return async (req, res, next) => {
        try {
            const guildId = req.params.guildId;
            const userId = req.user && req.user.id;
            const guild = req.guild; // { id, owner_id, ... } from Discord REST
            const antiNukeAccess = require('../utils/antiNukeAccess');
            const result = await antiNukeAccess.authorizeAntiNuke(guild, userId, requiredPermission || null);
            req.antiNukeAuth = result;
            if (result.ok) return next();

            if (result.reason === 'owner_unresolved') {
                return res.status(503).json({ error: 'Anti-Nuke ownership could not be resolved from Discord. Try again.', reason: 'owner_unresolved' });
            }
            if (result.reason === 'not_a_member') {
                return res.status(403).json({ error: 'You are not a member of this server.', reason: 'antiNuke_not_member' });
            }
            return res.status(403).json({
                error: 'You do not have permission for this Anti-Nuke action.',
                reason: 'antiNuke_permission_denied',
                permission: requiredPermission || null,
            });
        } catch (err) {
            console.error('[AUTH] requireAntiNukePermission error:', err.message);
            return res.status(500).json({ error: 'Anti-Nuke access could not be verified.', reason: 'antiNuke_error' });
        }
    };
}

/** Attach the viewer's Anti-Nuke access context to req.guild (page renders). */
async function attachAntiNukeAccess(req) {
    const antiNukeAccess = require('../utils/antiNukeAccess');
    const userId = req.user && req.user.id;
    if (!req.guild || !userId) return null;
    const guild = { id: req.guild.id, owner_id: req.guild.owner_id };
    const ctx = await antiNukeAccess.getGuildAccess(guild, userId);
    req.guild._antiNukeAccess = ctx;
    return ctx;
}

module.exports = { requireAuth, requireAuthReadonly, requireGuildAdmin, requireGuildAdminPage, guildPage, requireBeta, requireUpcoming, requireAntiNukePermission, attachAntiNukeAccess, touchIdleDeadline, isIdleExpired, IDLE_TIMEOUT_MS };
