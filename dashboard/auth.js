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
// dashboard/constants.js (SESSION_IDLE_TIMEOUT_MS env, default 120000ms).
const IDLE_TIMEOUT_MS = constants.SESSION_IDLE_TIMEOUT_MS;

// Refresh the session's idle deadline to "now + IDLE_TIMEOUT_MS". Called on
// every successful authenticated request (see requireAuth) and by the
// /api/session/heartbeat endpoint while the dashboard tab is visible. Writing
// the deadline onto the session (rather than just touching resave) makes the
// timeout survive serverless instance churn: the deadline lives in the
// Postgres-backed session row, not in process memory.
function touchIdleDeadline(req) {
    if (!req.session) return;
    req.session.idleExpiresAt = Date.now() + IDLE_TIMEOUT_MS;
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
        // calls). The client's periodic heartbeat keeps it alive between
        // navigations while the tab is visible.
        touchIdleDeadline(req);
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
 * Page-route variant of requireGuildAdmin. Verifies the same guild-management
 * access and bot presence, but instead of returning JSON errors it renders an
 * HTML error page (or redirects to /login on an expired session). On success it
 * also fetches the guild's channels, roles, and full config, attaching them as
 * req.guild._channels / req.guild._roles / req.guild._config so the
 * server-rendered page can pre-populate its forms in one round-trip.
 *
 * The JSON variant (requireGuildAdmin) is unchanged and still used by all
 * /api/* routes.
 */
async function requireGuildAdminPage(req, res, next) {
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

        let botGuild;
        try {
            botGuild = await discord.getBotGuild(guildId);
        } catch (err) {
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

        req.guild = {
            id: botGuild.id,
            name: botGuild.name,
            icon: botGuild.icon,
            owner_id: botGuild.owner_id,
            approximate_member_count: botGuild.approximate_member_count,
            userIsOwner: userGuild.owner,
        };

        // Fetch channels + roles + config for server-side form pre-population.
        // Each degrades gracefully so a partial Discord/DB failure still renders
        // the page with empty selectors rather than a 500.
        const [channels, roles, config] = await Promise.all([
            discord.getGuildChannels(req.guild.id)
                .then(cs => cs.map(c => ({ id: c.id, name: c.name })))
                .catch(err => { console.error('[AUTH] getGuildChannels failed:', err.message); return []; }),
            // Only show roles the bot can actually assign (below its highest
            // role, not integration-managed) so reaction-role / leveling
            // selectors never offer a role that fails with a 50007 error.
            discord.getGuildRoles(req.guild.id, { excludeUnassignable: true })
                .then(rs => rs.map(r => ({ id: r.id, name: r.name, position: r.position })))
                .catch(err => { console.error('[AUTH] getGuildRoles failed:', err.message); return []; }),
            dashboardDb.getGuildConfig(req.guild.id).catch(err => {
                console.error('[AUTH] getGuildConfig failed:', err.message);
                return { server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [] };
            }),
        ]);
        req.guild._channels = channels;
        req.guild._roles = roles;
        req.guild._config = config;
        // Beta access flag (allowed && enabled) — developer/owner-role users
        // bypass the gate entirely (they can exercise beta features anywhere).
        // Degrades to false on any DB error so non-beta servers stay locked.
        const [betaAccess, bypassGates] = await Promise.all([
            betaManager.canAccess(req.guild.id).catch(() => false),
            canBypassFeatureGates(req).catch(() => false),
        ]);
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
}

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

module.exports = { requireAuth, requireGuildAdmin, requireGuildAdminPage, requireBeta, requireUpcoming, touchIdleDeadline, isIdleExpired, IDLE_TIMEOUT_MS };
