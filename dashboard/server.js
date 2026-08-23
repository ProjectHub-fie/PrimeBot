/**
 * PrimeBot Dashboard — Express server.
 *
 * A standalone web app that lets Discord server admins log in with Discord
 * OAuth2 and configure PrimeBot for the servers they manage. It reads and
 * writes the same PostgreSQL tables the bot uses. The bot caches settings in
 * memory and re-reads the tables on a ~30s interval (see
 * SETTINGS_RELOAD_INTERVAL_MS), so dashboard saves take effect within that
 * window without a bot restart — provided the bot and dashboard point at the
 * same DATABASE_URL / WELCOME_DATABASE_URL.
 *
 * Run with:  npm run dashboard
 * Env vars:  PORT, DISCORD_TOKEN, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET,
 *            DISCORD_REDIRECT_URI, SESSION_SECRET
 */

const path = require('path');
const { Pool } = require('pg');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const PgSession = require('connect-pg-simple')(session);

const discord = require('./discord');
const turnstile = require('./turnstile');
const { requireAuth, requireGuildAdmin, requireGuildAdminPage, requireBeta, requireUpcoming } = require('./auth');
const dashboardDb = require('./db');
const constants = require('./constants');
const pages = require('./render/pages');
const guildPages = require('./render/guild-pages');

// Allow a dedicated token for dashboard REST calls; fall back to DISCORD_TOKEN.
if (!process.env.DASHBOARD_BOT_TOKEN && process.env.DISCORD_TOKEN) {
    process.env.DASHBOARD_BOT_TOKEN = process.env.DISCORD_TOKEN;
}
if (process.env.DASHBOARD_BOT_TOKEN && !process.env.DISCORD_TOKEN) {
    process.env.DISCORD_TOKEN = process.env.DASHBOARD_BOT_TOKEN;
}

const app = express();
// Trust the TLS-terminating proxy in front of us so req.secure / req.ip
// reflect the real client connection (HTTPS). Without this, express-session
// sees plain HTTP and refuses to set Secure cookies — login silently fails.
// (Vercel, the work host, and any reverse proxy front this app.)
app.set('trust proxy', 1);
const PORT = parseInt(process.env.DASHBOARD_PORT || process.env.PORT || 3000, 10);
// Resolve the public base URL in priority order:
//   1. DASHBOARD_BASE_URL  (explicit, always wins)
//   2. VERCEL_PROJECT_PRODUCTION_URL — the STABLE production domain on Vercel
//      (e.g. cpanel-primebot.vercel.app). This is critical: VERCEL_URL is a
//      per-deployment hashed preview URL that changes every deploy, so the
//      OAuth redirect_uri it produces never matches what's registered in the
//      Discord Developer Portal → "invalid redirect_uri".
//   3. VERCEL_URL — last-resort preview host
//   4. localhost for local dev
const BASE_URL = process.env.DASHBOARD_BASE_URL
    || (process.env.VERCEL_PROJECT_PRODUCTION_URL
        ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
        : (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `http://localhost:${PORT}`));
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || `${BASE_URL}/auth/callback`;

const SESSION_SECRET = process.env.SESSION_SECRET || 'primebot-dashboard-dev-secret-change-me';

// Idle auto-logout: while the dashboard tab is visible the client heartbeats
// /api/session/heartbeat, which refreshes this deadline. When the tab is
// hidden (backgrounded/minimized) the client stops heartbeating AND starts a
// local 120s countdown that ends in logout. The server-side deadline is the
// safety net for cases where the client JS can't run (tab closed, browser
// throttled the timer, crash) — once it lapses, the next authenticated request
// is treated as expired and the user is bounced to /login?error=idle_timeout.
const SESSION_IDLE_TIMEOUT_MS = constants.SESSION_IDLE_TIMEOUT_MS;

// On Vercel (serverless), MemoryStore is useless because each request may run
// in a fresh instance. Store sessions in the dedicated SEASON_DATABASE_URL pool
// (which falls back to DATABASE_URL), shared with the shardnode failover
// service so the dashboard and bot see the same rows.
//
// CRITICAL: the session pool must negotiate SSL the same way the bot's main
// pool does (server/db.js). Production Postgres on Vercel (Neon, Supabase,
// Vercel Postgres, etc.) REQUIRES SSL; a bare `new Pool({ connectionString })`
// without ssl silently fails every session write. The OAuth callback then
// redirects to "/" on a save error, the session row is never persisted, the
// next /api/me returns 401, and the user lands back on the login screen —
// i.e. "login works but never reaches the dashboard". So we reuse an
// already-SSL-aware pool rather than constructing a naive one.
function buildSessionStore() {
    let pool = null;
    try {
        pool = require('../server/seasonDb').seasonPool;
    } catch (err) {
        console.warn('[SESSION] Could not import season pool, falling back to a local pool:', err.message);
    }
    if (!pool && process.env.DATABASE_URL) {
        const dbUrl = process.env.DATABASE_URL;
        pool = new Pool({
            connectionString: dbUrl,
            ssl: /sslmode=require/.test(dbUrl) ? { rejectUnauthorized: false } : (process.env.DB_SSL === 'require' ? { rejectUnauthorized: false } : undefined),
        });
    }
    if (pool) {
        return new PgSession({
            pool,
            // Use a dedicated table — a generic "session" table may already
            // exist in the shared DB with a different schema (e.g. another app's
            // auth table), which would break connect-pg-simple.
            tableName: 'primebot_dashboard_session',
            // connect-pg-simple honors `createTableIfMissing` (the
            // `createTableIfNotExists` name is silently ignored).
            createTableIfMissing: true,
            pruneSessionInterval: false,
            // Surface connection failures instead of hanging on cold starts.
            errorLog: (err) => console.error('[SESSION] PgSession store error:', err && err.message ? err.message : err),
        });
    }
    // Local dev fallback (single process).
    return undefined;
}

// Resolved at boot via /users/@me — the real bot user ID (may differ from
// DISCORD_CLIENT_ID if the env points token + client id at different apps).
let botUserId = process.env.DISCORD_CLIENT_ID || null;
let botSelf = null;

// ── Middleware ──────────────────────────────────────────────────────────────

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Secure cookies whenever we're not on plain localhost. Vercel, the work host,
// and production all serve HTTPS, so the session cookie must be marked Secure
// or browsers will silently drop it.
const isLocalhost = BASE_URL.startsWith('http://localhost');
const cookieSecure = !isLocalhost;

const sessionStore = buildSessionStore();
app.use(session({
    name: constants.SESSION_COOKIE,
    secret: SESSION_SECRET,
    // Trust Vercel's TLS-terminating proxy so Secure cookies are set/sent
    // correctly (x-forwarded-proto: https). Without `proxy: true`,
    // express-session ignores the forward-proto header for the Secure-cookie
    // decision and login silently fails on serverless.
    proxy: true,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        httpOnly: true,
        secure: cookieSecure,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
}));

// Expose a few constants to all templates via res.locals.
app.use((req, res, next) => {
    res.locals.botName = constants.BOT_NAME;
    res.locals.botVersion = constants.BOT_VERSION;
    res.locals.botWebsite = constants.BOT_WEBSITE;
    res.locals.botSupport = constants.BOT_SUPPORT;
    res.locals.user = req.session && req.session.user;
    // Injected into the page shell for session-timeout.js (see render/layout.js).
    res.locals.idleTimeoutMs = SESSION_IDLE_TIMEOUT_MS;
    next();
});

// Static frontend assets.
app.use(express.static(path.join(__dirname, 'public')));

// Request logging — opt-in via DASHBOARD_LOG_REQUESTS=true (off by default).
if (process.env.DASHBOARD_LOG_REQUESTS === 'true') {
    app.use((req, res, next) => {
        console.log(`${req.method} ${req.url} — user:${req.session && req.session.user ? req.session.user.username : 'none'}`);
        next();
    });
}

// ── Auth routes ─────────────────────────────────────────────────────────────

app.get('/login', (req, res) => {
    if (req.session && req.session.user) return res.redirect('/');
    // Render the server-side login page; if ?error=... is present it shows a
    // human-readable reason (e.g. session persistence failed after Discord auth)
    // instead of silently bouncing back to Discord.
    res.type('html').send(pages.loginPage({ errorKey: req.query.error, turnstileSiteKey: constants.TURNSTILE_SITE_KEY }));
});

// Starts the Discord OAuth2 flow. The login page's "Login with Discord" button
// points here (separate from /login, which now renders the page). When
// TURNSTILE_SECRET_KEY is configured, the invisible Turnstile token from the
// login page must verify with Cloudflare before the OAuth redirect is issued.
app.get('/auth/discord', async (req, res) => {
    if (req.session && req.session.user) return res.redirect('/');
    if (turnstile.isTurnstileEnabled()) {
        try {
            const result = await turnstile.verifyTurnstile(req.query['cf-turnstile-response'], req.ip);
            if (!result.success) {
                console.warn('[AUTH] Turnstile verification failed:', result['error-codes'] || 'unknown');
                return res.redirect('/login?error=turnstile_failed');
            }
        } catch (err) {
            console.error('[AUTH] Turnstile verification error:', err.message);
            return res.redirect('/login?error=turnstile_failed');
        }
    }
    const params = new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: constants.OAUTH_SCOPE,
    });
    res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get('/auth/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) return res.redirect('/login?error=missing_code');
    try {
        const tokens = await discord.exchangeCode(code, REDIRECT_URI);
        const user = await discord.getCurrentUser(tokens.access_token);
        // Cache guild list right away so the dashboard loads fast.
        let guilds = [];
        try { guilds = await discord.getUserGuilds(tokens.access_token); } catch (err) {
            console.warn('[AUTH] Could not fetch guilds during login:', err.message);
        }

        req.session.accessToken = tokens.access_token;
        req.session.refreshToken = tokens.refresh_token;
        req.session.tokenExpiresAt = Date.now() + (tokens.expires_in * 1000);
        req.session.user = {
            id: user.id,
            username: user.username,
            discriminator: user.discriminator,
            globalName: user.global_name,
            avatar: user.avatar,
        };
        req.session.guilds = guilds;
        req.session.guildsFetchedAt = Date.now();
        // Start the idle-auto-logout clock: the deadline is refreshed by the
        // client heartbeat while the tab is visible and by every authenticated
        // request. See dashboard/auth.js touchIdleDeadline.
        req.session.idleExpiresAt = Date.now() + SESSION_IDLE_TIMEOUT_MS;

        console.log(`[AUTH] Login OK for ${user.username} (${user.id}); ${guilds.length} guilds`);

        // Persist the session before redirecting, otherwise the Set-Cookie
        // header is not guaranteed to be written before the browser follows
        // the redirect to "/" (causing a bounce back to /login).
        // If the session store is broken (e.g. SSL to Postgres failed), surface
        // it instead of redirecting to a dashboard that will immediately 401.
        req.session.save((err) => {
            if (err) {
                console.error('[AUTH] Session save failed — redirecting to login with error:', err.message);
                return res.redirect('/login?error=session_failed');
            }
            res.redirect('/');
        });
    } catch (err) {
        console.error('[AUTH] Callback error:', err.message);
        res.redirect('/login?error=auth_failed');
    }
});

app.get('/logout', (req, res) => {
    const reason = req.query.reason;
    req.session.destroy(() => {
        res.clearCookie(constants.SESSION_COOKIE);
        // An idle-timeout logout (vs a manual click) surfaces a friendly
        // "session expired" message on the login page. Manual logout keeps the
        // existing behavior of landing on "/" (which redirects to /login).
        if (reason === 'idle_timeout') {
            return res.redirect('/login?error=idle_timeout');
        }
        res.redirect('/');
    });
});

// ── Idle auto-logout heartbeat ──────────────────────────────────────────────
//
// While the dashboard tab is visible, session-timeout.js POSTs here on an
// interval (well under SESSION_IDLE_TIMEOUT_MS) to refresh the server-side idle
// deadline. The tab being visible ⇒ the user is "active"; a hidden tab stops
// heartbeating, so the deadline lapses after SESSION_IDLE_TIMEOUT_MS and the
// next authenticated request (or this very endpoint) logs them out. This is the
// server-side guarantee behind the client's Page-Visibility-driven countdown.
app.post('/api/session/heartbeat', requireAuth, (req, res) => {
    res.json({ ok: true, idleExpiresAt: req.session.idleExpiresAt, idleTimeoutMs: SESSION_IDLE_TIMEOUT_MS });
});

// Read-only accessor so the client can sync its local countdown to the server's
// authoritative deadline (handles clock drift / resumed sessions).
app.get('/api/session/heartbeat', requireAuth, (req, res) => {
    res.json({ ok: true, idleExpiresAt: req.session.idleExpiresAt, idleTimeoutMs: SESSION_IDLE_TIMEOUT_MS });
});

// ── API: current user ───────────────────────────────────────────────────────

app.get('/api/me', requireAuth, async (req, res) => {
    await resolveBotSelf();
    res.json({ user: req.session.user, bot: botSelf, clientId: process.env.DISCORD_CLIENT_ID });
});

// ── API: public platform stats (login screen, no auth required) ─────────────
//
// Aggregated adoption numbers pulled from the bot's settings tables. Used to
// render the animated stat cards + donut charts on the login page. Every query
// degrades to zero on failure, so a DB hiccup never blocks the login screen.

app.get('/api/stats', async (req, res) => {
    try {
        await resolveBotSelf();
        // The authoritative server count is "how many guilds the bot is in",
        // fetched from Discord via REST. server_settings rows are created
        // lazily and undercount guilds that were never configured. Fall back to
        // the DB count if the REST call fails (e.g. token issue) so the page
        // never renders a misleading 0.
        const restCount = await discord.getBotGuildCount();
        const stats = await dashboardDb.getPlatformStats(restCount);
        res.json({ ...stats, bot: botSelf, clientId: process.env.DISCORD_CLIENT_ID });
    } catch (err) {
        console.error('[API] /api/stats error:', err.message);
        // Return neutral stats so the login page still renders its graphic shell.
        res.json({
            servers: 0,
            botName: constants.BOT_NAME,
            botVersion: constants.BOT_VERSION,
            features: {
                leveling: { count: 0, percent: 0 },
                welcome: { count: 0, percent: 0 },
                autoReactions: { count: 0, percent: 0 },
                broadcasts: { count: 0, percent: 0 },
            },
            welcomeBanners: 0,
            bot: botSelf,
            clientId: process.env.DISCORD_CLIENT_ID,
        });
    }
});

// ── API: list manageable guilds (admin's guilds where the bot is present) ───

// Detailed bot stats for the Stats page. The dashboard process can't see the
// bot's in-memory runtime (ping/uptime/guilds.cache), so this returns what the
// dashboard CAN measure: the authoritative server count (Discord REST), the bot
// identity, version, and platform feature adoption.
app.get('/api/stats/bot', requireAuth, async (req, res) => {
    try {
        await resolveBotSelf();
        const restCount = await discord.getBotGuildCount();
        const stats = await dashboardDb.getPlatformStats(restCount);
        res.json({
            ...stats,
            bot: botSelf,
            clientId: process.env.DISCORD_CLIENT_ID,
            version: constants.BOT_VERSION,
        });
    } catch (err) {
        console.error('[API] /api/stats/bot error:', err.message);
        res.status(500).json({ error: 'Failed to load bot stats.' });
    }
});

// Shardnode + failover status for the Stats page. Reads the heartbeat/lease
// tables the bot's nodeFailover module writes.
app.get('/api/stats/nodes', requireAuth, async (req, res) => {
    try {
        const nodes = await dashboardDb.getNodeStats();
        res.json(nodes);
    } catch (err) {
        console.error('[API] /api/stats/nodes error:', err.message);
        res.status(500).json({ error: 'Failed to load node stats.' });
    }
});

app.get('/api/guilds', requireAuth, async (req, res) => {
    try {
        const accessToken = req.session.accessToken;
        let guilds = req.session.guilds;
        const fetchedAt = req.session.guildsFetchedAt || 0;
        const cacheFresh = Array.isArray(guilds) && Date.now() - fetchedAt <= 5 * 60 * 1000;
        if (!cacheFresh) {
            if (!accessToken) {
                // No user OAuth token available (e.g. debug session or token expired
                // and can't be refreshed). Fall back to whatever is cached so the
                // dashboard can still render instead of throwing.
                if (!Array.isArray(guilds)) guilds = [];
            } else {
                try {
                    guilds = await discord.getUserGuilds(accessToken);
                } catch (err) {
                    // Access token may have expired — try a refresh once.
                    if (req.session.refreshToken) {
                        try {
                            const tokens = await discord.refreshToken(req.session.refreshToken);
                            req.session.accessToken = tokens.access_token;
                            req.session.refreshToken = tokens.refresh_token || req.session.refreshToken;
                            req.session.tokenExpiresAt = Date.now() + (tokens.expires_in * 1000);
                            guilds = await discord.getUserGuilds(tokens.access_token);
                        } catch (refreshErr) {
                            console.warn('[API] token refresh failed:', refreshErr.message);
                            if (!Array.isArray(guilds)) guilds = [];
                        }
                    } else {
                        console.warn('[API] getUserGuilds failed and no refresh token:', err.message);
                        if (!Array.isArray(guilds)) guilds = [];
                    }
                }
                req.session.guilds = guilds;
                req.session.guildsFetchedAt = Date.now();
            }
        }

        const manageable = guilds.filter(g => discord.canManageGuild(g.permissions));

        // For each manageable guild, check bot presence in parallel (with a cap).
        const result = await Promise.all(manageable.slice(0, 50).map(async (g) => {
            let botInGuild = false;
            let config = null;
            try {
                await discord.getBotGuild(g.id);
                botInGuild = true;
                // Fetch config summary for the overview cards.
                config = await dashboardDb.getGuildConfig(g.id).catch(() => null);
            } catch (err) {
                botInGuild = false;
            }
            return {
                id: g.id,
                name: g.name,
                icon: g.icon,
                owner: g.owner,
                approximate_member_count: g.approximate_member_count,
                permissions: g.permissions,
                botPresent: botInGuild,
                welcomeEnabled: config?.welcome?.enabled ?? false,
                levelingEnabled: config?.server?.leveling?.enabled ?? true,
                prefix: config?.server?.prefix ?? constants.DEFAULT_PREFIX,
            };
        }));

        res.json({ guilds: result });
    } catch (err) {
        console.error('[API] /api/guilds error:', err.message);
        res.status(500).json({ error: 'Failed to load guilds.' });
    }
});

// ── API: full guild config (settings page) ──────────────────────────────────

app.get('/api/guilds/:guildId/config', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const config = await dashboardDb.getGuildConfig(req.guild.id);
        res.json({ guild: req.guild, config });
    } catch (err) {
        console.error('[API] get config error:', err.message);
        res.status(500).json({ error: 'Failed to load configuration.' });
    }
});

// ── API: guild channels (for selectors) ─────────────────────────────────────

app.get('/api/guilds/:guildId/channels', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const channels = await discord.getGuildChannels(req.guild.id);
        res.json({ channels: channels.map(c => ({ id: c.id, name: c.name })) });
    } catch (err) {
        console.error('[API] get channels error:', err.message);
        res.status(500).json({ error: 'Failed to load channels. Make sure PrimeBot has the View Channels permission.' });
    }
});

// ── API: update welcome settings ────────────────────────────────────────────

app.patch('/api/guilds/:guildId/welcome', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const allowed = [
            'enabled', 'channelId', 'message', 'bannerUrl', 'color',
            'dmEnabled', 'dmMessage',
            'showMemberCount', 'showJoinDate', 'showAccountAge',
            'customTitle', 'customFooter',
        ];
        const patch = {};
        for (const key of allowed) {
            if (key in req.body) patch[key] = req.body[key];
        }
        // Normalize booleans.
        for (const boolKey of ['enabled', 'dmEnabled', 'showMemberCount', 'showJoinDate', 'showAccountAge']) {
            if (boolKey in patch) patch[boolKey] = Boolean(patch[boolKey]);
        }
        // Null out empty channel id.
        if ('channelId' in patch && !patch.channelId) patch.channelId = null;
        const updated = await dashboardDb.upsertWelcomeSettings(req.guild.id, patch);
        recordWebsiteLog(req, 'Updated welcome message settings');
        res.json({ welcome: updated });
    } catch (err) {
        console.error('[API] update welcome error:', err.message);
        res.status(500).json({ error: 'Failed to update welcome settings.' });
    }
});

// ── API: update server settings (prefix, leveling, auto-reactions, broadcast) ─

app.patch('/api/guilds/:guildId/server', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const patch = {};

        if ('prefix' in body) patch.prefix = body.prefix;
        if ('receiveBroadcasts' in body) patch.receiveBroadcasts = Boolean(body.receiveBroadcasts);
        if ('broadcastChannelId' in body) patch.broadcastChannelId = body.broadcastChannelId || null;

        // Leveling sub-object — merge with current.
        if (body.leveling && typeof body.leveling === 'object') {
            const current = await dashboardDb.getServerSettings(req.guild.id);
            patch.leveling = {
                ...(current.leveling || {}),
                ...body.leveling,
            };
            if ('enabled' in patch.leveling) patch.leveling.enabled = Boolean(patch.leveling.enabled);
            if ('xpMultiplier' in patch.leveling) {
                const m = Number(patch.leveling.xpMultiplier);
                if (!Number.isFinite(m) || m <= 0 || m > 5) {
                    return res.status(400).json({ error: 'XP multiplier must be between 0 and 5.' });
                }
                patch.leveling.xpMultiplier = Number(m.toFixed(2));
            }
            if ('xpCooldown' in patch.leveling) {
                const seconds = Number(patch.leveling.xpCooldown);
                if (!Number.isFinite(seconds) || seconds < 5 || seconds > 300) {
                    return res.status(400).json({ error: 'XP cooldown must be between 5 and 300 seconds.' });
                }
                patch.leveling.xpCooldown = Math.round(seconds * 1000);
            }
            if ('levelUpChannelId' in patch.leveling) patch.leveling.levelUpChannelId = patch.leveling.levelUpChannelId || null;
        }

        // Auto-reactions sub-object — drop malformed entries (no trigger/emoji)
        // so a bad row can't silently break message.react() in the bot.
        if (body.autoReactions && typeof body.autoReactions === 'object') {
            const current = await dashboardDb.getServerSettings(req.guild.id);
            const reactions = Array.isArray(body.autoReactions.reactions)
                ? body.autoReactions.reactions
                    .filter(r => r && typeof r === 'object' && r.trigger && r.emoji)
                    .map(r => ({
                        trigger: String(r.trigger),
                        emoji: String(r.emoji),
                        caseSensitive: Boolean(r.caseSensitive),
                    }))
                : (current.autoReactions?.reactions || []);
            patch.autoReactions = {
                enabled: body.autoReactions.enabled ?? current.autoReactions?.enabled ?? false,
                reactions,
            };
            if ('enabled' in body.autoReactions) patch.autoReactions.enabled = Boolean(body.autoReactions.enabled);
        }

        // Auto-responder sub-object. Each response is normalized to
        // { trigger, response, caseSensitive, exactMatch }.
        if (body.autoResponder && typeof body.autoResponder === 'object') {
            const current = await dashboardDb.getServerSettings(req.guild.id);
            const responses = Array.isArray(body.autoResponder.responses)
                ? body.autoResponder.responses
                    .filter(r => r && typeof r === 'object' && r.trigger && r.response)
                    .map(r => ({
                        trigger: String(r.trigger),
                        response: String(r.response),
                        caseSensitive: Boolean(r.caseSensitive),
                        exactMatch: Boolean(r.exactMatch),
                    }))
                : (current.autoResponder?.responses || []);
            patch.autoResponder = {
                enabled: body.autoResponder.enabled ?? current.autoResponder?.enabled ?? false,
                responses,
            };
            if ('enabled' in body.autoResponder) patch.autoResponder.enabled = Boolean(body.autoResponder.enabled);
        }

        const updated = await dashboardDb.upsertServerSettings(req.guild.id, patch);
        if ('prefix' in patch) recordWebsiteLog(req, `Updated command prefix to "${patch.prefix}"`);
        if (body.leveling) recordWebsiteLog(req, 'Updated leveling settings');
        if (body.autoReactions) recordWebsiteLog(req, 'Updated auto-reactions settings');
        if (body.autoResponder) recordWebsiteLog(req, 'Updated auto-responder settings');
        if ('receiveBroadcasts' in body) recordWebsiteLog(req, `Updated broadcast settings (receive: ${body.receiveBroadcasts ? 'on' : 'off'})`);
        res.json({ server: updated });
    } catch (err) {
        console.error('[API] update server error:', err.message);
        res.status(500).json({ error: 'Failed to update server settings.' });
    }
});

// ── API: leveling role rewards (durable, separate LEVELING_DATABASE_URL pool)
// The bot re-reads these on its cache reload so dashboard changes take effect
// without a bot restart. Slash (/leveling addrole|removerole|listroles) writes
// to the same table.
app.get('/api/guilds/:guildId/leveling/rolerewards', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const rewards = await dashboardDb.getLevelingRoleRewards(req.guild.id);
        res.json({ roleRewards: rewards });
    } catch (err) {
        console.error('[API] get leveling role rewards error:', err.message);
        res.status(500).json({ error: 'Failed to load leveling role rewards.' });
    }
});

app.put('/api/guilds/:guildId/leveling/rolerewards', requireAuth, requireGuildAdmin, requireBeta, async (req, res) => {
    try {
        const rewards = await dashboardDb.setLevelingRoleRewards(req.guild.id, req.body?.roleRewards || []);
        recordWebsiteLog(req, 'Updated leveling role rewards');
        res.json({ roleRewards: rewards });
    } catch (err) {
        console.error('[API] set leveling role rewards error:', err.message);
        res.status(500).json({ error: 'Failed to save leveling role rewards.' });
    }
});

// ── API: leveling badges (beta) ─────────────────────────────────────────────
// Reads the user_badges table (LEVELING_DATABASE_URL pool) so the Badges tab
// can show a live ledger, and lets beta-server admins award/revoke achievement
// & special badges. Level badges are earned automatically on level-up and are
// not awardable from the dashboard. The catalog comes from config.leveling.badges
// (mirrored in constants.BADGE_CATALOG) — the API only stores awarded rows.

app.get('/api/guilds/:guildId/badges', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const badges = await dashboardDb.getGuildBadges(req.guild.id, req.query.userId);
        res.json({ badges });
    } catch (err) {
        console.error('[API] get badges error:', err.message);
        res.status(500).json({ error: 'Failed to load badges.' });
    }
});

app.post('/api/guilds/:guildId/badges/award', requireAuth, requireGuildAdmin, requireBeta, async (req, res) => {
    try {
        const { userId, badgeType, badgeId } = req.body || {};
        if (!userId || !badgeType || !badgeId) {
            return res.status(400).json({ error: 'userId, badgeType and badgeId are required.' });
        }
        if (!['achievement', 'special'].includes(badgeType)) {
            return res.status(400).json({ error: 'Only achievement and special badges can be awarded from the dashboard.' });
        }
        const catalog = constants.BADGE_CATALOG || {};
        const list = badgeType === 'achievement' ? catalog.achievementBadges : catalog.specialBadges;
        const badge = (list || []).find(b => b.id === badgeId);
        if (!badge) return res.status(400).json({ error: 'Badge not found in catalog.' });
        const badges = await dashboardDb.awardDashboardBadge(req.guild.id, { userId, badgeType, badge });
        recordWebsiteLog(req, `Awarded ${badgeType} badge "${badge.name}" to <@${userId}>`);
        res.json({ badges });
    } catch (err) {
        if (err.code === 'already_has_badge') {
            return res.status(409).json({ error: 'That member already has this badge.', reason: 'already_has_badge' });
        }
        console.error('[API] award badge error:', err.message);
        res.status(500).json({ error: 'Failed to award badge.' });
    }
});

app.delete('/api/guilds/:guildId/badges/:rowId', requireAuth, requireGuildAdmin, requireBeta, async (req, res) => {
    try {
        const rowId = parseInt(req.params.rowId, 10);
        if (!Number.isFinite(rowId)) return res.status(400).json({ error: 'Invalid badge row id.' });
        await dashboardDb.revokeDashboardBadge(req.guild.id, rowId);
        recordWebsiteLog(req, `Revoked badge row #${rowId}`);
        res.json({ ok: true });
    } catch (err) {
        console.error('[API] revoke badge error:', err.message);
        res.status(500).json({ error: 'Failed to revoke badge.' });
    }
});

// ── API: birthdays ──────────────────────────────────────────────────────────
// Reads/writes the birthdays + birthdays_guilds tables (BIRTHDAY_DATABASE_URL
// pool) so the Birthdays tab can list every registered birthday, add/remove
// entries, and set the announcement channel, birthday role and the custom
// embed image URL. The bot's BirthdayManager re-reads these tables every ~5s
// so dashboard edits take effect without a bot restart.

app.get('/api/guilds/:guildId/birthdays', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const [settings, birthdays] = await Promise.all([
            dashboardDb.getGuildBirthdaySettings(req.guild.id),
            dashboardDb.getGuildBirthdays(req.guild.id),
        ]);
        res.json({ settings, birthdays });
    } catch (err) {
        console.error('[API] get birthdays error:', err.message);
        res.status(500).json({ error: 'Failed to load birthdays.' });
    }
});

app.patch('/api/guilds/:guildId/birthdays', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const patch = {};
        if ('channelId' in body) patch.channelId = body.channelId || null;
        if ('roleId' in body) patch.roleId = body.roleId || null;
        if ('imageUrl' in body) {
            const url = String(body.imageUrl || '').trim();
            if (url && !/^https?:\/\/\S+/i.test(url)) {
                return res.status(400).json({ error: 'Image URL must be a valid http(s) URL.' });
            }
            patch.imageUrl = url || null;
        }
        const settings = await dashboardDb.upsertGuildBirthdaySettings(req.guild.id, patch);
        if ('imageUrl' in patch) recordWebsiteLog(req, patch.imageUrl ? 'Set a custom birthday embed image' : 'Cleared the custom birthday embed image');
        if ('channelId' in patch) recordWebsiteLog(req, 'Updated birthday announcement channel');
        if ('roleId' in patch) recordWebsiteLog(req, 'Updated birthday role');
        res.json({ settings });
    } catch (err) {
        console.error('[API] update birthday settings error:', err.message);
        res.status(500).json({ error: 'Failed to save birthday settings.' });
    }
});

app.post('/api/guilds/:guildId/birthdays', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const { userId, month, day, year } = req.body || {};
        const m = parseInt(month, 10);
        const d = parseInt(day, 10);
        const y = year != null && year !== '' ? parseInt(year, 10) : null;
        if (!userId || !/^\d{17,20}$/.test(String(userId))) {
            return res.status(400).json({ error: 'A valid member user ID (17-20 digits) is required.' });
        }
        if (!Number.isFinite(m) || m < 1 || m > 12 || !Number.isFinite(d) || d < 1 || d > 31) {
            return res.status(400).json({ error: 'Month must be 1-12 and day must be 1-31.' });
        }
        if (y != null && (!Number.isFinite(y) || y < 1900 || y > new Date().getFullYear())) {
            return res.status(400).json({ error: 'Year must be between 1900 and the current year.' });
        }
        const birthdays = await dashboardDb.addGuildBirthday(req.guild.id, { userId, month: m, day: d, year: y });
        recordWebsiteLog(req, `Added birthday for <@${userId}> (${m}/${d}${y ? `/${y}` : ''})`);
        res.json({ birthdays });
    } catch (err) {
        console.error('[API] add birthday error:', err.message);
        res.status(500).json({ error: 'Failed to add birthday.' });
    }
});

app.delete('/api/guilds/:guildId/birthdays/:userId', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const userId = String(req.params.userId || '');
        if (!/^\d{17,20}$/.test(userId)) return res.status(400).json({ error: 'Invalid user ID.' });
        const birthdays = await dashboardDb.removeGuildBirthday(req.guild.id, userId);
        recordWebsiteLog(req, `Removed birthday for <@${userId}>`);
        res.json({ birthdays });
    } catch (err) {
        console.error('[API] remove birthday error:', err.message);
        res.status(500).json({ error: 'Failed to remove birthday.' });
    }
});

// ── API: update logging settings (channel, webhook, events) ─────────────────

app.patch('/api/guilds/:guildId/logging', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const allowed = [
            'enabled', 'channelId', 'webhookUrl', 'webhookName',
            'events', 'includeBots', 'color',
        ];
        const patch = {};
        for (const key of allowed) {
            if (key in req.body) patch[key] = req.body[key];
        }
        if ('enabled' in patch)     patch.enabled = Boolean(patch.enabled);
        if ('includeBots' in patch) patch.includeBots = Boolean(patch.includeBots);
        if ('channelId' in patch)   patch.channelId = patch.channelId || null;
        if ('webhookUrl' in patch)  patch.webhookUrl = patch.webhookUrl || null;
        // Basic webhook URL sanity check — must be a Discord webhook if provided.
        if (patch.webhookUrl && !/^https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\//i.test(patch.webhookUrl)) {
            return res.status(400).json({ error: 'Webhook URL must be a valid Discord webhook URL.' });
        }
        if ('color' in patch && patch.color && !/^#[0-9a-fA-F]{6}$/.test(patch.color)) {
            return res.status(400).json({ error: 'Color must be a hex color like #5865F2.' });
        }
        const updated = await dashboardDb.upsertLoggingSettings(req.guild.id, patch);
        recordWebsiteLog(req, 'Updated server logging settings');
        res.json({ logging: updated });
    } catch (err) {
        console.error('[API] update logging error:', err.message);
        res.status(500).json({ error: 'Failed to update logging settings.' });
    }
});

// ── API: website logs (dashboard admin-action audit trail) ──────────────────
//
// Each settings save records a row in website_logs (LOG_DATABASE_URL pool). The
// General settings page fetches the most recent entries and renders them in a
// table (sl no, admin username, content, time) beside the prefix card.

app.get('/api/guilds/:guildId/logs/website', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit, 10) || 100;
        const logs = await dashboardDb.getWebsiteLogs(req.guild.id, limit);
        res.json({ logs });
    } catch (err) {
        console.error('[API] get website logs error:', err.message);
        res.status(500).json({ error: 'Failed to load website logs.' });
    }
});

// Record a website log entry for the current admin (fire-and-forget). Never
// throws — a logging failure must not break the settings save it accompanies.
function recordWebsiteLog(req, content) {
    const user = req.session && req.session.user;
    dashboardDb.addWebsiteLog(req.guild.id, {
        adminUserId: user && user.id || '',
        adminUsername: (user && (user.globalName || user.username)) || 'Unknown',
        content,
    }).catch(err => console.error('[API] website log write failed:', err.message));
}

// ── API: Premium Automod settings + warnings ─────────────────────────────────

app.patch('/api/guilds/:guildId/automod', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const allowed = [
            'enabled', 'logChannelId', 'muteRoleId',
            'exemptRoleIds', 'exemptChannelIds', 'rules',
            'warnThreshold', 'warnAction', 'warnActions',
            'dmEnabled', 'dmMessages', 'appealChannelId',
        ];
        const patch = {};
        for (const key of allowed) {
            if (key in req.body) patch[key] = req.body[key];
        }
        if ('enabled' in patch) patch.enabled = Boolean(patch.enabled);
        if ('logChannelId' in patch) patch.logChannelId = patch.logChannelId || null;
        if ('muteRoleId' in patch) patch.muteRoleId = patch.muteRoleId || null;
        if ('warnThreshold' in patch) patch.warnThreshold = parseInt(patch.warnThreshold, 10) || 3;
        if ('warnAction' in patch && !['warn', 'timeout', 'kick', 'ban'].includes(patch.warnAction)) {
            return res.status(400).json({ error: 'warnAction must be warn, timeout, kick, or ban.' });
        }
        if ('warnActions' in patch) {
            const wa = Array.isArray(patch.warnActions) ? patch.warnActions : [];
            const valid = wa.filter(a => ['warn', 'timeout', 'kick', 'ban'].includes(a));
            if (valid.length === 0) {
                return res.status(400).json({ error: 'warnActions must contain at least one of warn, timeout, kick, ban.' });
            }
            patch.warnActions = valid;
        }
        if ('dmEnabled' in patch) patch.dmEnabled = patch.dmEnabled !== false;
        if ('appealChannelId' in patch) patch.appealChannelId = patch.appealChannelId || null;
        const updated = await dashboardDb.upsertAutomodSettings(req.guild.id, patch);
        recordWebsiteLog(req, 'Updated automod settings');
        res.json({ automod: updated });
    } catch (err) {
        console.error('[API] update automod error:', err.message);
        res.status(500).json({ error: 'Failed to update automod settings.' });
    }
});

app.get('/api/guilds/:guildId/automod/warnings', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const warnings = await dashboardDb.getAutomodWarnings(req.guild.id);
        res.json({ warnings });
    } catch (err) {
        console.error('[API] get automod warnings error:', err.message);
        res.status(500).json({ error: 'Failed to load warnings.' });
    }
});

app.delete('/api/guilds/:guildId/automod/warnings', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const userId = req.query.userId || null;
        await dashboardDb.clearAutomodWarnings(req.guild.id, userId);
        res.json({ ok: true });
    } catch (err) {
        console.error('[API] clear automod warnings error:', err.message);
        res.status(500).json({ error: 'Failed to clear warnings.' });
    }
});

// ── API: Automod appeals ─────────────────────────────────────────────────────

app.get('/api/guilds/:guildId/automod/appeals', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const status = req.query.status || null;
        const appeals = await dashboardDb.getAutomodAppeals(req.guild.id, { status });
        res.json({ appeals });
    } catch (err) {
        console.error('[API] get automod appeals error:', err.message);
        res.status(500).json({ error: 'Failed to load appeals.' });
    }
});

app.post('/api/guilds/:guildId/automod/appeals', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const userId = String(req.body?.userId || '').trim();
        const action = String(req.body?.action || '').trim();
        const reason = String(req.body?.reason || '').trim();
        if (!userId || !action) {
            return res.status(400).json({ error: 'userId and action are required.' });
        }
        const appeal = await dashboardDb.submitAutomodAppeal(req.guild.id, { userId, action, reason });
        res.json({ appeal });
    } catch (err) {
        console.error('[API] submit automod appeal error:', err.message);
        res.status(500).json({ error: 'Failed to submit appeal.' });
    }
});

app.patch('/api/guilds/:guildId/automod/appeals/:id', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        const approved = req.body?.approved === true || req.body?.decision === 'approved';
        const note = String(req.body?.note || '').trim();
        const decidedBy = req.user?.discordId || null;
        const appeal = await dashboardDb.decideAutomodAppeal(id, { approved, decidedBy, note });
        if (!appeal) return res.status(404).json({ error: 'Appeal not found or already decided.' });
        // Ask the bot to reverse the action when approved (the bot reads the
        // status change on its next reload; reversal is best-effort).
        res.json({ appeal });
    } catch (err) {
        console.error('[API] decide automod appeal error:', err.message);
        res.status(500).json({ error: 'Failed to decide appeal.' });
    }
});

// ── API: guild roles (for reaction-role selectors) ──────────────────────────

app.get('/api/guilds/:guildId/roles', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        // Exclude roles the bot can't assign (at/above its highest role, or
        // integration-managed) so reaction-role / leveling selectors never offer
        // a role that would fail with a 50007 "Missing Access" error.
        const roles = await discord.getGuildRoles(req.guild.id, { excludeUnassignable: true });
        res.json({ roles: roles.map(r => ({
            id: r.id, name: r.name, position: r.position, color: r.color,
            mentionable: r.mentionable, hoist: r.hoist,
        })) });
    } catch (err) {
        console.error('[API] get roles error:', err.message);
        res.status(500).json({ error: 'Failed to load roles. Make sure PrimeBot has the Manage Roles permission.' });
    }
});

// ── API: reaction-role menus ────────────────────────────────────────────────
//
// Two creation flows mirror the /reactionrole slash command:
//   POST .../reactionroles  { attach: false, channelId, title, description,
//                            color, mode, mappings, ... }
//       → dashboard posts the embed via REST, captures the message id, persists
//         the row; the bot starts watching on its next cache reload.
//   POST .../reactionroles  { attach: true, channelId, messageId, mappings, ... }
//       → dashboard validates the message exists, adds the reactions via REST,
//         and persists the row.
//   PATCH .../reactionroles/:id   { ...patch }   edit settings/mappings
//   DELETE .../reactionroles/:id                  delete (and remove the bot's
//                                                 embed message if it sent it)

function rrEmojiDisplay(emoji) {
    if (/^\w+:\d+$/.test(emoji)) return `<:${emoji}>`;
    return emoji;
}

function rrEmbedPayload(menu) {
    const color = parseInt((menu.color || '#5865F2').replace('#', ''), 16);
    const fields = (menu.mappings || []).length
        ? [{ name: 'Roles', value: (menu.mappings || []).map(m => `${rrEmojiDisplay(m.emoji)} → <@&${m.roleId}>${m.label ? ` — ${m.label}` : ''}`).join('\n') }]
        : [];
    return {
        embeds: [{
            title: menu.title || 'Reaction Roles',
            description: menu.description || 'React to get a role!',
            color,
            fields,
            footer: { text: 'PrimeBot · Reaction Roles' },
        }],
    };
}

app.get('/api/guilds/:guildId/reactionroles', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const menus = await dashboardDb.getReactionRoles(req.guild.id);
        res.json({ reactionRoles: menus });
    } catch (err) {
        console.error('[API] get reaction roles error:', err.message);
        res.status(500).json({ error: 'Failed to load reaction roles.' });
    }
});

app.post('/api/guilds/:guildId/reactionroles', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const mappings = Array.isArray(body.mappings) ? body.mappings : [];
        if (mappings.length === 0) {
            return res.status(400).json({ error: 'Add at least one emoji→role mapping.' });
        }
        if (!body.channelId) {
            return res.status(400).json({ error: 'A channel is required.' });
        }

        // Normalize mappings through the dashboard's parser (dedupe + parse
        // custom-emoji mention form). The bot will re-normalize on its side.
        const cleanMappings = mappings.map(m => ({
            emoji: m.emoji, roleId: m.roleId, label: m.label || null,
        })).filter(m => m.emoji && m.roleId);

        const attach = !!body.attach;
        let messageId = body.messageId || null;

        if (attach) {
            if (!messageId) {
                return res.status(400).json({ error: 'A message ID is required to attach to an existing message.' });
            }
            // Validate the target message exists and the bot can see it.
            try {
                await discord.getChannelMessage(body.channelId, messageId);
            } catch (err) {
                return res.status(400).json({ error: 'Could not find that message. Make sure the bot can see the channel and message.' });
            }
            // Add the reactions to the existing message.
            for (const m of cleanMappings) {
                await discord.addMessageReaction(body.channelId, messageId, parseEmojiForDiscord(m.emoji)).catch(() => {});
            }
        } else {
            // Bot-created menu: post the embed via REST and capture the id.
            const menuForEmbed = {
                title: body.title, description: body.description,
                color: body.color, mappings: cleanMappings,
            };
            const sent = await discord.sendChannelMessage(body.channelId, rrEmbedPayload(menuForEmbed));
            messageId = sent.id;
            for (const m of cleanMappings) {
                await discord.addMessageReaction(body.channelId, messageId, parseEmojiForDiscord(m.emoji)).catch(() => {});
            }
        }

        const menu = await dashboardDb.createReactionRole(req.guild.id, {
            guildId: req.guild.id,
            channelId: body.channelId,
            messageId,
            title: body.title || null,
            description: attach ? null : (body.description || null),
            color: body.color || '#5865F2',
            mode: body.mode || 'normal',
            persistent: body.persistent !== false,
            includeBots: !!body.includeBots,
            requiredRoleId: body.requiredRoleId || null,
            exclusiveRoleId: body.exclusiveRoleId || null,
            mappings: cleanMappings,
            attach,
        });
        res.json({ reactionRole: menu });
    } catch (err) {
        console.error('[API] create reaction role error:', err.message);
        res.status(500).json({ error: 'Failed to create reaction role: ' + err.message });
    }
});

app.patch('/api/guilds/:guildId/reactionroles/:id', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid menu id.' });
        const body = req.body || {};
        const patch = {};
        for (const key of ['title', 'description', 'color', 'mode', 'persistent', 'includeBots', 'requiredRoleId', 'exclusiveRoleId', 'enabled', 'mappings']) {
            if (key in body) patch[key] = body[key];
        }
        const menu = await dashboardDb.updateReactionRole(id, patch);

        // If mappings or embed-visible fields changed on a bot-created menu,
        // re-render the embed and reconcile the reactions on the live message.
        const embedKeys = ['title', 'description', 'color', 'mappings'];
        if (embedKeys.some(k => k in patch) && menu && menu.messageId && menu.description != null) {
            try {
                await discord.editChannelMessage(menu.channelId, menu.messageId, rrEmbedPayload(menu));
            } catch (err) {
                console.error('[API] edit reaction-role embed failed:', err.message);
            }
            if (Array.isArray(patch.mappings)) {
                // Re-add all configured reactions (idempotent).
                for (const m of menu.mappings) {
                    await discord.addMessageReaction(menu.channelId, menu.messageId, parseEmojiForDiscord(m.emoji)).catch(() => {});
                }
            }
        }

        res.json({ reactionRole: menu });
    } catch (err) {
        console.error('[API] update reaction role error:', err.message);
        res.status(500).json({ error: 'Failed to update reaction role: ' + err.message });
    }
});

app.delete('/api/guilds/:guildId/reactionroles/:id', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid menu id.' });
        const menus = await dashboardDb.getReactionRoles(req.guild.id);
        const menu = menus.find(m => m.id === id);
        await dashboardDb.deleteReactionRole(id);
        // If the bot created the embed (description != null), delete the message.
        if (menu && menu.messageId && menu.description != null) {
            await discord.deleteChannelMessage(menu.channelId, menu.messageId).catch(() => {});
        }
        res.json({ ok: true });
    } catch (err) {
        console.error('[API] delete reaction role error:', err.message);
        res.status(500).json({ error: 'Failed to delete reaction role.' });
    }
});

// Convert a stored/entered emoji into the form Discord's reactions route wants.
// Custom emojis stored as "name:id" are accepted; the route uses the same form.
function parseEmojiForDiscord(emoji) {
    return emoji;
}

// ── API: ticket panels ──────────────────────────────────────────────────────
//
// Ticket panels are configurable ONLY from the dashboard (slash/prefix commands
// are disabled). The dashboard writes the DB row directly; the bot's
// TicketPanelManager picks it up on its cache reload.
//
//   GET    .../tickets                         list panels
//   POST   .../tickets                         create a panel
//   PATCH  .../tickets/:id                     edit a panel
//   DELETE .../tickets/:id                      delete a panel
//   POST   .../tickets/:id/clone               clone a panel under a new name
//   POST   .../tickets/:id/rename              rename a panel
//   POST   .../tickets/:id/send                send panel to a channel (capturing message id)
//   POST   .../tickets/:id/update              re-render an existing message by id ("update panel")

// Build the panel message payload (embed or plain) + the open-ticket button
// row, matching the bot's TicketPanelManager.buildPanelMessage so the dashboard
// posts exactly what the bot would.
function ticketPanelMessagePayload(panel) {
    const color = parseInt((panel.color || '#5865F2').replace('#', ''), 16);
    const buttonEmoji = panel.buttonEmoji || undefined;
    const styleMap = { Primary: 1, Secondary: 2, Success: 3, Danger: 4 };
    const buttonStyle = styleMap[panel.buttonStyle] || 1;
    const components = [{
        type: 1, // ActionRow
        components: [{
            type: 2, // Button
            style: buttonStyle,
            custom_id: `ticketpanel:open:${panel.id}`,
            label: panel.buttonLabel || 'Open Ticket',
            ...(buttonEmoji ? { emoji: { name: buttonEmoji } } : {}),
        }],
    }];
    if (panel.messageType === 'plain') {
        return {
            content: panel.content || panel.description || 'Click the button below to open a support ticket.',
            components,
        };
    }
    const embed = {
        title: panel.title || '🎫 Support Tickets',
        description: panel.description || 'Click the button below to open a support ticket.',
        color,
        ...(panel.footerText ? { footer: { text: panel.footerText } } : {}),
        ...(panel.thumbnailUrl ? { thumbnail: { url: panel.thumbnailUrl } } : {}),
        ...(panel.imageUrl ? { image: { url: panel.imageUrl } } : {}),
        timestamp: new Date().toISOString(),
    };
    return { content: panel.content || null, embeds: [embed], components };
}

// Name-conflict errors thrown by the ticket DB helpers carry err.status = 409;
// respond with that friendly message instead of a 500 with the raw error.
function ticketPanelError(res, err, what) {
    const status = err.status || 500;
    const message = status < 500 ? err.message : `Failed to ${what}: ${err.message}`;
    res.status(status).json({ error: message });
}

app.get('/api/guilds/:guildId/tickets', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const panels = await dashboardDb.getTicketPanels(req.guild.id);
        res.json({ ticketPanels: panels });
    } catch (err) {
        console.error('[API] get ticket panels error:', err.message);
        res.status(500).json({ error: 'Failed to load ticket panels.' });
    }
});

app.post('/api/guilds/:guildId/tickets', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        if (!body.name || !String(body.name).trim()) {
            return res.status(400).json({ error: 'A panel name is required.' });
        }
        const panel = await dashboardDb.createTicketPanel(req.guild.id, { ...body, createdBy: req.user.id });
        res.json({ ticketPanel: panel });
    } catch (err) {
        console.error('[API] create ticket panel error:', err.message);
        ticketPanelError(res, err, 'create ticket panel');
    }
});

app.patch('/api/guilds/:guildId/tickets/:id', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid panel id.' });
        const panel = await dashboardDb.updateTicketPanel(id, req.body || {});
        // If the panel was already sent and embed-visible fields changed,
        // re-render the live message so it stays in sync.
        if (panel && panel.messageId && panel.channelId) {
            try {
                await discord.editChannelMessage(panel.channelId, panel.messageId, ticketPanelMessagePayload(panel));
            } catch (err) {
                console.error('[API] edit ticket panel message failed:', err.message);
            }
        }
        res.json({ ticketPanel: panel });
    } catch (err) {
        console.error('[API] update ticket panel error:', err.message);
        ticketPanelError(res, err, 'update ticket panel');
    }
});

app.delete('/api/guilds/:guildId/tickets/:id', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid panel id.' });
        const panels = await dashboardDb.getTicketPanels(req.guild.id);
        const panel = panels.find(p => p.id === id);
        await dashboardDb.deleteTicketPanel(id);
        if (panel && panel.messageId && panel.channelId) {
            await discord.deleteChannelMessage(panel.channelId, panel.messageId).catch(() => {});
        }
        res.json({ ok: true });
    } catch (err) {
        console.error('[API] delete ticket panel error:', err.message);
        res.status(500).json({ error: 'Failed to delete ticket panel.' });
    }
});

app.post('/api/guilds/:guildId/tickets/:id/clone', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid panel id.' });
        const name = (req.body && req.body.name) || null;
        const panel = await dashboardDb.cloneTicketPanel(id, name);
        res.json({ ticketPanel: panel });
    } catch (err) {
        console.error('[API] clone ticket panel error:', err.message);
        ticketPanelError(res, err, 'clone ticket panel');
    }
});

app.post('/api/guilds/:guildId/tickets/:id/rename', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid panel id.' });
        const name = req.body && req.body.name;
        const panel = await dashboardDb.renameTicketPanel(id, name);
        res.json({ ticketPanel: panel });
    } catch (err) {
        console.error('[API] rename ticket panel error:', err.message);
        ticketPanelError(res, err, 'rename ticket panel');
    }
});

// Send the panel to a channel: post the panel message via REST and store the
// resulting channel/message id on the panel so the bot can later "update" it.
app.post('/api/guilds/:guildId/tickets/:id/send', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid panel id.' });
        const channelId = req.body && req.body.channelId;
        if (!channelId) return res.status(400).json({ error: 'A channel is required.' });
        const panel = await dashboardDb.updateTicketPanel(id, { channelId, enabled: true });
        const sent = await discord.sendChannelMessage(channelId, ticketPanelMessagePayload(panel));
        const updated = await dashboardDb.updateTicketPanel(id, { channelId, messageId: sent.id });
        res.json({ ticketPanel: updated });
    } catch (err) {
        console.error('[API] send ticket panel error:', err.message);
        res.status(500).json({ error: 'Failed to send ticket panel: ' + err.message });
    }
});

// Re-render an existing panel message by id (the "update panel" button). The
// messageId may be the panel's stored one or a new one supplied in the body.
app.post('/api/guilds/:guildId/tickets/:id/update', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid panel id.' });
        const panels = await dashboardDb.getTicketPanels(req.guild.id);
        const panel = panels.find(p => p.id === id);
        if (!panel) return res.status(404).json({ error: 'Ticket panel not found.' });
        const messageId = (req.body && req.body.messageId) || panel.messageId;
        const channelId = (req.body && req.body.channelId) || panel.channelId;
        if (!messageId) return res.status(400).json({ error: 'No message id. Send the panel to a channel first, or provide a message id.' });
        if (!channelId) return res.status(400).json({ error: 'No channel bound to this panel.' });
        // Validate the message exists.
        try {
            await discord.getChannelMessage(channelId, messageId);
        } catch (err) {
            return res.status(400).json({ error: 'Could not find that message. Make sure the bot can see the channel and message.' });
        }
        await discord.editChannelMessage(channelId, messageId, ticketPanelMessagePayload(panel));
        const updated = await dashboardDb.updateTicketPanel(id, { channelId, messageId });
        res.json({ ticketPanel: updated });
    } catch (err) {
        console.error('[API] update ticket panel message error:', err.message);
        res.status(500).json({ error: 'Failed to update ticket panel message: ' + err.message });
    }
});

// ── API: Live polls + live giveaways (Live page) ─────────────────────────────
//
// Read-only listing of all running and ended live polls and live giveaways.
// Live polls live in the main DB; live giveaways live in the LIVE_DATABASE_URL
// pool. The "Live" SPA page renders these in two panels, each with separate
// running and ended divs. Only ended items expose winners.

app.get('/api/live', requireAuth, async (req, res) => {
    try {
        const [polls, giveaways, endedPolls, endedGiveaways] = await Promise.all([
            dashboardDb.getLivePolls(),
            dashboardDb.getLiveGiveaways(),
            dashboardDb.getEndedLivePolls(),
            dashboardDb.getEndedLiveGiveaways(),
        ]);
        const runningPolls = polls.filter(p => p.isActive);
        const runningGiveaways = giveaways.filter(g => g.isActive && !g.ended);
        res.json({
            runningPolls,
            endedPolls,
            runningGiveaways,
            endedGiveaways,
        });
    } catch (err) {
        console.error('[API] /api/live error:', err.message);
        res.status(500).json({ error: 'Failed to load live data.' });
    }
});

// Split endpoints — one per live page. Each returns only the kind that page
// shows, so the polls page doesn't fetch giveaway rows (and vice versa).
app.get('/api/live/polls', requireAuth, async (req, res) => {
    try {
        const [polls, endedPolls] = await Promise.all([
            dashboardDb.getLivePolls(),
            dashboardDb.getEndedLivePolls(),
        ]);
        res.json({
            running: polls.filter(p => p.isActive),
            ended: endedPolls,
        });
    } catch (err) {
        console.error('[API] /api/live/polls error:', err.message);
        res.status(500).json({ error: 'Failed to load live polls.' });
    }
});

app.get('/api/live/giveaways', requireAuth, async (req, res) => {
    try {
        const [giveaways, endedGiveaways] = await Promise.all([
            dashboardDb.getLiveGiveaways(),
            dashboardDb.getEndedLiveGiveaways(),
        ]);
        res.json({
            running: giveaways.filter(g => g.isActive && !g.ended),
            ended: endedGiveaways,
        });
    } catch (err) {
        console.error('[API] /api/live/giveaways error:', err.message);
        res.status(500).json({ error: 'Failed to load live giveaways.' });
    }
});

// Per-guild live views for the server-features sidebar. Live polls/giveaways
// are cross-server (joined via pass code from any server), but each row records
// the channel it was created in. We filter to items created in THIS server's
// channels so the per-server tab shows "live activity in this server".
app.get('/api/guilds/:guildId/live/polls', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const channels = await discord.getGuildChannels(req.guild.id).catch(() => []);
        const ids = new Set((channels || []).map(c => String(c.id)));
        const [polls, endedPolls] = await Promise.all([
            dashboardDb.getLivePolls(),
            dashboardDb.getEndedLivePolls(),
        ]);
        const inGuild = p => p.channelId && ids.has(String(p.channelId));
        res.json({
            running: polls.filter(p => p.isActive).filter(inGuild),
            ended: endedPolls.filter(inGuild),
        });
    } catch (err) {
        console.error('[API] /api/guilds/:guildId/live/polls error:', err.message);
        res.status(500).json({ error: 'Failed to load live polls.' });
    }
});

app.get('/api/guilds/:guildId/live/giveaways', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const channels = await discord.getGuildChannels(req.guild.id).catch(() => []);
        const ids = new Set((channels || []).map(c => String(c.id)));
        const [giveaways, endedGiveaways] = await Promise.all([
            dashboardDb.getLiveGiveaways(),
            dashboardDb.getEndedLiveGiveaways(),
        ]);
        const inGuild = g => g.channelId && ids.has(String(g.channelId));
        res.json({
            running: giveaways.filter(g => g.isActive && !g.ended).filter(inGuild),
            ended: endedGiveaways.filter(inGuild),
        });
    } catch (err) {
        console.error('[API] /api/guilds/:guildId/live/giveaways error:', err.message);
        res.status(500).json({ error: 'Failed to load live giveaways.' });
    }
});

// ── API: Event management (📅 Events tab) ────────────────────────────────────

app.get('/api/guilds/:guildId/events', requireAuth, requireGuildAdmin, async (req, res) => {
    try {
        const schedules = await dashboardDb.getEventSchedules(req.guild.id);
        res.json({ schedules });
    } catch (err) {
        console.error('[API] get events error:', err.message);
        res.status(500).json({ error: 'Failed to load events.' });
    }
});

app.post('/api/guilds/:guildId/events', requireAuth, requireGuildAdmin, requireUpcoming, async (req, res) => {
    try {
        const schedule = await dashboardDb.createEventSchedule(req.guild.id, req.body || {}, req.user.id);
        res.json({ schedule });
    } catch (err) {
        console.error('[API] create event error:', err.message);
        res.status(500).json({ error: 'Failed to create event: ' + err.message });
    }
});

app.patch('/api/guilds/:guildId/events/:id', requireAuth, requireGuildAdmin, requireUpcoming, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid event id.' });
        const schedule = await dashboardDb.updateEventSchedule(id, req.body || {});
        res.json({ schedule });
    } catch (err) {
        console.error('[API] update event error:', err.message);
        res.status(500).json({ error: 'Failed to update event: ' + err.message });
    }
});

app.delete('/api/guilds/:guildId/events/:id', requireAuth, requireGuildAdmin, requireUpcoming, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid event id.' });
        await dashboardDb.deleteEventSchedule(id);
        res.json({ ok: true });
    } catch (err) {
        console.error('[API] delete event error:', err.message);
        res.status(500).json({ error: 'Failed to delete event.' });
    }
});

app.post('/api/guilds/:guildId/events/:id/start', requireAuth, requireGuildAdmin, requireUpcoming, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid event id.' });
        await dashboardDb.startEventSchedule(id);
        res.json({ ok: true });
    } catch (err) {
        console.error('[API] start event error:', err.message);
        res.status(500).json({ error: 'Failed to start event: ' + err.message });
    }
});

app.post('/api/guilds/:guildId/events/:id/cancel', requireAuth, requireGuildAdmin, requireUpcoming, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid event id.' });
        await dashboardDb.cancelEventSchedule(id);
        res.json({ ok: true });
    } catch (err) {
        console.error('[API] cancel event error:', err.message);
        res.status(500).json({ error: 'Failed to cancel event.' });
    }
});

// ── Page routes (server-rendered multi-page app) ────────────────────────────
//
// Each route renders its own real HTML page. The old SPA's single index.html +
// client-side pushState router is gone; /api/* JSON routes remain for the
// per-page client scripts to save settings.

// Build the manageable-guild list for the servers overview. Shared with the
// /api/guilds handler so the page and API stay consistent.
async function loadManageableGuilds(req) {
    const accessToken = req.session.accessToken;
    let guilds = req.session.guilds;
    const fetchedAt = req.session.guildsFetchedAt || 0;
    const cacheFresh = Array.isArray(guilds) && Date.now() - fetchedAt <= 5 * 60 * 1000;
    if (!cacheFresh) {
        if (!accessToken) {
            if (!Array.isArray(guilds)) guilds = [];
        } else {
            try {
                guilds = await discord.getUserGuilds(accessToken);
            } catch (err) {
                if (req.session.refreshToken) {
                    try {
                        const tokens = await discord.refreshToken(req.session.refreshToken);
                        req.session.accessToken = tokens.access_token;
                        req.session.refreshToken = tokens.refresh_token || req.session.refreshToken;
                        req.session.tokenExpiresAt = Date.now() + (tokens.expires_in * 1000);
                        guilds = await discord.getUserGuilds(tokens.access_token);
                    } catch (refreshErr) {
                        console.warn('[PAGE] token refresh failed:', refreshErr.message);
                        if (!Array.isArray(guilds)) guilds = [];
                    }
                } else {
                    console.warn('[PAGE] getUserGuilds failed and no refresh token:', err.message);
                    if (!Array.isArray(guilds)) guilds = [];
                }
            }
            req.session.guilds = guilds;
            req.session.guildsFetchedAt = Date.now();
        }
    }
    const manageable = guilds.filter(g => discord.canManageGuild(g.permissions));
    const result = await Promise.all(manageable.slice(0, 50).map(async (g) => {
        let botInGuild = false;
        let config = null;
        try {
            await discord.getBotGuild(g.id);
            botInGuild = true;
            config = await dashboardDb.getGuildConfig(g.id).catch(() => null);
        } catch (err) {
            botInGuild = false;
        }
        return {
            id: g.id,
            name: g.name,
            icon: g.icon,
            owner: g.owner,
            approximate_member_count: g.approximate_member_count,
            permissions: g.permissions,
            botPresent: botInGuild,
            welcomeEnabled: config?.welcome?.enabled ?? false,
            levelingEnabled: config?.server?.leveling?.enabled ?? true,
            prefix: config?.server?.prefix ?? constants.DEFAULT_PREFIX,
        };
    }));
    return result;
}

// Login route is handled above (renders the login page). The root and /dashboard
// both render the servers overview (requires a session; otherwise redirect to
// the login page).
app.get(['/', '/dashboard'], requireAuth, async (req, res) => {
    try {
        const guilds = await loadManageableGuilds(req);
        res.type('html').send(pages.overviewPage({
            guilds,
            clientId: process.env.DISCORD_CLIENT_ID,
            user: req.user,
        }));
    } catch (err) {
        console.error('[PAGE] overview error:', err.message);
        res.type('html').send(pages.notFoundPage({ user: req.session && req.session.user }));
    }
});

// Public docs page — the login screen links straight to it, so it must not
// require a session (requireAuth would bounce logged-out visitors back to
// /login, making the docs appear broken). Same pattern as the legal pages.
app.get('/docs', (req, res) => {
    res.type('html').send(pages.docsPage({ clientId: process.env.DISCORD_CLIENT_ID, user: req.session && req.session.user }));
});

// Public legal pages — linked from the login screen and the footer.
app.get('/privacy', (req, res) => {
    res.type('html').send(pages.privacyPage({ user: req.session && req.session.user }));
});
app.get('/terms', (req, res) => {
    res.type('html').send(pages.termsPage({ user: req.session && req.session.user }));
});

app.get('/stats', requireAuth, (req, res) => {
    res.type('html').send(pages.statsPage({ user: req.user }));
});

// Live is split into two separate pages. The old /live redirects to the polls
// page so any existing bookmarks keep working.
app.get('/live', (req, res) => res.redirect('/live/polls'));
app.get('/live/polls', requireAuth, (req, res) => {
    res.type('html').send(pages.livePollsPage({ user: req.user }));
});
app.get('/live/giveaways', requireAuth, (req, res) => {
    res.type('html').send(pages.liveGiveawaysPage({ user: req.user }));
});

// Guild settings: each tab is its own page. requireGuildAdminPage fetches
// channels/roles/config so the page is pre-populated server-side. Selecting a
// server lands on the prefix page; the rest of the features live behind the
// slide-in sidebar menu.
app.get('/guild/:guildId', (req, res) => res.redirect(`/guild/${req.params.guildId}/prefix`));

app.get('/guild/:guildId/welcome', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.welcomePage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/leveling', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.levelingPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/badges', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.badgesPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/rolerewards', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.roleRewardsPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/autoresponder', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.autoResponderPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/prefix', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.prefixPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/reactions', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.reactionsPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/reactionroles', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.reactionRolesPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/broadcast', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.broadcastPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/birthdays', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.birthdaysPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/logging', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.loggingPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/automod', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.automodPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/tickets', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.ticketsPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/events', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.eventsPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/live/polls', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.livePollsPage({ guild: req.guild, user: req.user })));
app.get('/guild/:guildId/live/giveaways', requireAuth, requireGuildAdminPage, (req, res) =>
    res.type('html').send(guildPages.liveGiveawaysPage({ guild: req.guild, user: req.user })));

// ── Health check ────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
    res.json({ ok: true, name: constants.BOT_NAME, version: constants.BOT_VERSION });
});

// ── 404 / error handlers ────────────────────────────────────────────────────

app.use((req, res) => {
    if (req.accepts('html')) return res.status(404).type('html').send(pages.notFoundPage({ user: req.session && req.session.user }));
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    console.error('[SERVER] Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ── Boot ────────────────────────────────────────────────────────────────────

function preflightCheck() {
    const missing = [];
    if (!process.env.DISCORD_TOKEN && !process.env.DASHBOARD_BOT_TOKEN) missing.push('DISCORD_TOKEN');
    if (!process.env.DISCORD_CLIENT_ID) missing.push('DISCORD_CLIENT_ID');
    if (!process.env.DISCORD_CLIENT_SECRET) missing.push('DISCORD_CLIENT_SECRET');
    if (missing.length) {
        console.warn(`⚠️  Dashboard will not work fully without: ${missing.join(', ')}`);
        if (missing.includes('DISCORD_CLIENT_SECRET')) {
            console.warn('   DISCORD_CLIENT_SECRET is required for OAuth2 login.');
            console.warn('   Get it from the Discord Developer Portal → your app → OAuth2 → Client Secret.');
        }
        if (missing.includes('DISCORD_TOKEN')) {
            console.warn('   DISCORD_TOKEN is used by the dashboard to look up guilds/channels the bot can see.');
            console.warn('   Without it, opening any server shows "bot token not configured" (HTTP 503).');
            console.warn('   On Vercel, set DISCORD_TOKEN (or DASHBOARD_BOT_TOKEN) in Settings → Environment Variables.');
        }
    }
    if (SESSION_SECRET === 'primebot-dashboard-dev-secret-change-me') {
        console.warn('⚠️  Using default SESSION_SECRET — set SESSION_SECRET in production.');
    }
    console.log(`🔗 PrimeBot Dashboard redirect URI: ${REDIRECT_URI}`);
    console.log(`   Add this to your Discord app's OAuth2 redirects.`);
}

// Resolve the bot's real user ID once (idempotent). Runs eagerly on boot and is
// also called lazily by /api/me so serverless cold starts still resolve it.
let botSelfPromise = null;
function resolveBotSelf() {
    if (botSelfPromise) return botSelfPromise;
    if (!process.env.DISCORD_TOKEN && !process.env.DASHBOARD_BOT_TOKEN) return Promise.resolve(null);
    botSelfPromise = (async () => {
        try {
            const self = await discord.getBotSelf();
            botSelf = self;
            botUserId = self.id;
            console.log(`🤖 Connected as bot user ${self.username} (${self.id})`);
            if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_ID !== self.id) {
                console.warn(`⚠️  DISCORD_CLIENT_ID (${process.env.DISCORD_CLIENT_ID}) does not match the bot token's user id (${self.id}).`);
                console.warn('   OAuth2 login uses DISCORD_CLIENT_ID; guild/channel lookups use the token.');
                console.warn('   Make sure both belong to the same application, or set DASHBOARD_BOT_TOKEN to the matching token.');
            }
            return self;
        } catch (err) {
            console.warn(`⚠️  Could not verify bot token (${err.message}). Guild/channel lookups may fail.`);
            return null;
        }
    })();
    return botSelfPromise;
}

// Kick off resolution immediately (safe — awaited lazily where needed).
resolveBotSelf();

// Only bind a listening socket when run directly (`npm run dashboard` / node).
// On Vercel the app is imported as a serverless handler — no listen() call.
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(` PrimeBot Dashboard running at ${BASE_URL}`);
        preflightCheck();
    });
}

// Exposed for Vercel's serverless runtime (@vercel/node) and for tests.
module.exports = app;
