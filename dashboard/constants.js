/**
 * Dashboard-wide constants and config defaults.
 * Mirrors the defaults used by the bot's managers so the dashboard writes
 * values the bot will read back correctly.
 */
const config = require('../config');
const { LOG_EVENTS } = require('../utils/logEvents');
const {
    RULES: AUTOMOD_RULES,
    ACTIONS: AUTOMOD_ACTIONS,
    SEVERITIES: AUTOMOD_SEVERITIES,
    RULE_CATEGORIES: AUTOMOD_SECTIONS,
    DEFAULT_DM_MESSAGES: AUTOMOD_DEFAULT_DM_MESSAGES,
} = require('../utils/automodRules');
const { PRESETS: AUTOMOD_PRESETS } = require('../utils/automodPresets');
const {
    NUKE_ACTIONS: ANTINUKE_ACTIONS,
    NUKE_RESPONSES: ANTINUKE_RESPONSES,
} = require('../utils/antiNukeRules');

module.exports = {
    // OAuth scopes requested at login. "guilds" lets us list the admin's servers.
    OAUTH_SCOPE: 'identify guilds',

    // Whether to request approximate member counts when listing user guilds.
    GUILD_CHANNELS_WITH_COUNTS: true,

    // Session cookie name.
    SESSION_COOKIE: 'primebot.sid',

    // ── Session inactivity policy (single source of truth) ──────────────────
    //
    // Idle timeout:        30 minutes of genuine inactivity → automatic logout.
    // Warning begins:      after 25 minutes idle the client shows a 5-minute
    //                      warning countdown; it is a UX affordance only.
    // Warning duration:    IDLE − WARNING = 5 minutes (derived, not duplicated).
    //
    // These drive both the client UX (dashboard/public/js/session-timeout.js)
    // and the server-side idle enforcement (dashboard/auth.js requireAuth +
    // the /api/session/heartbeat endpoint). The server is authoritative: it is
    // only consulted on authenticated requests / throttled activity syncs, so a
    // disabled/malicious client cannot keep an expired session alive.
    //
    // Neon compute optimization: the server-side idle deadline is persisted on
    // the existing Postgres-backed express-session row (primebot_dashboard_session)
    // and only re-written when SESSION_ACTIVITY_REFRESH_INTERVAL_MS has elapsed
    // since the previous write — never on every click/scroll/request. A
    // throttled activity sync happens at most once every 10 minutes.
    SESSION_IDLE_TIMEOUT_MS: Math.max(1000, parseInt(process.env.SESSION_IDLE_TIMEOUT_MS, 10) || 30 * 60 * 1000),

    // Idle time before the client starts the 5-minute warning countdown.
    // Must stay < SESSION_IDLE_TIMEOUT_MS.
    SESSION_WARNING_MS: Math.max(0, parseInt(process.env.SESSION_WARNING_MS, 10) || 25 * 60 * 1000),

    // Minimum time between server-side session-activity refreshes. The client
    // only issues an activity sync when the user has actually interacted AND
    // this much time has passed since the last refresh. All values in ms.
    SESSION_ACTIVITY_REFRESH_INTERVAL_MS: Math.max(5000, parseInt(process.env.SESSION_ACTIVITY_REFRESH_INTERVAL_MS, 10) || 10 * 60 * 1000),

    // Cloudflare Turnstile (invisible) public site key for the login page.
    // Empty string = widget not rendered. The matching TURNSTILE_SECRET_KEY
    // is read directly from the env by dashboard/turnstile.js.
    TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY || '',

    // Bot identity (for branding).
    BOT_NAME: 'PrimeBot',
    BOT_VERSION: config.version,
    BOT_WEBSITE: config.website,
    BOT_SUPPORT: config.supportServer,
    // Bot invite link (administrator scope + application commands). Used by the
    // "Invite" button on the dashboard login screen and the /invite command.
    BOT_INVITE_URL: 'https://discord.com/oauth2/authorize?client_id=1356575287151951943&permissions=8&integration_type=0&scope=bot%20applications.commands',
    BOT_CLIENT_ID: '1356575287151951943',

    // Default welcome message templates (kept in sync with config.welcome).
    DEFAULT_WELCOME_MESSAGE: config.welcome.serverMessage,
    DEFAULT_WELCOME_DM: config.welcome.dmMessage,
    DEFAULT_WELCOME_COLOR: '#5865F2',

    // Default prefix.
    DEFAULT_PREFIX: config.prefix,

    // Embed colors for the frontend palette.
    COLORS: config.colors,

    // Loggable event types shared with the bot (utils/logEvents.js).
    // Each entry: { key, label, icon (emoji, for bot embeds), iconName (SVG, for the dashboard), color, category }.
    LOG_EVENTS,

    // Automod rule types + actions shared with the bot (utils/automodRules.js).
    AUTOMOD_RULES,
    AUTOMOD_ACTIONS,
    // Severity catalog (low/medium/high/critical) — drives the dashboard badges
    // and mirrors the log-embed colors the bot uses.
    AUTOMOD_SEVERITIES,
    // Rule sections for the Automod page navigation (Anti-Spam, Content
    // Protection, Raid Protection).
    AUTOMOD_SECTIONS,
    // Default DM templates, so the DM editor can show the real default text.
    AUTOMOD_DEFAULT_DM_MESSAGES,
    // Ready-made protection profiles (utils/automodPresets.js).
    AUTOMOD_PRESETS,

    // Anti-Nuke catalogs (utils/antiNukeRules.js) for the upcoming Anti-Nuke tab.
    ANTINUKE_ACTIONS,
    ANTINUKE_RESPONSES,

    // Incident retention choices offered on the Automod → Settings section.
    AUTOMOD_RETENTION_OPTIONS: [
        { value: 7, label: '7 days' },
        { value: 30, label: '30 days' },
        { value: 90, label: '90 days' },
        { value: 180, label: '180 days' },
        { value: 0, label: 'Forever' },
    ],

    // Leveling badge catalog (config.leveling.badges). The dashboard's Badges
    // tab renders the achievement + special badges (awardable from the UI) and
    // lists the level badges (earned automatically on level-up). Mirrored here
    // so the page can render the catalog without an extra API round-trip.
    BADGE_CATALOG: (config.leveling && config.leveling.badges) || { levelBadges: [], achievementBadges: [], specialBadges: [] },
};
