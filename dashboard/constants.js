/**
 * Dashboard-wide constants and config defaults.
 * Mirrors the defaults used by the bot's managers so the dashboard writes
 * values the bot will read back correctly.
 */
const config = require('../config');
const { LOG_EVENTS } = require('../utils/logEvents');
const { RULES: AUTOMOD_RULES, ACTIONS: AUTOMOD_ACTIONS } = require('../utils/automodRules');

module.exports = {
    // OAuth scopes requested at login. "guilds" lets us list the admin's servers.
    OAUTH_SCOPE: 'identify guilds',

    // Whether to request approximate member counts when listing user guilds.
    GUILD_CHANNELS_WITH_COUNTS: true,

    // Session cookie name.
    SESSION_COOKIE: 'primebot.sid',

    // Idle auto-logout window (ms). While the dashboard tab is visible the
    // client heartbeats /api/session/heartbeat to keep the session alive; when
    // the tab is hidden for this long the session is destroyed and the user is
    // logged out automatically. Overridable via SESSION_IDLE_TIMEOUT_MS env.
    SESSION_IDLE_TIMEOUT_MS: Math.max(1000, parseInt(process.env.SESSION_IDLE_TIMEOUT_MS, 10) || 120000),

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
    // Each entry: { key, label, icon, color, category }.
    LOG_EVENTS,

    // Automod rule types + actions shared with the bot (utils/automodRules.js).
    AUTOMOD_RULES,
    AUTOMOD_ACTIONS,

    // Leveling badge catalog (config.leveling.badges). The dashboard's Badges
    // tab renders the achievement + special badges (awardable from the UI) and
    // lists the level badges (earned automatically on level-up). Mirrored here
    // so the page can render the catalog without an extra API round-trip.
    BADGE_CATALOG: (config.leveling && config.leveling.badges) || { levelBadges: [], achievementBadges: [], specialBadges: [] },
};
