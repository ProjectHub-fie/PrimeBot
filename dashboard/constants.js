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

    // Bot identity (for branding).
    BOT_NAME: 'PrimeBot',
    BOT_VERSION: config.version,
    BOT_WEBSITE: config.website,
    BOT_SUPPORT: config.supportServer,

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
};
