/**
 * Database access for the dashboard.
 *
 * Reuses the bot's existing pg pools so the dashboard reads/writes the exact
 * same rows the bot's managers use. Two pools are involved:
 *   - pool            → server_settings (prefix, leveling, auto-reactions, broadcast)
 *   - welcomePool     → welcome_settings (welcome messages/banners/DM)
 *
 * Both are created lazily in server/db.js and server/welcomeDb.js, so if an
 * env var is missing the pool still exists (queries will just fail and we
 * surface that to the dashboard UI gracefully).
 */

const { pool } = require('../server/db');

let welcomePool = null;
function getWelcomePool() {
    if (welcomePool) return welcomePool;
    try {
        welcomePool = require('../server/welcomeDb').welcomePool;
    } catch (err) {
        console.error('[DASHBOARD DB] welcomeDb unavailable:', err.message);
        welcomePool = { query: async () => { throw new Error('Welcome database not configured'); } };
    }
    return welcomePool;
}

const config = require('../config');
const constants = require('./constants');
const { normalizeGuildPrefix } = require('../utils/prefixHelper');
const { normalizeEvents, DEFAULT_ENABLED_EVENTS } = require('../utils/logEvents');

// ── server_settings (prefix, leveling, auto-reactions, broadcast) ────────────

const SERVER_SETTINGS_COLUMNS = `
    guild_id,
    prefix,
    receive_broadcasts,
    broadcast_channel_id,
    leveling_enabled,
    leveling_channel_id,
    xp_multiplier,
    xp_cooldown,
    auto_reactions_enabled,
    auto_reactions,
    no_prefix_users,
    updated_at
`;

async function ensureServerSettingsTable() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS server_settings (
            guild_id              VARCHAR(50) PRIMARY KEY,
            receive_broadcasts    BOOLEAN NOT NULL DEFAULT true,
            broadcast_channel_id  VARCHAR(50),
            leveling_enabled      BOOLEAN NOT NULL DEFAULT true,
            leveling_channel_id   VARCHAR(50),
            xp_multiplier         REAL NOT NULL DEFAULT 1.0,
            xp_cooldown           INTEGER NOT NULL DEFAULT 60000,
            auto_reactions_enabled BOOLEAN NOT NULL DEFAULT false,
            auto_reactions         JSONB NOT NULL DEFAULT '[]',
            no_prefix_users        JSONB NOT NULL DEFAULT '{}',
            prefix                 VARCHAR(10) DEFAULT '${config.prefix}',
            updated_at             TIMESTAMP DEFAULT NOW()
        )
    `);
    await pool.query(`ALTER TABLE server_settings ADD COLUMN IF NOT EXISTS prefix VARCHAR(10) DEFAULT '${config.prefix}'`);
}

async function getServerSettings(guildId) {
    await ensureServerSettingsTable();
    const res = await pool.query(`SELECT ${SERVER_SETTINGS_COLUMNS} FROM server_settings WHERE guild_id = $1`, [guildId]);
    if (res.rows.length === 0) return defaultServerSettings();
    return rowToServerSettings(res.rows[0]);
}

async function upsertServerSettings(guildId, patch) {
    await ensureServerSettingsTable();
    const current = await getServerSettings(guildId);
    const merged = { ...current, ...patch };

    // Normalize nested objects back to JSON strings.
    const autoReactions = JSON.stringify(merged.autoReactions?.reactions || []);
    const autoReactionsEnabled = merged.autoReactions?.enabled ?? false;
    const noPrefixUsers = JSON.stringify(merged.noPrefixUsers || {});
    const prefix = normalizeGuildPrefix(merged.prefix, config.prefix);
    const levelingEnabled = merged.leveling?.enabled ?? true;
    const levelingChannelId = merged.leveling?.levelUpChannelId ?? null;
    const xpMultiplier = Number(merged.leveling?.xpMultiplier) || 1.0;
    const xpCooldown = Number(merged.leveling?.xpCooldown) || 60000;

    await pool.query(`
        INSERT INTO server_settings (
            guild_id, prefix, receive_broadcasts, broadcast_channel_id,
            leveling_enabled, leveling_channel_id, xp_multiplier, xp_cooldown,
            auto_reactions_enabled, auto_reactions, no_prefix_users, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
        ON CONFLICT (guild_id) DO UPDATE SET
            prefix                 = EXCLUDED.prefix,
            receive_broadcasts     = EXCLUDED.receive_broadcasts,
            broadcast_channel_id   = EXCLUDED.broadcast_channel_id,
            leveling_enabled       = EXCLUDED.leveling_enabled,
            leveling_channel_id    = EXCLUDED.leveling_channel_id,
            xp_multiplier          = EXCLUDED.xp_multiplier,
            xp_cooldown            = EXCLUDED.xp_cooldown,
            auto_reactions_enabled = EXCLUDED.auto_reactions_enabled,
            auto_reactions         = EXCLUDED.auto_reactions,
            no_prefix_users        = EXCLUDED.no_prefix_users,
            updated_at             = NOW()
    `, [
        guildId, prefix,
        merged.receiveBroadcasts ?? true,
        merged.broadcastChannelId ?? null,
        levelingEnabled, levelingChannelId, xpMultiplier, xpCooldown,
        autoReactionsEnabled, autoReactions, noPrefixUsers,
    ]);

    return getServerSettings(guildId);
}

function defaultServerSettings() {
    return {
        prefix: config.prefix,
        receiveBroadcasts: true,
        broadcastChannelId: null,
        leveling: {
            enabled: true,
            levelUpChannelId: null,
            xpMultiplier: 1.0,
            xpCooldown: 60000,
        },
        autoReactions: { enabled: false, reactions: [] },
        noPrefixUsers: {},
    };
}

function rowToServerSettings(row) {
    return {
        prefix: normalizeGuildPrefix(row.prefix, config.prefix),
        receiveBroadcasts: row.receive_broadcasts,
        broadcastChannelId: row.broadcast_channel_id || null,
        leveling: {
            enabled: row.leveling_enabled,
            levelUpChannelId: row.leveling_channel_id || null,
            xpMultiplier: parseFloat(row.xp_multiplier) || 1.0,
            xpCooldown: row.xp_cooldown || 60000,
        },
        autoReactions: {
            enabled: row.auto_reactions_enabled,
            reactions: row.auto_reactions || [],
        },
        noPrefixUsers: row.no_prefix_users || {},
    };
}

// ── welcome_settings ────────────────────────────────────────────────────────

async function ensureWelcomeTable() {
    await getWelcomePool().query(`
        CREATE TABLE IF NOT EXISTS welcome_settings (
            guild_id              VARCHAR(50) PRIMARY KEY,
            enabled               BOOLEAN NOT NULL DEFAULT false,
            channel_id            VARCHAR(50),
            message               TEXT DEFAULT 'Welcome to the server, {member}! Enjoy your stay!',
            banner_url            TEXT,
            color                 VARCHAR(20) DEFAULT '#5865F2',
            dm_enabled            BOOLEAN NOT NULL DEFAULT false,
            dm_message            TEXT DEFAULT 'Hey {username}! Welcome to **{server}**!',
            show_member_count     BOOLEAN NOT NULL DEFAULT true,
            show_join_date        BOOLEAN NOT NULL DEFAULT true,
            show_account_age      BOOLEAN NOT NULL DEFAULT true,
            custom_title          VARCHAR(255),
            custom_footer         VARCHAR(255),
            updated_at            TIMESTAMP DEFAULT NOW()
        )
    `);
}

async function getWelcomeSettings(guildId) {
    await ensureWelcomeTable();
    const res = await getWelcomePool().query(`SELECT * FROM welcome_settings WHERE guild_id = $1`, [guildId]);
    if (res.rows.length === 0) return defaultWelcomeSettings();
    return rowToWelcomeSettings(res.rows[0]);
}

async function upsertWelcomeSettings(guildId, patch) {
    await ensureWelcomeTable();
    const current = await getWelcomeSettings(guildId);
    const merged = { ...current, ...patch };

    await getWelcomePool().query(`
        INSERT INTO welcome_settings (
            guild_id, enabled, channel_id, message, banner_url, color,
            dm_enabled, dm_message,
            show_member_count, show_join_date, show_account_age,
            custom_title, custom_footer, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
        ON CONFLICT (guild_id) DO UPDATE SET
            enabled           = EXCLUDED.enabled,
            channel_id        = EXCLUDED.channel_id,
            message           = EXCLUDED.message,
            banner_url        = EXCLUDED.banner_url,
            color             = EXCLUDED.color,
            dm_enabled        = EXCLUDED.dm_enabled,
            dm_message        = EXCLUDED.dm_message,
            show_member_count = EXCLUDED.show_member_count,
            show_join_date    = EXCLUDED.show_join_date,
            show_account_age  = EXCLUDED.show_account_age,
            custom_title      = EXCLUDED.custom_title,
            custom_footer     = EXCLUDED.custom_footer,
            updated_at        = NOW()
    `, [
        guildId,
        merged.enabled ?? false,
        merged.channelId ?? null,
        merged.message ?? config.welcome.serverMessage,
        merged.bannerUrl ?? null,
        merged.color ?? '#5865F2',
        merged.dmEnabled ?? false,
        merged.dmMessage ?? config.welcome.dmMessage,
        merged.showMemberCount ?? true,
        merged.showJoinDate ?? true,
        merged.showAccountAge ?? true,
        merged.customTitle ?? null,
        merged.customFooter ?? null,
    ]);

    return getWelcomeSettings(guildId);
}

function defaultWelcomeSettings() {
    return {
        enabled: false,
        channelId: null,
        message: config.welcome.serverMessage,
        bannerUrl: null,
        color: '#5865F2',
        dmEnabled: false,
        dmMessage: config.welcome.dmMessage,
        showMemberCount: true,
        showJoinDate: true,
        showAccountAge: true,
        customTitle: null,
        customFooter: null,
    };
}

function rowToWelcomeSettings(row) {
    return {
        enabled: row.enabled,
        channelId: row.channel_id || null,
        message: row.message || config.welcome.serverMessage,
        bannerUrl: row.banner_url || null,
        color: row.color || '#5865F2',
        dmEnabled: row.dm_enabled,
        dmMessage: row.dm_message || config.welcome.dmMessage,
        showMemberCount: row.show_member_count,
        showJoinDate: row.show_join_date,
        showAccountAge: row.show_account_age,
        customTitle: row.custom_title || null,
        customFooter: row.custom_footer || null,
    };
}

// ── logging_settings ───────────────────────────────────────────────────────

async function ensureLoggingTable() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS logging_settings (
            guild_id              VARCHAR(50) PRIMARY KEY,
            enabled               BOOLEAN NOT NULL DEFAULT false,
            channel_id            VARCHAR(50),
            webhook_url           TEXT,
            webhook_name          VARCHAR(100) DEFAULT 'PrimeBot Logs',
            events                JSONB NOT NULL DEFAULT '[]',
            include_bots          BOOLEAN NOT NULL DEFAULT false,
            color                 VARCHAR(20) DEFAULT '#5865F2',
            updated_at            TIMESTAMP DEFAULT NOW()
        )
    `);
    await pool.query(`ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS webhook_name  VARCHAR(100) DEFAULT 'PrimeBot Logs'`);
    await pool.query(`ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS events        JSONB NOT NULL DEFAULT '[]'`);
    await pool.query(`ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS include_bots  BOOLEAN NOT NULL DEFAULT false`);
    await pool.query(`ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS color         VARCHAR(20) DEFAULT '#5865F2'`);
}

async function getLoggingSettings(guildId) {
    await ensureLoggingTable();
    const res = await pool.query(`SELECT * FROM logging_settings WHERE guild_id = $1`, [guildId]);
    if (res.rows.length === 0) return defaultLoggingSettings();
    return rowToLoggingSettings(res.rows[0]);
}

async function upsertLoggingSettings(guildId, patch) {
    await ensureLoggingTable();
    const current = await getLoggingSettings(guildId);
    const merged = { ...current, ...patch };

    await pool.query(`
        INSERT INTO logging_settings (
            guild_id, enabled, channel_id, webhook_url, webhook_name,
            events, include_bots, color, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
        ON CONFLICT (guild_id) DO UPDATE SET
            enabled      = EXCLUDED.enabled,
            channel_id   = EXCLUDED.channel_id,
            webhook_url  = EXCLUDED.webhook_url,
            webhook_name = EXCLUDED.webhook_name,
            events       = EXCLUDED.events,
            include_bots = EXCLUDED.include_bots,
            color        = EXCLUDED.color,
            updated_at   = NOW()
    `, [
        guildId,
        merged.enabled ?? false,
        merged.channelId ?? null,
        merged.webhookUrl ?? null,
        (merged.webhookName || 'PrimeBot Logs').slice(0, 100),
        JSON.stringify(normalizeEvents(merged.events)),
        merged.includeBots ?? false,
        merged.color ?? '#5865F2',
    ]);

    return getLoggingSettings(guildId);
}

function defaultLoggingSettings() {
    return {
        enabled: false,
        channelId: null,
        webhookUrl: null,
        webhookName: 'PrimeBot Logs',
        events: [...DEFAULT_ENABLED_EVENTS],
        includeBots: false,
        color: '#5865F2',
    };
}

function rowToLoggingSettings(row) {
    return {
        enabled: row.enabled,
        channelId: row.channel_id || null,
        webhookUrl: row.webhook_url || null,
        webhookName: row.webhook_name || 'PrimeBot Logs',
        events: normalizeEvents(row.events),
        includeBots: row.include_bots,
        color: row.color || '#5865F2',
    };
}

// ── Combined view (one fetch per guild for the settings page) ───────────────

async function getGuildConfig(guildId) {
    const [server, welcome, logging] = await Promise.all([
        getServerSettings(guildId).catch(err => {
            console.error('[DASHBOARD DB] server_settings read failed:', err.message);
            return defaultServerSettings();
        }),
        getWelcomeSettings(guildId).catch(err => {
            console.error('[DASHBOARD DB] welcome_settings read failed:', err.message);
            return defaultWelcomeSettings();
        }),
        getLoggingSettings(guildId).catch(err => {
            console.error('[DASHBOARD DB] logging_settings read failed:', err.message);
            return defaultLoggingSettings();
        }),
    ]);
    return { server, welcome, logging };
}

// ── Aggregated platform stats (public — shown on the login screen) ──────────
//
// These run simple COUNTs against the same tables the bot uses, so the numbers
// reflect real, live configuration. Each query is wrapped so a missing/unreachable
// database degrades to zero rather than throwing the whole endpoint — the login
// page still renders, just with neutral stats.

async function _count(query, fallback = 0) {
    try {
        const res = await pool.query(query);
        return Number(res.rows[0]?.count ?? fallback);
    } catch (err) {
        console.error('[DASHBOARD DB] stats count failed:', err.message);
        return fallback;
    }
}

async function _welcomeCount(query, fallback = 0) {
    try {
        const res = await getWelcomePool().query(query);
        return Number(res.rows[0]?.count ?? fallback);
    } catch (err) {
        console.error('[DASHBOARD DB] welcome stats count failed:', err.message);
        return fallback;
    }
}

async function getPlatformStats() {
    const [
        totalServers,
        levelingEnabled,
        welcomeEnabled,
        autoReactionsEnabled,
        broadcastEnabled,
        welcomeBanners,
    ] = await Promise.all([
        _count(`SELECT COUNT(*) FROM server_settings`),
        _count(`SELECT COUNT(*) FROM server_settings WHERE leveling_enabled = true`),
        _welcomeCount(`SELECT COUNT(*) FROM welcome_settings WHERE enabled = true`),
        _count(`SELECT COUNT(*) FROM server_settings WHERE auto_reactions_enabled = true`),
        _count(`SELECT COUNT(*) FROM server_settings WHERE receive_broadcasts = true`),
        _welcomeCount(`SELECT COUNT(*) FROM welcome_settings WHERE banner_url IS NOT NULL AND banner_url <> ''`),
    ]);

    // Adoption ratios (guard against divide-by-zero). These drive the donut charts.
    const pct = (n, d) => (d > 0 ? Math.round((n / d) * 100) : 0);

    return {
        servers: totalServers,
        botName: constants.BOT_NAME,
        botVersion: constants.BOT_VERSION,
        features: {
            leveling: { count: levelingEnabled, percent: pct(levelingEnabled, totalServers) },
            welcome: { count: welcomeEnabled, percent: pct(welcomeEnabled, totalServers) },
            autoReactions: { count: autoReactionsEnabled, percent: pct(autoReactionsEnabled, totalServers) },
            broadcasts: { count: broadcastEnabled, percent: pct(broadcastEnabled, totalServers) },
        },
        welcomeBanners,
    };
}

module.exports = {
    getServerSettings,
    upsertServerSettings,
    defaultServerSettings,
    getWelcomeSettings,
    upsertWelcomeSettings,
    defaultWelcomeSettings,
    getLoggingSettings,
    upsertLoggingSettings,
    defaultLoggingSettings,
    getGuildConfig,
    getPlatformStats,
};
