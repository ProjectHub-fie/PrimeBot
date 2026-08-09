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
const { normalizeGuildPrefix } = require('../utils/prefixHelper');

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

// ── Combined view (one fetch per guild for the settings page) ───────────────

async function getGuildConfig(guildId) {
    const [server, welcome] = await Promise.all([
        getServerSettings(guildId).catch(err => {
            console.error('[DASHBOARD DB] server_settings read failed:', err.message);
            return defaultServerSettings();
        }),
        getWelcomeSettings(guildId).catch(err => {
            console.error('[DASHBOARD DB] welcome_settings read failed:', err.message);
            return defaultWelcomeSettings();
        }),
    ]);
    return { server, welcome };
}

module.exports = {
    getServerSettings,
    upsertServerSettings,
    defaultServerSettings,
    getWelcomeSettings,
    upsertWelcomeSettings,
    defaultWelcomeSettings,
    getGuildConfig,
};
