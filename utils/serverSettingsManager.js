const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const { pool } = require('../server/db');

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS server_settings (
        guild_id              VARCHAR(50) PRIMARY KEY,
        receive_broadcasts    BOOLEAN NOT NULL DEFAULT true,
        broadcast_channel_id  VARCHAR(50),
        welcome_enabled       BOOLEAN NOT NULL DEFAULT false,
        welcome_channel_id    VARCHAR(50),
        welcome_message       TEXT DEFAULT 'Welcome to the server, {member}! Enjoy your stay!',
        welcome_banner_url    TEXT,
        welcome_color         VARCHAR(20) DEFAULT '#5865F2',
        welcome_dm_enabled    BOOLEAN NOT NULL DEFAULT false,
        welcome_dm_message    TEXT DEFAULT 'Hey {username}! Welcome to **{server}**!',
        welcome_show_member_count  BOOLEAN NOT NULL DEFAULT true,
        welcome_show_join_date     BOOLEAN NOT NULL DEFAULT true,
        welcome_show_account_age   BOOLEAN NOT NULL DEFAULT true,
        welcome_custom_title  VARCHAR(255),
        welcome_custom_footer VARCHAR(255),
        leveling_enabled      BOOLEAN NOT NULL DEFAULT true,
        leveling_channel_id   VARCHAR(50),
        xp_multiplier         REAL NOT NULL DEFAULT 1.0,
        xp_cooldown           INTEGER NOT NULL DEFAULT 60000,
        auto_reactions_enabled BOOLEAN NOT NULL DEFAULT false,
        auto_reactions         JSONB NOT NULL DEFAULT '[]',
        no_prefix_users        JSONB NOT NULL DEFAULT '{}',
        updated_at             TIMESTAMP DEFAULT NOW()
    )
`;

/**
 * Manages server-specific settings and preferences — backed by PostgreSQL.
 * The in-memory Map acts as a read-through cache; writes go straight to DB
 * (fire-and-forget so callers stay synchronous).
 */
class ServerSettingsManager {
    constructor(client) {
        this.client = client;
        this.serverSettings = new Map();
        this._tableReady = false;

        this._init().catch(err =>
            console.error('[SERVER SETTINGS] Initialisation failed:', err.message)
        );
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    async _ensureTable() {
        if (this._tableReady) return;
        await pool.query(CREATE_TABLE_SQL);
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._migrateFromJson();
        await this.loadSettings();
    }

    /** One-time import of existing serverSettings.json data. */
    async _migrateFromJson() {
        const fs = require('fs');
        const path = require('path');
        const jsonPath = path.join(__dirname, '../data/serverSettings.json');
        const donePath = jsonPath + '.migrated';
        if (!fs.existsSync(jsonPath) || fs.existsSync(donePath)) return;

        try {
            const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            let count = 0;
            for (const [guildId, s] of Object.entries(data)) {
                try {
                    const lev = s.leveling || {};
                    const ar = s.autoReactions || {};
                    await pool.query(`
                        INSERT INTO server_settings (
                            guild_id, receive_broadcasts, broadcast_channel_id,
                            welcome_enabled, welcome_channel_id, welcome_message,
                            welcome_banner_url, welcome_color,
                            welcome_dm_enabled, welcome_dm_message,
                            welcome_show_member_count, welcome_show_join_date, welcome_show_account_age,
                            welcome_custom_title, welcome_custom_footer,
                            leveling_enabled, leveling_channel_id, xp_multiplier, xp_cooldown,
                            auto_reactions_enabled, auto_reactions, no_prefix_users
                        ) VALUES (
                            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                            $16,$17,$18,$19,$20,$21,$22
                        ) ON CONFLICT (guild_id) DO NOTHING
                    `, [
                        guildId,
                        s.receiveBroadcasts !== false,
                        s.broadcastChannelId || null,
                        s.welcomeEnabled || false,
                        s.welcomeChannelId || null,
                        s.welcomeMessage || 'Welcome to the server, {member}! Enjoy your stay!',
                        s.welcomeBannerUrl || null,
                        s.welcomeColor || '#5865F2',
                        s.welcomeDmEnabled || false,
                        s.welcomeDmMessage || 'Hey {username}! Welcome to **{server}**!',
                        s.welcomeShowMemberCount !== false,
                        s.welcomeShowJoinDate !== false,
                        s.welcomeShowAccountAge !== false,
                        s.welcomeCustomTitle || null,
                        s.welcomeCustomFooter || null,
                        lev.enabled !== false,
                        lev.levelUpChannelId || null,
                        lev.xpMultiplier || 1.0,
                        lev.xpCooldown || 60000,
                        ar.enabled || false,
                        JSON.stringify(ar.reactions || []),
                        JSON.stringify(s.noPrefixUsers || {}),
                    ]);
                    count++;
                } catch (e) {
                    console.error(`[SERVER SETTINGS] Migration: failed on guild ${guildId}:`, e.message);
                }
            }
            fs.renameSync(jsonPath, donePath);
            console.log(`[SERVER SETTINGS] Migrated ${count} guilds from JSON → DB.`);
        } catch (err) {
            console.error('[SERVER SETTINGS] JSON migration failed:', err.message);
        }
    }

    _rowToSettings(row) {
        return {
            receiveBroadcasts: row.receive_broadcasts,
            broadcastChannelId: row.broadcast_channel_id || null,
            welcomeEnabled: row.welcome_enabled,
            welcomeChannelId: row.welcome_channel_id || null,
            welcomeMessage: row.welcome_message || 'Welcome to the server, {member}! Enjoy your stay!',
            welcomeBannerUrl: row.welcome_banner_url || null,
            welcomeColor: row.welcome_color || config.colors.primary,
            welcomeDmEnabled: row.welcome_dm_enabled,
            welcomeDmMessage: row.welcome_dm_message || 'Hey {username}! Welcome to **{server}**!',
            welcomeShowMemberCount: row.welcome_show_member_count,
            welcomeShowJoinDate: row.welcome_show_join_date,
            welcomeShowAccountAge: row.welcome_show_account_age,
            welcomeCustomTitle: row.welcome_custom_title || null,
            welcomeCustomFooter: row.welcome_custom_footer || null,
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

    _defaultSettings() {
        return {
            receiveBroadcasts: true,
            broadcastChannelId: null,
            welcomeEnabled: false,
            welcomeChannelId: null,
            welcomeMessage: 'Welcome to the server, {member}! Enjoy your stay!',
            welcomeBannerUrl: config.welcome?.bannerUrl || null,
            welcomeColor: config.colors.primary,
            welcomeDmEnabled: config.welcome?.sendDM || false,
            welcomeDmMessage: config.welcome?.dmMessage || 'Hey {username}! Welcome to **{server}**!',
            welcomeShowMemberCount: true,
            welcomeShowJoinDate: true,
            welcomeShowAccountAge: true,
            welcomeCustomTitle: null,
            welcomeCustomFooter: null,
            leveling: {
                enabled: true,
                levelUpChannelId: null,
                xpMultiplier: 1.0,
                xpCooldown: 60000,
            },
            autoReactions: {
                enabled: false,
                reactions: [],
            },
            noPrefixUsers: {},
        };
    }

    /** Upsert one guild's settings to DB — fire-and-forget. */
    _saveGuildSettings(guildId) {
        this._saveGuildSettingsAsync(guildId).catch(err =>
            console.error(`[SERVER SETTINGS] DB save failed for guild ${guildId}:`, err.message)
        );
    }

    async _saveGuildSettingsAsync(guildId) {
        const s = this.getGuildSettings(guildId);
        await this._ensureTable();
        await pool.query(`
            INSERT INTO server_settings (
                guild_id, receive_broadcasts, broadcast_channel_id,
                welcome_enabled, welcome_channel_id, welcome_message,
                welcome_banner_url, welcome_color,
                welcome_dm_enabled, welcome_dm_message,
                welcome_show_member_count, welcome_show_join_date, welcome_show_account_age,
                welcome_custom_title, welcome_custom_footer,
                leveling_enabled, leveling_channel_id, xp_multiplier, xp_cooldown,
                auto_reactions_enabled, auto_reactions, no_prefix_users, updated_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                $16,$17,$18,$19,$20,$21,$22, NOW()
            )
            ON CONFLICT (guild_id) DO UPDATE SET
                receive_broadcasts    = EXCLUDED.receive_broadcasts,
                broadcast_channel_id  = EXCLUDED.broadcast_channel_id,
                welcome_enabled       = EXCLUDED.welcome_enabled,
                welcome_channel_id    = EXCLUDED.welcome_channel_id,
                welcome_message       = EXCLUDED.welcome_message,
                welcome_banner_url    = EXCLUDED.welcome_banner_url,
                welcome_color         = EXCLUDED.welcome_color,
                welcome_dm_enabled    = EXCLUDED.welcome_dm_enabled,
                welcome_dm_message    = EXCLUDED.welcome_dm_message,
                welcome_show_member_count  = EXCLUDED.welcome_show_member_count,
                welcome_show_join_date     = EXCLUDED.welcome_show_join_date,
                welcome_show_account_age   = EXCLUDED.welcome_show_account_age,
                welcome_custom_title  = EXCLUDED.welcome_custom_title,
                welcome_custom_footer = EXCLUDED.welcome_custom_footer,
                leveling_enabled      = EXCLUDED.leveling_enabled,
                leveling_channel_id   = EXCLUDED.leveling_channel_id,
                xp_multiplier         = EXCLUDED.xp_multiplier,
                xp_cooldown           = EXCLUDED.xp_cooldown,
                auto_reactions_enabled = EXCLUDED.auto_reactions_enabled,
                auto_reactions         = EXCLUDED.auto_reactions,
                no_prefix_users        = EXCLUDED.no_prefix_users,
                updated_at             = NOW()
        `, [
            guildId,
            s.receiveBroadcasts,
            s.broadcastChannelId,
            s.welcomeEnabled,
            s.welcomeChannelId,
            s.welcomeMessage,
            s.welcomeBannerUrl,
            s.welcomeColor,
            s.welcomeDmEnabled,
            s.welcomeDmMessage,
            s.welcomeShowMemberCount,
            s.welcomeShowJoinDate,
            s.welcomeShowAccountAge,
            s.welcomeCustomTitle,
            s.welcomeCustomFooter,
            s.leveling.enabled,
            s.leveling.levelUpChannelId,
            s.leveling.xpMultiplier,
            s.leveling.xpCooldown,
            s.autoReactions.enabled,
            JSON.stringify(s.autoReactions.reactions),
            JSON.stringify(s.noPrefixUsers),
        ]);
    }

    // ─── Public API (identical surface to the original) ──────────────────────

    async loadSettings() {
        try {
            await this._ensureTable();
            const res = await pool.query('SELECT * FROM server_settings');
            for (const row of res.rows) {
                this.serverSettings.set(row.guild_id, this._rowToSettings(row));
            }
            console.log(`[SERVER SETTINGS] Loaded settings for ${this.serverSettings.size} servers.`);
        } catch (error) {
            console.error('[SERVER SETTINGS] Error loading settings:', error);
        }
    }

    getGuildSettings(guildId) {
        if (!this.serverSettings.has(guildId)) {
            this.serverSettings.set(guildId, this._defaultSettings());
        }
        return this.serverSettings.get(guildId);
    }

    updateGuildSetting(guildId, setting, value) {
        const guildSettings = this.getGuildSettings(guildId);
        guildSettings[setting] = value;
        this.serverSettings.set(guildId, guildSettings);
        this._saveGuildSettings(guildId);
        return true;
    }

    // ── Broadcast ─────────────────────────────────────────────────────────────

    toggleBroadcastReception(guildId) {
        const s = this.getGuildSettings(guildId);
        const newValue = !s.receiveBroadcasts;
        s.receiveBroadcasts = newValue;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return newValue;
    }

    setBroadcastChannel(guildId, channelId) {
        return this.updateGuildSetting(guildId, 'broadcastChannelId', channelId);
    }

    getBroadcastChannel(guildId) {
        return this.getGuildSettings(guildId).broadcastChannelId || null;
    }

    receivesBroadcasts(guildId) {
        return this.getGuildSettings(guildId).receiveBroadcasts;
    }

    getOptedOutServers() {
        const out = [];
        for (const [id, s] of this.serverSettings.entries()) {
            if (!s.receiveBroadcasts) out.push(id);
        }
        return out;
    }

    getBroadcastReceptionCount() {
        let count = 0;
        for (const s of this.serverSettings.values()) {
            if (s.receiveBroadcasts) count++;
        }
        const serversWithoutSettings = this.client.guilds.cache.size - this.serverSettings.size;
        return count + Math.max(0, serversWithoutSettings);
    }

    // ── No-prefix mode ────────────────────────────────────────────────────────

    enableNoPrefixMode(guildId, userId, minutes = 10) {
        if (!userId) return { success: false, message: 'Invalid user' };
        if (minutes <= 0 || minutes > 60) return { success: false, message: 'Duration must be between 1 and 60 minutes' };

        try {
            const s = this.getGuildSettings(guildId);
            if (!s.noPrefixUsers) s.noPrefixUsers = {};
            const expirationTime = Date.now() + minutes * 60 * 1000;
            s.noPrefixUsers[userId] = expirationTime;
            this.serverSettings.set(guildId, s);
            this._saveGuildSettings(guildId);
            return { success: true, message: `No-prefix mode enabled for ${minutes} minute${minutes !== 1 ? 's' : ''}`, expiresAt: expirationTime };
        } catch (err) {
            console.error(`[SERVER SETTINGS] Error enabling no-prefix mode:`, err);
            return { success: false, message: 'An error occurred.' };
        }
    }

    disableNoPrefixMode(guildId, userId) {
        if (!userId) return false;
        const s = this.getGuildSettings(guildId);
        if (!s.noPrefixUsers || !s.noPrefixUsers[userId]) return false;
        delete s.noPrefixUsers[userId];
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return true;
    }

    hasNoPrefixMode(guildId, userId) {
        try {
            if (!guildId || !userId) return false;
            const s = this.getGuildSettings(guildId);
            if (!s.noPrefixUsers || !s.noPrefixUsers[userId]) return false;
            if (Date.now() > s.noPrefixUsers[userId]) {
                delete s.noPrefixUsers[userId];
                this._saveGuildSettings(guildId);
                return false;
            }
            return true;
        } catch (err) {
            console.error(`[SERVER SETTINGS] Error checking no-prefix mode:`, err);
            return false;
        }
    }

    getNoPrefixExpiration(guildId, userId) {
        if (!userId) return null;
        const s = this.getGuildSettings(guildId);
        if (!s.noPrefixUsers) return null;
        const exp = s.noPrefixUsers[userId];
        if (!exp) return null;
        if (Date.now() > exp) {
            delete s.noPrefixUsers[userId];
            this.serverSettings.set(guildId, s);
            this._saveGuildSettings(guildId);
            return null;
        }
        return exp;
    }

    // ── Welcome ───────────────────────────────────────────────────────────────

    isWelcomeEnabled(guildId) { return this.getGuildSettings(guildId).welcomeEnabled; }

    toggleWelcome(guildId) {
        const s = this.getGuildSettings(guildId);
        const newValue = !s.welcomeEnabled;
        s.welcomeEnabled = newValue;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return newValue;
    }

    toggleWelcomeDm(guildId) {
        const s = this.getGuildSettings(guildId);
        const newValue = !s.welcomeDmEnabled;
        s.welcomeDmEnabled = newValue;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return newValue;
    }

    setWelcomeChannel(guildId, channelId) { return this.updateGuildSetting(guildId, 'welcomeChannelId', channelId); }
    setWelcomeMessage(guildId, message)   { return this.updateGuildSetting(guildId, 'welcomeMessage', message); }
    setWelcomeDmMessage(guildId, message) { return this.updateGuildSetting(guildId, 'welcomeDmMessage', message); }
    setWelcomeBanner(guildId, url)        { return this.updateGuildSetting(guildId, 'welcomeBannerUrl', url); }
    setWelcomeColor(guildId, color)       { return this.updateGuildSetting(guildId, 'welcomeColor', color); }

    getWelcomeSettings(guildId) {
        const s = this.getGuildSettings(guildId);
        return {
            enabled: s.welcomeEnabled,
            channelId: s.welcomeChannelId,
            message: s.welcomeMessage,
            bannerUrl: s.welcomeBannerUrl,
            color: s.welcomeColor,
            dmEnabled: s.welcomeDmEnabled,
            dmMessage: s.welcomeDmMessage,
            showMemberCount: s.welcomeShowMemberCount,
            showJoinDate: s.welcomeShowJoinDate,
            showAccountAge: s.welcomeShowAccountAge,
            customTitle: s.welcomeCustomTitle,
            customFooter: s.welcomeCustomFooter,
        };
    }

    updateWelcomeSettings(guildId, updates = {}) {
        const s = this.getGuildSettings(guildId);
        const keyMap = {
            enabled: 'welcomeEnabled',
            channelId: 'welcomeChannelId',
            message: 'welcomeMessage',
            bannerUrl: 'welcomeBannerUrl',
            color: 'welcomeColor',
            dmEnabled: 'welcomeDmEnabled',
            dmMessage: 'welcomeDmMessage',
            showMemberCount: 'welcomeShowMemberCount',
            showJoinDate: 'welcomeShowJoinDate',
            showAccountAge: 'welcomeShowAccountAge',
            customTitle: 'welcomeCustomTitle',
            customFooter: 'welcomeCustomFooter',
        };
        for (const [key, value] of Object.entries(updates)) {
            s[keyMap[key] || key] = value;
        }
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return true;
    }

    toggleWelcomeFeature(guildId, feature) {
        const valid = ['welcomeShowMemberCount', 'welcomeShowJoinDate', 'welcomeShowAccountAge'];
        if (!valid.includes(feature)) return false;
        const s = this.getGuildSettings(guildId);
        const newValue = !s[feature];
        s[feature] = newValue;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return newValue;
    }

    // ── Leveling ──────────────────────────────────────────────────────────────

    isLevelingEnabled(guildId) { return this.getGuildSettings(guildId).leveling?.enabled || false; }

    toggleLeveling(guildId) {
        const s = this.getGuildSettings(guildId);
        if (!s.leveling) s.leveling = { enabled: false, levelUpChannelId: null, xpMultiplier: 1.0, xpCooldown: 60000 };
        s.leveling.enabled = !s.leveling.enabled;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return s.leveling.enabled;
    }

    setLevelingChannel(guildId, channelId) {
        const s = this.getGuildSettings(guildId);
        if (!s.leveling) s.leveling = { enabled: true, levelUpChannelId: null, xpMultiplier: 1.0, xpCooldown: 60000 };
        s.leveling.levelUpChannelId = channelId;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return true;
    }

    setXpMultiplier(guildId, multiplier) {
        if (multiplier <= 0 || multiplier > 5) return false;
        const s = this.getGuildSettings(guildId);
        if (!s.leveling) s.leveling = { enabled: true, levelUpChannelId: null, xpMultiplier: 1.0, xpCooldown: 60000 };
        s.leveling.xpMultiplier = parseFloat(multiplier.toFixed(2));
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return true;
    }

    setXpCooldown(guildId, cooldownSeconds) {
        if (cooldownSeconds < 5 || cooldownSeconds > 300) return false;
        const s = this.getGuildSettings(guildId);
        if (!s.leveling) s.leveling = { enabled: true, levelUpChannelId: null, xpMultiplier: 1.0, xpCooldown: 60000 };
        s.leveling.xpCooldown = cooldownSeconds * 1000;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return true;
    }

    getLevelingSettings(guildId) {
        const s = this.getGuildSettings(guildId);
        if (!s.leveling) {
            s.leveling = { enabled: true, levelUpChannelId: null, xpMultiplier: 1.0, xpCooldown: 60000 };
            this.serverSettings.set(guildId, s);
        }
        return s.leveling;
    }

    // ── Auto-reactions ────────────────────────────────────────────────────────

    addAutoReaction(guildId, trigger, emoji, caseSensitive = false) {
        if (!trigger || !emoji) return false;
        const s = this.getGuildSettings(guildId);
        if (!s.autoReactions) s.autoReactions = { enabled: true, reactions: [] };
        const idx = s.autoReactions.reactions.findIndex(r => r.trigger.toLowerCase() === trigger.toLowerCase());
        if (idx !== -1) {
            s.autoReactions.reactions[idx] = { trigger, emoji, caseSensitive };
        } else {
            s.autoReactions.reactions.push({ trigger, emoji, caseSensitive });
        }
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return true;
    }

    removeAutoReaction(guildId, trigger) {
        if (!trigger) return false;
        const s = this.getGuildSettings(guildId);
        if (!s.autoReactions?.reactions) return false;
        const before = s.autoReactions.reactions.length;
        s.autoReactions.reactions = s.autoReactions.reactions.filter(
            r => r.trigger.toLowerCase() !== trigger.toLowerCase()
        );
        if (s.autoReactions.reactions.length === before) return false;
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return true;
    }

    toggleAutoReactions(guildId) {
        const s = this.getGuildSettings(guildId);
        if (!s.autoReactions) {
            s.autoReactions = { enabled: true, reactions: [] };
        } else {
            s.autoReactions.enabled = !s.autoReactions.enabled;
        }
        this.serverSettings.set(guildId, s);
        this._saveGuildSettings(guildId);
        return s.autoReactions.enabled;
    }

    getAutoReactions(guildId) {
        const s = this.getGuildSettings(guildId);
        if (!s.autoReactions) {
            s.autoReactions = { enabled: false, reactions: [] };
            this.serverSettings.set(guildId, s);
        }
        return s.autoReactions;
    }

    getTriggeredReactions(guildId, content) {
        if (!content) return [];
        const s = this.getGuildSettings(guildId);
        if (!s.autoReactions?.enabled) return [];
        const triggered = [];
        for (const reaction of s.autoReactions.reactions) {
            let msg = content;
            let trig = reaction.trigger;
            if (!reaction.caseSensitive) { msg = msg.toLowerCase(); trig = trig.toLowerCase(); }
            if (msg.includes(trig)) triggered.push(reaction.emoji);
        }
        return triggered;
    }
}

module.exports = ServerSettingsManager;
