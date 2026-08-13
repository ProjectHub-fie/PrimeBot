const { automodPool: pool } = require('../server/automodDb');
const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const { normalizeRules, metaFor, normalizeAction, ACTION_BY_KEY, matchRule } = require('./automodRules');
const { logEvent } = require('./serverLogger');

/**
 * Premium Automod — backed by PostgreSQL (AUTOMOD_DATABASE_URL, falls back to
 * DATABASE_URL; dedicated pool in server/automodDb.js).
 *
 * Mirrors the caching pattern of LoggingSettingsManager / ReactionRoleManager:
 * an in-memory Map holds per-guild settings (read-through cache), writes go
 * straight to DB (fire-and-forget), and the table is re-read on a ~30s + 5s
 * interval so dashboard saves take effect without a bot restart.
 *
 * On every message, scanMessage() runs the guild's enabled rules against the
 * message content/author and enforces the configured action (delete, warn,
 * timeout, kick, ban). Manual moderator warnings (/warn, prefix warn) and
 * automod warnings share the same ledger (automod_warnings); when a member's
 * warning count reaches warnThreshold, the configured warnAction is applied —
 * the premium "escalation" feature, free.
 *
 * Failures are fire-and-forget: an automod enforcement error never throws back
 * into the message handler.
 */

const CREATE_SETTINGS_SQL = `
    CREATE TABLE IF NOT EXISTS automod_settings (
        guild_id            VARCHAR(50) PRIMARY KEY,
        enabled             BOOLEAN NOT NULL DEFAULT false,
        log_channel_id      VARCHAR(50),
        mute_role_id        VARCHAR(50),
        exempt_role_ids     JSONB NOT NULL DEFAULT '[]',
        exempt_channel_ids  JSONB NOT NULL DEFAULT '[]',
        rules               JSONB NOT NULL DEFAULT '[]',
        warn_threshold      INTEGER NOT NULL DEFAULT 3,
        warn_action         VARCHAR(20) DEFAULT 'timeout',
        updated_at          TIMESTAMP DEFAULT NOW()
    )
`;
const ENSURE_COLUMNS_SQL = `
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS log_channel_id     VARCHAR(50);
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS mute_role_id       VARCHAR(50);
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_role_ids    JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_channel_ids JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS rules              JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_threshold     INTEGER NOT NULL DEFAULT 3;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_action        VARCHAR(20) DEFAULT 'timeout';
`;

const CREATE_WARNINGS_SQL = `
    CREATE TABLE IF NOT EXISTS automod_warnings (
        id           SERIAL PRIMARY KEY,
        guild_id     VARCHAR(50) NOT NULL,
        user_id      VARCHAR(50) NOT NULL,
        moderator_id VARCHAR(50),
        reason       TEXT NOT NULL DEFAULT '',
        rule_type    VARCHAR(40),
        created_at   TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS automod_warnings_guild_user_idx
        ON automod_warnings (guild_id, user_id);
    CREATE INDEX IF NOT EXISTS automod_warnings_guild_idx
        ON automod_warnings (guild_id);
`;

// In-memory spam tracker (not persisted): userId|guildId -> [{content, ts}]
const spamWindow = new Map();
const SPAM_WINDOW_TTL = 60_000;

class AutomodManager {
    constructor(client) {
        this.client = client;
        this._cache = new Map();
        this._tableReady = false;
        this._init().catch(err =>
            console.error('[AUTOMOD] Init failed:', err.message)
        );
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    async _ensureTable() {
        if (this._tableReady) return;
        await pool.query(CREATE_SETTINGS_SQL);
        await pool.query(ENSURE_COLUMNS_SQL);
        await pool.query(CREATE_WARNINGS_SQL);
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._loadAll();
        this._startReloadInterval();
    }

    _startReloadInterval() {
        const ms = parseInt(process.env.SETTINGS_RELOAD_INTERVAL_MS, 10) || 30000;
        setInterval(() => {
            this._loadAll().catch(err =>
                console.error('[AUTOMOD] Background reload failed:', err.message)
            );
        }, ms).unref?.();
        setInterval(() => {
            this._refreshFromDatabase().catch(err =>
                console.error('[AUTOMOD] Refresh failed:', err.message)
            );
        }, 5000).unref?.();
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const res = await pool.query('SELECT * FROM automod_settings');
        for (const row of res.rows) {
            const next = this._rowToSettings(row);
            const previous = this._cache.get(row.guild_id);
            if (!previous || JSON.stringify(previous) !== JSON.stringify(next)) {
                this._cache.set(row.guild_id, next);
                if (previous) {
                    console.log(`[AUTOMOD] Applied database update for guild ${row.guild_id}.`);
                }
            }
        }
    }

    async _loadAll() {
        try {
            const res = await pool.query('SELECT * FROM automod_settings');
            for (const row of res.rows) {
                this._cache.set(row.guild_id, this._rowToSettings(row));
            }
            console.log(`[AUTOMOD] Loaded settings for ${this._cache.size} servers.`);
        } catch (err) {
            console.error('[AUTOMOD] Failed to load settings:', err.message);
        }
    }

    _rowToSettings(row) {
        return {
            enabled: row.enabled,
            logChannelId: row.log_channel_id || null,
            muteRoleId: row.mute_role_id || null,
            exemptRoleIds: normalizeIdArray(row.exempt_role_ids),
            exemptChannelIds: normalizeIdArray(row.exempt_channel_ids),
            rules: normalizeRules(row.rules),
            warnThreshold: Math.max(1, parseInt(row.warn_threshold, 10) || 3),
            warnAction: normalizeAction(row.warn_action, 'timeout'),
        };
    }

    _defaults() {
        return {
            enabled: false,
            logChannelId: null,
            muteRoleId: null,
            exemptRoleIds: [],
            exemptChannelIds: [],
            rules: [],
            warnThreshold: 3,
            warnAction: 'timeout',
        };
    }

    getSettings(guildId) {
        if (!this._cache.has(guildId)) this._cache.set(guildId, this._defaults());
        return this._cache.get(guildId);
    }

    isEnabled(guildId) {
        return this.getSettings(guildId).enabled;
    }

    // ─── Persistence ─────────────────────────────────────────────────────────

    _save(guildId) {
        this._saveAsync(guildId).catch(err =>
            console.error(`[AUTOMOD] Save failed for guild ${guildId}:`, err.message)
        );
    }

    async _saveAsync(guildId) {
        const s = this.getSettings(guildId);
        await this._ensureTable();
        await pool.query(`
            INSERT INTO automod_settings (
                guild_id, enabled, log_channel_id, mute_role_id,
                exempt_role_ids, exempt_channel_ids, rules,
                warn_threshold, warn_action, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                enabled            = EXCLUDED.enabled,
                log_channel_id     = EXCLUDED.log_channel_id,
                mute_role_id       = EXCLUDED.mute_role_id,
                exempt_role_ids    = EXCLUDED.exempt_role_ids,
                exempt_channel_ids = EXCLUDED.exempt_channel_ids,
                rules              = EXCLUDED.rules,
                warn_threshold     = EXCLUDED.warn_threshold,
                warn_action        = EXCLUDED.warn_action,
                updated_at         = NOW()
        `, [
            guildId, s.enabled, s.logChannelId, s.muteRoleId,
            JSON.stringify(s.exemptRoleIds), JSON.stringify(s.exemptChannelIds),
            JSON.stringify(s.rules), s.warnThreshold, s.warnAction,
        ]);
    }

    /** Bulk replace settings (from the dashboard or slash command). */
    updateSettings(guildId, patch = {}) {
        const next = { ...this.getSettings(guildId) };
        if ('enabled' in patch)           next.enabled = Boolean(patch.enabled);
        if ('logChannelId' in patch)      next.logChannelId = patch.logChannelId || null;
        if ('muteRoleId' in patch)        next.muteRoleId = patch.muteRoleId || null;
        if ('exemptRoleIds' in patch)     next.exemptRoleIds = normalizeIdArray(patch.exemptRoleIds);
        if ('exemptChannelIds' in patch)  next.exemptChannelIds = normalizeIdArray(patch.exemptChannelIds);
        if ('rules' in patch)             next.rules = normalizeRules(patch.rules);
        if ('warnThreshold' in patch)    next.warnThreshold = Math.max(1, parseInt(patch.warnThreshold, 10) || 3);
        if ('warnAction' in patch)        next.warnAction = normalizeAction(patch.warnAction, 'timeout');
        this._cache.set(guildId, next);
        this._save(guildId);
        return next;
    }

    // ─── Warnings ledger ─────────────────────────────────────────────────────

    async addWarning(guildId, userId, { moderatorId = null, reason = '', ruleType = null } = {}) {
        await this._ensureTable();
        await pool.query(`
            INSERT INTO automod_warnings (guild_id, user_id, moderator_id, reason, rule_type)
            VALUES ($1,$2,$3,$4,$5)
        `, [guildId, userId, moderatorId, String(reason || '').slice(0, 1000) || 'No reason provided', ruleType]);
        return this.getWarningCount(guildId, userId);
    }

    async removeWarnings(guildId, userId, count = 1) {
        await this._ensureTable();
        if (count === 'all') {
            await pool.query('DELETE FROM automod_warnings WHERE guild_id = $1 AND user_id = $2', [guildId, userId]);
            return 0;
        }
        const n = Math.max(1, parseInt(count, 10) || 1);
        // Delete the most recent N warnings.
        await pool.query(`
            DELETE FROM automod_warnings WHERE id IN (
                SELECT id FROM automod_warnings
                WHERE guild_id = $1 AND user_id = $2
                ORDER BY created_at DESC
                LIMIT $3
            )
        `, [guildId, userId, n]);
        return this.getWarningCount(guildId, userId);
    }

    async getWarnings(guildId, userId) {
        await this._ensureTable();
        const res = await pool.query(
            'SELECT * FROM automod_warnings WHERE guild_id = $1 AND user_id = $2 ORDER BY created_at DESC',
            [guildId, userId]
        );
        return res.rows.map(r => ({
            id: r.id, userId: r.user_id, moderatorId: r.moderator_id,
            reason: r.reason, ruleType: r.rule_type, createdAt: r.created_at,
        }));
    }

    async getWarningCount(guildId, userId) {
        await this._ensureTable();
        const res = await pool.query(
            'SELECT COUNT(*)::int AS count FROM automod_warnings WHERE guild_id = $1 AND user_id = $2',
            [guildId, userId]
        );
        return res.rows[0]?.count || 0;
    }

    // ─── Exemption check ──────────────────────────────────────────────────────

    isExempt(message, settings) {
        if (!message.guild) return true;
        const member = message.member;
        if (member && member.permissions.has(PermissionFlagsBits.Administrator)) return true;
        const exemptRoles = new Set(settings.exemptRoleIds);
        if (member && member.roles.cache.some(r => exemptRoles.has(r.id))) return true;
        const exemptChannels = new Set(settings.exemptChannelIds);
        if (exemptChannels.has(message.channelId)) return true;
        return false;
    }

    // ─── Rule matching ────────────────────────────────────────────────────────

    /** Test a single rule against a message. Returns { reason } on match or null. */
    matchRule(rule, ctx) {
        return matchRule(rule, ctx, spamWindow);
    }

    // ─── Enforcement ──────────────────────────────────────────────────────────

    /** Run the guild's rules against a message and enforce the first match. */
    async scanMessage(message) {
        try {
            if (!message.guild || message.author.bot) return null;
            const guildId = message.guild.id;
            const settings = this.getSettings(guildId);
            if (!settings.enabled) return null;
            if (this.isExempt(message, settings)) return null;

            const ctx = {
                content: message.content || '',
                guildId,
                userId: message.author.id,
                channelId: message.channelId,
            };
            if (!ctx.content) return null;

            for (const rule of settings.rules) {
                const match = this.matchRule(rule, ctx);
                if (match) {
                    await this._enforce(message, rule, match.reason, settings);
                    return { rule: rule.type, action: rule.action, reason: match.reason };
                }
            }
            return null;
        } catch (err) {
            console.error('[AUTOMOD] scanMessage failed:', err.message);
            return null;
        }
    }

    async _enforce(message, rule, reason, settings) {
        const meta = metaFor(rule.type);
        const target = message.member || message.author;
        const logFields = [
            { name: 'Member', value: `${target.user ? target.user.tag : target.tag} (<@${message.author.id}>)`, inline: false },
            { name: 'Channel', value: `<#${message.channelId}>`, inline: true },
            { name: 'Rule', value: `${meta.icon} ${meta.label} (\`${rule.type}\`)`, inline: true },
            { name: 'Action', value: ACTION_BY_KEY[rule.action]?.label || rule.action, inline: true },
            { name: 'Reason', value: reason, inline: false },
        ];
        if (message.content) {
            logFields.push({ name: 'Message', value: truncate(message.content, 1024), inline: false });
        }

        switch (rule.action) {
            case 'delete':
                await message.delete().catch(() => {});
                await this._notifyMember(message, `Your message in **${message.guild.name}** was removed: ${reason}.`);
                break;
            case 'warn':
                await message.delete().catch(() => {});
                await this.addWarning(message.guild.id, message.author.id, {
                    moderatorId: null, reason, ruleType: rule.type,
                });
                const count = await this.getWarningCount(message.guild.id, message.author.id);
                await this._notifyMember(message, `⚠️ **Warning ${count}/${settings.warnThreshold}** in **${message.guild.name}**: ${reason}. Further warnings may escalate to **${settings.warnAction}**.`);
                if (count >= settings.warnThreshold) {
                    await this._applyEscalation(message, settings, count);
                }
                break;
            case 'timeout':
                await message.delete().catch(() => {});
                await this._applyTimeout(message, 600, reason);
                break;
            case 'kick':
                await message.delete().catch(() => {});
                await message.member?.kick(`Automod: ${reason}`).catch(() => {});
                break;
            case 'ban':
                await message.delete().catch(() => {});
                await message.guild.members.ban(message.author.id, { reason: `Automod: ${reason}` }).catch(() => {});
                break;
        }

        // Send to the automod log channel (if configured) and to server logging.
        this._logToChannel(message, settings, meta, logFields);
        logEvent(this.client, message.guild.id, {
            type: 'memberUpdate',
            title: 'Automod action',
            description: `${meta.icon} **${meta.label}** → **${ACTION_BY_KEY[rule.action]?.label || rule.action}**`,
            fields: logFields,
        });
    }

    async _applyEscalation(message, settings, count) {
        const action = settings.warnAction;
        try {
            if (action === 'timeout') {
                await this._applyTimeout(message, 3600, `Reached ${count} warnings (automod escalation)`);
            } else if (action === 'kick') {
                await message.member?.kick(`Automod escalation: ${count} warnings`).catch(() => {});
            } else if (action === 'ban') {
                await message.guild.members.ban(message.author.id, { reason: `Automod escalation: ${count} warnings` }).catch(() => {});
            }
            await this._notifyMember(message, `🚫 You reached **${count}** warnings in **${message.guild.name}** and were escalated to **${action}**.`);
            await this.removeWarnings(message.guild.id, message.author.id, 'all').catch(() => {});
        } catch (err) {
            console.error('[AUTOMOD] escalation failed:', err.message);
        }
    }

    async _applyTimeout(message, seconds, reason) {
        const member = message.member;
        if (!member) return;
        // Prefer Discord native timeout (moderate members) when the bot can.
        if (member.moderatable) {
            await member.timeout(seconds * 1000, reason).catch(() => {});
            return;
        }
        // Fall back to the configured mute role.
        const muteRoleId = this.getSettings(message.guild.id).muteRoleId;
        if (muteRoleId) {
            await member.roles.add(muteRoleId, `Automod: ${reason}`).catch(() => {});
        }
    }

    async _notifyMember(message, text) {
        try {
            await message.author.send(text).catch(() => {});
        } catch { /* DMs may be closed — fire and forget */ }
    }

    _logToChannel(message, settings, meta, fields) {
        if (!settings.logChannelId) return;
        const embed = new EmbedBuilder()
            .setColor(0xED4245)
            .setTitle(`${meta.icon} Automod · ${meta.label}`)
            .setTimestamp();
        for (const f of fields) {
            if (f && f.name && f.value) embed.addFields({ name: f.name, value: String(f.value), inline: !!f.inline });
        }
        embed.setFooter({ text: 'PrimeBot Automod' });
        this.client.channels.fetch(settings.logChannelId)
            .then(ch => ch?.send?.({ embeds: [embed] }).catch(() => {}))
            .catch(() => {});
    }

    // ─── Manual moderation helpers (used by /warn, /mute, prefix commands) ─────
    //
    // These accept either a discord.js Message (prefix) or a CommandInteraction
    // (slash). Interactions expose `.user` where messages expose `.author`; both
    // have `.guild`, `.channel`, and `.member` (the invoker).

    _moderatorId(invoker) {
        return invoker?.author?.id || invoker?.user?.id || null;
    }

    async warnMember(invoker, member, reason) {
        const count = await this.addWarning(invoker.guild.id, member.id, {
            moderatorId: this._moderatorId(invoker), reason,
        });
        const settings = this.getSettings(invoker.guild.id);
        let escalated = false;
        if (count >= settings.warnThreshold) {
            await this._applyEscalation({ guild: invoker.guild, member, author: member.user }, settings, count);
            escalated = true;
        }
        return { count, escalated, warnThreshold: settings.warnThreshold, warnAction: settings.warnAction };
    }

    async muteMember(invoker, member, seconds = null, reason = 'Muted by moderator') {
        if (member.moderatable && seconds) {
            await member.timeout(seconds * 1000, reason).catch(() => {});
        } else {
            const muteRoleId = this.getSettings(invoker.guild.id).muteRoleId;
            if (muteRoleId) {
                await member.roles.add(muteRoleId, reason).catch(() => {});
            } else if (member.moderatable) {
                await member.timeout((seconds || 600) * 1000, reason).catch(() => {});
            }
        }
    }

    async unmuteMember(invoker, member) {
        if (member.communicationDisabledUntilTimestamp) {
            await member.timeout(null, 'Unmuted by moderator').catch(() => {});
        }
        const muteRoleId = this.getSettings(invoker.guild.id).muteRoleId;
        if (muteRoleId && member.roles.cache.has(muteRoleId)) {
            await member.roles.remove(muteRoleId, 'Unmuted by moderator').catch(() => {});
        }
    }
}

function normalizeIdArray(v) {
    if (!Array.isArray(v)) return [];
    return v.map(x => String(x || '').trim()).filter(Boolean);
}

function truncate(str, n) {
    const s = String(str || '');
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

module.exports = AutomodManager;
