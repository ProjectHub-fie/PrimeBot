const { automodPool: pool } = require('../server/automodDb');
const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const {
    normalizeRules, metaFor, normalizeAction, normalizeActions,
    normalizeWarnActions, normalizeDmMessages, ACTION_BY_KEY, matchRule,
    renderDmMessage, DEFAULT_DM_MESSAGES,
} = require('./automodRules');
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
        warn_actions        JSONB NOT NULL DEFAULT '["timeout"]',
        dm_enabled          BOOLEAN NOT NULL DEFAULT true,
        dm_messages         JSONB NOT NULL DEFAULT '{}',
        dm_user              BOOLEAN NOT NULL DEFAULT true,
        use_appeal           BOOLEAN NOT NULL DEFAULT false,
        appeal_channel_id   VARCHAR(50),
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
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_actions       JSONB NOT NULL DEFAULT '["timeout"]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_enabled         BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_messages        JSONB NOT NULL DEFAULT '{}';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_user             BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS use_appeal          BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS appeal_channel_id  VARCHAR(50);
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

const CREATE_APPEALS_SQL = `
    CREATE TABLE IF NOT EXISTS automod_appeals (
        id            SERIAL PRIMARY KEY,
        guild_id      VARCHAR(50) NOT NULL,
        user_id       VARCHAR(50) NOT NULL,
        action        VARCHAR(20) NOT NULL,
        reason        TEXT NOT NULL DEFAULT '',
        status        VARCHAR(20) NOT NULL DEFAULT 'pending',
        decision_note TEXT,
        decided_by    VARCHAR(50),
        decided_at    TIMESTAMP,
        reversed      BOOLEAN NOT NULL DEFAULT false,
        created_at    TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS automod_appeals_guild_idx
        ON automod_appeals (guild_id);
    CREATE INDEX IF NOT EXISTS automod_appeals_guild_status_idx
        ON automod_appeals (guild_id, status);
    ALTER TABLE automod_appeals ADD COLUMN IF NOT EXISTS reversed BOOLEAN NOT NULL DEFAULT false;
`;

const CREATE_EMBEDS_SQL = `
    CREATE TABLE IF NOT EXISTS automod_embeds (
        guild_id   VARCHAR(50) NOT NULL,
        cid        INTEGER      NOT NULL,
        action      VARCHAR(60),
        rule_type   VARCHAR(40),
        user_id     VARCHAR(50),
        reason      TEXT NOT NULL DEFAULT '',
        message_id  VARCHAR(50),
        channel_id   VARCHAR(50),
        created_at  TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (guild_id, cid)
    );
    CREATE INDEX IF NOT EXISTS automod_embeds_guild_idx ON automod_embeds (guild_id);
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
        await pool.query(CREATE_APPEALS_SQL);
        await pool.query(CREATE_EMBEDS_SQL);
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._loadAll();
        this._startReloadInterval();
        this._startAppealReversalPoller();
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

    /**
     * Poll for appeals approved from the dashboard (status='approved',
     * reversed=false) and reverse the underlying action. The dashboard and bot
     * share only the DB, so this is how a dashboard approval reaches the bot.
     * Marks each reversed appeal so it is processed only once.
     */
    _startAppealReversalPoller() {
        const ms = parseInt(process.env.APPEAL_POLL_INTERVAL_MS, 10) || 15000;
        setInterval(() => {
            this._processApprovedAppeals().catch(err =>
                console.error('[AUTOMOD] Appeal reversal poll failed:', err.message)
            );
        }, ms).unref?.();
    }

    async _processApprovedAppeals() {
        await this._ensureTable();
        const res = await pool.query(
            `SELECT * FROM automod_appeals WHERE status = 'approved' AND reversed = false LIMIT 50`
        );
        for (const row of res.rows) {
            const appeal = this._rowToAppeal(row);
            await this._reverseAction(appeal).catch(() => {});
            await pool.query('UPDATE automod_appeals SET reversed = true WHERE id = $1', [appeal.id]);
            console.log(`[AUTOMOD] Reversed appeal #${appeal.id} (${appeal.action}) in guild ${appeal.guildId}.`);
        }
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
        const warnActions = Array.isArray(row.warn_actions) && row.warn_actions.length
            ? normalizeWarnActions(row.warn_actions, 'timeout')
            : [normalizeAction(row.warn_action, 'timeout')];
        return {
            enabled: row.enabled,
            logChannelId: row.log_channel_id || null,
            muteRoleId: row.mute_role_id || null,
            exemptRoleIds: normalizeIdArray(row.exempt_role_ids),
            exemptChannelIds: normalizeIdArray(row.exempt_channel_ids),
            rules: normalizeRules(row.rules),
            warnThreshold: Math.max(1, parseInt(row.warn_threshold, 10) || 3),
            warnAction: warnActions[0],
            warnActions,
            dmEnabled: row.dm_enabled !== false,
            dmMessages: normalizeDmMessages(row.dm_messages),
            dmUser: row.dm_user !== false,
            useAppeal: row.use_appeal === true,
            appealChannelId: row.appeal_channel_id || null,
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
            warnActions: ['timeout'],
            dmEnabled: true,
            dmMessages: {},
            dmUser: true,
            useAppeal: false,
            appealChannelId: null,
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
                warn_threshold, warn_action, warn_actions,
                dm_enabled, dm_messages, dm_user, use_appeal, appeal_channel_id, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                enabled            = EXCLUDED.enabled,
                log_channel_id     = EXCLUDED.log_channel_id,
                mute_role_id       = EXCLUDED.mute_role_id,
                exempt_role_ids    = EXCLUDED.exempt_role_ids,
                exempt_channel_ids = EXCLUDED.exempt_channel_ids,
                rules              = EXCLUDED.rules,
                warn_threshold     = EXCLUDED.warn_threshold,
                warn_action        = EXCLUDED.warn_action,
                warn_actions       = EXCLUDED.warn_actions,
                dm_enabled         = EXCLUDED.dm_enabled,
                dm_messages        = EXCLUDED.dm_messages,
                dm_user            = EXCLUDED.dm_user,
                use_appeal         = EXCLUDED.use_appeal,
                appeal_channel_id  = EXCLUDED.appeal_channel_id,
                updated_at         = NOW()
        `, [
            guildId, s.enabled, s.logChannelId, s.muteRoleId,
            JSON.stringify(s.exemptRoleIds), JSON.stringify(s.exemptChannelIds),
            JSON.stringify(s.rules), s.warnThreshold, s.warnAction,
            JSON.stringify(s.warnActions), s.dmEnabled,
            JSON.stringify(s.dmMessages), s.dmUser, s.useAppeal, s.appealChannelId,
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
        if ('warnThreshold' in patch)     next.warnThreshold = Math.max(1, parseInt(patch.warnThreshold, 10) || 3);
        if ('warnAction' in patch)        next.warnAction = normalizeAction(patch.warnAction, 'timeout');
        if ('warnActions' in patch) {
            next.warnActions = normalizeWarnActions(patch.warnActions, next.warnAction || 'timeout');
            next.warnAction = next.warnActions[0];
        }
        if ('dmEnabled' in patch)         next.dmEnabled = patch.dmEnabled !== false;
        if ('dmMessages' in patch)        next.dmMessages = normalizeDmMessages(patch.dmMessages);
        if ('dmUser' in patch)            next.dmUser = patch.dmUser !== false;
        if ('useAppeal' in patch)        next.useAppeal = patch.useAppeal === true;
        if ('appealChannelId' in patch)   next.appealChannelId = patch.appealChannelId || null;
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
                authorCreatedAt: message.author?.createdAt || null,
            };
            if (!ctx.content && !ctx.authorCreatedAt) return null;

            for (const rule of settings.rules) {
                const match = this.matchRule(rule, ctx);
                if (match) {
                    const applied = await this._enforce(message, rule, match.reason, settings, null);
                    return { rule: rule.type, actions: applied, reason: match.reason };
                }
            }
            return null;
        } catch (err) {
            console.error('[AUTOMOD] scanMessage failed:', err.message);
            return null;
        }
    }

    /**
     * Enforce a rule's actions (multi-action) against a message. `delete` is
     * always applied first (so the offending content is removed before further
     * action), then each remaining action runs in order. Returns the list of
     * action keys actually applied. `invoker` is the moderator Message or
     * CommandInteraction responsible for the action (null for fully automatic
     * rule triggers, where the bot itself acts).
     */
    async _enforce(message, rule, reason, settings, invoker = null) {
        const meta = metaFor(rule.type);
        const actions = Array.isArray(rule.actions) && rule.actions.length
            ? rule.actions
            : (rule.action ? [rule.action] : ['delete']);
        // Always delete first if delete is among the actions.
        const ordered = [...actions].sort((a) => (a === 'delete' ? -1 : 0));
        const applied = [];

        // Every automod log embed gets a per-server CID (the embed number, stored in
        // automod_embeds). Generate it up-front so the ban-DM can reference it and the
        // embed title becomes "<type> (CID n)".
        let cid = null;
        if (settings.logChannelId) {
            cid = await this._createEmbedRecord({
                guildId: message.guild.id, channelId: message.channelId,
                userId: message.author.id, action: actions.join(','), ruleType: rule.type, reason,
            });
        }

        // Delete the message up-front if a delete action is present.

        if (ordered.includes('delete')) {
            await message.delete().catch(() => {});
            applied.push('delete');
        }

        const ctx = {
            guild: message.guild,
            member: message.member,
            author: message.author,
            invoker,
            reason,
            settings,
            ruleType: rule.type,
            cid,
        };

        for (const action of ordered) {
            if (action === 'delete') continue;
            try {
                await this._executeAction(action, ctx);
                applied.push(action);
            } catch (err) {
                console.error(`[AUTOMOD] action ${action} failed:`, err.message);
            }
        }

        const actionLabels = applied.map(a => ACTION_BY_KEY[a]?.label || a).join(', ');
        const logFields = [
            { name: 'Member', value: `${ctx.member?.user?.tag || ctx.author?.tag} (<@${ctx.author.id}>)`, inline: false },
            { name: 'Channel', value: `<#${message.channelId}>`, inline: true },
            { name: 'Rule', value: `${meta.icon} ${meta.label} (\`${rule.type}\`)`, inline: true },
            { name: 'Actions', value: actionLabels, inline: true },
            { name: 'Responsible moderator', value: this._moderatorLabel(invoker), inline: true },
            { name: 'Reason', value: reason, inline: false },
        ];
        if (cid) logFields.push({ name: 'CID', value: String(cid), inline: true });
        if (message.content) {
            logFields.push({ name: 'Message', value: truncate(message.content, 1024), inline: false });
        }
        const sentMsg = await this._logToChannel(message, settings, meta, logFields, cid);
        if (cid && sentMsg?.id) {
            await pool.query(
                `UPDATE automod_embeds SET message_id = $3 WHERE guild_id = $1 AND cid = $2`,
                [String(message.guild.id), cid, String(sentMsg.id)]
            ).catch(() => {});
        }
        await logEvent(this.client, message.guild.id, {
            type: 'memberUpdate',
            title: `Automod action (CID ${cid || '—'})`,
            description: `${meta.icon} **${meta.label}** → **${actionLabels}**`,
            fields: logFields,
        });

        return applied;
    }

    /**
     * Execute a single moderation action. Shared by rule enforcement and warn
     * escalation. `ctx` = { guild, member, author, reason, settings, count }.
     * Sends the appropriate DM (when enabled) for the action.
     */
    async _executeAction(action, ctx) {
        const { guild, member, author, reason, settings } = ctx;
        const serverName = guild?.name || 'this server';
        const actionLabel = ACTION_BY_KEY[action]?.label || action;
        const dmEnabled = settings ? settings.dmEnabled !== false : true;
        const dm = (key) => {
            if (!dmEnabled) return Promise.resolve();
            return this._dmMember(author, renderDmMessage(key, {
                server: serverName, reason, actionLabel, threshold: settings?.warnThreshold ?? '',
            }, settings?.dmMessages));
        };

        switch (action) {
            case 'delete':
                // Handled by the caller; no-op here.
                break;
            case 'warn': {
                await this.addWarning(guild.id, author.id, {
                    moderatorId: null, reason, ruleType: ctx.ruleType,
                });
                const count = await this.getWarningCount(guild.id, author.id);
                await dm('warn');
                if (settings && count >= settings.warnThreshold) {
                    await this._applyEscalation(ctx, settings, count);
                }
                break;
            }
            case 'timeout':
                await this._applyTimeout(guild, member, ctx.timeoutSeconds || 600, reason);
                await dm('timeout');
                break;
            case 'kick':
                await member?.kick(`Automod: ${reason}`).catch(() => {});
                await dm('kick');
                break;
            case 'ban':
                await guild.members.ban(author.id, { reason: `Automod: ${reason}` }).catch(() => {});
                // Prefer the "Ban DM" flow (all-fields embed + optional Appeal button,
                // driven by the dashboard Automod tab → "DM user"/"Use appeal"）. Only
                // fall back to the plain automod DM when the appeal manager is absent or
                // didn't send (DM off / DM blocked).
                const appealMgr = this.client?.appealManager;
                if (appealMgr?.sendBanDm) {

                    const sent = await appealMgr.sendBanDm({
                        guild,
                        user: author,
                        reason,
                        rule: metaFor(ctx.ruleType)?.label || null,
                        action: 'ban',
                        moderator: null,
                        cid: ctx.cid || null,
                    }).catch(() => false);
                    if (!sent) await dm('ban');
                } else {
                    await dm('ban');
                }
                break;
        }
    }

    async _applyEscalation(ctx, settings, count) {
        const actions = Array.isArray(settings.warnActions) && settings.warnActions.length
            ? settings.warnActions
            : (settings.warnAction ? [settings.warnAction] : ['timeout']);
        const dmEnabled = settings ? settings.dmEnabled !== false : true;
        try {
            for (const action of actions) {
                if (action === 'warn' || action === 'delete') continue; // skip pointless escalation
                await this._executeAction(action, {
                    ...ctx,
                    reason: `Reached ${count} warnings (automod escalation)`,
                    timeoutSeconds: 3600,
                });
            }
            const actionLabel = actions.map(a => ACTION_BY_KEY[a]?.label || a)
                .filter(l => !['Warn'].includes(l)).join(', ') || 'timeout';
            if (dmEnabled) {
                await this._dmMember(ctx.author, renderDmMessage('escalation', {
                    server: ctx.guild?.name || 'this server', action: actionLabel,
                    reason: `Reached ${count} warnings`, actionLabel, threshold: settings.warnThreshold,
                }, settings.dmMessages));
            }
            await this.removeWarnings(ctx.guild.id, ctx.author.id, 'all').catch(() => {});
        } catch (err) {
            console.error('[AUTOMOD] escalation failed:', err.message);
        }
    }

    async _applyTimeout(guild, member, seconds, reason) {
        if (!member) return;
        // Prefer Discord native timeout (moderate members) when the bot can.
        if (member.moderatable) {
            await member.timeout(seconds * 1000, reason).catch(() => {});
            return;
        }
        // Fall back to the configured mute role.
        const muteRoleId = this.getSettings(guild.id).muteRoleId;
        if (muteRoleId) {
            await member.roles.add(muteRoleId, `Automod: ${reason}`).catch(() => {});
        }
    }

    async _dmMember(author, text) {
        if (!author) return;
        try {
            await author.send(text).catch(() => {});
        } catch { /* DMs may be closed — fire and forget */ }
    }

    async _logToChannel(message, settings, meta, fields, cid = null) {
        if (!settings.logChannelId) return;
        const embed = new EmbedBuilder()
            .setColor(0xED4245)
            .setTitle(cid ? `${meta.icon} Automod · ${meta.label} (CID ${cid})` : `${meta.icon} Automod · ${meta.label}`)
            .setTimestamp();
        for (const f of fields) {
            if (f && f.name && f.value) embed.addFields({ name: f.name, value: String(f.value), inline: !!f.inline });
        }
        embed.setFooter({ text: 'PrimeBot Automod' });
        try {
            const ch = await this.client.channels.fetch(settings.logChannelId);
            const msg = await ch?.send?.({ embeds: [embed] }).catch(() => null);
            return msg || null;
        } catch {
            return null;
        }
    }

    /**
     * Create the automod_embeds ledger row for this enforcement and return the next
     * per-server CID (the primary key / embed number). The CID is generated lazily:
     * MAX(cid)+1 within the guild, ensuring monotonically increasing embed numbers.
     */
    async _createEmbedRecord({ guildId, channelId = null, userId = null, action = null, ruleType = null, reason = '' }) {
        await this._ensureTable();
        try {
            const res = await pool.query(`
                INSERT INTO automod_embeds (guild_id, cid, action, rule_type, user_id, reason, channel_id)
                SELECT $1, COALESCE(MAX(cid), 0) + 1, $2, $3, $4, $5, $6
                FROM automod_embeds WHERE guild_id = $1
                RETURNING cid
            `, [String(guildId), String(action || ''), String(ruleType || ''), String(userId || ''), String(reason || ''), String(channelId || '')]);
            return res.rows[0] ? Number(res.rows[0].cid) : null;
        } catch (err) {
            console.error('[AUTOMOD] Failed to create embed CID:', err.message);
            return null;
        }
    }

    /**
     * Set/change/remove the persisted reason for an automod embed. `$rmr` /
     * `$rename (CID) [reason]` and the dashboard's CID pane drive this. An empty
     * reason *removes* the stored reason.
     * @returns {Promise<number>} 1 if a row was updated, 0 if the CID didn't exist.
     */
    async setEmbedReason(guildId, cid, reason = '') {
        await this._ensureTable();
        const cidNum = parseInt(cid, 10);
        if (!Number.isFinite(cidNum)) return 0;
        const res = await pool.query(
            `UPDATE automod_embeds SET reason = $3 WHERE guild_id = $1 AND cid = $2`,
            [String(guildId), cidNum, String(reason || '' ).slice(0, 1000)]
        );
        return res.rowCount || 0;
    }
    // ─── Manual moderation helpers (used by /warn, /mute, prefix commands) ─────
    //
    // These accept either a discord.js Message (prefix) or a CommandInteraction
    // (slash). Interactions expose `.user` where messages expose `.author`; both
    // have `.guild`, `.channel`, and `.member` (the invoker).

    _moderatorId(invoker) {
        return invoker?.author?.id || invoker?.user?.id || null;
    }

    // Human-readable "responsible moderator" line for automod embeds. Accepts a
    // prefix Message (`.author`) or a slash CommandInteraction (`.user`). When
    // the action was fully automatic (no human invoker) the bot itself is
    // credited as the moderator.
    _moderatorLabel(invoker) {
        const user = invoker?.author || invoker?.user || null;
        if (!user) return 'PrimeBot Automod (automatic)';
        const id = user.id ? ` (<@${user.id}>)` : '';
        return `${user.tag || user.username || 'unknown'}${id}`;
    }

    async warnMember(invoker, member, reason) {
        const count = await this.addWarning(invoker.guild.id, member.id, {
            moderatorId: this._moderatorId(invoker), reason,
        });
        const settings = this.getSettings(invoker.guild.id);
        let escalated = false;
        if (count >= settings.warnThreshold) {
            await this._applyEscalation({
                guild: invoker.guild, member, author: member.user, invoker, reason, settings,
            }, settings, count);
            escalated = true;
        }
        return { count, escalated, warnThreshold: settings.warnThreshold, warnAction: settings.warnAction, warnActions: settings.warnActions };
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

    // ─── Appeals ─────────────────────────────────────────────────────────────
    //
    // Members punished by automod can file an appeal (via /appeal or the
    // dashboard). Moderators review pending appeals and approve/deny them.
    // Approving reverses the action where possible: unbans, removes timeout/mute.

    async submitAppeal({ guildId, userId, action, reason }) {
        await this._ensureTable();
        const res = await pool.query(`
            INSERT INTO automod_appeals (guild_id, user_id, action, reason)
            VALUES ($1,$2,$3,$4)
            RETURNING *
        `, [guildId, userId, normalizeAction(action, 'timeout'), String(reason || '').slice(0, 1000) || 'No reason provided']);
        return this._rowToAppeal(res.rows[0]);
    }

    async getAppeals(guildId, { status = null } = {}) {
        await this._ensureTable();
        const params = [guildId];
        let q = 'SELECT * FROM automod_appeals WHERE guild_id = $1';
        if (status) { q += ' AND status = $2'; params.push(status); }
        q += ' ORDER BY created_at DESC LIMIT 200';
        const res = await pool.query(q, params);
        return res.rows.map(r => this._rowToAppeal(r));
    }

    async getAppeal(id) {
        await this._ensureTable();
        const res = await pool.query('SELECT * FROM automod_appeals WHERE id = $1', [id]);
        return res.rows[0] ? this._rowToAppeal(res.rows[0]) : null;
    }

    async decideAppeal(id, { approved, decidedBy, note = '' }) {
        await this._ensureTable();
        const status = approved ? 'approved' : 'denied';
        const res = await pool.query(`
            UPDATE automod_appeals
            SET status = $2, decision_note = $3, decided_by = $4, decided_at = NOW()
            WHERE id = $1 AND status = 'pending'
            RETURNING *
        `, [id, status, String(note || '').slice(0, 1000), decidedBy]);
        const appeal = res.rows[0] ? this._rowToAppeal(res.rows[0]) : null;
        if (appeal && approved) {
            // Reversal is best-effort; mark reversed so the dashboard-approval
            // poller doesn't double-process it.
            const reversed = await this._reverseAction(appeal).then(() => true).catch(() => false);
            if (reversed) {
                await pool.query('UPDATE automod_appeals SET reversed = true WHERE id = $1', [appeal.id]).catch(() => {});
                appeal.reversed = true;
            }
        }
        return appeal;
    }

    /**
     * Reverse a previously-applied automod action when an appeal is approved.
     * Best-effort: unban, remove timeout, remove mute role. Failures are
     * fire-and-forget.
     */
    async _reverseAction(appeal) {
        const guild = this.client?.guilds?.cache?.get(appeal.guildId);
        if (!guild) return;
        const member = await guild.members.fetch(appeal.userId).catch(() => null);
        if (appeal.action === 'ban') {
            await guild.members.unban(appeal.userId, 'Appeal approved').catch(() => {});
        } else if (member) {
            if (member.communicationDisabledUntilTimestamp) {
                await member.timeout(null, 'Appeal approved').catch(() => {});
            }
            const muteRoleId = this.getSettings(appeal.guildId).muteRoleId;
            if (muteRoleId && member.roles.cache.has(muteRoleId)) {
                await member.roles.remove(muteRoleId, 'Appeal approved').catch(() => {});
            }
        }
    }

    _rowToAppeal(row) {
        return {
            id: row.id,
            guildId: row.guild_id,
            userId: row.user_id,
            action: row.action,
            reason: row.reason,
            status: row.status,
            decisionNote: row.decision_note || null,
            decidedBy: row.decided_by || null,
            decidedAt: row.decided_at || null,
            reversed: row.reversed === true,
            createdAt: row.created_at,
        };
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
