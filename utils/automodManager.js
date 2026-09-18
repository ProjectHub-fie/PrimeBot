const { automodPool: pool } = require('../server/automodDb');
const { AdaptivePoller } = require('./adaptivePoller');
const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const {
    normalizeRules, metaFor, normalizeAction, normalizeActions,
    normalizeWarnActions, normalizeWarnLadder, normalizeDmMessages,
    normalizeStringList, severityMeta, ACTION_BY_KEY, matchRule,
    renderDmMessage, DEFAULT_DM_MESSAGES, buildDetectionTexts,
    pruneDetectionState, checkCooldown, isExemptFromRule, RULE_BY_KEY,
    MESSAGE_RULE_KEYS, JOIN_RULE_KEYS, normalizeSeverity,
} = require('./automodRules');
const { logEvent } = require('./serverLogger');

/**
 * Premium Automod — backed by PostgreSQL (AUTOMOD_DATABASE_URL, falls back to
 * DATABASE_URL; dedicated pool in server/automodDb.js).
 *
 * Mirrors the caching pattern of LoggingSettingsManager / ReactionRoleManager:
 * an in-memory Map holds per-guild settings (read-through cache), writes go
 * straight to DB (fire-and-forget), and the table is re-read by an AdaptivePoller
 * so dashboard saves take effect without a bot restart.
 *
 * ── Database-efficiency contract (Neon) ─────────────────────────────────────
 * The message hot path NEVER queries PostgreSQL:
 *
 *   message → cached guild config (Map) → in-memory rule evaluation
 *           → only on a violation: one incident INSERT (+ one embed-ledger row)
 *
 * All short-lived state (flood windows, duplicate windows, join bursts,
 * per-rule cooldowns) lives in in-memory Maps that are opportunistically pruned;
 * nothing about a normal message is ever persisted. Analytics are computed by
 * the dashboard from the incident table with indexed, time-bounded queries —
 * never by the bot on the hot path.
 *
 * ── Fail-safe contract ──────────────────────────────────────────────────────
 * Every rule and every action is individually wrapped: rule A succeeding while
 * rule B throws must not abort the scan. Bot/webhook/system messages and
 * PrimeBot's own messages are skipped so an enforcement action can never
 * re-trigger the engine (loop protection).
 */

const CREATE_SETTINGS_SQL = `
    CREATE TABLE IF NOT EXISTS automod_settings (
        guild_id            VARCHAR(50) PRIMARY KEY,
        enabled             BOOLEAN NOT NULL DEFAULT false,
        log_channel_id      VARCHAR(50),
        mute_role_id        VARCHAR(50),
        exempt_role_ids     JSONB NOT NULL DEFAULT '[]',
        exempt_channel_ids  JSONB NOT NULL DEFAULT '[]',
        exempt_user_ids     JSONB NOT NULL DEFAULT '[]',
        rules               JSONB NOT NULL DEFAULT '[]',
        warn_threshold      INTEGER NOT NULL DEFAULT 3,
        warn_action         VARCHAR(20) DEFAULT 'timeout',
        warn_actions        JSONB NOT NULL DEFAULT '["timeout"]',
        warn_ladder         JSONB NOT NULL DEFAULT '[]',
        dm_enabled          BOOLEAN NOT NULL DEFAULT true,
        dm_messages         JSONB NOT NULL DEFAULT '{}',
        dm_user              BOOLEAN NOT NULL DEFAULT true,
        use_appeal           BOOLEAN NOT NULL DEFAULT false,
        appeal_channel_id   VARCHAR(50),
        dry_run             BOOLEAN NOT NULL DEFAULT false,
        raid_lockdown       BOOLEAN NOT NULL DEFAULT false,
        raid_alert_channel_id VARCHAR(50),
        incident_retention_days INTEGER NOT NULL DEFAULT 30,
        updated_at          TIMESTAMP DEFAULT NOW()
    )
`;
const ENSURE_COLUMNS_SQL = `
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS log_channel_id     VARCHAR(50);
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS mute_role_id       VARCHAR(50);
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_role_ids    JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_channel_ids JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_user_ids    JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS rules              JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_threshold     INTEGER NOT NULL DEFAULT 3;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_action        VARCHAR(20) DEFAULT 'timeout';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_actions       JSONB NOT NULL DEFAULT '["timeout"]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_ladder        JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_enabled         BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_messages        JSONB NOT NULL DEFAULT '{}';
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_user             BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS use_appeal          BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS appeal_channel_id  VARCHAR(50);
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dry_run            BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS raid_lockdown      BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS raid_alert_channel_id VARCHAR(50);
    ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS incident_retention_days INTEGER NOT NULL DEFAULT 30;
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

// Incident ledger — the searchable, paginated history behind the dashboard's
// Incident Center + Analytics. One row per enforcement (never per message), so
// the table grows at the rate of *violations*, not traffic. Indexed for the
// dashboard's actual query shapes: (guild_id, created_at DESC) for the list,
// (guild_id, rule_type) / (guild_id, severity) for the filter dropdowns.
const CREATE_INCIDENTS_SQL = `
    CREATE TABLE IF NOT EXISTS automod_incidents (
        id          SERIAL PRIMARY KEY,
        guild_id    VARCHAR(50) NOT NULL,
        user_id     VARCHAR(50),
        username    VARCHAR(120),
        channel_id  VARCHAR(50),
        message_id  VARCHAR(50),
        rule_type   VARCHAR(40) NOT NULL,
        actions     JSONB NOT NULL DEFAULT '[]',
        severity    VARCHAR(20) NOT NULL DEFAULT 'medium',
        reason      TEXT NOT NULL DEFAULT '',
        dry_run     BOOLEAN NOT NULL DEFAULT false,
        cid         INTEGER,
        created_at  TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS automod_incidents_guild_created_idx
        ON automod_incidents (guild_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS automod_incidents_guild_rule_idx
        ON automod_incidents (guild_id, rule_type);
    CREATE INDEX IF NOT EXISTS automod_incidents_guild_severity_idx
        ON automod_incidents (guild_id, severity);
    CREATE INDEX IF NOT EXISTS automod_incidents_guild_user_idx
        ON automod_incidents (guild_id, user_id);
`;

// ── In-memory detection state (never persisted) ──────────────────────────────
// These Maps hold the short-lived windows every stateful rule reads. They are
// owned by the module (not per manager) so the message hot path never touches
// PostgreSQL, and they are pruned opportunistically (see _pruneState).
const spamWindow  = new Map(); // flood:      guildId|channelId|userId -> [{content, ts}]
const dupWindow   = new Map(); // duplicates: guildId|channelId|userId -> [{content, ts}]
const joinWindow  = new Map(); // raid joins: guildId -> [{ts, accountAgeDays}]
const nameWindow  = new Map(); // raid names: guildId -> [{ts, username}]
const cooldowns   = new Map(); // cooldowns:  guildId|rule|userId -> expiresAtMs
const DETECTION_STATE = {
    spam: spamWindow,
    dupes: dupWindow,
    joins: joinWindow,
    names: nameWindow,
    cooldown: cooldowns,
};

class AutomodManager {
    constructor(client) {
        this.client = client;
        this._cache = new Map();
        this._tableReady = false;
        this._reloadTimer = null;
        this._appealPoller = null;
        this._retentionTimer = null;
        this._lastPruneAt = 0;
        // Dry-run counters are per-process and advisory only (the dashboard reads
        // the incident table for the real numbers); reset on restart.
        this._dryRunCounts = new Map(); // guildId -> number of detections
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
        await pool.query(CREATE_INCIDENTS_SQL);
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._loadAll();
        this._startReloadInterval();
        this._startAppealReversalPoller();
        this._startRetentionCleanup();
    }

    /**
     * Opportunistically prune the in-memory detection maps. Runs at most once
     * per 30s and only walks the maps — never the database.
     */
    _pruneState() {
        const now = Date.now();
        if (now - this._lastPruneAt < 30000) return;
        this._lastPruneAt = now;
        for (const store of [spamWindow, dupWindow, joinWindow, nameWindow, cooldowns]) {
            try {
                pruneDetectionState(store);
            } catch { /* pruning must never throw into the hot path */ }
        }
    }

    _startReloadInterval() {
        if (this._reloadTimer) return;
        // One adaptive poller replaces the fixed 60s reload + 15s refresh pair
        // (both ran a full `SELECT * FROM automod_settings`). It backs off while
        // the table is quiet so a dormant deployment stops waking Neon.
        this._reloadTimer = new AdaptivePoller({
            name: 'AUTOMOD',
            task: () => this._refreshFromDatabase(),
        });
        this._reloadTimer.start();
    }

    /**
     * Retention cleanup: delete incidents older than the guild's configured
     * retention window. Batched (one bounded DELETE per run), scheduled hourly
     * via an AdaptivePoller that backs off while there is nothing to delete, so
     * a quiet deployment costs one cheap query per hour. Disabled entirely when
     * `AUTOMOD_RETENTION_ENABLED=false`.
     */
    _startRetentionCleanup() {
        if (this._retentionTimer) return;
        if (process.env.AUTOMOD_RETENTION_ENABLED === 'false') return;
        this._retentionTimer = new AdaptivePoller({
            name: 'AUTOMOD RETENTION',
            task: () => this._cleanupIncidents(),
            initialMs: parseInt(process.env.AUTOMOD_RETENTION_INTERVAL_MS, 10) || 60 * 60 * 1000,
            maxMs: 6 * 60 * 60 * 1000,
            quietTicks: 1,
        });
        this._retentionTimer.start();
    }

    /** @returns {Promise<boolean>} true when at least one row was deleted. */
    async _cleanupIncidents() {
        await this._ensureTable();
        // A single bounded statement: the sub-select finds guilds whose retention
        // window has lapsed and removes at most 500 of their oldest rows. This
        // avoids a huge unbounded DELETE and never scans the table per tick.
        const res = await pool.query(`
            DELETE FROM automod_incidents
            WHERE id IN (
                SELECT i.id FROM automod_incidents i
                JOIN automod_settings s ON s.guild_id = i.guild_id
                WHERE s.incident_retention_days > 0
                  AND i.created_at < NOW() - (s.incident_retention_days || ' days')::interval
                ORDER BY i.created_at ASC
                LIMIT 500
            )
        `);
        const deleted = res.rowCount || 0;
        if (deleted > 0) console.log(`[AUTOMOD] Retention cleanup removed ${deleted} old incident(s).`);
        return deleted > 0;
    }

    /**
     * Poll for appeals approved from the dashboard (status='approved',
     * reversed=false) and reverse the underlying action. The dashboard and bot
     * share only the DB, so this is how a dashboard approval reaches the bot.
     * Marks each reversed appeal so it is processed only once.
     *
     * Adaptive: approves are rare, so a fixed 30s scan cost ~2,880 queries a
     * day against an almost-always-empty result. The poller now backs off while
     * nothing is approved (resuming the fast interval the moment an approval
     * appears), which keeps Neon suspended on quiet deployments.
     */
    _startAppealReversalPoller() {
        if (this._appealPoller) return;
        this._appealPoller = new AdaptivePoller({
            name: 'AUTOMOD APPEALS',
            task: () => this._processApprovedAppeals(),
            initialMs: parseInt(process.env.APPEAL_POLL_INTERVAL_MS, 10) || 30000,
        });
        this._appealPoller.start();
    }

    /** @returns {Promise<boolean>} true when at least one appeal was reversed. */
    async _processApprovedAppeals() {
        await this._ensureTable();
        const res = await pool.query(
            `SELECT * FROM automod_appeals WHERE status = 'approved' AND reversed = false LIMIT 50`
        );
        if (res.rows.length === 0) return false;
        for (const row of res.rows) {
            const appeal = this._rowToAppeal(row);
            await this._reverseAction(appeal).catch(() => {});
            await pool.query('UPDATE automod_appeals SET reversed = true WHERE id = $1', [appeal.id]);
            console.log(`[AUTOMOD] Reversed appeal #${appeal.id} (${appeal.action}) in guild ${appeal.guildId}.`);
        }
        return true;
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const res = await pool.query('SELECT * FROM automod_settings');
        let changed = false;
        for (const row of res.rows) {
            const next = this._rowToSettings(row);
            const previous = this._cache.get(row.guild_id);
            if (!previous || JSON.stringify(previous) !== JSON.stringify(next)) {
                this._cache.set(row.guild_id, next);
                changed = true;
                if (previous) {
                    console.log(`[AUTOMOD] Applied database update for guild ${row.guild_id}.`);
                }
            }
        }
        return changed;
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
        const warnThreshold = Math.max(1, parseInt(row.warn_threshold, 10) || 3);
        return {
            enabled: row.enabled,
            logChannelId: row.log_channel_id || null,
            muteRoleId: row.mute_role_id || null,
            exemptRoleIds: normalizeIdArray(row.exempt_role_ids),
            exemptChannelIds: normalizeIdArray(row.exempt_channel_ids),
            exemptUserIds: normalizeIdArray(row.exempt_user_ids),
            rules: normalizeRules(row.rules),
            warnThreshold,
            warnAction: warnActions[0],
            warnActions,
            warnLadder: normalizeWarnLadder(row.warn_ladder, { threshold: warnThreshold, warnActions }),
            dmEnabled: row.dm_enabled !== false,
            dmMessages: normalizeDmMessages(row.dm_messages),
            dmUser: row.dm_user !== false,
            useAppeal: row.use_appeal === true,
            appealChannelId: row.appeal_channel_id || null,
            dryRun: row.dry_run === true,
            raidLockdown: row.raid_lockdown === true,
            raidAlertChannelId: row.raid_alert_channel_id || null,
            incidentRetentionDays: Math.max(0, parseInt(row.incident_retention_days, 10) || 0),
        };
    }

    _defaults() {
        return {
            enabled: false,
            logChannelId: null,
            muteRoleId: null,
            exemptRoleIds: [],
            exemptChannelIds: [],
            exemptUserIds: [],
            rules: [],
            warnThreshold: 3,
            warnAction: 'timeout',
            warnActions: ['timeout'],
            warnLadder: [{ count: 3, actions: ['timeout'] }],
            dmEnabled: true,
            dmMessages: {},
            dmUser: true,
            useAppeal: false,
            appealChannelId: null,
            dryRun: false,
            raidLockdown: false,
            raidAlertChannelId: null,
            incidentRetentionDays: 30,
        };
    }

    getSettings(guildId) {
        if (!this._cache.has(guildId)) this._cache.set(guildId, this._defaults());
        return this._cache.get(guildId);
    }

    isEnabled(guildId) {
        return this.getSettings(guildId).enabled;
    }

    isDryRun(guildId) {
        return this.getSettings(guildId).dryRun === true;
    }

    /** Number of violations detected (but not enforced) while in dry-run. */
    getDryRunCount(guildId) {
        return this._dryRunCounts.get(String(guildId)) || 0;
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
                exempt_role_ids, exempt_channel_ids, exempt_user_ids, rules,
                warn_threshold, warn_action, warn_actions, warn_ladder,
                dm_enabled, dm_messages, dm_user, use_appeal, appeal_channel_id,
                dry_run, raid_lockdown, raid_alert_channel_id, incident_retention_days, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                enabled            = EXCLUDED.enabled,
                log_channel_id     = EXCLUDED.log_channel_id,
                mute_role_id       = EXCLUDED.mute_role_id,
                exempt_role_ids    = EXCLUDED.exempt_role_ids,
                exempt_channel_ids = EXCLUDED.exempt_channel_ids,
                exempt_user_ids    = EXCLUDED.exempt_user_ids,
                rules              = EXCLUDED.rules,
                warn_threshold     = EXCLUDED.warn_threshold,
                warn_action        = EXCLUDED.warn_action,
                warn_actions       = EXCLUDED.warn_actions,
                warn_ladder        = EXCLUDED.warn_ladder,
                dm_enabled         = EXCLUDED.dm_enabled,
                dm_messages        = EXCLUDED.dm_messages,
                dm_user            = EXCLUDED.dm_user,
                use_appeal         = EXCLUDED.use_appeal,
                appeal_channel_id  = EXCLUDED.appeal_channel_id,
                dry_run            = EXCLUDED.dry_run,
                raid_lockdown      = EXCLUDED.raid_lockdown,
                raid_alert_channel_id = EXCLUDED.raid_alert_channel_id,
                incident_retention_days = EXCLUDED.incident_retention_days,
                updated_at         = NOW()
        `, [
            guildId, s.enabled, s.logChannelId, s.muteRoleId,
            JSON.stringify(s.exemptRoleIds), JSON.stringify(s.exemptChannelIds),
            JSON.stringify(normalizeIdArray(s.exemptUserIds)),
            JSON.stringify(s.rules), s.warnThreshold, s.warnAction,
            JSON.stringify(s.warnActions), JSON.stringify(s.warnLadder || []), s.dmEnabled,
            JSON.stringify(s.dmMessages), s.dmUser, s.useAppeal, s.appealChannelId,
            s.dryRun === true, s.raidLockdown === true, s.raidAlertChannelId || null,
            Math.max(0, parseInt(s.incidentRetentionDays, 10) || 0),
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
        if ('exemptUserIds' in patch)     next.exemptUserIds = normalizeIdArray(patch.exemptUserIds);
        if ('rules' in patch)             next.rules = normalizeRules(patch.rules);
        if ('warnThreshold' in patch)     next.warnThreshold = Math.max(1, parseInt(patch.warnThreshold, 10) || 3);
        if ('warnAction' in patch)        next.warnAction = normalizeAction(patch.warnAction, 'timeout');
        if ('warnActions' in patch) {
            next.warnActions = normalizeWarnActions(patch.warnActions, next.warnAction || 'timeout');
            next.warnAction = next.warnActions[0];
        }
        if ('warnLadder' in patch) {
            next.warnLadder = normalizeWarnLadder(patch.warnLadder, {
                threshold: next.warnThreshold, warnActions: next.warnActions,
            });
        }
        if ('dmEnabled' in patch)         next.dmEnabled = patch.dmEnabled !== false;
        if ('dmMessages' in patch)        next.dmMessages = normalizeDmMessages(patch.dmMessages);
        if ('dmUser' in patch)            next.dmUser = patch.dmUser !== false;
        if ('useAppeal' in patch)        next.useAppeal = patch.useAppeal === true;
        if ('appealChannelId' in patch)   next.appealChannelId = patch.appealChannelId || null;
        if ('dryRun' in patch)            next.dryRun = patch.dryRun === true;
        if ('raidLockdown' in patch)      next.raidLockdown = patch.raidLockdown === true;
        if ('raidAlertChannelId' in patch) next.raidAlertChannelId = patch.raidAlertChannelId || null;
        if ('incidentRetentionDays' in patch) {
            next.incidentRetentionDays = Math.max(0, parseInt(patch.incidentRetentionDays, 10) || 0);
        }
        // Keep the legacy flat threshold/actions in sync with the ladder so the
        // dashboard, slash command and legacy readers all agree.
        if (next.warnLadder && next.warnLadder.length) {
            next.warnThreshold = next.warnLadder[0].count;
            next.warnActions = next.warnLadder[0].actions;
            next.warnAction = next.warnActions[0];
        }
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

    /**
     * Guild-wide exemption check (administrators, exempt roles, exempt channels,
     * exempt users). Per-rule exemptions are evaluated separately in
     * `_ruleApplies` so a rule can be tightened without loosening the others.
     */
    isExempt(message, settings) {
        if (!message.guild) return true;
        const member = message.member;
        const roleIds = member && member.roles && member.roles.cache
            ? member.roles.cache.map(r => r.id)
            : [];
        return isExemptFromRule(null, settings, {
            userId: message.author && message.author.id,
            channelId: message.channelId,
            roleIds,
            isAdministrator: !!(member && member.permissions
                && member.permissions.has(PermissionFlagsBits.Administrator)),
        });
    }

    /**
     * Should this specific rule be evaluated for this subject? Combines the
     * guild-wide exemptions with the rule's own exemption lists and the rule's
     * per-member cooldown. Never throws.
     */
    _ruleApplies(rule, settings, subject) {
        try {
            if (isExemptFromRule(rule, settings, subject)) return false;
            const key = `${subject.guildId}|${rule.type}|${subject.userId || '?'}`;
            return checkCooldown(DETECTION_STATE, key, rule.cooldown);
        } catch (err) {
            console.error('[AUTOMOD] exemption check failed:', err.message);
            return false;
        }
    }

    // ─── Rule matching ────────────────────────────────────────────────────────

    /** Test a single rule against a message/join context. */
    matchRule(rule, ctx) {
        return matchRule(rule, ctx, DETECTION_STATE);
    }

    /**
     * Evaluate a context against a guild's rules WITHOUT enforcing anything.
     * Returns the list of matching rules (in priority order) — used by the
     * dashboard's Test Rule tool and by dry-run detection.
     */
    evaluate(settings, ctx, { rules = null } = {}) {
        const list = Array.isArray(rules) ? rules : (settings && settings.rules) || [];
        const matches = [];
        for (const rule of list) {
            if (!rule || rule.enabled === false) continue;
            try {
                const m = matchRule(rule, ctx, DETECTION_STATE);
                if (m) matches.push({ rule, reason: m.reason, severity: m.severity || rule.severity });
            } catch (err) {
                // Fail-safe: one bad rule must not stop the others.
                console.error(`[AUTOMOD] rule ${rule.type} threw during evaluation:`, err.message);
            }
        }
        return matches;
    }

    /**
     * Dry-run / test evaluation. Runs the guild's rules against a synthetic
     * context and returns what *would* happen — no Discord action, no database
     * write, no punishment. Safe to call from the dashboard at any time.
     */
    testContent(guildId, { content = '', username = '', attachments = [], accountAgeDays = null } = {}) {
        const settings = this.getSettings(guildId);
        const subject = {
            guildId,
            userId: 'test',
            channelId: 'test',
            roleIds: [],
            isAdministrator: false,
        };
        const ctx = {
            content: String(content || '').slice(0, 4000),
            guildId,
            userId: 'test',
            channelId: 'test',
            username: String(username || ''),
            attachments: Array.isArray(attachments) ? attachments.slice(0, 10) : [],
            authorCreatedAt: Number.isFinite(accountAgeDays)
                ? new Date(Date.now() - accountAgeDays * 86400000)
                : null,
        };
        const results = [];
        for (const rule of settings.rules) {
            if (!rule || rule.enabled === false) continue;
            const exempt = isExemptFromRule(rule, settings, subject);
            let match = null;
            try {
                match = exempt ? null : matchRule(rule, ctx, {});
            } catch (err) {
                results.push({ type: rule.type, label: metaFor(rule.type).label, error: err.message });
                continue;
            }
            if (match) {
                results.push({
                    type: rule.type,
                    label: metaFor(rule.type).label,
                    icon: metaFor(rule.type).icon,
                    reason: match.reason,
                    severity: match.severity || rule.severity,
                    actions: rule.actions,
                    actionLabels: rule.actions.map(a => (ACTION_BY_KEY[a] || {}).label || a),
                    exempt,
                    wouldEnforce: !settings.dryRun,
                });
            } else if (exempt) {
                results.push({ type: rule.type, label: metaFor(rule.type).label, exempt: true, skipped: true });
            }
        }
        return {
            enabled: settings.enabled,
            dryRun: settings.dryRun === true,
            matches: results.filter(r => r.reason || r.error),
            skipped: results.filter(r => r.skipped),
        };
    }

    // ─── Enforcement ──────────────────────────────────────────────────────────

    /**
     * Run the guild's rules against a message and enforce the FIRST match.
     *
     * Hot-path guarantees:
     *   • no database access unless a rule actually matches;
     *   • bot/webhook/system messages are ignored (loop protection);
     *   • in dry-run, the violation is recorded but nothing is enforced.
     */
    async scanMessage(message) {
        try {
            if (!message.guild || !message.author) return null;
            // Loop protection: never scan anything the bot itself produced, other
            // bots, webhooks or Discord system messages — otherwise an enforcement
            // action (delete/log) could feed back into the engine.
            if (message.author.bot) return null;
            if (message.webhookId) return null;
            if (message.system) return null;
            const clientId = this.client && this.client.user && this.client.user.id;
            if (clientId && message.author.id === clientId) return null;

            const guildId = message.guild.id;
            const settings = this.getSettings(guildId);
            if (!settings.enabled) return null;

            // Opportunistic, cheap, at-most-every-30s map pruning.
            this._pruneState();

            const attachments = message.attachments
                ? Array.from(message.attachments.values()).map(a => ({ name: a.name, size: a.size }))
                : [];
            const ctx = {
                content: message.content || '',
                guildId,
                userId: message.author.id,
                channelId: message.channelId,
                username: message.author.username || '',
                attachments,
                authorCreatedAt: message.author.createdAt || null,
                guildInviteCode: null,
            };
            if (!ctx.content && attachments.length === 0 && !ctx.authorCreatedAt) return null;

            const roleIds = message.member && message.member.roles && message.member.roles.cache
                ? message.member.roles.cache.map(r => r.id)
                : [];
            const isAdministrator = !!(message.member && message.member.permissions
                && message.member.permissions.has(PermissionFlagsBits.Administrator));

            for (const rule of settings.rules) {
                if (!rule || rule.enabled === false) continue;
                if (!MESSAGE_RULE_KEYS.includes(rule.type)) continue; // join rules run elsewhere
                const subject = { guildId, userId: ctx.userId, channelId: ctx.channelId, roleIds, isAdministrator };
                if (!this._ruleApplies(rule, settings, subject)) continue;
                let match = null;
                try {
                    match = matchRule(rule, ctx, DETECTION_STATE);
                } catch (err) {
                    console.error(`[AUTOMOD] rule ${rule.type} threw:`, err.message);
                    continue;
                }
                if (!match) continue;

                // Dry run: record the detection, enforce nothing.
                if (settings.dryRun) {
                    this._dryRunCounts.set(guildId, (this._dryRunCounts.get(guildId) || 0) + 1);
                    await this._recordIncident({
                        guildId, userId: ctx.userId, username: ctx.username,
                        channelId: ctx.channelId, messageId: message.id,
                        ruleType: rule.type, actions: rule.actions, severity: match.severity || rule.severity,
                        reason: match.reason, dryRun: true,
                    }).catch(() => {});
                    await this._logToChannel(message, settings, metaFor(rule.type), [
                        { name: 'Mode', value: '🧪 Dry run — no action taken', inline: false },
                        { name: 'Member', value: `<@${ctx.userId}>`, inline: true },
                        { name: 'Rule', value: `${metaFor(rule.type).label}`, inline: true },
                        { name: 'Reason', value: match.reason, inline: false },
                    ], null, { severity: match.severity || rule.severity, dryRun: true }).catch(() => {});
                    return { rule: rule.type, actions: [], reason: match.reason, dryRun: true };
                }

                const applied = await this._enforce(message, rule, match.reason, settings, null);
                return { rule: rule.type, actions: applied, reason: match.reason };
            }
            return null;
        } catch (err) {
            // Fail-safe: an automod failure never propagates into messageCreate.
            console.error('[AUTOMOD] scanMessage failed:', err.message);
            return null;
        }
    }

    /**
     * Evaluate a member JOIN against the guild's raid-protection rules
     * (raidJoin / raidSimilarNames). Returns the matches (empty when nothing
     * tripped). Called from events/guildMemberAdd.js.
     */
    async scanMemberJoin(member) {
        try {
            if (!member || !member.guild || !member.user) return null;
            if (member.user.bot) return null;
            const guildId = member.guild.id;
            const settings = this.getSettings(guildId);
            if (!settings.enabled) return null;

            const raidRules = settings.rules.filter(r => r.enabled !== false && JOIN_RULE_KEYS.includes(r.type));
            if (raidRules.length === 0) return null;

            const created = member.user.createdAt || null;
            const accountAgeDays = created ? (Date.now() - created.getTime()) / 86400000 : null;
            const ctx = {
                guildId,
                userId: member.id,
                username: member.user.username || '',
                accountAgeDays,
            };

            const applied = [];
            for (const rule of raidRules) {
                const subject = { guildId, userId: member.id, channelId: null, roleIds: [], isAdministrator: false };
                if (!this._ruleApplies(rule, settings, subject)) continue;
                let match = null;
                try {
                    match = matchRule(rule, ctx, DETECTION_STATE);
                } catch (err) {
                    console.error(`[AUTOMOD] join rule ${rule.type} threw:`, err.message);
                    continue;
                }
                if (!match) continue;
                if (settings.dryRun) {
                    this._dryRunCounts.set(guildId, (this._dryRunCounts.get(guildId) || 0) + 1);
                    await this._recordIncident({
                        guildId, userId: member.id, username: ctx.username, channelId: null,
                        messageId: null, ruleType: rule.type, actions: rule.actions,
                        severity: match.severity || rule.severity, reason: match.reason, dryRun: true,
                    }).catch(() => {});
                    continue;
                }
                const ok = await this._enforceJoin(member, rule, match.reason, settings);
                applied.push({ rule: rule.type, actions: ok });
            }
            if (applied.length === 0) return null;
            return { guildId, applied };
        } catch (err) {
            console.error('[AUTOMOD] scanMemberJoin failed:', err.message);
            return null;
        }
    }

    /** Enforce a raid rule against a joining member. Never throws. */
    async _enforceJoin(member, rule, reason, settings) {
        const guild = member.guild;
        const meta = metaFor(rule.type);
        const actions = Array.isArray(rule.actions) && rule.actions.length ? rule.actions : ['warn'];
        const applied = [];
        const ctx = {
            guild, member, author: member.user, invoker: null, reason,
            settings, ruleType: rule.type, cid: null,
        };
        for (const action of actions) {
            try {
                await this._executeAction(action, ctx);
                applied.push(action);
            } catch (err) {
                console.error(`[AUTOMOD] raid action ${action} failed:`, err.message);
            }
        }
        const cid = await this._createEmbedRecord({
            guildId: guild.id, channelId: null, userId: member.id,
            action: actions.join(','), ruleType: rule.type, reason,
        }).catch(() => null);
        await this._recordIncident({
            guildId: guild.id, userId: member.id, username: member.user.username,
            channelId: null, messageId: null, ruleType: rule.type, actions: applied,
            severity: rule.severity || meta.severity, reason, dryRun: false, cid,
        }).catch(() => {});
        await this._logToChannel(null, settings, meta, [
            { name: 'Member', value: `<@${member.id}> (\`${member.user.tag || member.user.username}\`)`, inline: false },
            { name: 'Rule', value: `${meta.icon} ${meta.label}`, inline: true },
            { name: 'Actions', value: applied.map(a => (ACTION_BY_KEY[a] || {}).label || a).join(', ') || 'none', inline: true },
            { name: 'Reason', value: reason, inline: false },
        ], cid, { severity: rule.severity || meta.severity, guildId: guild.id }).catch(() => {});
        // Raid lockdown: alert the raid channel + optionally lock the guild's
        // channels down (only when the admin explicitly enabled it).
        await this._handleRaidResponse(guild, settings, rule, reason).catch(() => {});
        return applied;
    }

    /**
     * Raid response. Sends a high-priority alert to the configured raid alert
     * channel and, when `raidLockdown` is enabled, raises the guild's
     * verification level to HIGH so Discord gates new joins. Deliberately
     * conservative: we never mass-kick or mass-ban on a weak signal.
     */
    async _handleRaidResponse(guild, settings, rule, reason) {
        const alertChannelId = settings.raidAlertChannelId || settings.logChannelId;
        if (alertChannelId) {
            try {
                const ch = await this.client.channels.fetch(alertChannelId);
                if (ch && typeof ch.send === 'function') {
                    const embed = new EmbedBuilder()
                        .setColor(0xED4245)
                        .setTitle('🚨 Raid protection triggered')
                        .setDescription(`**${metaFor(rule.type).label}** — ${reason}`)
                        .addFields(
                            { name: 'Server', value: guild.name, inline: true },
                            { name: 'Recommended', value: 'Review the member list and enable Verification Level: High', inline: true },
                        )
                        .setTimestamp()
                        .setFooter({ text: 'PrimeBot Automod · Raid Protection' });
                    await ch.send({ embeds: [embed] });
                }
            } catch (err) {
                console.error('[AUTOMOD] raid alert failed:', err.message);
            }
        }
        if (settings.raidLockdown && guild.verificationLevel !== 4) {
            try {
                await guild.setVerificationLevel(4, 'Automod raid protection');
                console.log(`[AUTOMOD] Raised verification level in guild ${guild.id} (raid protection).`);
            } catch (err) {
                console.error('[AUTOMOD] raid lockdown failed:', err.message);
            }
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

        // Every automod action gets a per-server CID (the embed number, stored in
        // automod_embeds). Generate it up-front — regardless of whether a log channel
        // is configured yet — so the CID is always recorded in the ledger (and shown
        // in the ban-DM, dashboard CID pane, etc.), never silently missing.
        let cid = await this._createEmbedRecord({
            guildId: message.guild.id, channelId: message.channelId,
            userId: message.author.id, action: actions.join(','), ruleType: rule.type, reason,
        });

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
        const sentMsg = await this._logToChannel(message, settings, meta, logFields, cid, { severity: rule.severity || meta.severity });
        if (cid && sentMsg?.id) {
            await pool.query(
                `UPDATE automod_embeds SET message_id = $3 WHERE guild_id = $1 AND cid = $2`,
                [String(message.guild.id), cid, String(sentMsg.id)]
            ).catch(() => {});
        }
        await this._recordIncident({
            guildId: message.guild.id, userId: message.author.id,
            username: ctx.author.username || '', channelId: message.channelId,
            messageId: message.id, ruleType: rule.type, actions: applied,
            severity: rule.severity || meta.severity, reason, dryRun: false, cid,
        }).catch(() => {});
        await logEvent(this.client, message.guild.id, {
            type: 'memberUpdate',
            title: `Automod action (CID ${cid || '—'})`,
            description: `${meta.icon} **${meta.label}** → **${actionLabels}**`,
            fields: logFields,
        });

        return applied;
    }

    // ─── Incidents + analytics ────────────────────────────────────────────────
    //
    // One row per enforcement. Written only when a rule actually matched, so the
    // hot path stays read-only. All analytics are computed from this table by
    // the dashboard with indexed, time-bounded aggregate queries.

    async _recordIncident({
        guildId, userId = null, username = null, channelId = null, messageId = null,
        ruleType, actions = [], severity = 'medium', reason = '', dryRun = false, cid = null,
    }) {
        try {
            await this._ensureTable();
            await pool.query(`
                INSERT INTO automod_incidents
                    (guild_id, user_id, username, channel_id, message_id, rule_type,
                     actions, severity, reason, dry_run, cid)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            `, [
                String(guildId), userId ? String(userId) : null,
                username ? String(username).slice(0, 120) : null,
                channelId ? String(channelId) : null,
                messageId ? String(messageId) : null,
                String(ruleType || 'unknown').slice(0, 40),
                JSON.stringify(Array.isArray(actions) ? actions : []),
                normalizeSeverity(severity),
                String(reason || '').slice(0, 1000),
                dryRun === true,
                Number.isFinite(cid) ? cid : null,
            ]);
        } catch (err) {
            // Incident recording is best-effort — it must never break enforcement.
            console.error('[AUTOMOD] failed to record incident:', err.message);
        }
    }

    /**
     * Search incidents for a guild. Filtered + paginated so the dashboard never
     * loads the whole history. All filters are parameterized (no string concat
     * into SQL).
     */
    async getIncidents(guildId, {
        ruleType = null, severity = null, action = null, channelId = null,
        dryRun = null, search = null, sinceDays = null,
        limit = 25, offset = 0,
    } = {}) {
        await this._ensureTable();
        const where = ['guild_id = $1'];
        const params = [String(guildId)];
        const push = (v) => { params.push(v); return `$${params.length}`; };
        if (ruleType) where.push(`rule_type = ${push(String(ruleType))}`);
        if (severity) where.push(`severity = ${push(normalizeSeverity(severity))}`);
        if (channelId) where.push(`channel_id = ${push(String(channelId))}`);
        if (dryRun === true) where.push('dry_run = true');
        if (dryRun === false) where.push('dry_run = false');
        if (Array.isArray(action) && action.length) where.push(`actions ?| ${push(action)}`);
        else if (typeof action === 'string' && action) where.push(`actions ? ${push(action)}`);
        if (search) {
            const like = `%${String(search).slice(0, 100).replace(/[%_]/g, '')}%`;
            where.push(`(username ILIKE ${push(like)} OR user_id ILIKE ${push(like)} OR reason ILIKE ${push(like)})`);
        }
        const days = parseInt(sinceDays, 10);
        if (Number.isFinite(days) && days > 0) {
            where.push(`created_at > NOW() - (${push(days)} || ' days')::interval`);
        }
        const lim = Math.min(100, Math.max(1, parseInt(limit, 10) || 25));
        const off = Math.max(0, parseInt(offset, 10) || 0);
        const whereSql = where.join(' AND ');
        const [rows, count] = await Promise.all([
            pool.query(
                `SELECT * FROM automod_incidents WHERE ${whereSql} ORDER BY created_at DESC LIMIT ${lim} OFFSET ${off}`,
                params
            ),
            pool.query(`SELECT COUNT(*)::int AS count FROM automod_incidents WHERE ${whereSql}`, params),
        ]);
        return {
            total: count.rows[0]?.count || 0,
            limit: lim,
            offset: off,
            incidents: rows.rows.map(rowToIncident),
        };
    }

    /**
     * Aggregated analytics for a guild over a time window. Runs a small, fixed
     * set of indexed GROUP BY queries (never per-message), which the dashboard
     * caches client-side.
     */
    async getAnalytics(guildId, { days = 30 } = {}) {
        await this._ensureTable();
        const d = Math.min(365, Math.max(1, parseInt(days, 10) || 30));
        const base = `FROM automod_incidents WHERE guild_id = $1 AND created_at > NOW() - ($2 || ' days')::interval`;
        const params = [String(guildId), String(d)];
        const [totals, byRule, bySeverity, byAction, byChannel, byUser, overTime] = await Promise.all([
            pool.query(`SELECT
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE dry_run = false)::int AS enforced,
                    COUNT(*) FILTER (WHERE dry_run = true)::int AS dry_run,
                    COUNT(DISTINCT user_id)::int AS users
                ${base}`, params),
            pool.query(`SELECT rule_type, COUNT(*)::int AS count ${base} GROUP BY rule_type ORDER BY count DESC LIMIT 20`, params),
            pool.query(`SELECT severity, COUNT(*)::int AS count ${base} GROUP BY severity ORDER BY count DESC`, params),
            pool.query(`SELECT act AS action, COUNT(*)::int AS count
                FROM automod_incidents, jsonb_array_elements_text(actions) AS act
                WHERE guild_id = $1 AND created_at > NOW() - ($2 || ' days')::interval
                GROUP BY act ORDER BY count DESC`, params),
            pool.query(`SELECT channel_id, COUNT(*)::int AS count ${base} GROUP BY channel_id ORDER BY count DESC LIMIT 10`, params),
            pool.query(`SELECT user_id, MAX(username) AS username, COUNT(*)::int AS count ${base} GROUP BY user_id ORDER BY count DESC LIMIT 10`, params),
            pool.query(`SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS day, COUNT(*)::int AS count
                ${base} GROUP BY day ORDER BY day ASC`, params),
        ]);
        const t = totals.rows[0] || {};
        return {
            days: d,
            totals: {
                total: t.total || 0,
                enforced: t.enforced || 0,
                dryRun: t.dry_run || 0,
                users: t.users || 0,
            },
            byRule: byRule.rows.map(r => ({ key: r.rule_type, count: r.count })),
            bySeverity: bySeverity.rows.map(r => ({ key: r.severity, count: r.count })),
            byAction: byAction.rows.map(r => ({ key: r.action, count: r.count })),
            byChannel: byChannel.rows.map(r => ({ key: r.channel_id, count: r.count })),
            topUsers: byUser.rows.map(r => ({ userId: r.user_id, username: r.username, count: r.count })),
            overTime: overTime.rows.map(r => ({ day: r.day, count: r.count })),
        };
    }

    /** Apply a preset to a guild (merging over its current settings). */
    applyPreset(guildId, presetKey) {
        const { buildPresetPatch } = require('./automodPresets');
        const patch = buildPresetPatch(presetKey, this.getSettings(guildId));
        if (!patch) return null;
        return this.updateSettings(guildId, patch);
    }

    /**
     * Execute a single moderation action. Shared by rule enforcement and warn
     * escalation. `ctx` = { guild, member, author, reason, settings, count }.
     * Sends the appropriate DM (when enabled) for the action.
     *
     * Every Discord-touching action is permission-guarded *before* the call so a
     * bot that lacks the permission (or sits below the target in the role
     * hierarchy) skips that action cleanly instead of throwing, and the rest of
     * the action chain still runs.
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
            case 'log':
                // The incident/logging sweep already ran in _enforce; nothing to do.
                break;
            case 'warn': {
                await this.addWarning(guild.id, author.id, {
                    moderatorId: null, reason, ruleType: ctx.ruleType,
                });
                const count = await this.getWarningCount(guild.id, author.id);
                await dm('warn');
                await this._applyLadder(ctx, settings, count);
                break;
            }
            case 'timeout': {
                const ok = this._canModerate(guild, member, PermissionFlagsBits.ModerateMembers);
                if (!ok && !settings?.muteRoleId) {
                    console.warn(`[AUTOMOD] skipping timeout for ${author?.id} — missing Moderate Members or role hierarchy.`);
                    break;
                }
                await this._applyTimeout(guild, member, ctx.timeoutSeconds || 600, reason);
                await dm('timeout');
                break;
            }
            case 'kick': {
                const ok = this._canModerate(guild, member, PermissionFlagsBits.KickMembers);
                if (!ok) {
                    console.warn(`[AUTOMOD] skipping kick for ${author?.id} — missing Kick Members or role hierarchy.`);
                    break;
                }
                await member?.kick(`Automod: ${reason}`).catch(err =>
                    console.error('[AUTOMOD] kick failed:', err.message));
                await dm('kick');
                break;
            }
            case 'ban': {
                const ok = this._canModerate(guild, member, PermissionFlagsBits.BanMembers, { allowAbsentMember: true });
                if (!ok) {
                    console.warn(`[AUTOMOD] skipping ban for ${author?.id} — missing Ban Members or role hierarchy.`);
                    break;
                }
                await guild.members.ban(author.id, { reason: `Automod: ${reason}` }).catch(err =>
                    console.error('[AUTOMOD] ban failed:', err.message));
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
    }

    /**
     * Can the bot perform a moderation action against `member`? Checks both the
     * required Discord permission and the role hierarchy. Never throws.
     * With `allowAbsentMember` the hierarchy check is skipped (used by ban,
     * where the member may already have left).
     */
    _canModerate(guild, member, permission, { allowAbsentMember = false } = {}) {
        try {
            const me = guild && guild.members && guild.members.me;
            if (!me) return false;
            if (permission && !me.permissions.has(permission)) return false;
            if (allowAbsentMember && !member) return true;
            if (!member) return false;
            // Owner is always above the bot; never punish unless the bot is the owner.
            if (guild.ownerId && member.id === guild.ownerId && me.id !== guild.ownerId) return false;
            if (member.id === me.id) return false;
            if (typeof member.manageable === 'boolean') return member.manageable;
            // Fallback for stubs/tests without the discord.js helper: compare positions.
            const myTop = me.roles && me.roles.highest ? me.roles.highest.position : Infinity;
            const theirTop = member.roles && member.roles.highest ? member.roles.highest.position : 0;
            return myTop > theirTop;
        } catch {
            return false;
        }
    }

    /**
     * Apply the warning-escalation LADDER. Walks every configured step whose
     * count has been reached (highest first) and fires its actions, so a guild
     * can express 1→warn, 3→timeout, 5→kick, 7→ban and have the right rung fire.
     * Falls back to the legacy flat (warnThreshold + warnActions) pair for old
     * configurations.
     */
    async _applyLadder(ctx, settings, count) {
        if (!settings) return false;
        const ladder = Array.isArray(settings.warnLadder) && settings.warnLadder.length
            ? settings.warnLadder
            : [{ count: settings.warnThreshold || 3, actions: settings.warnActions || ['timeout'] }];
        // The highest rung that has been reached is the one that fires.
        const reached = ladder.filter(s => count >= s.count).sort((a, b) => b.count - a.count)[0];
        if (!reached) return false;
        return this._applyEscalation(ctx, settings, count, reached.actions);
    }

    async _applyEscalation(ctx, settings, count, actionsOverride = null) {
        const actions = Array.isArray(actionsOverride) && actionsOverride.length
            ? actionsOverride
            : (Array.isArray(settings?.warnActions) && settings.warnActions.length
                ? settings.warnActions
                : (settings?.warnAction ? [settings.warnAction] : ['timeout']));
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

    /**
     * Post an incident embed to the guild's automod log channel. The embed color
     * is driven by the rule's severity so a HIGH/CRITICAL violation is visually
     * distinct from a LOW one. Fire-and-forget: a logging failure never throws
     * back into the event handler.
     *
     * Returns the sent Message (used to back-fill the embed-ledger message id) or
     * null when there is no log channel / the send failed.
     */
    async _logToChannel(message, settings, meta, fields, cid = null, { severity = null } = {}) {
        if (!settings || !settings.logChannelId) return null;
        const sev = severityMeta(severity || (meta && meta.severity) || 'medium');
        const embed = new EmbedBuilder()
            .setColor(sev.color)
            .setTitle(cid ? `${meta.icon} Automod · ${meta.label} (CID ${cid})` : `${meta.icon} Automod · ${meta.label}`)
            .setTimestamp();
        for (const f of fields) {
            if (f && f.name && f.value) embed.addFields({ name: f.name, value: String(f.value), inline: !!f.inline });
        }
        embed.setFooter({ text: `PrimeBot Automod · Severity ${sev.label}` });
        try {
            const ch = await this.client.channels.fetch(settings.logChannelId);
            if (!ch || typeof ch.send !== 'function') {
                console.error(`[AUTOMOD] Log channel ${settings.logChannelId} is not a sendable channel (it may have been deleted/renamed). Skipping automod log.`);
                return null;
            }
            const msg = await ch.send({ embeds: [embed] });
            return msg || null;
        } catch (err) {
            console.error('[AUTOMOD] Automod log delivery failed:', err.message);
            return null;
        }
    }

    /**
     * Create the automod_embeds ledger row for this enforcement and return the next
     * per-server CID (the primary key / embed number). The CID is generated lazily:
     * MAX(cid)+1 within the guild, ensuring monotonically increasing embed numbers.
     */
    async _createEmbedRecord({ guildId, channelId = null, userId = null, action = null, ruleType = null, reason = '' }) {
        try {
            await this._ensureTable();
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

/** Map an automod_incidents row to the camelCase shape the dashboard consumes. */
function rowToIncident(row) {
    return {
        id: row.id,
        userId: row.user_id,
        username: row.username,
        channelId: row.channel_id,
        messageId: row.message_id,
        ruleType: row.rule_type,
        actions: Array.isArray(row.actions) ? row.actions : [],
        severity: row.severity,
        reason: row.reason,
        dryRun: row.dry_run === true,
        cid: row.cid,
        createdAt: row.created_at,
    };
}

module.exports = AutomodManager;
// Also expose the class as a named property so `AutomodManager` can be reached
// either way (`require(...)` or `require(...).AutomodManager`).
module.exports.AutomodManager = AutomodManager;
module.exports.rowToIncident = rowToIncident;
