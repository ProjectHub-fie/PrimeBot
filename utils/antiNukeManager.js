/**
 * AntiNukeManager — per-guild Anti-Nuke configuration + detection executor.
 *
 * Two responsibilities:
 *
 *   1. CONFIGURATION — an in-memory Map keyed by guild, write-through to
 *      Postgres via the dedicated ANUKE_DATABASE_URL pool (server/anukeDb.js;
 *      falls back to FALLBACK_DATABASE_URL then DATABASE_URL), and a shared
 *      cache-scheduler refresh so dashboard saves take effect without a bot
 *      restart. Identical shape/behaviour to the other settings managers.
 *
 *   2. DETECTION — the executor that consumes correlated audit-log entries
 *      (utils/antiNukeAudit.js), feeds them through the bounded sliding-window
 *      detector (utils/antiNukeDetector.js), evaluates trust + thresholds, and
 *      runs the response plan (utils/antiNukeContainment.js).
 *
 * The pipeline is exactly the one the feature spec describes:
 *
 *     gateway event → audit-log correlation → responsible user → trust check →
 *     burst detector → risk evaluation → response (alert / containment / lockdown)
 *
 * Cross-node safety: PrimeBot runs as three shard nodes sharing one database.
 * Only the node that owns a guild's shard should process its events (Discord
 * only delivers a gateway event to that node), so no node processes a guild it
 * does not have cached. When a response is about to fire, the incident is
 * claimed atomically in `antinuke_dedup` so a duplicate observation (audit-log
 * retry, reconnect replay) on another node cannot double-respond.
 *
 * Safety invariants (never violated):
 *   • never punish the owner / the bot / trusted users / trusted roles
 *   • never punish when the executor could not be identified
 *   • never ban or kick a moderator automatically
 *   • never remove a role at/above the bot's highest role
 *   • dry-run performs detection + alerting but zero containment
 */

const { getCacheScheduler } = require('./cacheScheduler');
const {
    normalizeAntiNukeSettings, defaultAntiNukeSettings,
    NUKE_ACTION_BY_KEY, isTrusted, watchFor,
} = require('./antiNukeRules');
const { AntiNukeDetector } = require('./antiNukeDetector');
const { correlateAuditEntry } = require('./antiNukeAudit');
const {
    validateBotPermissions, buildSecurityAlertEmbed,
    computeDangerousRoleRemovals, stripDangerousRoles,
    applyLockdown, restoreLockdown, severityColor,
} = require('./antiNukeContainment');
const { anukePool: pool, claimDedupKey, pruneDedupKeys } = require('../server/anukeDb');

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_settings (
        guild_id           VARCHAR(50) PRIMARY KEY,
        enabled            BOOLEAN NOT NULL DEFAULT false,
        alert_channel_id   VARCHAR(50),
        responses          JSONB NOT NULL DEFAULT '[]',
        trusted_user_ids   JSONB NOT NULL DEFAULT '[]',
        trusted_role_ids   JSONB NOT NULL DEFAULT '[]',
        watched            JSONB NOT NULL DEFAULT '{}',
        dry_run            BOOLEAN NOT NULL DEFAULT true,
        updated_at         TIMESTAMP DEFAULT NOW()
    )
`;

// Keep the SELECT list explicit (never `SELECT *`) so a future large JSON
// column is not pulled on every poll.
const SETTINGS_COLUMNS = `guild_id, enabled, alert_channel_id, responses,
    trusted_user_ids, trusted_role_ids, watched, dry_run,
    dangerous_permissions, lockdown, response_cooldown_seconds,
    setup_method, setup_status, setup_state, updated_at`;

// Bound the incident-history query so the dashboard never loads unbounded rows.
const MAX_INCIDENT_LIMIT = 100;
const DEFAULT_INCIDENT_LIMIT = 25;

class AntiNukeManager {
    constructor(client) {
        this.client = client;
        this._cache = new Map();
        this._tableReady = false;
        this._reloadTimer = null;
        this._dedupPruneTimer = null;
        this.detector = new AntiNukeDetector();
        // Audit-entry ids already counted, so the same underlying action is not
        // counted twice when both the live audit-log stream and a per-event
        // correlation path observe it. Bounded (cleared when it grows).
        this._seenEventIds = new Set();
        // Set once the live audit-log stream (`guildAuditLogEntryCreate`) has
        // been observed, which makes the per-event correlation fallback
        // unnecessary (it would only add API calls).
        this._auditStreamAvailable = false;
        // Optional listener hook (dashboard/live views can subscribe).
        this._listeners = new Set();
        this._init().catch(err =>
            console.error('[ANTINUKE] Init failed:', err.message)
        );
    }

    // ── Configuration ───────────────────────────────────────────────────────

    async _ensureTable() {
        if (this._tableReady) return;
        await pool.query(CREATE_TABLE_SQL);
        // The extended columns are created by server/anukeDb.js ensureAnukeTables;
        // run it here too so a manager booted before any dashboard request still
        // gets them (idempotent, memoized process-wide).
        try {
            const { ensureAnukeTables } = require('../server/anukeDb');
            await ensureAnukeTables();
        } catch (_) { /* the base table above is enough to start */ }
        this._tableReady = true;
    }

    async _init() {
        try {
            await this._ensureTable();
        } catch (err) {
            // A boot-time DB failure must not abort the reload loop — retry on
            // the next tick (the same hardening the other managers use).
            console.error('[ANTINUKE] ensureTable failed at boot:', err.message);
        }
        await this._loadAll().catch(err => console.error('[ANTINUKE] loadAll failed:', err.message));
        this._startReloadInterval();
        this._startDedupPrune();
    }

    _startReloadInterval() {
        if (this._reloadTimer) return;
        this._reloadTimer = getCacheScheduler().register('ANTINUKE', () => this._refreshFromDatabase());
    }

    _startDedupPrune() {
        if (this._dedupPruneTimer) return;
        // Hourly is plenty; the table is tiny and expiry only needs to be
        // roughly enforced. Unref'd so it never keeps the process alive.
        this._dedupPruneTimer = setInterval(() => { pruneDedupKeys().catch(() => {}); }, 60 * 60 * 1000);
        this._dedupPruneTimer.unref?.();
    }

    async _loadAll() {
        const res = await pool.query(`SELECT ${SETTINGS_COLUMNS} FROM antinuke_settings`);
        for (const row of res.rows) this._cache.set(row.guild_id, rowToSettings(row));
        if (res.rows.length) console.log(`[ANTINUKE] Loaded settings for ${res.rows.length} servers.`);
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const res = await pool.query(`SELECT ${SETTINGS_COLUMNS} FROM antinuke_settings`);
        let changed = false;
        for (const row of res.rows) {
            const next = rowToSettings(row);
            const prev = this._cache.get(row.guild_id);
            if (!prev || JSON.stringify(prev) !== JSON.stringify(next)) {
                this._cache.set(row.guild_id, next);
                changed = true;
            }
        }
        return changed;
    }

    getSettings(guildId) {
        if (!this._cache.has(guildId)) this._cache.set(guildId, defaultAntiNukeSettings());
        return this._cache.get(guildId);
    }

    isEnabled(guildId) {
        const s = this.getSettings(guildId);
        return s.enabled === true;
    }

    async _saveAsync(guildId) {
        const s = this.getSettings(guildId);
        await this._ensureTable();
        await pool.query(`
            INSERT INTO antinuke_settings (
                guild_id, enabled, alert_channel_id, responses,
                trusted_user_ids, trusted_role_ids, watched, dry_run,
                dangerous_permissions, lockdown, response_cooldown_seconds,
                setup_method, setup_status, setup_state, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                enabled                  = EXCLUDED.enabled,
                alert_channel_id         = EXCLUDED.alert_channel_id,
                responses                = EXCLUDED.responses,
                trusted_user_ids         = EXCLUDED.trusted_user_ids,
                trusted_role_ids         = EXCLUDED.trusted_role_ids,
                watched                  = EXCLUDED.watched,
                dry_run                  = EXCLUDED.dry_run,
                dangerous_permissions    = EXCLUDED.dangerous_permissions,
                lockdown                 = EXCLUDED.lockdown,
                response_cooldown_seconds= EXCLUDED.response_cooldown_seconds,
                setup_method             = EXCLUDED.setup_method,
                setup_status             = EXCLUDED.setup_status,
                setup_state              = EXCLUDED.setup_state,
                updated_at               = NOW()
        `, [
            guildId, s.enabled, s.alertChannelId,
            JSON.stringify(s.responses), JSON.stringify(s.trustedUserIds),
            JSON.stringify(s.trustedRoleIds), JSON.stringify(s.watched),
            s.dryRun !== false,
            JSON.stringify(s.dangerousPermissions), JSON.stringify(s.lockdown),
            s.responseCooldownSeconds,
            s.setupMethod || null, s.setupStatus || 'not_started',
            JSON.stringify(s.setupState || {}),
        ]);
    }

    updateSettings(guildId, patch = {}) {
        const current = this.getSettings(guildId);
        const next = normalizeAntiNukeSettings({ ...current, ...patch });
        // Carry the setup metadata through the normalizer (it is not part of the
        // detection shape, so preserve it explicitly).
        next.setupMethod = patch.setupMethod !== undefined ? patch.setupMethod : (current.setupMethod || null);
        next.setupStatus = patch.setupStatus !== undefined ? patch.setupStatus : (current.setupStatus || 'not_started');
        next.setupState = patch.setupState !== undefined ? patch.setupState : (current.setupState || {});
        this._cache.set(guildId, next);
        // A security-config change should not wait for the shared scheduler's
        // next tick — snap the shared cadence back to its fast interval.
        try { this._reloadTimer?.notifyActivity?.(); } catch (_) { /* optional */ }
        this._saveAsync(guildId).catch(err =>
            console.error(`[ANTINUKE] Save failed for guild ${guildId}:`, err.message)
        );
        return next;
    }

    /** Persist + await (used by the dashboard so a save is confirmed on write). */
    async updateSettingsAsync(guildId, patch = {}) {
        const next = this.updateSettings(guildId, patch);
        await this._saveAsync(guildId);
        return next;
    }

    /** The persisted setup-wizard state for a guild (for `/antinuke setup`). */
    async getSetup(guildId) {
        const s = this.getSettings(guildId);
        return { method: s.setupMethod || null, status: s.setupStatus || 'not_started', state: s.setupState || null };
    }

    /** Persist the setup-wizard state only (atomic single-row upsert). */
    async saveSetup(guildId, { method = null, status = 'not_started', state = null } = {}) {
        return this.updateSettingsAsync(guildId, { setupMethod: method, setupStatus: status, setupState: state });
    }

    // ── Trust ───────────────────────────────────────────────────────────────

    /**
     * Resolve whether `userId` is exempt in `guild`, consulting the live member
     * cache for trusted roles. The owner and the bot itself are always exempt.
     */
    async isExempt(guild, userId, settings = null) {
        if (!guild || !userId) return true;
        if (guild.ownerId && userId === guild.ownerId) return true;
        const me = guild.members && guild.members.me;
        if (me && userId === me.id) return true;
        const s = settings || this.getSettings(guild.id);
        let roleIds = [];
        try {
            const member = guild.members && guild.members.cache
                ? guild.members.cache.get(userId)
                : null;
            if (member && member.roles && member.roles.cache) {
                roleIds = Array.from(member.roles.cache.keys());
            }
        } catch (_) { roleIds = []; }
        return isTrusted({ userId, roleIds, guildOwnerId: guild.ownerId, settings: s });
    }

    // ── Detection entry point ───────────────────────────────────────────────

    /**
     * Process one gateway event. Called from events/guildAuditLogEntryCreate.js
     * (the correlation path) OR directly by the specific event handlers when
     * they know the target id.
     *
     * @param {object} p
     * @param {import('discord.js').Guild} p.guild
     * @param {string} p.actionKey     a NUKE_ACTIONS key
     * @param {object} [p.query]       audit correlation overrides (targetId, …)
     * @param {string} [p.knownExecutorId]  skip correlation when already known
     * @param {object} [p.details]     extra context for the incident record
     * @returns {Promise<object>} the evaluation result (never throws)
     */
    async processEvent({ guild, actionKey, query = {}, knownExecutorId = null, details = {} }) {
        try {
            if (!guild) return { handled: false, reason: 'no_guild' };
            const action = NUKE_ACTION_BY_KEY[actionKey];
            if (!action) return { handled: false, reason: 'unknown_action' };

            // Dedup the same underlying action when both the live audit-log
            // stream and a per-event correlation observe it. Keyed on the audit
            // entry id when present, else on (action, executor, target).
            const eventKey = this._eventKey(actionKey, knownExecutorId, details);
            if (eventKey) {
                if (this._seenEventIds.has(eventKey)) return { handled: false, reason: 'duplicate_event' };
                this._seenEventIds.add(eventKey);
                if (this._seenEventIds.size > 1000) this._seenEventIds.clear();
            }

            const settings = this.getSettings(guild.id);
            if (!settings.enabled) return { handled: false, reason: 'disabled' };
            const watch = watchFor(settings, actionKey);
            if (!watch || watch.enabled === false) return { handled: false, reason: 'action_disabled' };

            // Attribution. Prefer a known executor (e.g. the bot's own action);
            // otherwise correlate the audit log. Never punish without one.
            let executorId = knownExecutorId || null;
            let attribution = knownExecutorId ? 'known' : 'unknown';
            let executorName = null;
            let correlation = null;
            if (!executorId) {
                correlation = await correlateAuditEntry(guild, {
                    auditEvent: action.auditEvent,
                    targetId: query.targetId,
                    targetType: query.targetType != null ? query.targetType : action.targetType,
                    ignoreExecutors: [this.client && this.client.user ? this.client.user.id : null].filter(Boolean),
                    seenKeys: this._seenAuditKeys(),
                    ...query,
                });
                if (correlation.ok) {
                    executorId = correlation.executorId;
                    attribution = 'audit_log';
                    executorName = correlation.executor && correlation.executor.tag ? correlation.executor.tag : null;
                } else if (correlation.missingPermission) {
                    // Detection cannot attribute → alert-only, and note it.
                    return await this._handleUnattributed({ guild, settings, action, watch, reason: 'missing_audit_permission', details });
                }
            }

            if (!executorId) {
                return await this._handleUnattributed({ guild, settings, action, watch, reason: 'executor_unknown', details });
            }

            // Trust gate — owner/bot/trusted never count toward a threshold.
            if (await this.isExempt(guild, executorId, settings)) {
                return { handled: false, reason: 'trusted', executorId };
            }

            // Record into the bounded sliding window and evaluate.
            const verdict = this.detector.record({
                guildId: guild.id,
                actionKey,
                executorId,
                threshold: watch.threshold,
                seconds: watch.seconds,
            });

            if (!verdict.tripped) {
                return { handled: false, reason: 'below_threshold', count: verdict.count, executorId };
            }

            return await this._respond({
                guild, settings, action, watch,
                executorId, executorName, attribution, verdict, details,
            });
        } catch (err) {
            // Detection must never crash an event handler.
            console.error('[ANTINUKE] processEvent failed:', err.message);
            return { handled: false, reason: 'error', error: err.message };
        }
    }

    /**
     * Correlate a specific gateway event to its audit entry and process it.
     * Used by the per-event handlers (guildBanAdd, channelDelete, …) as a
     * fallback for deployments where the live audit-log stream is unavailable.
     * Skips the API call entirely once the live stream has been observed.
     *
     * @param {object} p
     * @param {import('discord.js').Guild} p.guild
     * @param {string} p.actionKey
     * @param {string} [p.targetId]
     * @param {number} [p.targetType]
     * @param {object} [p.details]
     */
    async processFromEvent({ guild, actionKey, targetId = null, targetType = null, details = {} }) {
        if (this._auditStreamAvailable) {
            // The live audit-log stream owns detection — no API round trip.
            return { handled: false, reason: 'audit_stream_active' };
        }
        return this.processEvent({
            guild, actionKey,
            query: { targetId, targetType },
            details,
        });
    }

    /** Mark the live audit-log stream as observed (called by the event handler). */
    noteAuditStream() {
        this._auditStreamAvailable = true;
    }

    /** Dedup key for one underlying action (audit id preferred). */
    _eventKey(actionKey, executorId, details) {
        const auditId = details && details.auditEntryId;
        if (auditId) return `a:${auditId}`;
        const target = details && details.targetId;
        if (executorId && target) return `e:${actionKey}:${executorId}:${target}`;
        return null;
    }

    /** Small bounded set of consumed audit keys (dedupes a retried read). */
    _seenAuditKeys() {
        if (!this._auditSeen) this._auditSeen = new Set();
        if (this._auditSeen.size > 500) this._auditSeen.clear();
        return this._auditSeen;
    }

    async _handleUnattributed({ guild, settings, action, watch, reason, details }) {
        // An unattributable burst is still a signal worth surfacing, but the
        // spec is explicit: never punish when the executor is unknown. We log
        // an informational incident and alert, with no containment.
        const dedupKey = `unattr|${guild.id}|${action.key}|${Math.floor(Date.now() / (Math.max(1, watch.seconds) * 1000))}`;
        let claimed = true;
        try { claimed = await claimDedupKey(dedupKey, { guildId: guild.id, ttlSeconds: Math.max(10, watch.seconds) }); }
        catch (_) { claimed = true; }
        if (!claimed) return { handled: false, reason: 'deduped', executorId: null };

        await this._alert({
            guild, settings, action, watch,
            executorId: null, executorName: null,
            attribution: 'unknown',
            reason,
            responseLabel: 'Alert only (executor unknown — no containment)',
        });
        await this._recordIncident({
            guildId: guild.id, executorId: null, executorName: null,
            action: action.key, module: action.module, severity: action.severity,
            count: 0, threshold: watch.threshold, windowSeconds: watch.seconds,
            responseTaken: ['alertChannel'], responseResult: { reason }, responseOk: true,
            dryRun: settings.dryRun !== false, attribution: 'unknown',
            details: `${reason}${details && details.summary ? ` · ${details.summary}` : ''}`,
        });
        return { handled: true, reason: 'unattributed_alert', executorId: null };
    }

    // ── Response ────────────────────────────────────────────────────────────

    async _respond({ guild, settings, action, watch, executorId, executorName, attribution, verdict, details }) {
        const dryRun = settings.dryRun !== false;
        const responses = Array.isArray(settings.responses) ? settings.responses : [];

        // Cross-node + cross-process dedup: one incident per (guild, action,
        // executor, window). Claim atomically in the DB; if another node owns it,
        // stand down.
        const windowBucket = Math.floor(Date.now() / (Math.max(1, watch.seconds) * 1000));
        const dedupKey = `${guild.id}|${action.key}|${executorId}|${windowBucket}`;
        let claimed = true;
        try { claimed = await claimDedupKey(dedupKey, { guildId: guild.id, ttlSeconds: Math.max(30, watch.seconds * 2) }); }
        catch (err) { console.error('[ANTINUKE] dedup claim failed (responding anyway):', err.message); }
        if (!claimed) return { handled: false, reason: 'deduped', executorId };

        // Response cooldown: a sustained attack must not flood alerts/containment.
        const cooldownOk = this.detector.tryConsumeCooldown(guild.id, action.key, settings.responseCooldownSeconds);
        if (!cooldownOk) return { handled: false, reason: 'cooldown', executorId };

        const member = await this._fetchMember(guild, executorId);
        const executorLabel = member
            ? `${member.user ? member.user.tag : member.id} (\`${executorId}\`)`
            : `<@${executorId}> (\`${executorId}\`)`;

        const responseResult = { dryRun, taken: [], errors: [] };
        const permCheck = validateBotPermissions(guild);

        for (const key of responses) {
            try {
                if (key === 'alertOwner' || key === 'alertChannel') continue; // handled by _alert below
                if (key === 'logOnly' || key === 'manualReview') { responseResult.taken.push(key); continue; }
                if (dryRun) { responseResult.taken.push(`${key} (dry-run — skipped)`); continue; }

                if (key === 'removeRoles') {
                    if (!permCheck.checks.find(c => c.key === 'ManageRoles')?.available) {
                        responseResult.errors.push('removeRoles: missing Manage Roles');
                        continue;
                    }
                    const botMember = guild.members && guild.members.me;
                    const plan = computeDangerousRoleRemovals({
                        member,
                        botMember,
                        guildOwnerId: guild.ownerId,
                        botUserId: this.client && this.client.user ? this.client.user.id : null,
                        trustedRoleIds: settings.trustedRoleIds,
                        dangerousPermissions: settings.dangerousPermissions,
                    });
                    if (plan.reason) { responseResult.errors.push(`removeRoles: ${plan.reason}`); continue; }
                    const res = await stripDangerousRoles(member, plan, `Anti-Nuke: ${action.label}`);
                    responseResult.taken.push('removeRoles');
                    responseResult.removedRoles = res.removed.map(r => r.roleId);
                    if (res.failed.length) responseResult.errors.push(`removeRoles partial: ${res.failed.length} failed`);
                } else if (key === 'lockdown') {
                    if (!settings.lockdown || settings.lockdown.enabled === false) {
                        responseResult.errors.push('lockdown: disabled in settings');
                        continue;
                    }
                    const record = await applyLockdown(guild, {
                        settings,
                        reason: `Anti-Nuke: ${action.label} by ${executorId}`,
                        startedBy: executorId,
                    });
                    await this._saveLockdown(guild.id, record, executorId, action.label);
                    responseResult.taken.push('lockdown');
                    responseResult.lockdown = { pausedInvites: record.pausedInvites, warnings: record.warnings };
                } else {
                    responseResult.taken.push(key);
                }
            } catch (err) {
                responseResult.errors.push(`${key}: ${err.message}`);
            }
        }

        await this._alert({
            guild, settings, action, watch,
            executorId, executorName, attribution,
            responseLabel: this._responseLabel(responses, dryRun, responseResult),
            dryRun,
        });

        const responseOk = responseResult.errors.length === 0;
        await this._recordIncident({
            guildId: guild.id, executorId, executorName,
            action: action.key, module: action.module, severity: action.severity,
            count: verdict.count, threshold: verdict.threshold, windowSeconds: verdict.seconds,
            responseTaken: responses, responseResult, responseOk,
            dryRun, attribution,
            details: details && details.summary ? String(details.summary).slice(0, 1000) : '',
        });

        this._emit({
            guildId: guild.id, action: action.key, executorId,
            severity: action.severity, count: verdict.count, dryRun,
        });

        return {
            handled: true, reason: dryRun ? 'dry_run' : 'responded',
            executorId, count: verdict.count, responseResult,
        };
    }

    _responseLabel(responses, dryRun, responseResult) {
        const alerts = responses.filter(r => r === 'alertOwner' || r === 'alertChannel' || r === 'logOnly' || r === 'manualReview');
        const contains = responses.filter(r => r === 'removeRoles' || r === 'lockdown');
        const parts = [];
        if (alerts.length) parts.push(alerts.join(', '));
        if (contains.length) parts.push(dryRun ? `dry-run (${contains.join(', ')})` : contains.join(', '));
        return parts.join(' · ') || 'log only';
    }

    // ── Alerts ──────────────────────────────────────────────────────────────

    async _alert({ guild, settings, action, watch, executorId, executorName, attribution, responseLabel, reason, dryRun = null }) {
        const isDry = dryRun === null ? settings.dryRun !== false : dryRun;
        const executorLabel = reason === 'missing_audit_permission'
            ? '⚠️ Could not attribute — the bot needs **View Audit Log**.'
            : (executorId
                ? `${executorName || ''} <@${executorId}> (\`${executorId}\`)`.trim()
                : '⚠️ Unknown (audit log could not identify the executor).');

        const embed = buildSecurityAlertEmbed({
            title: 'Potential Nuke Attempt Detected',
            threatLabel: action.label,
            severity: action.severity,
            executorLabel,
            actionSummary: `${watch.threshold}+ ${action.label.toLowerCase()} in ${watch.seconds}s`,
            windowLabel: `${watch.seconds} seconds`,
            responseLabel: responseLabel || 'Log only',
            guildName: guild.name,
            dryRun: isDry,
        });

        // Never ping @everyone/@here — strict allowed_mentions.
        const payload = { embeds: [embed], allowedMentions: { parse: [] } };

        // Alert channel.
        if (settings.responses.includes('alertChannel') && settings.alertChannelId) {
            try {
                const ch = await this.client.channels.fetch(settings.alertChannelId).catch(() => null);
                if (ch && typeof ch.send === 'function') await ch.send(payload);
                else console.error(`[ANTINUKE] Alert channel ${settings.alertChannelId} is not sendable (deleted?).`);
            } catch (err) {
                console.error('[ANTINUKE] Alert channel delivery failed:', err.message);
            }
        }

        // Owner DM.
        if (settings.responses.includes('alertOwner')) {
            try {
                const owner = await guild.fetchOwner().catch(() => null);
                if (owner && typeof owner.send === 'function') await owner.send(payload);
            } catch (err) {
                console.error('[ANTINUKE] Owner DM failed:', err.message);
            }
        }
    }

    // ── Incidents ───────────────────────────────────────────────────────────

    async _recordIncident({
        guildId, executorId = null, executorName = null, action, module = null,
        severity = 'medium', count = 0, threshold = 0, windowSeconds = 0,
        responseTaken = [], responseResult = {}, responseOk = false,
        dryRun = false, attribution = 'unknown', details = '',
    }) {
        try {
            await this._ensureTable();
            await pool.query(`
                INSERT INTO antinuke_incidents
                    (guild_id, executor_id, executor_name, action, module, severity,
                     count, threshold, window_seconds, response_taken, response_result,
                     response_ok, dry_run, attribution, details)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            `, [
                String(guildId),
                executorId ? String(executorId) : null,
                executorName ? String(executorName).slice(0, 120) : null,
                String(action).slice(0, 60), module ? String(module).slice(0, 30) : null,
                String(severity).slice(0, 20),
                Math.max(0, Number(count) || 0), Math.max(0, Number(threshold) || 0),
                Math.max(0, Number(windowSeconds) || 0),
                JSON.stringify(Array.isArray(responseTaken) ? responseTaken : []),
                JSON.stringify(responseResult || {}),
                responseOk === true, dryRun === true,
                String(attribution).slice(0, 30), String(details || '').slice(0, 1000),
            ]);
        } catch (err) {
            // Incident recording is best-effort — it must never break detection.
            console.error('[ANTINUKE] failed to record incident:', err.message);
        }
    }

    /**
     * Read the incident ledger for a guild (filtered + paginated). All filters
     * are parameterized; results are capped so the dashboard never loads the
     * whole history.
     */
    async getIncidents(guildId, { action = null, severity = null, executorId = null, dryRun = null, limit = DEFAULT_INCIDENT_LIMIT, offset = 0 } = {}) {
        await this._ensureTable();
        const where = ['guild_id = $1'];
        const params = [String(guildId)];
        const push = (v) => { params.push(v); return `$${params.length}`; };
        if (action) where.push(`action = ${push(String(action))}`);
        if (severity) where.push(`severity = ${push(String(severity))}`);
        if (executorId) where.push(`executor_id = ${push(String(executorId))}`);
        if (dryRun === true) where.push('dry_run = true');
        if (dryRun === false) where.push('dry_run = false');
        const lim = Math.min(MAX_INCIDENT_LIMIT, Math.max(1, parseInt(limit, 10) || DEFAULT_INCIDENT_LIMIT));
        const off = Math.max(0, parseInt(offset, 10) || 0);
        const whereSql = where.join(' AND ');
        const [rows, count] = await Promise.all([
            pool.query(`SELECT * FROM antinuke_incidents WHERE ${whereSql} ORDER BY created_at DESC LIMIT ${lim} OFFSET ${off}`, params),
            pool.query(`SELECT COUNT(*)::int AS count FROM antinuke_incidents WHERE ${whereSql}`, params),
        ]);
        return { total: count.rows[0]?.count || 0, limit: lim, offset: off, incidents: rows.rows.map(rowToIncident) };
    }

    /** Small aggregate summary for the dashboard's activity overview. */
    async getIncidentSummary(guildId, { days = 30 } = {}) {
        await this._ensureTable();
        const d = Math.min(365, Math.max(1, parseInt(days, 10) || 30));
        const res = await pool.query(`
            SELECT action, severity, COUNT(*)::int AS count, SUM(CASE WHEN dry_run THEN 1 ELSE 0 END)::int AS dry_runs
            FROM antinuke_incidents
            WHERE guild_id = $1 AND created_at > NOW() - ($2 || ' days')::interval
            GROUP BY action, severity
        `, [String(guildId), String(d)]);
        const total = res.rows.reduce((sum, r) => sum + (r.count || 0), 0);
        return { total, days: d, byAction: res.rows };
    }

    // ── Lockdown ────────────────────────────────────────────────────────────

    async _saveLockdown(guildId, record, startedBy = null, reason = '') {
        try {
            await this._ensureTable();
            await pool.query(`
                INSERT INTO antinuke_lockdowns (guild_id, active, started_at, started_by, reason, state, updated_at)
                VALUES ($1, true, NOW(), $2, $3, $4, NOW())
                ON CONFLICT (guild_id) DO UPDATE SET
                    active = true, started_at = NOW(), started_by = EXCLUDED.started_by,
                    reason = EXCLUDED.reason, state = EXCLUDED.state, updated_at = NOW()
            `, [String(guildId), startedBy ? String(startedBy) : null, String(reason || '').slice(0, 500), JSON.stringify(record || {})]);
        } catch (err) {
            console.error('[ANTINUKE] failed to persist lockdown:', err.message);
        }
    }

    async getLockdown(guildId) {
        try {
            await this._ensureTable();
            const res = await pool.query('SELECT * FROM antinuke_lockdowns WHERE guild_id = $1', [String(guildId)]);
            if (res.rows.length === 0) return { active: false, state: null, startedAt: null, reason: '' };
            const row = res.rows[0];
            return {
                active: row.active === true,
                state: row.state || null,
                startedAt: row.started_at || null,
                startedBy: row.started_by || null,
                reason: row.reason || '',
            };
        } catch (err) {
            console.error('[ANTINUKE] getLockdown failed:', err.message);
            return { active: false, state: null, startedAt: null, reason: '' };
        }
    }

    /** Manually engage lockdown for a guild (dashboard/command). */
    async engageLockdown(guild, { startedBy = null, reason = 'Manual lockdown' } = {}) {
        const settings = this.getSettings(guild.id);
        const record = await applyLockdown(guild, { settings, reason, startedBy });
        await this._saveLockdown(guild.id, record, startedBy, reason);
        await this._recordIncident({
            guildId: guild.id, action: 'manualLockdown', module: 'server',
            severity: 'high', responseTaken: ['lockdown'], responseResult: { record },
            responseOk: record.warnings.length === 0, dryRun: false,
            attribution: startedBy ? 'manual' : 'manual', details: reason,
        });
        return record;
    }

    /** Lift a lockdown, restoring only what lockdown changed. */
    async liftLockdown(guild, { reason = 'Lockdown lifted' } = {}) {
        const current = await this.getLockdown(guild.id);
        if (!current.active || !current.state) {
            return { restored: null, warnings: ['no_active_lockdown'] };
        }
        const { restored, warnings } = await restoreLockdown(guild, current.state, { reason });
        try {
            await this._ensureTable();
            await pool.query('UPDATE antinuke_lockdowns SET active = false, updated_at = NOW() WHERE guild_id = $1', [String(guild.id)]);
        } catch (err) {
            console.error('[ANTINUKE] failed to clear lockdown:', err.message);
        }
        await this._recordIncident({
            guildId: guild.id, action: 'lockdownLifted', module: 'server',
            severity: 'info', responseTaken: ['restore'], responseResult: { restored, warnings },
            responseOk: warnings.length === 0, dryRun: false, attribution: 'manual', details: reason,
        });
        return { restored, warnings };
    }

    // ── Permission diagnostics ──────────────────────────────────────────────

    /** The bot's permission state in a guild (for the dashboard warning). */
    getPermissionReport(guild) {
        return validateBotPermissions(guild);
    }

    // ── Listener plumbing (optional) ────────────────────────────────────────

    onIncident(fn) {
        if (typeof fn === 'function') this._listeners.add(fn);
        return () => this._listeners.delete(fn);
    }

    _emit(payload) {
        for (const fn of this._listeners) {
            try { fn(payload); } catch (_) { /* a listener must never break detection */ }
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    async _fetchMember(guild, userId) {
        if (!guild || !userId) return null;
        try {
            if (guild.members && guild.members.cache && guild.members.cache.get(userId)) {
                return guild.members.cache.get(userId);
            }
            if (guild.members && typeof guild.members.fetch === 'function') {
                return await guild.members.fetch(userId);
            }
        } catch (_) { /* the member may have left — containment is best-effort */ }
        return null;
    }

    /** Stats for the dashboard/stats endpoint. */
    stats() {
        return { ...this.detector.stats(), guilds: this._cache.size };
    }
}

function rowToSettings(row) {
    const normalized = normalizeAntiNukeSettings({
        enabled: row.enabled,
        alertChannelId: row.alert_channel_id || null,
        responses: row.responses,
        trustedUserIds: row.trusted_user_ids,
        trustedRoleIds: row.trusted_role_ids,
        watched: row.watched,
        dryRun: row.dry_run !== false,
        dangerousPermissions: row.dangerous_permissions,
        lockdown: row.lockdown,
        responseCooldownSeconds: row.response_cooldown_seconds,
        updatedAt: row.updated_at || null,
    });
    normalized.setupMethod = row.setup_method || null;
    normalized.setupStatus = row.setup_status || 'not_started';
    normalized.setupState = row.setup_state || {};
    return normalized;
}

function rowToIncident(row) {
    return {
        id: row.id,
        guildId: row.guild_id,
        executorId: row.executor_id,
        executorName: row.executor_name,
        action: row.action,
        module: row.module,
        severity: row.severity,
        count: row.count,
        threshold: row.threshold,
        windowSeconds: row.window_seconds,
        responseTaken: row.response_taken || [],
        responseResult: row.response_result || {},
        responseOk: row.response_ok === true,
        dryRun: row.dry_run === true,
        attribution: row.attribution,
        details: row.details,
        createdAt: row.created_at,
    };
}

module.exports = AntiNukeManager;
module.exports.AntiNukeManager = AntiNukeManager;
module.exports.rowToSettings = rowToSettings;
module.exports.rowToIncident = rowToIncident;
module.exports.severityColor = severityColor;
