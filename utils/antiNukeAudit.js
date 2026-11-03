/**
 * Anti-Nuke — audit-log correlation.
 *
 * A Discord gateway event (channelDelete, guildBanAdd, …) does NOT name the
 * moderator who caused it. The only reliable way to attribute the action is to
 * read the guild's audit log, find the entry that matches the event, and take
 * its `executorId`. This module does exactly that, and nothing else: it is pure
 * orchestration around `guild.fetchAuditLogs()` with the validation rules that
 * keep attribution honest.
 *
 * The rules (all of which have bitten real anti-nuke implementations):
 *
 *   1. Wait a short moment before reading. Discord writes the audit entry a
 *      beat after the gateway event fires, so reading immediately misses it.
 *   2. Match on type AND target id. A recent entry of the right type but the
 *      wrong target is a *different* action — never attribute it.
 *   3. Match on time. An entry created long before the event is stale (it may
 *      have been read from cache); an entry from the future is impossible.
 *   4. Ignore the bot's own entries and, optionally, a known actor. Otherwise
 *      the bot attributes its own cleanup to an innocent moderator.
 *   5. Never guess. If no entry matches, return `{ executorId: null }` and the
 *      caller must NOT punish — it can only alert/log.
 *   6. Handle a missing View Audit Log permission (Discord throws 50013) by
 *      returning a structured `missingPermission` result instead of throwing.
 *
 * The result is always a plain object, so a caller can act on it without a
 * try/catch of its own:
 *
 *   { ok, executorId, executor, entry, reason, missingPermission, error }
 */

const { AuditLogEvent } = require('discord.js');

// How long to wait for the audit entry to propagate before reading. Discord
// usually writes within ~200ms; 700ms is a safe ceiling that keeps the detector
// responsive without hammering the API.
const DEFAULT_DELAY_MS = 700;
// How far in the past an entry may have been created and still count as
// "this event". Anything older is treated as unrelated.
const DEFAULT_MAX_AGE_MS = 15000;
// Entries fetched per audit-log read. A small page is enough: the matching
// entry is almost always the most recent one of its type.
const DEFAULT_LIMIT = 8;
// Bounded retries when the first read comes back empty (the entry can lag).
const DEFAULT_RETRIES = 2;

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Resolve a discord.js AuditLogEvent name ('ChannelDelete') to its numeric
 * value. Accepts a number too (already resolved). Returns null when unknown.
 */
function resolveAuditEventType(nameOrNumber) {
    if (typeof nameOrNumber === 'number') return nameOrNumber;
    if (!nameOrNumber) return null;
    const value = AuditLogEvent[nameOrNumber];
    return typeof value === 'number' ? value : null;
}

/**
 * Normalize the many shapes a target can take into `{ id, type, extra }`.
 * Audit entries expose `target` as a partial object (id + sometimes more), or
 * `targetId` as a plain string on older payloads.
 */
function readTargetId(entry) {
    if (!entry) return null;
    const t = entry.target;
    if (t && typeof t === 'object' && t.id) return String(t.id);
    if (typeof t === 'string') return t;
    if (entry.targetId) return String(entry.targetId);
    return null;
}

/** Channel type of the audit entry's target, if Discord included it. */
function readTargetType(entry) {
    const t = entry && entry.target;
    if (t && typeof t === 'object' && t.type != null) return Number(t.type);
    if (entry && entry.targetType != null) return Number(entry.targetType);
    return null;
}

/**
 * Core matcher. Returns the first entry that matches the requested shape, or
 * null. Pure — no Discord calls — so it can be unit-tested directly.
 *
 * @param {Iterable} entries        audit-log entries (newest first)
 * @param {object}   opts
 * @param {number}   opts.type      AuditLogEvent numeric value
 * @param {string}   [opts.targetId]    require this target id
 * @param {number}   [opts.targetType]  require this target channel type
 * @param {number}   opts.now          current epoch ms
 * @param {number}   [opts.maxAgeMs]   reject entries older than this
 * @param {string[]} [opts.ignoreExecutors] executor ids to skip (the bot)
 * @param {Set}      [opts.seenKeys]   dedupe keys already consumed
 */
function matchAuditEntry(entries, opts = {}) {
    const {
        type, targetId = null, targetType = null,
        now = Date.now(), maxAgeMs = DEFAULT_MAX_AGE_MS,
        ignoreExecutors = [], seenKeys = null,
    } = opts;
    const ignore = new Set(ignoreExecutors.filter(Boolean));
    for (const entry of entries) {
        if (!entry) continue;
        if (Number(entry.action) !== Number(type)) continue;
        if (targetId != null && readTargetId(entry) !== String(targetId)) continue;
        if (targetType != null && readTargetType(entry) !== Number(targetType)) continue;
        const executorId = entry.executorId ? String(entry.executorId) : null;
        // An entry with no executor cannot attribute anything.
        if (!executorId) continue;
        if (ignore.has(executorId)) continue;
        const created = Number(entry.createdTimestamp) || 0;
        if (created && now - created > maxAgeMs) continue;   // too old → unrelated
        if (created && created - now > 5000) continue;       // in the future → impossible
        const key = dedupeKey(entry);
        if (seenKeys && seenKeys.has(key)) continue;         // already consumed
        return entry;
    }
    return null;
}

/**
 * Stable identity for an audit entry, used to prevent the same entry being
 * consumed twice (e.g. when a retry sees it again, or a duplicate gateway event
 * arrives).
 */
function dedupeKey(entry) {
    if (!entry) return '';
    return `${entry.id || ''}|${entry.action || ''}|${readTargetId(entry) || ''}|${entry.executorId || ''}`;
}

/**
 * Fetch and correlate one audit entry.
 *
 * @param {import('discord.js').Guild} guild
 * @param {object} query
 * @param {string|number} query.auditEvent  AuditLogEvent name or value
 * @param {string}   [query.targetId]      expected target id
 * @param {number}   [query.targetType]    expected target channel type
 * @param {number}   [query.delayMs]       wait before the first read
 * @param {number}   [query.maxAgeMs]
 * @param {number}   [query.limit]
 * @param {number}   [query.retries]
 * @param {string[]} [query.ignoreExecutors]
 * @param {Set}      [query.seenKeys]
 * @param {Function} [query.fetchAuditLogs] override for tests
 * @returns {Promise<object>} always resolves
 */
async function correlateAuditEntry(guild, query = {}) {
    const type = resolveAuditEventType(query.auditEvent);
    if (type == null) {
        return { ok: false, executorId: null, reason: 'unknown_audit_event', auditEvent: query.auditEvent };
    }
    if (!guild) return { ok: false, executorId: null, reason: 'no_guild' };

    const delayMs = Number.isFinite(query.delayMs) ? query.delayMs : DEFAULT_DELAY_MS;
    const retries = Number.isFinite(query.retries) ? query.retries : DEFAULT_RETRIES;
    const limit = Number.isFinite(query.limit) ? query.limit : DEFAULT_LIMIT;
    const fetchLogs = query.fetchAuditLogs
        || (typeof guild.fetchAuditLogs === 'function' ? guild.fetchAuditLogs.bind(guild) : null);

    if (!fetchLogs) return { ok: false, executorId: null, reason: 'audit_log_unavailable' };

    if (delayMs > 0) await delay(delayMs);

    for (let attempt = 0; attempt <= retries; attempt++) {
        let logs;
        try {
            logs = await fetchLogs({ limit, type });
        } catch (err) {
            // 50013 Missing Permissions = the bot lacks View Audit Log. That is a
            // configuration problem, not a crash — report it so the dashboard can
            // warn and the caller can degrade to alert-only.
            const code = err && (err.code || err.status);
            if (code === 50013 || code === '50013' || /missing permissions/i.test(err.message || '')) {
                return { ok: false, executorId: null, reason: 'missing_audit_permission', missingPermission: true };
            }
            if (attempt >= retries) {
                return { ok: false, executorId: null, reason: 'audit_fetch_failed', error: err.message };
            }
            await delay(250 * (attempt + 1));
            continue;
        }

        const entries = logs && logs.entries ? logs.entries.values() : [];
        const entry = matchAuditEntry(entries, {
            type,
            targetId: query.targetId != null ? query.targetId : null,
            targetType: query.targetType != null ? query.targetType : null,
            now: Date.now(),
            maxAgeMs: Number.isFinite(query.maxAgeMs) ? query.maxAgeMs : DEFAULT_MAX_AGE_MS,
            ignoreExecutors: query.ignoreExecutors || [],
            seenKeys: query.seenKeys || null,
        });

        if (entry) {
            if (query.seenKeys && typeof query.seenKeys.add === 'function') query.seenKeys.add(dedupeKey(entry));
            return {
                ok: true,
                executorId: String(entry.executorId),
                executor: entry.executor || null,
                entry,
                targetId: readTargetId(entry),
                reason: 'matched',
            };
        }

        // Nothing matched yet — give Discord another beat before retrying.
        if (attempt < retries) await delay(400 * (attempt + 1));
    }

    // No matching entry. Attribution is impossible: the caller must NOT punish.
    return { ok: false, executorId: null, reason: 'no_matching_entry' };
}

module.exports = {
    correlateAuditEntry,
    matchAuditEntry,
    resolveAuditEventType,
    readTargetId,
    readTargetType,
    dedupeKey,
    DEFAULT_DELAY_MS,
    DEFAULT_MAX_AGE_MS,
};
