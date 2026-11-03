/**
 * Anti-Nuke — audit-entry → watched-action mapping.
 *
 * The primary detection source is the `guildAuditLogEntryCreate` gateway event
 * (requires the GuildModeration intent). That event hands us the audit entry
 * directly, so the executor is known without a second API round-trip — the most
 * reliable attribution Discord offers.
 *
 * One audit entry can map to more than one watched action:
 *
 *   ChannelDelete         → channelDelete, and categoryDelete when the target
 *                           was a category
 *   RoleUpdate            → rolePermissionUpdate, and the permission-grant
 *                           actions when the change set adds a dangerous bit
 *   MemberRoleUpdate      → memberRoleUpdate, botPermissionEscalation,
 *                           adminGrant (when the added role grants Administrator)
 *
 * `evaluateAuditEntry` is the single place that decides which actions an entry
 * counts for. It is pure over the entry + guild (it only reads the role cache),
 * so it is unit-testable with plain objects.
 */

const { AuditLogEvent, PermissionFlagsBits } = require('discord.js');
const {
    NUKE_ACTIONS, NUKE_ACTION_BY_KEY, DANGEROUS_PERMISSION_BY_KEY,
} = require('./antiNukeRules');
const { readTargetId, readTargetType } = require('./antiNukeAudit');

// Reverse index: auditEvent name → action keys that watch it. Built once.
const AUDIT_EVENT_INDEX = (() => {
    const idx = new Map();
    for (const action of NUKE_ACTIONS) {
        if (!idx.has(action.auditEvent)) idx.set(action.auditEvent, []);
        idx.get(action.auditEvent).push(action.key);
    }
    return idx;
})();

/** Watched-action keys that watch a given AuditLogEvent name. */
function actionsForAuditEvent(auditEventName) {
    return AUDIT_EVENT_INDEX.get(auditEventName) || [];
}

/** The AuditLogEvent name for a numeric entry.action (or null). */
function auditEventName(actionValue) {
    if (typeof actionValue === 'string') return actionValue;
    return AuditLogEvent[actionValue] || null;
}

/**
 * Extract the permission change from a RoleUpdate entry's `changes`. Returns
 * `{ granted: BigInt, removed: BigInt }` where `granted` holds the bits that
 * were added and `removed` the bits taken away. Returns null when the entry
 * carries no permission change.
 */
function readPermissionChange(entry) {
    const changes = Array.isArray(entry && entry.changes) ? entry.changes : [];
    for (const change of changes) {
        if (!change || change.key !== 'permissions') continue;
        try {
            const before = BigInt(change.old != null ? change.old : 0);
            const after = BigInt(change.new != null ? change.new : 0);
            return { granted: after & ~before, removed: before & ~after, before, after };
        } catch (_) {
            return null;
        }
    }
    return null;
}

/** Role ids added to a member by a MemberRoleUpdate entry (best-effort). */
function readAddedRoleIds(entry) {
    const changes = Array.isArray(entry && entry.changes) ? entry.changes : [];
    const ids = [];
    for (const change of changes) {
        if (!change) continue;
        if (change.key === '$add' || change.key === 'roles') {
            const arr = Array.isArray(change.new) ? change.new : (change.new ? [change.new] : []);
            for (const r of arr) {
                const id = typeof r === 'string' ? r : (r && r.id);
                if (id) ids.push(String(id));
            }
        }
    }
    return ids;
}

/** Does `role` grant the given permission key (from the dangerous catalog)? */
function roleGrants(role, permissionKey) {
    const meta = DANGEROUS_PERMISSION_BY_KEY[permissionKey];
    if (!meta || !role) return false;
    try {
        if (role.permissions && typeof role.permissions.has === 'function') return role.permissions.has(meta.flag);
        if (role.permissions && role.permissions.bitfield != null) {
            return (BigInt(role.permissions.bitfield) & meta.flag) === meta.flag;
        }
    } catch (_) { /* an unreadable role grants nothing we can prove */ }
    return false;
}

/**
 * Did this entry grant the watched permission?
 *
 *   • RoleUpdate: compare the permission bitfield change directly.
 *   • MemberRoleUpdate: look up each added role and test the permission on it
 *     (a member gains a permission by gaining a role).
 */
function entryGrantsPermission(entry, permissionKey, guild) {
    const name = auditEventName(entry && entry.action);
    if (name === 'RoleUpdate') {
        const change = readPermissionChange(entry);
        if (!change) return false;
        if (permissionKey === 'dangerous') {
            for (const meta of Object.values(DANGEROUS_PERMISSION_BY_KEY)) {
                if ((change.granted & meta.flag) === meta.flag) return true;
            }
            return false;
        }
        const meta = DANGEROUS_PERMISSION_BY_KEY[permissionKey];
        return meta ? (change.granted & meta.flag) === meta.flag : false;
    }
    if (name === 'MemberRoleUpdate') {
        const addedIds = readAddedRoleIds(entry);
        if (addedIds.length === 0) return false;
        const roleCache = guild && guild.roles && guild.roles.cache ? guild.roles.cache : null;
        if (!roleCache) return false;
        for (const id of addedIds) {
            const role = roleCache.get(id);
            if (!role) continue;
            if (permissionKey === 'dangerous') {
                for (const meta of Object.values(DANGEROUS_PERMISSION_BY_KEY)) {
                    if (roleGrants(role, meta.key)) return true;
                }
            } else if (roleGrants(role, permissionKey)) {
                return true;
            }
        }
        return false;
    }
    return false;
}

/** Human summary of an entry, for the incident details column. */
function describeEntry(entry) {
    if (!entry) return '';
    const target = readTargetId(entry) || 'unknown';
    const bits = [];
    if (entry.executorId) bits.push(`executor ${entry.executorId}`);
    bits.push(`target ${target}`);
    return bits.join(' · ');
}

/**
 * Evaluate one audit entry against the catalog. Returns the list of watched
 * actions this entry counts for, each with a `details` summary.
 *
 * @returns {Array<{ actionKey: string, details: string }>}
 */
function evaluateAuditEntry(entry, guild) {
    if (!entry) return [];
    const name = auditEventName(entry.action);
    if (!name) return [];
    const candidates = actionsForAuditEvent(name);
    const out = [];
    for (const key of candidates) {
        const action = NUKE_ACTION_BY_KEY[key];
        if (!action) continue;
        // Target-type filter (e.g. categoryDelete only fires for categories).
        if (action.targetType != null && readTargetType(entry) !== action.targetType) continue;
        // Permission filter (only count the entry when the permission was granted).
        if (action.permission && !entryGrantsPermission(entry, action.permission, guild)) continue;
        out.push({ actionKey: key, details: describeEntry(entry) });
    }
    return out;
}

/** Every watched action key, for diagnostics/tests. */
function watchedActionKeys() {
    return NUKE_ACTIONS.map(a => a.key);
}

module.exports = {
    actionsForAuditEvent,
    auditEventName,
    evaluateAuditEntry,
    entryGrantsPermission,
    readPermissionChange,
    readAddedRoleIds,
    roleGrants,
    describeEntry,
    watchedActionKeys,
    AUDIT_EVENT_INDEX,
    PermissionFlagsBits,
};
