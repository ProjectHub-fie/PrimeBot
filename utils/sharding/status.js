/**
 * Fleet status aggregation — the SINGLE source of truth shared by the Discord
 * `$stats` command and the dashboard stats API/page.
 *
 * Both surfaces call `describeFleet()` with the same rows (`bot_node_status` +
 * `bot_shard_assignment`) and therefore cannot disagree about health, role,
 * shard ownership or totals.
 *
 * Two axes are deliberately independent:
 *   health  online | degraded | stale | offline | never   (is the process ok?)
 *   role    active | standby                              (is it serving shards?)
 * A healthy node that owns shards is ALWAYS `active`; a node is only `standby`
 * when it owns zero shards, which is the one case where the word is true.
 */

const ROLE_ORDER = ['sn1', 'sn2', 'sn3'];

/** User-facing label. Internal role keys (sn1…) stay untouched. */
function clusterLabel(role, index = null) {
    const known = ROLE_ORDER.indexOf(String(role || '').toLowerCase());
    if (known >= 0) return `Cluster ${known + 1}`;
    if (Number.isInteger(index)) return `Cluster ${index + 1}`;
    return String(role || 'Cluster');
}

const HEALTH_LABELS = Object.freeze({
    online: 'Online',
    degraded: 'Degraded',
    stale: 'Stale data',
    offline: 'Offline',
    never: 'No data',
});

const ROLE_LABELS = Object.freeze({ active: 'Active', standby: 'Standby', unknown: 'Unknown' });

function healthOf(node, staleAfterMs) {
    if (!node || node.ageMs == null) return { health: 'never', reasons: ['no heartbeat yet'] };
    const age = Number(node.ageMs);
    if (!Number.isFinite(age)) return { health: 'never', reasons: ['no heartbeat yet'] };
    if (age > staleAfterMs) return { health: 'offline', reasons: [`no heartbeat for ${Math.round(age / 1000)}s`] };
    if (age > staleAfterMs / 2) return { health: 'stale', reasons: [`last heartbeat ${Math.round(age / 1000)}s ago`] };

    const assigned = Number(node.shardTotal ?? (node.shardIds || []).length ?? 0);
    // Only judge readiness when the node actually reported it — a pre-upgrade
    // row with no shard_ready column must not read as degraded.
    if (node.shardReady != null && assigned > 0 && Number(node.shardReady) < assigned) {
        return { health: 'degraded', reasons: [`${Number(node.shardReady)}/${assigned} shards ready`] };
    }
    if (node.processHealth && ['dead', 'stopped'].includes(node.processHealth)) {
        return { health: 'offline', reasons: ['process reported dead'] };
    }
    return { health: 'online', reasons: [] };
}

/**
 * @param {object} input
 * @param {Array} input.nodes        rows from bot_node_status (one per role)
 * @param {Array} input.assignments  rows from bot_shard_assignment
 * @param {number} input.shardCount
 * @param {number} input.staleAfterMs
 * @returns {object} fleet description consumed by every status surface
 */
function describeFleet({
    nodes = [],
    assignments = [],
    shardCount = 0,
    staleAfterMs = 90000,
    now = Date.now(),
} = {}) {
    const byRole = new Map();
    for (const node of nodes) {
        if (!node || !node.role) continue;
        const role = String(node.role).toLowerCase();
        const current = byRole.get(role);
        // Freshest row wins (a pre-upgrade deployment can leave an orphan row).
        if (!current || (Number(node.ageMs) || Infinity) < (Number(current.ageMs) || Infinity)) {
            byRole.set(role, { ...node, role });
        }
    }

    const roles = [...new Set([...ROLE_ORDER, ...byRole.keys()])];
    const ownersFromDb = new Map();
    for (const row of assignments) {
        const shardId = Number(row.shardId);
        if (!Number.isInteger(shardId)) continue;
        if (!ownersFromDb.has(shardId)) ownersFromDb.set(shardId, []);
        ownersFromDb.get(shardId).push({ role: String(row.ownerRole).toLowerCase(), ageMs: row.ageMs });
    }

    const clusters = roles.map((role, index) => {
        const node = byRole.get(role) || null;
        const { health, reasons } = healthOf(node, staleAfterMs);
        const reportedShards = Array.isArray(node?.shardIds) ? node.shardIds.map(Number).filter(Number.isInteger) : [];
        const dbShards = [...ownersFromDb.entries()]
            .filter(([, owners]) => owners.some(o => o.role === role))
            .map(([shardId]) => shardId);
        const shardIds = [...new Set(reportedShards.length ? reportedShards : dbShards)].sort((a, b) => a - b);
        const shardReady = node?.shardReady == null ? null : Number(node.shardReady);
        const shardTotal = node?.shardTotal == null ? shardIds.length : Number(node.shardTotal);
        // ROLE is about serving shards, never about health. A node that has
        // never reported is UNKNOWN — not a standby (it may be serving).
        const role_ = !node ? 'unknown' : (shardIds.length > 0 ? 'active' : 'standby');

        return {
            role,
            label: clusterLabel(role, index),
            nodeName: node?.nodeName || null,
            health,
            healthLabel: HEALTH_LABELS[health],
            roleLabel: ROLE_LABELS[role_],
            servingRole: role_,
            shardIds,
            shardCount: shardIds.length,
            shardReady,
            shardTotal,
            guildCount: node?.guildCount == null ? null : Number(node.guildCount),
            memberCount: node?.memberCount == null ? null : Number(node.memberCount),
            uptimeSeconds: node?.uptimeSeconds == null ? null : Number(node.uptimeSeconds),
            ramMB: node?.ramMB == null ? null : Number(node.ramMB),
            ramTotalMB: node?.ramTotalMB == null ? null : Number(node.ramTotalMB),
            cpuPercent: node?.cpuPercent == null ? null : Number(node.cpuPercent),
            pid: node?.pid ?? null,
            version: node?.version || null,
            ageMs: node?.ageMs == null ? null : Math.round(Number(node.ageMs)),
            lastHeartbeat: node?.lastHeartbeat || null,
            reasons,
        };
    });

    // A shard owned by two nodes would double-count its guilds.
    const duplicates = [...ownersFromDb.entries()]
        .filter(([, owners]) => owners.length > 1)
        .map(([shardId, owners]) => ({ shardId, roles: owners.map(o => o.role) }));

    const duplicatedRoles = new Set(duplicates.flatMap(d => d.roles));
    const guildNodes = clusters.filter(c => c.guildCount != null && !duplicatedRoles.has(c.role));
    const guilds = guildNodes.reduce((sum, c) => sum + c.guildCount, 0);
    const members = clusters
        .filter(c => c.memberCount != null && !duplicatedRoles.has(c.role))
        .reduce((sum, c) => sum + c.memberCount, 0);

    const assignedShards = new Set([...ownersFromDb.keys()].filter(id => id >= 0 && id < Math.max(shardCount, 0)));
    const readyShards = clusters.reduce((sum, c) => sum + (c.shardReady == null ? 0 : Math.min(c.shardReady, c.shardTotal || 0)), 0);

    const online = clusters.filter(c => c.health !== 'offline' && c.health !== 'never');
    const totals = {
        shards: shardCount,
        shardsAssigned: assignedShards.size,
        shardsReady: Math.min(readyShards, shardCount),
        guilds,
        // Only trustworthy when no shard is double-owned AND every serving
        // cluster reported a guild count — a partial sum must never be shown as
        // the fleet total.
        guildsReliable: duplicates.length === 0
            && clusters.some(c => c.servingRole === 'active')
            && clusters.filter(c => c.servingRole === 'active').every(c => c.guildCount != null),
        members,
        clusters: clusters.length,
        clustersOnline: online.length,
        clustersHealthy: clusters.filter(c => c.health === 'online').length,
        clustersActive: clusters.filter(c => c.servingRole === 'active').length,
        clustersStandby: clusters.filter(c => c.servingRole === 'standby').length,
        clustersOffline: clusters.filter(c => c.health === 'offline').length,
        clustersUnknown: clusters.filter(c => c.health === 'never').length,
        clustersStale: clusters.filter(c => c.health === 'stale').length,
        duplicates: duplicates.length,
    };

    return {
        clusters,
        // `nodes` is kept as an alias: existing API consumers read this field.
        nodes: clusters,
        totals,
        duplicates,
        // Missing telemetry is never healthy: an unknown cluster could be the
        // one serving half the fleet.
        healthy: duplicates.length === 0
            && totals.clustersOffline === 0
            && totals.clustersUnknown === 0
            && totals.clustersActive > 0,
        staleAfterMs,
        generatedAt: new Date(now).toISOString(),
    };
}

module.exports = { describeFleet, clusterLabel, ROLE_ORDER, HEALTH_LABELS, ROLE_LABELS, healthOf };
