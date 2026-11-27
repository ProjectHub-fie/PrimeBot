/**
 * Active-active sharding configuration.
 *
 * Three nodes run the bot at the same time, each owning a disjoint slice of
 * the shard set. Everything that decides *which* shards a node runs is
 * environment driven; nothing about a specific deployment is hardcoded.
 */

const DEFAULTS = Object.freeze({
    shardCount: 0,
    nodes: ['sn1', 'sn2', 'sn3'],
    strategy: 'balanced',
    leaseMs: 90000,
    heartbeatMs: 30000,
    coordinatorUrl: null,
    coordinatorToken: null,
    coordinatorTimeoutMs: 4000,
    maxPerNode: 0,
});

function toInt(value, fallback) {
    const n = Number.parseInt(value, 10);
    return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function parseNodeList(raw) {
    const list = String(raw || '')
        .split(',')
        .map(v => v.trim().toLowerCase())
        .filter(Boolean);
    return list.length ? [...new Set(list)] : [...DEFAULTS.nodes];
}

/**
 * Resolve the sharding configuration for this process.
 *
 * `enabled` is true only when SHARD_COUNT is a positive integer, so every
 * existing single-process deployment keeps its current behaviour untouched.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @param {{ role?: string }} [opts]
 */
function resolveShardConfig(env = process.env, { role = null } = {}) {
    const shardCount = toInt(env.SHARD_COUNT, DEFAULTS.shardCount);
    // An explicit SHARD_NODES list is authoritative: a node whose role is not in
    // it owns nothing (a 4th box must not silently steal a share). With the list
    // unset we default to sn1..sn3 and make sure this node is in it.
    const explicitNodes = String(env.SHARD_NODES || '').trim().length > 0;
    const nodes = parseNodeList(env.SHARD_NODES);
    const strategy = String(env.SHARD_STRATEGY || DEFAULTS.strategy).trim().toLowerCase();
    const leaseMs = toInt(env.SHARD_LEASE_MS, DEFAULTS.leaseMs);
    const heartbeatMs = toInt(env.SHARD_HEARTBEAT_INTERVAL_MS, DEFAULTS.heartbeatMs);
    const explicitMax = toInt(env.SHARD_MAX_PER_NODE, DEFAULTS.maxPerNode);
    const liveNodes = Math.max(1, nodes.length);
    const maxPerNode = explicitMax > 0 ? explicitMax : Math.max(1, Math.ceil(shardCount / liveNodes) + 1);

    return {
        enabled: shardCount > 0,
        shardCount,
        nodes: role && !explicitNodes && !nodes.includes(role) ? [...nodes, role] : nodes,
        strategy,
        leaseMs,
        heartbeatMs,
        // A shard is claimable once its owner has not renewed for this long.
        // Three missed heartbeats by default: slow enough that a brief blip
        // never moves shards, fast enough that a dead node is covered quickly.
        staleAfterMs: Math.max(leaseMs, heartbeatMs * 3),
        maxPerNode,
        coordinatorUrl: env.SHARD_COORDINATOR_URL ? String(env.SHARD_COORDINATOR_URL).trim() : null,
        coordinatorToken: env.SHARD_COORDINATOR_TOKEN ? String(env.SHARD_COORDINATOR_TOKEN).trim() : null,
        coordinatorTimeoutMs: toInt(env.SHARD_COORDINATOR_TIMEOUT_MS, DEFAULTS.coordinatorTimeoutMs),
        role,
    };
}

module.exports = { resolveShardConfig, DEFAULTS, parseNodeList };
