/**
 * Shard runtime — the glue between the coordinator and this bot process.
 *
 * Responsibilities:
 *  - resolve the shard config + this node's identity,
 *  - claim this node's shards from the coordinator,
 *  - apply the claimed shard set to the discord.js client BEFORE login,
 *  - publish shard/guild/CPU/RAM telemetry for the heartbeat,
 *  - renew the shard leases on a timer and release them on shutdown.
 *
 * Everything is inert unless SHARD_COUNT is set, so a single-process
 * deployment behaves exactly as before.
 */

const os = require('os');
const { resolveShardConfig } = require('./config');
const { resolveNodeIdentity } = require('../nodeIdentity');
const { ShardCoordinator, MemoryShardStore } = require('./coordinator');
const { planAssignment, shardsFor } = require('./assignment');

const STARTED_AT = new Date();

function createShardRuntime({
    env = process.env,
    logger = console,
    store = null,
    client = null,
} = {}) {
    const identity = resolveNodeIdentity(env);
    const config = resolveShardConfig(env, { role: identity.role });
    const enabled = config.enabled;

    let shardStore = store;
    if (enabled && !shardStore) {
        // Loaded lazily so a deployment without SHARD_COUNT never touches the
        // shard tables (or the season pool) at all.
        const { PostgresShardStore } = require('./store');
        shardStore = new PostgresShardStore();
    }

    const coordinator = enabled
        ? new ShardCoordinator({ store: shardStore, role: identity.role, nodeName: identity.nodeName, config, logger })
        : null;

    let currentShards = [];
    let lastCpu = process.cpuUsage();
    let lastCpuAt = Date.now();
    let loop = null;
    let shardLost = false;

    function cpuPercent() {
        try {
            const now = Date.now();
            const usage = process.cpuUsage(lastCpu);
            const elapsedMs = Math.max(1, now - lastCpuAt);
            lastCpu = process.cpuUsage();
            lastCpuAt = now;
            const pct = ((usage.user + usage.system) / 1000) / elapsedMs * 100;
            return Math.max(0, Math.min(999, Math.round(pct * 10) / 10));
        } catch (_) {
            return null;
        }
    }

    function memoryMB() {
        try {
            return Math.round(process.memoryUsage().rss / 1024 / 1024);
        } catch (_) {
            return null;
        }
    }

    function shardState(target = client) {
        const collection = target && target.shards ? target.shards : null;
        if (!collection || typeof collection[Symbol.iterator] !== 'function') {
            return { shardIds: [...currentShards], shardReady: 0, shardTotal: currentShards.length };
        }
        const ids = [];
        let ready = 0;
        for (const shard of collection.values()) {
            ids.push(Number(shard.id));
            if (shard.status === 'ready') ready++;
        }
        return {
            shardIds: ids.length ? ids.sort((a, b) => a - b) : [...currentShards],
            shardReady: ready,
            shardTotal: ids.length || currentShards.length,
        };
    }

    /** Telemetry merged into the heartbeat row. */
    function telemetry(target = client) {
        if (!enabled) return null;
        const state = shardState(target);
        return {
            shardIds: state.shardIds,
            shardReady: state.shardReady,
            shardTotal: state.shardTotal,
            startedAt: STARTED_AT,
            cpuPercent: cpuPercent(),
            ramMB: memoryMB(),
            ramTotalMB: Math.round(os.totalmem() / 1024 / 1024),
            pid: process.pid,
            version: process.env.npm_package_version || null,
        };
    }

    /** Claim this node's shards. Never throws — a coordinator outage must not stop boot. */
    async function claim() {
        if (!enabled) return { shardIds: [], reason: 'disabled' };
        try {
            const result = await coordinator.claim();
            currentShards = result.shardIds;
            const label = result.shardIds.length ? result.shardIds.join(',') : 'none';
            logger.log(`[SHARD] ${identity.role} claimed shards ${label} (${result.reason})`);
            return result;
        } catch (err) {
            logger.error('[SHARD] coordinator claim failed:', err.message);
            return { shardIds: [...currentShards], reason: 'coordinator_error', error: err.message };
        }
    }

    /** Apply the claimed shards to the client (must run before client.login). */
    function applyToClient(target = client) {
        if (!enabled || !target || !target.options) return false;
        if (!currentShards.length) return false;
        target.options.shards = [...currentShards];
        target.options.shardCount = config.shardCount;
        return true;
    }

    /**
     * Renew the leases on a timer. Shards are never moved while the process is
     * running (that needs a reconnect), so this only keeps ownership alive and
     * reports a lost shard loudly.
     */
    function startLoop({ getClient = () => client, intervalMs = config.heartbeatMs } = {}) {
        if (!enabled || loop) return loop;
        loop = setInterval(() => {
            coordinator.renew().catch(err => logger.warn('[SHARD] renew failed:', err.message));
            const live = shardState(getClient());
            const missing = currentShards.filter(id => !live.shardIds.includes(id));
            if (missing.length && !shardLost) {
                shardLost = true;
                logger.warn(`[SHARD] shards ${missing.join(',')} are no longer connected — run a restart to re-claim`);
            }
        }, Math.max(5000, intervalMs));
        if (loop.unref) loop.unref();
        return loop;
    }

    function stopLoop() {
        if (loop) clearInterval(loop);
        loop = null;
    }

    async function release() {
        stopLoop();
        if (!enabled || !coordinator) return [];
        return coordinator.release().catch(() => []);
    }

    function snapshot() {
        if (!enabled) {
            return { enabled: false, plan: {}, order: [], shardCount: 0, assignments: [], nodes: [], owned: [] };
        }
        return coordinator.snapshot().then(s => ({ enabled: true, ...s }));
    }

    function planPreview() {
        const plan = planAssignment({ shardCount: config.shardCount, nodes: config.nodes, strategy: config.strategy });
        return { ...plan, mine: shardsFor(plan.plan, identity.role) };
    }

    return {
        enabled,
        config,
        identity,
        coordinator,
        claim,
        applyToClient,
        telemetry,
        startLoop,
        stopLoop,
        release,
        snapshot,
        planPreview,
        get shardIds() { return [...currentShards]; },
        get shardLost() { return shardLost; },
        startedAt: STARTED_AT,
        MemoryShardStore,
    };
}

module.exports = { createShardRuntime };
