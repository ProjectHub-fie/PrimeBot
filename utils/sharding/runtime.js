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
    // `NODE_ROLE` is authoritative when set. When it is not, every host falls
    // back to sn1 — and three hosts that all think they are sn1 can only ever
    // have ONE of them online (they all plan the same shards). So a node
    // without an explicit role negotiates a free one instead.
    const explicitRole = String(env.NODE_ROLE || '').trim().length > 0;
    let roleCollisionWarned = false;

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

    /**
     * Pick a role that no other live process is reporting.
     *
     * Only runs when `NODE_ROLE` is unset. A peer is identified by `pid` (the
     * heartbeat table is keyed by role, so two hosts with the same role
     * overwrite each other's row — the pid is what distinguishes them).
     *
     * @returns {Promise<string>} the role this node will use
     */
    async function negotiateRole() {
        if (!enabled) return identity.role;
        if (explicitRole) {
            // An explicit NODE_ROLE is never rewritten, but two hosts that were
            // both configured as sn1 can only ever have one of them online.
            // Say so once, with the fix, instead of standing by silently.
            if (!roleCollisionWarned) {
                const peer = await coordinator.roleTakenByPeer().catch(() => null);
                if (peer) {
                    roleCollisionWarned = true;
                    logger.warn(`[SHARD] NODE_ROLE=${identity.role} is already served by another node (pid ${peer.pid}) — this host cannot serve. Give every host its own NODE_ROLE (sn1/sn2/sn3) or unset NODE_ROLE so it is negotiated.`);
                }
            }
            return identity.role;
        }
        try {
            const taken = await coordinator.roleTakenByPeer();
            if (!taken) return identity.role;
            const live = await shardStore.listNodes();
            const fresh = live.filter(n => n.ageMs != null && n.ageMs <= config.staleAfterMs);
            const free = config.nodes.find(role => !fresh.some(n => n.role === role));
            if (!free) return identity.role; // every role is live — stand by
            const previous = identity.role;
            identity.role = free;
            coordinator.setRole(free);
            // Every other identity consumer (monitor pulse, status views)
            // resolves from the environment, so keep it in sync.
            env.NODE_ROLE = free;
            if (env === process.env) process.env.NODE_ROLE = free;
            logger.log(`[SHARD] role ${previous} is already served by another node (pid ${taken.pid}) — adopting ${free}`);
            return free;
        } catch (err) {
            logger.warn('[SHARD] role negotiation failed:', err.message);
            return identity.role;
        }
    }

    /** Claim this node's shards. Never throws — a coordinator outage must not stop boot. */
    async function claim() {
        if (!enabled) return { shardIds: [], reason: 'disabled' };
        try {
            await negotiateRole();
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

    /**
     * Serve EVERY shard from this process.
     *
     * The escape hatch for a fleet that cannot talk to the shard store: an
     * empty claim would otherwise leave every node standing by, which is
     * exactly "the bot is completely offline". Only the primary role calls
     * this, so at most one node serves (no dual-active).
     */
    function serveAllShards(target = client) {
        if (!enabled) return false;
        const count = Math.max(1, config.shardCount);
        currentShards = Array.from({ length: count }, (_, i) => i);
        if (target && target.options) {
            target.options.shards = [...currentShards];
            target.options.shardCount = count;
        }
        return true;
    }

    /** Check the shard store before relying on it (boot diagnostics). */
    async function checkStore() {
        if (!enabled) return { ok: false, reason: 'disabled' };
        try {
            await shardStore.ensureTables();
            return { ok: true };
        } catch (err) {
            return { ok: false, error: err.message };
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
        negotiateRole,
        applyToClient,
        serveAllShards,
        checkStore,
        telemetry,
        startLoop,
        stopLoop,
        release,
        snapshot,
        planPreview,
        get shardIds() { return [...currentShards]; },
        get role() { return identity.role; },
        explicitRole,
        get shardLost() { return shardLost; },
        startedAt: STARTED_AT,
        MemoryShardStore,
    };
}

module.exports = { createShardRuntime };
