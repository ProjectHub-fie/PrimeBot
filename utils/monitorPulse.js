/**
 * Per-node status pulse builder.
 *
 * Each shard node posts a lightweight status pulse alongside its failover
 * heartbeat (the active node) or on its own steady timer (a standby node that
 * holds no Discord connection). The pulse carries INDEPENDENT signals so the
 * monitoring worker can tell "process running but gateway broken" apart from
 * "healthy standby with no gateway because it is unassigned", and so a restart
 * (pid / startedAt drift) is detectable.
 *
 * The signals are deliberately separate and are never collapsed into one
 * "healthy" boolean:
 *   processHealth      - is the OS process alive? (healthy | running)
 *   role               - sn1 | sn2 | sn3 (the node's configured priority)
 *   gatewayConnected   - is the Discord websocket connected?
 *   gatewayReady       - is the Discord websocket READY (all shards up)?
 *   shardsTotal/Ready/Active - how many shards this node is assigned / up
 *
 * A standby node legitimately has gatewayConnected=false, gatewayReady=false
 * and shardsTotal=0: it holds no Discord connection and is assigned no shards.
 * That is a HEALTHY state, not a fault - the worker classifies it from the
 * role + process health, never from the absence of a gateway.
 */

const { resolveNodeIdentity } = require('./nodeIdentity');

const STARTED_AT = new Date();

/**
 * Build the pulse payload for this process.
 * @param {object} client discord.js client (may be disconnected / undefined on
 *                a standby node that has not logged in).
 * @param {{ pulseIntervalMs?: number }} [opts]
 */
function buildPulse(client, opts = {}) {
    // Resolved per pulse, not at module load: a node without an explicit
    // NODE_ROLE adopts a free role during shard negotiation (see
    // utils/sharding/runtime.js), and the pulse must report the role the
    // process actually serves — otherwise every host pulses as sn1 and the
    // (node_name, role) keyed table keeps only one of them.
    const nodeIdentity = resolveNodeIdentity(process.env);
    const clientObj = client || {};
    const ws = clientObj.ws || {};
    const shards = clientObj.shards || null;

    // Gateway states a discord.js client can be in.
    const wsStatus = ws.status; // 0 = ready, 1 = connecting, 2 = reconnecting, ...
    const wsReady = Number(wsStatus) === 0;
    const wsConnecting = Number(wsStatus) === 1 || Number(wsStatus) === 2;

    // discord.js exposes `client.shards` as a Collection (has .size / iterable).
    const shardsTotal = shards ? (Number(shards.size) || 0) : 0;
    let shardsReady = 0;
    let shardsActive = 0;
    const shardIds = [];
    if (shards && typeof shards[Symbol.iterator] === 'function') {
        for (const shard of shards) {
            shardIds.push(Number(shard.id));
            if (shard.status === 'ready') shardsReady++;
            if (shard.status === 'ready' || shard.status === 'idle') shardsActive++;
        }
    }
    shardIds.sort((a, b) => a - b);

    return {
        nodeName: nodeIdentity.nodeId,
        nodeId: nodeIdentity.nodeId,
        role: nodeIdentity.role,
        // 'healthy' means the process is up AND has a usable gateway; 'running'
        // means the process is up with no gateway (a normal standby). We never
        // report 'dead' - an unresponsive process simply stops pulsing, which
        // the worker detects from heartbeat age.
        processHealth: clientObj.user ? 'healthy' : 'running',
        gatewayConnected: wsReady || wsConnecting,
        gatewayReady: wsReady,
        shardsTotal,
        shardsReady,
        shardsActive,
        // Active-active: WHICH shards this node owns (the dashboard shows the
        // assignment per node), plus the guilds and CPU cost of serving them.
        shardIds,
        guildCount: clientObj.guilds?.cache?.size ?? null,
        cpuPercent: typeof opts.cpuPercent === 'function' ? opts.cpuPercent() : null,
        pid: process.pid,
        startedAt: STARTED_AT,
        resource: {
            uptimeSeconds: Math.floor(process.uptime()),
            nodeVersion: process.version,
            platform: process.platform,
            memoryMB: Number.isFinite(process.memoryUsage?.().rss) ? Math.round(process.memoryUsage().rss / 1024 / 1024) : null,
            // Publish the cadence we are actually using so the worker's staleness
            // threshold scales with the writer's own interval instead of a fixed
            // constant that a slower node would always fail.
            pulseIntervalMs: Number(opts.pulseIntervalMs) > 0 ? Number(opts.pulseIntervalMs) : PULSE_INTERVAL_MS,
        },
    };
}

// -- Pulse loop --------------------------------------------------------------
// The ACTIVE node's pulse rides the failover heartbeat (nodeFailover.writePulse).
// A standby node holds no Discord connection, so this dedicated (single,
// unref'd) timer keeps its pulse fresh - otherwise only the active node would
// ever appear in monitoring and every standby would read as "no data".
//
// The cadence is STEADY (not activity-gated). Monitoring liveness requires a
// predictable beat: if a standby backed off to a multi-minute cadence while the
// worker was also idling, every check would land outside the staleness window
// and a healthy standby would be reported as offline. The active node already
// heartbeats every 30s (a failover guarantee), so Neon is kept awake regardless
// and backing the pulse off would buy nothing but blind spots.
const PULSE_INTERVAL_MS = parseInt(process.env.MONITOR_PULSE_INTERVAL_MS, 10) || 30000;
let pulseTimer = null;
let pulseClient = null;

function startPulseLoop(client) {
    pulseClient = client || null;
    stopPulseLoop();
    const write = async () => {
        try {
            const { upsertNodePulse } = require('../server/monitorDb');
            await upsertNodePulse(buildPulse(pulseClient, { pulseIntervalMs: PULSE_INTERVAL_MS }));
        } catch (err) {
            console.warn('[STATUS] pulse write failed:', err.message);
        }
    };
    const tick = () => {
        write().finally(() => {
            if (!pulseTimer) return;
            pulseTimer = setTimeout(tick, PULSE_INTERVAL_MS);
            pulseTimer.unref?.();
        });
    };
    write();
    pulseTimer = setTimeout(tick, PULSE_INTERVAL_MS);
    pulseTimer.unref?.();
}

function stopPulseLoop() {
    if (pulseTimer) { clearTimeout(pulseTimer); pulseTimer = null; }
    pulseClient = null;
}

module.exports = {
    buildPulse, STARTED_AT, startPulseLoop, stopPulseLoop, PULSE_INTERVAL_MS,
    // Kept for callers that read it at load time; the live role is on the pulse.
    get NODE_IDENTITY() { return resolveNodeIdentity(process.env); },
};
