/**
 * Per-node status pulse builder.
 *
 * Each shard node posts a lightweight status pulse alongside its failover
 * heartbeat. The pulse carries everything the monitoring worker needs to tell
 * "process running but gateway broken" apart from "fully healthy", and to
 * detect restarts (pid/startedAt drift).
 *
 * Node identity MUST be stable and unique per node. We take it from
 * utils/nodeFailover (NODE_NAME has a stable role-based default) rather than
 * `process.env.NODE_NAME || 'local'` — the old fallback made every node that
 * did not set NODE_NAME report the SAME name, so they overwrote each other's
 * single monitor_node_pulse row (PK = node_name) and the page showed only one
 * of the three nodes.
 */

const STARTED_AT = new Date();

// Standby nodes have no failover heartbeat loop, so this dedicated loop keeps
// their pulse fresh. While idle (no Discord activity — always true for a
// standby) it backs off to keep Neon quiet; the interval it is actually using
// is reported in the pulse so the worker's stale threshold scales with it and a
// slow-but-alive standby is never mistaken for a dead one.
const PULSE_INTERVAL_MS = parseInt(process.env.MONITOR_PULSE_INTERVAL_MS, 10) || 30000;
const STANDBY_IDLE_INTERVAL_MS = parseInt(process.env.MONITOR_STANDBY_IDLE_INTERVAL_MS, 10) || 5 * 60000;

function nodeIdentity() {
    try {
        const nf = require('./nodeFailover');
        return { nodeName: nf.NODE_NAME, role: nf.NODE_ROLE };
    } catch (_) {
        return {
            nodeName: process.env.NODE_NAME || 'local',
            role: (process.env.NODE_ROLE || 'sn1').toString().trim().toLowerCase(),
        };
    }
}

function standbyIntervalMs() {
    try {
        if (require('./activityGate').isIdle()) return STANDBY_IDLE_INTERVAL_MS;
    } catch (_) {}
    return PULSE_INTERVAL_MS;
}

/**
 * The cadence THIS node is currently using, in ms. The active node rides the
 * failover heartbeat; a standby uses the standby loop cadence. Reported in the
 * pulse so peers can judge staleness against the writer's own interval.
 */
function pulseIntervalFor(client) {
    if (client && client.user) {
        try { return require('./nodeFailover').currentHeartbeatIntervalMs(); } catch (_) {}
    }
    return standbyIntervalMs();
}

/**
 * Build the pulse payload for this process.
 * @param {object} client discord.js client (may be disconnected / undefined on
 *                a standby node that has not logged in).
 */
function buildPulse(client) {
    const clientObj = client || {};
    const ws = clientObj.ws || {};
    const shards = clientObj.shards ? Array.from(clientObj.shards) : [];

    // Gateway states a discord.js client can be in.
    const wsStatus = ws.status; // 0 = ready, 1 = connecting, 2 = reconnecting, ...
    const wsReady = Number(wsStatus) === 0;
    const wsConnecting = Number(wsStatus) === 1 || Number(wsStatus) === 2;

    const shardIds = shards.map(s => s.id).filter(n => Number.isInteger(n)).sort((a, b) => a - b);
    const shardsTotal = shards.length;
    let shardsReady = 0;
    let shardsActive = 0;
    for (const shard of shards) {
        if (shard.status === 'ready') shardsReady++;
        if (shard.status === 'ready' || shard.status === 'idle') shardsActive++;
    }

    const { nodeName, role } = nodeIdentity();

    return {
        nodeName,
        role,
        processHealth: clientObj.user ? 'healthy' : 'running',
        gatewayConnected: wsReady || wsConnecting,
        gatewayReady: wsReady,
        shardsTotal: Number(shardsTotal) || 0,
        shardsReady,
        shardsActive,
        shardIds,
        pid: process.pid,
        startedAt: STARTED_AT,
        resource: {
            pulseIntervalMs: pulseIntervalFor(clientObj),
            uptimeSeconds: Math.floor(process.uptime()),
            nodeVersion: process.version,
            platform: process.platform,
            memoryMB: Number.isFinite(process.memoryUsage?.().rss) ? Math.round(process.memoryUsage().rss / 1024 / 1024) : null,
        },
    };
}

// ── Standby pulse loop ───────────────────────────────────────────────────────
// The ACTIVE node's pulse rides the failover heartbeat (nodeFailover.writePulse).
// Standby nodes have no heartbeat loop, so this dedicated (single, unref'd,
// idle-aware) timer keeps their pulse fresh so the status worker can see all
// three nodes independently even when only one holds the Discord lease.

let pulseTimer = null;
let pulseClient = null;

function startPulseLoop(client) {
    pulseClient = client || null;
    stopPulseLoop();
    const write = async () => {
        try {
            const { upsertNodePulse } = require('../server/monitorDb');
            await upsertNodePulse(buildPulse(pulseClient));
        } catch (err) {
            console.warn('[STATUS] pulse write failed:', err.message);
        }
    };
    const tick = () => {
        write().finally(() => {
            if (!pulseTimer) return;
            const next = standbyIntervalMs();
            pulseTimer = setTimeout(tick, next);
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
    buildPulse, STARTED_AT, startPulseLoop, stopPulseLoop,
    PULSE_INTERVAL_MS, STANDBY_IDLE_INTERVAL_MS, standbyIntervalMs, nodeIdentity,
};