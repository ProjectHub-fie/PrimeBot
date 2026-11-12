/**
 * Per-node status pulse builder.
 *
 * Each shard node posts a lightweight status pulse alongside its failover
 * heartbeat. The pulse carries everything the monitoring worker needs to tell
 * "process running but gateway broken" apart from "fully healthy", and to
 * detect restarts (pid/startedAt drift).
 */

const STARTED_AT = new Date();

/**
 * Build the pulse payload for this process.
 * @param {object} client discord.js client (may be disconnected / undefined on
 *                a standby node that has not logged in).
 */
function buildPulse(client) {
    const clientObj = client || {};
    const ws = clientObj.ws || {};
    const shards = Array.isArray(clientObj.shards) ? clientObj.shards : null;

    // Gateway states a discord.js client can be in.
    const wsStatus = ws.status; // 0 = ready, 1 = connecting, 2 = reconnecting, ...
    const wsReady = Number(wsStatus) === 0;
    const wsConnecting = Number(wsStatus) === 1 || Number(wsStatus) === 2;

    const shardsTotal = shards ? shards.length : (clientObj.shards?.size || 0);
    let shardsReady = 0;
    let shardsActive = 0;
    if (shards) {
        for (const shard of shards) {
            if (shard.status === 'ready') shardsReady++;
            if (shard.status === 'ready' || shard.status === 'idle') shardsActive++;
        }
    }

    return {
        nodeName: process.env.NODE_NAME || 'local',
        role: (process.env.NODE_ROLE || 'sn1').toString().trim().toLowerCase(),
        processHealth: clientObj.user ? 'healthy' : (clientObj ? 'running' : 'standby'),
        gatewayConnected: wsReady || wsConnecting,
        gatewayReady: wsReady,
        shardsTotal: Number(shardsTotal) || 0,
        shardsReady,
        shardsActive,
        pid: process.pid,
        startedAt: STARTED_AT,
        resource: {
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

const PULSE_INTERVAL_MS = parseInt(process.env.MONITOR_PULSE_INTERVAL_MS, 10) || 30000;
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
            let next = PULSE_INTERVAL_MS;
            try {
                if (require('./activityGate').isIdle() && !pulseClient?.user) next = 5 * 60000; // quiet standby
            } catch (_) {}
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

module.exports = { buildPulse, STARTED_AT, startPulseLoop, stopPulseLoop, PULSE_INTERVAL_MS };