const { db } = require('../server/db');
const { sql } = require('drizzle-orm');

// Two-host failover configuration.
// Set NODE_ROLE=primary on panel.visionhost.com and NODE_ROLE=secondary on wispbyte.com.
const NODE_ROLE = (process.env.NODE_ROLE || 'primary').toLowerCase();
const NODE_NAME = process.env.NODE_NAME || (NODE_ROLE === 'secondary' ? 'wispbyte.com' : 'panel.visionhost.com');

const HEARTBEAT_INTERVAL_MS = 15000;
const FAILOVER_THRESHOLD_MS = 45000;
const MONITOR_INTERVAL_MS = 10000;

let heartbeatTimer = null;
let tableReady = false;

async function ensureTable() {
    if (tableReady) return;
    await db.execute(sql`
        CREATE TABLE IF NOT EXISTS bot_node_status (
            role VARCHAR(20) PRIMARY KEY,
            node_name VARCHAR(255) NOT NULL,
            last_heartbeat TIMESTAMP NOT NULL DEFAULT NOW(),
            active BOOLEAN NOT NULL DEFAULT false
        )
    `);
    tableReady = true;
}

async function writeHeartbeat(role, active) {
    await ensureTable();
    await db.execute(sql`
        INSERT INTO bot_node_status (role, node_name, last_heartbeat, active)
        VALUES (${role}, ${NODE_NAME}, NOW(), ${active})
        ON CONFLICT (role) DO UPDATE SET
            node_name = EXCLUDED.node_name,
            last_heartbeat = NOW(),
            active = EXCLUDED.active
    `);
}

async function getStatus(role) {
    await ensureTable();
    const result = await db.execute(sql`
        SELECT node_name, last_heartbeat, active
        FROM bot_node_status
        WHERE role = ${role}
    `);
    const row = (result.rows || result)[0];
    return row || null;
}

async function getPrimaryAgeMs() {
    const row = await getStatus('primary');
    if (!row || !row.active) return Infinity;
    const last = new Date(row.last_heartbeat).getTime();
    return Date.now() - last;
}

function startHeartbeatLoop(role) {
    stopHeartbeatLoop();
    writeHeartbeat(role, true).catch(err => console.error(`[FAILOVER] Heartbeat write failed for ${role}:`, err.message));
    heartbeatTimer = setInterval(() => {
        writeHeartbeat(role, true).catch(err => console.error(`[FAILOVER] Heartbeat write failed for ${role}:`, err.message));
    }, HEARTBEAT_INTERVAL_MS);
}

function stopHeartbeatLoop() {
    if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
        heartbeatTimer = null;
    }
}

async function markInactive(role) {
    try {
        await writeHeartbeat(role, false);
    } catch (err) {
        console.error(`[FAILOVER] Failed to mark ${role} inactive:`, err.message);
    }
}

module.exports = {
    NODE_ROLE,
    NODE_NAME,
    HEARTBEAT_INTERVAL_MS,
    FAILOVER_THRESHOLD_MS,
    MONITOR_INTERVAL_MS,
    ensureTable,
    writeHeartbeat,
    getStatus,
    getPrimaryAgeMs,
    startHeartbeatLoop,
    stopHeartbeatLoop,
    markInactive,
};
