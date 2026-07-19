const { db } = require('../server/db');
const { sql } = require('drizzle-orm');

// Two-host failover configuration.
// Set NODE_ROLE=sn1 on panel.visionhost.com and NODE_ROLE=sn2 on wispbyte.com.
function normalizeNodeRole(rawRole) {
    const value = String(rawRole || 'sn1').trim().toLowerCase();
    if (value === 'sn2' || value === 'secondary' || value === 'secoundary') return 'sn2';
    if (value === 'sn1' || value === 'primary') return 'sn1';
    return 'sn1';
}

const NODE_ROLE = normalizeNodeRole(process.env.NODE_ROLE);
// Use NODE_NAME if explicitly set; otherwise use a stable role-based name.
// We deliberately skip process.env.HOSTNAME because hosting panels assign
// random container hostnames that change between restarts, which causes the
// DB to treat the same physical host as a brand-new node every time it starts.
const NODE_NAME = process.env.NODE_NAME || (NODE_ROLE === 'sn2' ? 'wispbyte.com' : 'panel.visionhost.com');

const HEARTBEAT_INTERVAL_MS = 15000;
const FAILOVER_THRESHOLD_MS = 45000;
const MONITOR_INTERVAL_MS = 10000;

let heartbeatTimer = null;
let tableReady = false;
let leaseTableReady = false;

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

async function ensureLeaseTable() {
    if (leaseTableReady) return;
    await db.execute(sql`
        CREATE TABLE IF NOT EXISTS bot_failover_lock (
            id INTEGER PRIMARY KEY DEFAULT 1,
            owner_node_name VARCHAR(255) NOT NULL,
            owner_role VARCHAR(20) NOT NULL,
            acquired_at TIMESTAMP NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);
    leaseTableReady = true;
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
    // Compute heartbeat age using the DATABASE's clock (NOW()), not this
    // process's local clock. The two hosts running this bot are separate
    // physical machines and their system clocks can drift out of sync with
    // each other; comparing a remote timestamp against a local Date.now()
    // can make a perfectly fresh heartbeat look stale (or vice versa),
    // causing both nodes to think they should be active at the same time.
    const result = await db.execute(sql`
        SELECT node_name, last_heartbeat, active,
               EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) * 1000 AS age_ms
        FROM bot_node_status
        WHERE role = ${role}
    `);
    const row = (result.rows || result)[0];
    return row || null;
}

async function getPrimaryAgeMs() {
    const row = await getStatus('sn1');
    if (!row || !row.active) return Infinity;
    return Number(row.age_ms);
}

// Looks for any OTHER node (different node_name) that is currently marked active
// with a fresh heartbeat. Used at startup/monitoring time so a node never logs
// into Discord while another instance is already online, even if NODE_ROLE was
// misconfigured (e.g. both hosts left unset/defaulting to "sn1").
// Heartbeat age is computed by the database itself (see getStatus) so
// clock drift between the two hosts can't cause a false "stale"/"fresh" read.
async function getOtherActiveNode(selfNodeName) {
    await ensureTable();
    const result = await db.execute(sql`
        SELECT role, node_name, last_heartbeat, active,
               EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) * 1000 AS age_ms
        FROM bot_node_status
        WHERE active = true AND node_name != ${selfNodeName}
    `);
    const rows = result.rows || result;
    for (const row of rows) {
        const ageMs = Number(row.age_ms);
        if (ageMs <= FAILOVER_THRESHOLD_MS) {
            return { role: row.role, nodeName: row.node_name, ageMs };
        }
    }
    return null;
}

function startHeartbeatLoop(role) {
    stopHeartbeatLoop();
    console.log(`[FAILOVER] Starting heartbeat loop for role=${role} node=${NODE_NAME}`);
    writeHeartbeat(role, true)
        .then(() => refreshLease(NODE_NAME, role))
        .then(() => console.log(`[FAILOVER] Initial heartbeat written for role=${role} node=${NODE_NAME}`))
        .catch(err => console.error(`[FAILOVER] Heartbeat write failed for ${role}:`, err.message));
    heartbeatTimer = setInterval(() => {
        writeHeartbeat(role, true)
            .then(() => refreshLease(NODE_NAME, role))
            .catch(err => console.error(`[FAILOVER] Heartbeat write failed for ${role}:`, err.message));
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

async function acquireLease(role, nodeName) {
    await ensureLeaseTable();

    try {
        console.log(`[FAILOVER] Attempting to acquire lease for role=${role} node=${nodeName}`);
        const insertResult = await db.execute(sql`
            INSERT INTO bot_failover_lock (id, owner_node_name, owner_role, acquired_at, last_seen)
            VALUES (1, ${nodeName}, ${role}, NOW(), NOW())
            ON CONFLICT (id) DO NOTHING
        `);
        const inserted = Number(insertResult?.rowCount || 0) > 0;
        if (inserted) {
            console.log(`[FAILOVER] Lease acquired successfully for role=${role} node=${nodeName}`);
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: false };
        }

        const existing = await db.execute(sql`
            SELECT owner_node_name, owner_role,
                   EXTRACT(EPOCH FROM (NOW() - last_seen)) * 1000 AS age_ms
            FROM bot_failover_lock
            WHERE id = 1
        `);
        const row = (existing.rows || existing)[0];
        if (!row) {
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: false };
        }

        if (row.owner_node_name === nodeName) {
            await db.execute(sql`
                UPDATE bot_failover_lock
                SET last_seen = NOW()
                WHERE id = 1 AND owner_node_name = ${nodeName}
            `);
            console.log(`[FAILOVER] Reusing existing lease for role=${role} node=${nodeName}`);
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: false };
        }

        const ageMs = Number(row.age_ms || 0);

        // sn1 always wins — steal the lease unconditionally from any
        // other holder (sn2 or a stale sn1). This makes "set NODE_ROLE=sn1
        // and restart" the reliable way to promote a host without manual DB edits.
        if (role === 'sn1') {
            await db.execute(sql`
                UPDATE bot_failover_lock
                SET owner_node_name = ${nodeName}, owner_role = ${role}, acquired_at = NOW(), last_seen = NOW()
                WHERE id = 1
            `);
            console.warn(`[FAILOVER] sn1 forced takeover from ${row.owner_node_name} (role=${row.owner_role}, age=${Math.round(ageMs / 1000)}s)`);
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: true };
        }

        // sn2 only takes over when the current lease has gone stale.
        if (ageMs > FAILOVER_THRESHOLD_MS) {
            await db.execute(sql`
                UPDATE bot_failover_lock
                SET owner_node_name = ${nodeName}, owner_role = ${role}, acquired_at = NOW(), last_seen = NOW()
                WHERE id = 1
            `);
            console.warn(`[FAILOVER] Lease expired for ${row.owner_node_name}; sn2 taking over as node=${nodeName}`);
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: true };
        }

        console.warn(`[FAILOVER] Lease is held by ${row.owner_node_name} (role=${row.owner_role}) age=${Math.round(ageMs / 1000)}s; standing by`);
        return { acquired: false, ownerNodeName: row.owner_node_name, ownerRole: row.owner_role, ageMs };
    } catch (err) {
        console.error('[FAILOVER] Lease acquisition failed:', err.message);
        return { acquired: false, ownerNodeName: null, ownerRole: role, ageMs: Infinity };
    }
}

async function refreshLease(nodeName, role) {
    try {
        await ensureLeaseTable();
        const result = await db.execute(sql`
            UPDATE bot_failover_lock
            SET last_seen = NOW(), owner_role = ${role}
            WHERE id = 1 AND owner_node_name = ${nodeName}
        `);
        return Number(result?.rowCount || 0) > 0;
    } catch (err) {
        console.error('[FAILOVER] Lease heartbeat refresh failed:', err.message);
        return false;
    }
}

async function releaseLease(nodeName) {
    try {
        await ensureLeaseTable();
        await db.execute(sql`
            DELETE FROM bot_failover_lock
            WHERE id = 1 AND owner_node_name = ${nodeName}
        `);
    } catch (err) {
        console.error('[FAILOVER] Lease release failed:', err.message);
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
    getOtherActiveNode,
    startHeartbeatLoop,
    stopHeartbeatLoop,
    markInactive,
    acquireLease,
    refreshLease,
    releaseLease,
};
