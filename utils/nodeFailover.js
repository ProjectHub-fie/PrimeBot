const { seasonDb } = require('../server/seasonDb');
const { sql } = require('drizzle-orm');

// Three-host failover configuration.
// Set NODE_ROLE=sn1 on panel.visionhost.com, NODE_ROLE=sn2 on wispbyte.com,
// and NODE_ROLE=sn3 on the third host (e.g. Replit).
// Priority: sn1 > sn2 > sn3
function normalizeNodeRole(rawRole) {
    const value = String(rawRole || 'sn1').trim().toLowerCase();
    if (value === 'sn2' || value === 'secondary'  || value === 'secoundary') return 'sn2';
    if (value === 'sn3' || value === 'tertiary')                              return 'sn3';
    if (value === 'sn1' || value === 'primary')                               return 'sn1';
    return 'sn1';
}

// Role priority: lower number = higher priority (wins the lease).
// sn1 always wins; sn2 beats sn3; sn3 is last resort.
const ROLE_PRIORITY = { sn1: 1, sn2: 2, sn3: 3 };

const NODE_ROLE = normalizeNodeRole(process.env.NODE_ROLE);
// Use NODE_NAME if explicitly set; otherwise use a stable role-based name.
// We deliberately skip process.env.HOSTNAME because hosting panels assign
// random container hostnames that change between restarts, which causes the
// DB to treat the same physical host as a brand-new node every time it starts.
const NODE_NAME = process.env.NODE_NAME || (
    NODE_ROLE === 'sn2' ? 'NU3049' :
    NODE_ROLE === 'sn3' ? 'NUKN09' :
                          'NR0008'
);

const HEARTBEAT_INTERVAL_MS = parseInt(process.env.FAILOVER_HEARTBEAT_INTERVAL_MS, 10) || 30000;
// Cadence used once the bot has seen no Discord activity for a while.
//
// Failover is a liveness guarantee: a standby must be able to detect that the
// active node has died and take over. That only works if the active node keeps
// publishing a liveness signal on a short, predictable cadence, so this
// DEFAULTS TO THE FAST CADENCE — an idle-but-alive active node keeps
// heartbeating every 30s and a standby takes over within ~45s of it actually
// dying.
//
// Setting it LONGER than Neon's ~5-minute suspend window (e.g. 360000) is an
// explicit trade-off: the endpoint can suspend and the Neon bill drops, but a
// standby then needs that whole window (idle cadence + grace) to notice the
// active node is gone. Do not set it unless you accept slow failover.
const IDLE_HEARTBEAT_INTERVAL_MS =
    parseInt(process.env.FAILOVER_IDLE_HEARTBEAT_INTERVAL_MS, 10) || HEARTBEAT_INTERVAL_MS;
// Extra tolerance beyond a writer's own interval before its heartbeat is stale.
// The old code compared age directly to FAILOVER_THRESHOLD_MS (45s), i.e. a
// 15s grace on the 30s heartbeat. Keeping that grace constant means a node on
// the fast cadence is judged exactly as before, while a node that has slowed to
// the idle cadence gets the same 15s grace on top of its longer interval.
const FAILOVER_THRESHOLD_MS = 45000;
const HEARTBEAT_GRACE_MS = Math.max(0, FAILOVER_THRESHOLD_MS - HEARTBEAT_INTERVAL_MS);
const MONITOR_INTERVAL_MS = 10000;

/**
 * Cadence to use for the next heartbeat. While the bot is handling Discord
 * events it stays at the fast interval (failover takeover stays ~45s); once the
 * bot has been quiet for a few minutes it drops to the idle interval so Neon can
 * suspend between touches. A deployment that wants a fixed cadence can set
 * FAILOVER_IDLE_HEARTBEAT_INTERVAL_MS equal to FAILOVER_HEARTBEAT_INTERVAL_MS.
 */
function currentHeartbeatIntervalMs() {
    if (IDLE_HEARTBEAT_INTERVAL_MS <= HEARTBEAT_INTERVAL_MS) return HEARTBEAT_INTERVAL_MS;
    try {
        return require('./activityGate').isIdle()
            ? IDLE_HEARTBEAT_INTERVAL_MS
            : HEARTBEAT_INTERVAL_MS;
    } catch (_) {
        return HEARTBEAT_INTERVAL_MS;
    }
}

/**
 * Is a heartbeat of `ageMs` still fresh, given the writer's own interval?
 * A node that has slowed down to the idle cadence must not be mistaken for a
 * dead node by a peer still running the fast cadence (which would trigger a
 * spurious takeover), so the tolerance scales with each writer's published
 * interval rather than a single fixed value.
 */
function isHeartbeatFresh(ageMs, intervalMs) {
    const base = Number(intervalMs) > 0 ? Number(intervalMs) : HEARTBEAT_INTERVAL_MS;
    return Number(ageMs) < base + HEARTBEAT_GRACE_MS;
}

/**
 * Whether the current lease holder should be considered alive. A holder is
 * alive when its lease is fresh OR it has a fresh bot_node_status heartbeat.
 * The heartbeat arm matters because the lease's `last_seen` is not refreshed
 * until the holder's combined heartbeat+lease statement runs; a holder that is
 * still booting therefore has a fresh heartbeat but a briefly-stale lease, and
 * a lower-priority peer must NOT seize the lease from it (the "sn2/sn3 interact
 * while sn1 is online" race). Pure so it can be tested without a database.
 */
function isHolderConsideredAlive(leaseAgeMs, holderHeartbeatFresh) {
    return Number(leaseAgeMs) <= FAILOVER_THRESHOLD_MS || holderHeartbeatFresh === true;
}

/** True when the bot has seen no Discord activity for a while (see activityGate). */
function activityIsIdle() {
    try {
        return require('./activityGate').isIdle();
    } catch (_) {
        return false;
    }
}


let heartbeatTimer = null;
let tableReady = false;
let leaseTableReady = false;
// Set once this node has deliberately stepped down. A step-down calls
// markInactive() (heartbeat active=false) and then exits, but an in-flight
// heartbeat tick can land AFTER the active=false write and flip the row back
// to active=true — a "zombie" heartbeat that makes peers think a stepped-down
// node is still alive and keeps the fleet in a confused dual-active state.
// Once marked inactive, an active heartbeat is refused until the next explicit
// startHeartbeatLoop() (which clears the flag for a fresh takeover).
let inactiveMarked = false;

// Optional provider of live bot runtime stats (guild + member counts) that only
// the connected Discord client knows. Set via setStatsProvider() from index.js;
// the values ride on the heartbeat row so the dashboard can show the ACTUAL
// member count without any bot↔dashboard IPC.
let statsProvider = null;
function setStatsProvider(fn) {
    statsProvider = typeof fn === 'function' ? fn : null;
}

async function ensureTable() {
    if (tableReady) return;
    await seasonDb.execute(sql`
        CREATE TABLE IF NOT EXISTS bot_node_status (
            role VARCHAR(20) PRIMARY KEY,
            node_name VARCHAR(255) NOT NULL,
            last_heartbeat TIMESTAMP NOT NULL DEFAULT NOW(),
            active BOOLEAN NOT NULL DEFAULT false
        )
    `);
    // Self-migrate older tables that predate the live-stats columns.
    await seasonDb.execute(sql`ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS guild_count INTEGER`);
    await seasonDb.execute(sql`ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS member_count BIGINT`);
    // The node publishes the cadence it is currently using, so a peer decides
    // whether the heartbeat is stale relative to the writer's own interval
    // instead of a single fixed threshold. Without this a node that has slowed
    // to the idle cadence would look dead to a peer on the fast cadence.
    await seasonDb.execute(sql`ALTER TABLE bot_node_status ADD COLUMN IF NOT EXISTS heartbeat_interval_ms INTEGER`);
    tableReady = true;
}

async function ensureLeaseTable() {
    if (leaseTableReady) return;
    await seasonDb.execute(sql`
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
    // Refuse to resurrect a node that has deliberately stepped down (see
    // inactiveMarked). markInactive() itself passes active=false and is allowed.
    if (active && inactiveMarked) return;
    await ensureTable();
    // Live guild/member counts from the connected client, when a provider is
    // registered (only the ACTIVE node is logged in, so only it has counts).
    // A provider failure must never break the heartbeat itself.
    let guildCount = null;
    let memberCount = null;
    if (statsProvider) {
        try {
            const stats = await statsProvider();
            if (stats && Number.isFinite(Number(stats.guildCount))) guildCount = Number(stats.guildCount);
            if (stats && Number.isFinite(Number(stats.memberCount))) memberCount = Number(stats.memberCount);
        } catch (err) {
            console.warn('[FAILOVER] stats provider failed (heartbeat continues):', err.message);
        }
    }
    const intervalMs = currentHeartbeatIntervalMs();
    await seasonDb.execute(sql`
        INSERT INTO bot_node_status (role, node_name, last_heartbeat, active, guild_count, member_count, heartbeat_interval_ms)
        VALUES (${role}, ${NODE_NAME}, NOW(), ${active}, ${guildCount}, ${memberCount}, ${intervalMs})
        ON CONFLICT (role) DO UPDATE SET
            node_name = EXCLUDED.node_name,
            last_heartbeat = NOW(),
            active = EXCLUDED.active,
            guild_count = EXCLUDED.guild_count,
            member_count = EXCLUDED.member_count,
            heartbeat_interval_ms = EXCLUDED.heartbeat_interval_ms
    `);
}

/**
 * Heartbeat + lease refresh in ONE round trip.
 *
 * These ran as two separate statements every 30s for the life of the process, so
 * the connection/scheduling overhead was paid twice. Neither can be deferred or
 * backed off (the failover lease is a liveness guarantee), but they can share a
 * single statement: the heartbeat upsert runs in a data-modifying CTE and the
 * lease UPDATE is the outer command, whose row count is the "still hold the
 * lease" signal the caller expects.
 *
 * @returns {Promise<boolean>} true when this node still holds the lease.
 */
async function writeHeartbeatWithLease(role) {
    // A stepped-down node must not overwrite its active=false row from a
    // still-armed tick. Treat it as "lease not held" so the caller takes the
    // same step-down path instead of resurrecting the node.
    if (inactiveMarked) return false;
    await ensureTable();
    if (!leaseTableReady) {
        try { await ensureLeaseTable(); } catch (_) { /* handled below */ }
    }

    let guildCount = null;
    let memberCount = null;
    if (statsProvider) {
        try {
            const stats = await statsProvider();
            if (stats && Number.isFinite(Number(stats.guildCount))) guildCount = Number(stats.guildCount);
            if (stats && Number.isFinite(Number(stats.memberCount))) memberCount = Number(stats.memberCount);
        } catch (err) {
            console.warn('[FAILOVER] stats provider failed (heartbeat continues):', err.message);
        }
    }

    const intervalMs = currentHeartbeatIntervalMs();
    const result = await seasonDb.execute(sql`
        WITH hb AS (
            INSERT INTO bot_node_status (role, node_name, last_heartbeat, active, guild_count, member_count, heartbeat_interval_ms)
            VALUES (${role}, ${NODE_NAME}, NOW(), true, ${guildCount}, ${memberCount}, ${intervalMs})
            ON CONFLICT (role) DO UPDATE SET
                node_name = EXCLUDED.node_name,
                last_heartbeat = NOW(),
                active = EXCLUDED.active,
                guild_count = EXCLUDED.guild_count,
                member_count = EXCLUDED.member_count,
                heartbeat_interval_ms = EXCLUDED.heartbeat_interval_ms
            RETURNING 1
        )
        UPDATE bot_failover_lock
        SET last_seen = NOW(), owner_role = ${role}
        WHERE id = 1 AND owner_node_name = ${NODE_NAME}
    `);
    return Number(result?.rowCount || 0) > 0;
}

async function getStatus(role) {
    await ensureTable();
    // Compute heartbeat age using the DATABASE's clock (NOW()), not this
    // process's local clock. The two hosts running this bot are separate
    // physical machines and their system clocks can drift out of sync with
    // each other; comparing a remote timestamp against a local Date.now()
    // can make a perfectly fresh heartbeat look stale (or vice versa),
    // causing both nodes to think they should be active at the same time.
    const result = await seasonDb.execute(sql`
        SELECT node_name, last_heartbeat, active, heartbeat_interval_ms,
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
// with a fresh heartbeat AND has a higher priority than selfRole (lower number).
// selfRole is optional; when omitted any other active node is returned.
async function getOtherActiveNode(selfNodeName, selfRole) {
    await ensureTable();
    const result = await seasonDb.execute(sql`
        SELECT role, node_name, last_heartbeat, active,
               EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) * 1000 AS age_ms,
               heartbeat_interval_ms
        FROM bot_node_status
        WHERE active = true AND node_name != ${selfNodeName}
    `);
    const rows = result.rows || result;
    const selfPriority = ROLE_PRIORITY[selfRole] ?? 99;
    for (const row of rows) {
        const ageMs = Number(row.age_ms);
        if (!isHeartbeatFresh(ageMs, row.heartbeat_interval_ms)) continue;
        const otherPriority = ROLE_PRIORITY[row.role] ?? 99;
        // Only return nodes that have HIGHER priority (lower number) than us,
        // so sn2 never steps down because sn3 became active.
        if (selfRole && otherPriority >= selfPriority) continue;
        return { role: row.role, nodeName: row.node_name, ageMs };
    }
    return null;
}

function startHeartbeatLoop(role, onLeaseStolen) {
    stopHeartbeatLoop();
    // A fresh takeover clears any previous step-down so this node may heartbeat
    // active again. stopHeartbeatLoop() above already disarms the old timer.
    inactiveMarked = false;
    console.log(`[FAILOVER] Starting heartbeat loop for role=${role} node=${NODE_NAME} (fast=${HEARTBEAT_INTERVAL_MS}ms idle=${IDLE_HEARTBEAT_INTERVAL_MS}ms)`);
    writeHeartbeat(role, true)
        .then(() => refreshLease(NODE_NAME, role))
        .then(() => console.log(`[FAILOVER] Initial heartbeat written for role=${role} node=${NODE_NAME}`))
        .catch(err => console.error(`[FAILOVER] Heartbeat write failed for ${role}:`, err.message));

    // Self-scheduling tick instead of setInterval: each tick re-reads the
    // activity gate and picks the fast cadence while the bot is in use, or the
    // long idle cadence once it has gone quiet so Neon can suspend. A fixed
    // 30s loop kept the compute endpoint awake 24/7 and spent the whole free
    // allowance on an idle bot — the actual cause of the overage.
    const tick = () => {
        // One combined statement instead of the previous heartbeat-write +
        // lease-refresh pair. If the combined statement ever fails, fall back to
        // the two original calls so failover correctness never depends on the
        // optimisation.
        writeHeartbeatWithLease(role)
            .then(stillHaveLease => {
                if (!stillHaveLease && typeof onLeaseStolen === 'function') {
                    console.warn(`[FAILOVER] Lease no longer held for ${role} (stolen by higher-priority node). Triggering step-down.`);
                    onLeaseStolen();
                }
            })
            .catch(() => {
                writeHeartbeat(role, true)
                    .then(() => refreshLease(NODE_NAME, role))
                    .then(stillHaveLease => {
                        if (!stillHaveLease && typeof onLeaseStolen === 'function') {
                            console.warn(`[FAILOVER] Lease no longer held for ${role} (stolen by higher-priority node). Triggering step-down.`);
                            onLeaseStolen();
                        }
                    })
                    .catch(err => console.error(`[FAILOVER] Heartbeat write failed for ${role}:`, err.message));
            })
            .finally(() => {
                if (!heartbeatTimer) return; // stopped during the write
                heartbeatTimer = setTimeout(tick, currentHeartbeatIntervalMs());
                heartbeatTimer.unref?.();
            });
    };
    heartbeatTimer = setTimeout(tick, HEARTBEAT_INTERVAL_MS);
    heartbeatTimer.unref?.();
}

function stopHeartbeatLoop() {
    if (heartbeatTimer) {
        // The loop is self-scheduling with setTimeout; clearTimeout also clears
        // a timeout handle, and the pending tick checks the handle before
        // rescheduling, so no tick is left armed.
        clearTimeout(heartbeatTimer);
        heartbeatTimer = null;
    }
}

async function markInactive(role) {
    // Disarm the loop and block any further active heartbeat BEFORE writing
    // active=false, so an in-flight tick cannot race past us and flip the row
    // back to true after we have stepped down.
    stopHeartbeatLoop();
    inactiveMarked = true;
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
        const insertResult = await seasonDb.execute(sql`
            INSERT INTO bot_failover_lock (id, owner_node_name, owner_role, acquired_at, last_seen)
            VALUES (1, ${nodeName}, ${role}, NOW(), NOW())
            ON CONFLICT (id) DO NOTHING
        `);
        const inserted = Number(insertResult?.rowCount || 0) > 0;
        if (inserted) {
            console.log(`[FAILOVER] Lease acquired successfully for role=${role} node=${nodeName}`);
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: false };
        }

        const existing = await seasonDb.execute(sql`
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
            await seasonDb.execute(sql`
                UPDATE bot_failover_lock
                SET last_seen = NOW()
                WHERE id = 1 AND owner_node_name = ${nodeName}
            `);
            console.log(`[FAILOVER] Reusing existing lease for role=${role} node=${nodeName}`);
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: false };
        }

        const ageMs = Number(row.age_ms || 0);
        const myPriority    = ROLE_PRIORITY[role]            ?? 99;
        const holderPriority = ROLE_PRIORITY[row.owner_role] ?? 99;

        // Is the CURRENT holder alive? The lease's own `last_seen` is only
        // refreshed by (a) the holder's combined heartbeat+lease statement and
        // (b) the holder's startup acquireLease(). A holder that is mid-startup
        // can leave a lease that looks stale for a few seconds even though its
        // bot_node_status heartbeat is perfectly fresh. Treating that as "stale"
        // is what let a lower-priority node (sn2/sn3) seize the lease from a
        // healthy sn1 that was still booting — the "sn2 and sn3 interact while
        // sn1 is online" symptom. So a holder is considered alive when EITHER
        // its lease is fresh OR it has a fresh heartbeat.
        const holderStatus = await getStatus(row.owner_role);
        const holderHeartbeatFresh = Boolean(holderStatus)
            && holderStatus.active
            && isHeartbeatFresh(Number(holderStatus.age_ms), holderStatus.heartbeat_interval_ms);

        // Higher-priority node always reclaims the lease unconditionally.
        // sn1 > sn2 > sn3.  This makes "set NODE_ROLE=sn1 and restart" the
        // reliable way to promote a host without manual DB edits.
        if (myPriority < holderPriority) {
            await seasonDb.execute(sql`
                UPDATE bot_failover_lock
                SET owner_node_name = ${nodeName}, owner_role = ${role}, acquired_at = NOW(), last_seen = NOW()
                WHERE id = 1
            `);
            // Distinguish a normal "I was offline, lower-priority covered, now I'm back"
            // reclaim from a genuine dual-active conflict where the other node is still fresh.
            // A fresh heartbeat counts as "was covering" even if the lease briefly
            // looked stale (the starting-node race).
            const wasCovering = ageMs < FAILOVER_THRESHOLD_MS || holderHeartbeatFresh;
            if (wasCovering) {
                console.log(`[FAILOVER] ${role} returning — reclaiming lease from ${row.owner_node_name} (role=${row.owner_role}) which was covering while offline (lease age=${Math.round(ageMs / 1000)}s). It will step down shortly.`);
            } else {
                console.warn(`[FAILOVER] ${role} reclaiming stale lease from ${row.owner_node_name} (role=${row.owner_role}, lease age=${Math.round(ageMs / 1000)}s)`);
            }
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: true, wasCovering };
        }

        // Lower-priority node (or equal) only takes over when the holder is not
        // considered alive (stale lease AND no fresh heartbeat). Requiring both
        // closes the race where a healthy starting node (fresh heartbeat,
        // briefly stale lease) was displaced by sn2/sn3.
        if (myPriority >= holderPriority && !isHolderConsideredAlive(ageMs, holderHeartbeatFresh)) {
            await seasonDb.execute(sql`
                UPDATE bot_failover_lock
                SET owner_node_name = ${nodeName}, owner_role = ${role}, acquired_at = NOW(), last_seen = NOW()
                WHERE id = 1
            `);
            console.warn(`[FAILOVER] Lease expired for ${row.owner_node_name}; ${role} taking over as node=${nodeName}`);
            return { acquired: true, ownerNodeName: nodeName, ownerRole: role, stolen: true };
        }

        const why = holderHeartbeatFresh
            ? `holder ${row.owner_node_name} (role=${row.owner_role}) has a fresh heartbeat`
            : `lease held by ${row.owner_node_name}`;
        console.warn(`[FAILOVER] ${why} (lease age=${Math.round(ageMs / 1000)}s); ${role} standing by`);
        return { acquired: false, ownerNodeName: row.owner_node_name, ownerRole: row.owner_role, ageMs };
    } catch (err) {
        console.error('[FAILOVER] Lease acquisition failed:', err.message);
        return { acquired: false, ownerNodeName: null, ownerRole: role, ageMs: Infinity };
    }
}

async function refreshLease(nodeName, role) {
    try {
        await ensureLeaseTable();
        const result = await seasonDb.execute(sql`
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

async function getLease() {
    try {
        await ensureLeaseTable();
        const result = await seasonDb.execute(sql`
            SELECT owner_node_name, owner_role,
                   EXTRACT(EPOCH FROM (NOW() - last_seen)) * 1000 AS age_ms
            FROM bot_failover_lock
            WHERE id = 1
        `);
        const row = (result.rows || result)[0];
        if (!row) return null;
        return { ownerNodeName: row.owner_node_name, ownerRole: row.owner_role, ageMs: Number(row.age_ms) };
    } catch (err) {
        console.error('[FAILOVER] getLease failed:', err.message);
        return null;
    }
}

async function releaseLease(nodeName) {
    try {
        await ensureLeaseTable();
        await seasonDb.execute(sql`
            DELETE FROM bot_failover_lock
            WHERE id = 1 AND owner_node_name = ${nodeName}
        `);
    } catch (err) {
        console.error('[FAILOVER] Lease release failed:', err.message);
    }
}

// Explicit lease transfer. This is the API that was missing from the shardnode
// failover flow. It moves the single-row bot_failover_lock ownership to a new
// bearer (targetNodeName / targetRole) instead of only supporting "acquire" and
// "delete" at the database boundary.
async function transferLease(targetNodeName, targetRole, fromNodeName = null, { force = false } = {}) {
    try {
        await ensureLeaseTable();
        const current = await getLease();
        if (!current) {
            await seasonDb.execute(sql`
                INSERT INTO bot_failover_lock (id, owner_node_name, owner_role, acquired_at, last_seen)
                VALUES (1, ${targetNodeName}, ${targetRole}, NOW(), NOW())
                ON CONFLICT (id) DO UPDATE SET
                    owner_node_name = EXCLUDED.owner_node_name,
                    owner_role = EXCLUDED.owner_role,
                    acquired_at = NOW(),
                    last_seen = NOW()
            `);
            return {
                transferred: true,
                ownerNodeName: targetNodeName,
                ownerRole: targetRole,
                reason: 'created lease row during transfer',
            };
        }

        if (fromNodeName && current.ownerNodeName !== fromNodeName && !force) {
            console.warn(`[FAILOVER] Lease transfer request rejected: current owner is ${current.ownerNodeName} instead of ${fromNodeName}.`);
            return {
                transferred: false,
                ownerNodeName: current.ownerNodeName,
                ownerRole: current.ownerRole,
                ageMs: current.ageMs,
                reason: 'owner mismatch',
            };
        }

        const result = await seasonDb.execute(sql`
            UPDATE bot_failover_lock
            SET owner_node_name = ${targetNodeName}, owner_role = ${targetRole}, acquired_at = NOW(), last_seen = NOW()
            WHERE id = 1
        `);
        const rowCount = Number(result?.rowCount || 0);
        if (rowCount <= 0) {
            return {
                transferred: false,
                ownerNodeName: current.ownerNodeName,
                ownerRole: current.ownerRole,
                ageMs: current.ageMs,
                reason: 'lease row was not updated',
            };
        }

        console.log(`[FAILOVER] Lease transferred from ${current.ownerNodeName} to ${targetNodeName} (${targetRole}).`);
        return {
            transferred: true,
            ownerNodeName: targetNodeName,
            ownerRole: targetRole,
            ageMs: 0,
            reason: 'lease updated',
        };
    } catch (err) {
        console.error('[FAILOVER] Lease transfer failed:', err.message);
        return {
            transferred: false,
            ownerNodeName: null,
            ownerRole: null,
            ageMs: Infinity,
            reason: err.message,
        };
    }
}

// Returns true when the lease is currently held by a DIFFERENT node that has
// HIGHER priority than selfRole (lower ROLE_PRIORITY number).  Used by the
// post-takeover standby monitor so it can step down the moment a higher-priority
// node reclaims the lease — without waiting for that node to write its first
// heartbeat to bot_node_status (which only happens after login).
async function isLeaseHeldByHigherPriority(selfRole, selfNodeName) {
    try {
        const lease = await getLease();
        if (!lease) return false;
        if (lease.ownerNodeName === selfNodeName) return false;
        const myPriority     = ROLE_PRIORITY[selfRole]       ?? 99;
        const holderPriority = ROLE_PRIORITY[lease.ownerRole] ?? 99;
        return holderPriority < myPriority;
    } catch (err) {
        console.error('[FAILOVER] isLeaseHeldByHigherPriority check failed:', err.message);
        return false;
    }
}

module.exports = {
    NODE_ROLE,
    NODE_NAME,
    ROLE_PRIORITY,
    HEARTBEAT_INTERVAL_MS,
    IDLE_HEARTBEAT_INTERVAL_MS,
    currentHeartbeatIntervalMs,
    isHeartbeatFresh,
    isHolderConsideredAlive,
    activityIsIdle,
    FAILOVER_THRESHOLD_MS,
    MONITOR_INTERVAL_MS,
    ensureTable,
    writeHeartbeat,
    writeHeartbeatWithLease,
    setStatsProvider,
    getStatus,
    getPrimaryAgeMs,
    getOtherActiveNode,
    getLease,
    startHeartbeatLoop,
    stopHeartbeatLoop,
    markInactive,
    acquireLease,
    refreshLease,
    releaseLease,
    transferLease,
    isLeaseHeldByHigherPriority,
};
