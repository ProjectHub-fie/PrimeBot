// Tests for the activity-adaptive failover heartbeat thresholds.
//
// The heartbeat itself needs a live database, so it is not exercised here.
// What is pinned is the pure decision logic that keeps failover correct once
// the heartbeat slows down: a node that has dropped to its long idle cadence
// must still count as alive to a peer running the fast cadence. A single fixed
// 45s threshold would have a fast peer declare a sleeping node dead and trigger
// a spurious takeover, so staleness is judged against the interval each writer
// publishes on its heartbeat row.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const nodeFailover = require('../utils/nodeFailover');
const activityGate = require('../utils/activityGate');
const { HEARTBEAT_INTERVAL_MS, IDLE_HEARTBEAT_INTERVAL_MS, isHeartbeatFresh, currentHeartbeatIntervalMs } = nodeFailover;

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'utils', 'nodeFailover.js'), 'utf8');

test('the idle cadence is longer than Neon\'s suspend window', () => {
    // If the idle heartbeat were under ~5 minutes it would wake the endpoint
    // before Neon could suspend, which is the whole point of the change.
    assert.ok(IDLE_HEARTBEAT_INTERVAL_MS > 5 * 60 * 1000, 'idle heartbeat must clear the 5-minute suspend window');
    assert.ok(IDLE_HEARTBEAT_INTERVAL_MS > HEARTBEAT_INTERVAL_MS);
});

test('a fast node is judged stale at the original 45s grace', () => {
    // The old code treated age > 45000 as stale for the 30s heartbeat; keep that
    // exact boundary for a fast writer.
    const interval = HEARTBEAT_INTERVAL_MS; // 30s
    assert.equal(isHeartbeatFresh(40000, interval), true, '40s on a 30s writer is fresh');
    assert.equal(isHeartbeatFresh(72000, interval), false, '72s on a 30s writer is stale');
    assert.equal(isHeartbeatFresh(44999, interval), true);
    assert.equal(isHeartbeatFresh(45001, interval), false);
});

test('a node on the idle cadence is not mistaken for dead by a fast peer', () => {
    // The idle writer beats every IDLE_HEARTBEAT_INTERVAL_MS; a peer must wait
    // one interval + the same 15s grace before calling it stale.
    const idle = IDLE_HEARTBEAT_INTERVAL_MS; // 6 min
    assert.equal(isHeartbeatFresh(idle, idle), true, 'one full idle period is fresh');
    assert.equal(isHeartbeatFresh(idle + 14000, idle), true, 'still inside the grace margin');
    assert.equal(isHeartbeatFresh(idle + 16000, idle), false, 'past the grace margin is stale');
});

test('a missing/legacy interval column falls back to the fast assumption', () => {
    // Rows written before heartbeat_interval_ms existed have null here; treating
    // them as a fast writer preserves the exact old behaviour.
    assert.equal(isHeartbeatFresh(40000, null), true);
    assert.equal(isHeartbeatFresh(70000, null), false);
});

test('a holder with a fresh heartbeat is never considered dead (sn1-startup race)', () => {
    // A starting node has a fresh heartbeat but the lease can briefly look stale
    // before its combined heartbeat+lease statement runs. A lower-priority peer
    // must not take over.
    assert.equal(nodeFailover.isHolderConsideredAlive(60000, true), true, 'fresh heartbeat keeps the holder alive');
    assert.equal(nodeFailover.isHolderConsideredAlive(60000, false), false, 'stale lease + no heartbeat = dead');
    assert.equal(nodeFailover.isHolderConsideredAlive(10000, false), true, 'fresh lease alone is enough');
});

test('the lower-priority takeover requires the holder to be dead', () => {
    // Static guard: sn2/sn3 must not seize while the holder has a fresh heartbeat,
    // and must consult the shared helper rather than only the lease age.
    assert.ok(
        /isHolderConsideredAlive\(ageMs, holderHeartbeatFresh\)/.test(SOURCE),
        'takeover must use the lease-or-heartbeat liveness check'
    );
});

test('markInactive disarms the heartbeat before writing active=false', () => {
    // The step-down race (a zombie heartbeat resurrecting a stepped-down node)
    // is closed by setting inactiveMarked and stopping the loop before the write.
    const body = SOURCE.match(/async function markInactive\(role\)\s*\{[\s\S]*?\n\}/)[0];
    const stopIdx = body.indexOf('stopHeartbeatLoop()');
    const markIdx = body.indexOf('inactiveMarked = true');
    const writeIdx = body.indexOf('writeHeartbeat(role, false)');
    assert.ok(stopIdx !== -1 && markIdx !== -1 && writeIdx !== -1, 'markInactive must stop, flag, then write');
    assert.ok(stopIdx < writeIdx, 'the loop must be stopped before marking inactive');
    assert.ok(markIdx < writeIdx, 'the inactive flag must be set before the write');
});

test('an active heartbeat is refused after step-down', () => {
    assert.ok(
        /if \(active && inactiveMarked\) return;/.test(SOURCE),
        'writeHeartbeat must refuse to resurrect a stepped-down node'
    );
    assert.ok(
        /if \(inactiveMarked\) return false;/.test(SOURCE),
        'writeHeartbeatWithLease must refuse after step-down'
    );
});

test('currentHeartbeatIntervalMs picks fast while busy and idle once quiet', () => {
    activityGate.reset();
    assert.equal(currentHeartbeatIntervalMs(), HEARTBEAT_INTERVAL_MS, 'active bot keeps the fast cadence');

    const realNow = Date.now;
    try {
        Date.now = () => realNow() + 10 * 60 * 1000; // 10 minutes of silence
        assert.equal(currentHeartbeatIntervalMs(), IDLE_HEARTBEAT_INTERVAL_MS, 'idle bot drops to the slow cadence');
    } finally {
        Date.now = realNow;
        activityGate.reset();
    }
});
