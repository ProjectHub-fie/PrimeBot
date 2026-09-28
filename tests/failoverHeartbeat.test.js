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

const nodeFailover = require('../utils/nodeFailover');
const activityGate = require('../utils/activityGate');
const { HEARTBEAT_INTERVAL_MS, IDLE_HEARTBEAT_INTERVAL_MS, isHeartbeatFresh, currentHeartbeatIntervalMs } = nodeFailover;

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
