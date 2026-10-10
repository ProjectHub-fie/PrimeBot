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

test('the idle cadence defaults to the fast liveness cadence', () => {
    // Failover is a liveness guarantee: a standby can only detect a dead active
    // node if the active node keeps publishing a heartbeat on a short, predictable
    // cadence. So the idle cadence must default to the fast one — an idle-but-alive
    // active node still beats every 30s and a standby takes over within ~45s of it
    // actually dying. A long (>=5 min) idle cadence is an explicit opt-in that
    // trades prompt failover for Neon compute savings.
    assert.equal(
        IDLE_HEARTBEAT_INTERVAL_MS,
        HEARTBEAT_INTERVAL_MS,
        'idle cadence must default to the fast cadence so failover stays prompt'
    );
    assert.ok(HEARTBEAT_INTERVAL_MS <= 45000, 'the fast cadence must keep takeover within the 45s threshold');
});

test('a node that published a long idle cadence is only stale after it elapses', () => {
    // If a deployment opts into the slow/idle cadence, staleness scales with the
    // writer's own published interval so a slow writer is not mistaken for dead.
    const idle = 6 * 60 * 1000;
    assert.equal(isHeartbeatFresh(idle, idle), true, 'one full idle period is fresh');
    assert.equal(isHeartbeatFresh(idle + 14000, idle), true, 'still inside the grace margin');
    assert.equal(isHeartbeatFresh(idle + 16000, idle), false, 'past the grace margin is stale');
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

test('currentHeartbeatIntervalMs stays fast when idle by default (failover liveness)', () => {
    // By default the idle cadence equals the fast cadence, so an idle-but-alive
    // active node keeps beating every 30s and a standby can detect its death
    // within ~45s. The activity gate only changes the cadence when a deployment
    // has opted into a longer FAILOVER_IDLE_HEARTBEAT_INTERVAL_MS.
    activityGate.reset();
    assert.equal(currentHeartbeatIntervalMs(), HEARTBEAT_INTERVAL_MS, 'active bot keeps the fast cadence');

    const realNow = Date.now;
    try {
        Date.now = () => realNow() + 10 * 60 * 1000; // 10 minutes of silence
        assert.equal(
            currentHeartbeatIntervalMs(),
            HEARTBEAT_INTERVAL_MS,
            'idle bot still beats fast by default, so failover stays prompt'
        );
    } finally {
        Date.now = realNow;
        activityGate.reset();
    }
});

test('index.js surfaces a throttled "standing by" reason', () => {
    // A standby that is deliberately waiting on a still-"fresh" higher-priority
    // node must say so (throttled), otherwise "sn2 never wakes while sn1 is
    // offline" is invisible in the logs.
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    assert.match(src, /Standing by — higher-priority node/, 'monitor logs why it is standing by');
    assert.match(src, /lastStandbyLogAt/, 'the diagnostic is throttled');
});

test('the post-takeover monitor defaults to the fast step-down cadence', () => {
    // An active-but-idle node must still check quickly whether a higher-priority
    // node reclaimed the lease; backing off to the long idle interval would leave
    // the node interacting with Discord (dual-active) for minutes after sn1
    // returned. The monitor idle interval must therefore default to the fast
    // active interval, not a multi-minute value.
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const m = src.match(/const IDLE_INTERVAL_MS\s*=\s*\n?\s*parseInt\(process\.env\.FAILOVER_MONITOR_IDLE_INTERVAL_MS, 10\)\s*\|\|\s*([^;]+);/);
    assert.ok(m, 'monitor idle interval is parsed from its env var');
    assert.equal(m[1].trim(), 'ACTIVE_INTERVAL', 'monitor idle interval defaults to the fast active interval');
    assert.ok(!/\|\|\s*6\s*\*\s*60\s*\*\s*1000/.test(src), 'index.js no longer defaults the monitor to a 6-minute cadence');
});
