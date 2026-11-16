/**
 * Regression tests for the false-positive OUTAGE reporting.
 *
 * Production reported "Shard Node 1: OUTAGE" and "PrimeBot service: OUTAGE"
 * while the node was running and the bot was operational. Two independent
 * causes, both pinned here:
 *
 *   ROOT CAUSE A (the actual production bug) — the steady-state failover tick
 *   (`nodeFailover.writeHeartbeatWithLease`) never published the status pulse.
 *   Only the boot/fallback `writeHeartbeat()` called `writePulse()`, so the
 *   active node wrote its `monitor_node_pulse` row once at boot and then went
 *   silent. After ~3 missed beats the worker classified the still-running node
 *   as `unavailable` → a false node + service OUTAGE.
 *
 *   ROOT CAUSE B (classification) — a late heartbeat was treated as a CONFIRMED
 *   outage immediately, and a standby node failure (or an unmeasurable
 *   component) could push the SERVICE banner into an outage.
 *
 * The tests below cover the eleven required scenarios. Pure / fake-pool only —
 * no real database, no network.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const statusWorker = require('../utils/statusWorker');
const { summarize } = require('../dashboard/statusView');

// ── helpers ──────────────────────────────────────────────────────────────────

function pulse(role, over = {}) {
    const base = {
        role,
        nodeName: `node-${role}`,
        nodeId: `node-${role}`,
        ageMs: 5000,
        processHealth: 'running',
        gatewayConnected: false,
        gatewayReady: false,
        shardsTotal: 0,
        shardsReady: 0,
        shardsActive: 0,
        startedAt: new Date('2025-01-01T00:00:00Z'),
        resource: { pulseIntervalMs: 30000 },
    };
    return { ...base, ...over };
}

const activeNode = (role, over = {}) => pulse(role, {
    processHealth: 'healthy', gatewayConnected: true, gatewayReady: true,
    shardsTotal: 5, shardsReady: 5, shardsActive: 5, ...over,
});

const NAMES = { sn1: 'NR0008', sn2: 'NU3049', sn3: 'NUKN09' };
const leaseFor = (role) => ({ activeNodeId: NAMES[role], activeRole: role });

// ── ROOT CAUSE A: the steady-state heartbeat publishes the pulse ─────────────

test('ROOT CAUSE A: the steady-state failover tick publishes the monitoring pulse', async () => {
    // Static guard: writeHeartbeatWithLease must call writePulse(). Without it
    // the active node's pulse goes stale after ~90s and the dashboard shows a
    // false OUTAGE for a perfectly healthy node.
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils', 'nodeFailover.js'), 'utf8');
    const body = src.match(/async function writeHeartbeatWithLease\(role\)\s*\{[\s\S]*?\n\}/)[0];
    assert.match(body, /await writePulse\(\)/, 'the steady-state tick must publish the pulse');
});

test('ROOT CAUSE A (behaviour): writeHeartbeatWithLease invokes the pulse provider', async () => {
    // Drive the real module against a fake season pool so no DB is contacted.
    const seasonDbPath = require.resolve('../server/seasonDb');
    const failoverPath = require.resolve('../utils/nodeFailover');
    const monitorPath = require.resolve('../server/monitorDb');
    const saved = { seasonDb: require.cache[seasonDbPath], failover: require.cache[failoverPath], monitor: require.cache[monitorPath] };
    try {
        delete require.cache[seasonDbPath];
        delete require.cache[failoverPath];
        delete require.cache[monitorPath];
        const seasonDb = require(seasonDbPath);
        seasonDb.seasonDb.execute = async () => ({ rowCount: 1, rows: [{ '?column?': 1 }] });

        let pulseWrites = 0;
        const monitorDb = require(monitorPath);
        monitorDb.upsertNodePulse = async () => { pulseWrites++; };

        const nodeFailover = require(failoverPath);
        nodeFailover.setPulseProvider(() => ({ nodeName: 'NR0008', resource: {} }));

        // The steady-state tick (the one the heartbeat loop runs every 30s).
        await nodeFailover.writeHeartbeatWithLease('sn1');
        assert.equal(pulseWrites, 1, 'the steady-state tick wrote exactly one pulse');
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            const p = k === 'seasonDb' ? seasonDbPath : k === 'failover' ? failoverPath : monitorPath;
            if (v) require.cache[p] = v; else delete require.cache[p];
        }
    }
});

// ── 1. Running node with a successful heartbeat ──────────────────────────────

test('1: a running node with a successful heartbeat is operational (never outage)', () => {
    const state = statusWorker.evaluateState([activeNode('sn1', { nodeName: NAMES.sn1 })], leaseFor('sn1'));
    assert.equal(state.nodes.sn1.status, 'operational');
    assert.equal(state.nodes.sn1.online, true);
    assert.equal(state.bot.status, 'operational');
    assert.equal(state.fleet.online, 1);
    assert.equal(state.fleet.offline, 0);
});

// ── 2. Running node with a delayed heartbeat ─────────────────────────────────

test('2: a delayed heartbeat is STALE, not a confirmed outage', () => {
    const state = statusWorker.evaluateState([activeNode('sn1', { nodeName: NAMES.sn1, ageMs: 100000 })], leaseFor('sn1'));
    assert.equal(state.nodes.sn1.status, 'stale');
    assert.equal(state.nodes.sn1.online, true, 'still online');
    assert.notEqual(state.nodes.sn1.status, 'unavailable');
    // The service is not declared down from a single late beat.
    assert.notEqual(state.bot.status, 'unavailable');
    assert.equal(state.fleet.offline, 0, 'a stale node is not counted offline');
    assert.equal(state.fleet.stale, 1);
});

// ── 3. Temporary database failure ────────────────────────────────────────────

test('3: a temporary database failure (pulse unreadable) does not fabricate an outage', () => {
    // A monitoring query returning incomplete data is modelled as an empty
    // pulse set: the nodes are UNKNOWN, never fabricated as down.
    const state = statusWorker.evaluateState([], { activeNodeId: null });
    assert.equal(state.nodes.sn1.status, 'never');
    assert.equal(state.fleet.unknown, 3);
    assert.equal(state.fleet.offline, 0, 'unknown is not offline');
    assert.equal(state.bot.status, 'never', 'insufficient data, not an outage');
});

// ── 4. All three nodes running with two standby ──────────────────────────────

test('4: one active + two healthy standbys → healthy service, 3/3 online, 0 offline', () => {
    const pulses = [
        activeNode('sn1', { nodeName: NAMES.sn1 }),
        pulse('sn2', { nodeName: NAMES.sn2 }),
        pulse('sn3', { nodeName: NAMES.sn3 }),
    ];
    const state = statusWorker.evaluateState(pulses, leaseFor('sn1'));
    assert.equal(state.bot.status, 'operational');
    assert.equal(state.fleet.online, 3);
    assert.equal(state.fleet.healthy, 3);
    assert.equal(state.fleet.active, 1);
    assert.equal(state.fleet.standby, 2);
    assert.equal(state.fleet.offline, 0);
    assert.equal(state.fleet.redundancyIntact, true);
    assert.equal(state.nodes.sn1.isActive, true);
    assert.equal(state.nodes.sn2.isActive, false);
    assert.equal(state.nodes.sn3.isActive, false);
});

// ── 5. PrimeBot operational while one standby node fails ─────────────────────

test('5: a standby node failing reduces redundancy but never declares the service down', () => {
    const pulses = [
        activeNode('sn1', { nodeName: NAMES.sn1 }),
        pulse('sn2', { nodeName: NAMES.sn2 }),
        pulse('sn3', { nodeName: NAMES.sn3, ageMs: 999999 }),
    ];
    const state = statusWorker.evaluateState(pulses, leaseFor('sn1'));
    assert.equal(state.nodes.sn3.status, 'unavailable');
    assert.equal(state.fleet.offline, 1);
    assert.equal(state.fleet.online, 2);
    assert.equal(state.fleet.redundancyIntact, false);
    // The SERVICE is still available — the active node serves Discord.
    assert.equal(state.bot.status, 'operational');

    // And the overall banner is a partial degradation, never a service outage.
    const components = {
        bot: { status: 'operational' },
        website: { status: 'operational' },
        api: { status: 'operational' },
        db: { status: 'operational' },
        gateway: { status: 'operational' },
        sn1: { status: 'operational' },
        sn2: { status: 'operational' },
        sn3: { status: 'unavailable' },
    };
    const { overall } = summarize(components, []);
    assert.equal(overall.key, 'degraded', 'standby failure = redundancy reduced, not outage');
    assert.notEqual(overall.key, 'major');
    assert.notEqual(overall.key, 'critical');
});

// ── 6. Actual active shard failure ───────────────────────────────────────────

test('6: a genuine active-node failure is a real service outage', () => {
    const pulses = [
        activeNode('sn1', { nodeName: NAMES.sn1, ageMs: 999999 }),
        pulse('sn2', { nodeName: NAMES.sn2 }),
        pulse('sn3', { nodeName: NAMES.sn3 }),
    ];
    const state = statusWorker.evaluateState(pulses, leaseFor('sn1'));
    assert.equal(state.nodes.sn1.status, 'unavailable');
    assert.equal(state.fleet.active, 0);
    // The bot is NOT operational — this is a real outage, surfaced honestly.
    assert.notEqual(state.bot.status, 'operational');

    const components = {
        bot: { status: 'unavailable' },
        website: { status: 'operational' },
        api: { status: 'operational' },
        db: { status: 'operational' },
        gateway: { status: 'unavailable' },
        sn1: { status: 'unavailable' },
        sn2: { status: 'operational' },
        sn3: { status: 'operational' },
    };
    const { overall } = summarize(components, []);
    assert.ok(['major', 'critical'].includes(overall.key), `expected an outage banner, got ${overall.key}`);
});

// ── 7. Actual Discord Gateway disconnection ──────────────────────────────────

test('7: a real gateway disconnection degrades the service (not stale/unknown)', () => {
    const pulses = [activeNode('sn1', { nodeName: NAMES.sn1, gatewayConnected: false, gatewayReady: false })];
    const state = statusWorker.evaluateState(pulses, leaseFor('sn1'));
    assert.equal(state.nodes.sn1.status, 'degraded');
    assert.equal(state.nodes.sn1.statusReason, 'gateway_not_ready');
    assert.equal(state.gateway.status, 'unavailable');
    assert.equal(state.bot.status, 'degraded');
});

// ── 8. Monitoring endpoint unavailable ───────────────────────────────────────

test('8: a monitoring endpoint that returns nothing is UNKNOWN, never OUTAGE', () => {
    const state = statusWorker.evaluateState([], { activeNodeId: null });
    assert.equal(state.bot.status, 'never');
    const { overall } = summarize({ bot: { status: 'never' }, website: { status: 'unknown' } }, []);
    assert.equal(overall.key, 'no_data', 'insufficient monitoring info is not an outage');
});

// ── 9. Recovery after an actual outage ───────────────────────────────────────

test('9: recovery after a real outage', () => {
    const down = statusWorker.evaluateState([activeNode('sn1', { nodeName: NAMES.sn1, ageMs: 999999 })], leaseFor('sn1'));
    assert.equal(down.bot.status, 'unavailable');
    const up = statusWorker.evaluateState([activeNode('sn1', { nodeName: NAMES.sn1, ageMs: 4000 })], leaseFor('sn1'));
    assert.equal(up.bot.status, 'operational');
    assert.equal(up.nodes.sn1.status, 'operational');
});

// ── 10. Stale cached status ──────────────────────────────────────────────────

test('10: stale monitoring data surfaces as STALE and never as an outage', () => {
    // A node whose last pulse is well past the healthy window but not yet
    // confirmed dead.
    const state = statusWorker.evaluateState([activeNode('sn1', { nodeName: NAMES.sn1, ageMs: 120000 })], leaseFor('sn1'));
    assert.equal(state.nodes.sn1.status, 'stale');
    assert.equal(state.gateway.status, 'stale', 'a stale active node yields a stale gateway reading');
    assert.equal(state.bot.status, 'stale', 'the service reports stale, not outage');
    assert.notEqual(state.bot.status, 'unavailable');

    // And the overall banner must not become an outage because of it.
    const { overall } = summarize({
        bot: { status: 'stale' },
        website: { status: 'operational' },
        api: { status: 'operational' },
        db: { status: 'operational' },
        gateway: { status: 'stale' },
        sn1: { status: 'stale' },
    }, []);
    assert.equal(overall.key, 'operational');
});

test('10b: a STALE component never opens an outage incident', async () => {
    const incidents = [];
    let creates = 0;
    const mon = {
        async getOpenIncidents() { return incidents.filter(i => i.status !== 'resolved'); },
        async insertObservation() {},
        async createIncident(o) { creates++; const inc = { id: incidents.length + 1, status: 'investigating', ...o }; incidents.push(inc); return inc; },
        async resolveIncident() { return null; },
        async updateIncident() { return null; },
    };
    for (let i = 0; i < 5; i++) await statusWorker.apply({ sn1: { status: 'stale', detail: {} } }, mon);
    assert.equal(creates, 0, 'stale data must never page anyone');
});

// ── 11. Conflicting monitoring worker updates ────────────────────────────────

test('11: conflicting worker updates cannot double-count or duplicate an incident', async () => {
    // Two ticks disagreeing (one sees stale, one sees unavailable) must not
    // produce two incidents for the same continuous problem, and the stale tick
    // must not create one at all.
    const incidents = [];
    let creates = 0;
    const mon = {
        async getOpenIncidents() { return incidents.filter(i => i.status !== 'resolved'); },
        async insertObservation() {},
        async createIncident(o) { creates++; const inc = { id: incidents.length + 1, status: 'investigating', ...o }; incidents.push(inc); return inc; },
        async resolveIncident() { return null; },
        async updateIncident() { return null; },
    };
    await statusWorker.apply({ sn1: { status: 'stale' } }, mon);
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    assert.equal(creates, 1, 'exactly one incident for the continuous outage');

    // Only one worker holds the lease at a time (atomic DB claim) — a second
    // worker can never run concurrently and fight over the same component.
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'monitorDb.js'), 'utf8');
    assert.match(src, /acquireWorkerLease/, 'worker coordination is lease-based');
    assert.match(src, /lease_expires_at < NOW\(\) OR monitor_worker\.holder = EXCLUDED\.holder/,
        'the lease claim is atomic and only steals an expired lease');
});

// ── The exact production expectation ─────────────────────────────────────────

test('the expected production shape: HEALTHY service, sn1 active, sn2/sn3 standby, 3/3 online, 0/3 offline', () => {
    const pulses = [
        activeNode('sn1', { nodeName: NAMES.sn1 }),
        pulse('sn2', { nodeName: NAMES.sn2 }),
        pulse('sn3', { nodeName: NAMES.sn3 }),
    ];
    const state = statusWorker.evaluateState(pulses, leaseFor('sn1'));
    assert.deepEqual(
        {
            service: state.bot.status,
            sn1: state.nodes.sn1.status,
            sn2: state.nodes.sn2.status,
            sn3: state.nodes.sn3.status,
            online: state.fleet.online,
            offline: state.fleet.offline,
        },
        { service: 'operational', sn1: 'operational', sn2: 'operational', sn3: 'operational', online: 3, offline: 0 }
    );
    // Standby nodes are never penalised for having no gateway / no shards.
    assert.equal(state.nodes.sn2.gateway.ready, false);
    assert.equal(state.nodes.sn2.shards.assigned, 0);
    assert.equal(state.nodes.sn2.online, true);
    assert.equal(state.nodes.sn2.healthy, true);
});
