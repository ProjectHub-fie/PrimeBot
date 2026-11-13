const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

// Node role / health / gateway classification + uptime + incident reporting.
// These are the regressions for the "standby nodes shown as offline/degraded"
// and "NO DATA shown as 100% uptime" bugs. Pure modules only — no DB/network.

const statusWorker = require('../utils/statusWorker');
const monitorPulse = require('../utils/monitorPulse');
const statusView = require('../dashboard/statusView');
const { computeUptime30 } = statusView;

// Build a node pulse the way a real node would.
function pulse(role, over = {}) {
    return {
        role,
        nodeName: `node-${role}`,
        ageMs: 5000,
        processHealth: 'healthy',
        gatewayConnected: true,
        gatewayReady: true,
        shardsTotal: 5,
        shardsReady: 5,
        shardsActive: 5,
        shardIds: [0, 1, 2, 3, 4],
        startedAt: new Date('2026-01-01T00:00:00Z'),
        resource: { pulseIntervalMs: 30000 },
        ...over,
    };
}

// A standby node: online process, but no shards and no gateway.
function standbyPulse(role, over = {}) {
    return pulse(role, {
        nodeName: `node-${role}`,
        gatewayConnected: false,
        gatewayReady: false,
        shardsTotal: 0,
        shardsReady: 0,
        shardsActive: 0,
        shardIds: [],
        ...over,
    });
}

// ── 1. All three nodes online: 3/3 ───────────────────────────────────────────
test('all three nodes online → 3/3 online, 1 active, 2 standby', () => {
    const pulses = [
        pulse('sn1', { nodeName: 'NR0008' }),
        standbyPulse('sn2', { nodeName: 'NU3049' }),
        standbyPulse('sn3', { nodeName: 'NUKN09' }),
    ];
    // The failover lock names the ACTIVE node (sn1).
    const state = statusWorker.evaluateState(pulses, { nodeName: 'NR0008', role: 'sn1' });
    assert.equal(state.nodes.sn1.health, 'online');
    assert.equal(state.nodes.sn1.role, 'active');
    assert.equal(state.nodes.sn2.health, 'online');
    assert.equal(state.nodes.sn2.role, 'standby');
    assert.equal(state.nodes.sn3.health, 'online');
    assert.equal(state.nodes.sn3.role, 'standby');
    assert.equal(state.bot.status, 'operational');
});

// ── 2. Roles: Node 1 active, Nodes 2 & 3 standby ─────────────────────────────
test('roles are taken from the failover lock, not the monitoring worker lease', () => {
    const pulses = [pulse('sn1', { nodeName: 'NR0008' }), standbyPulse('sn2', { nodeName: 'NU3049' })];
    // The failover lock says sn1 is active.
    const state = statusWorker.evaluateState(pulses, { nodeName: 'NR0008', role: 'sn1' });
    assert.equal(state.activeRole, 'sn1');
    assert.equal(state.nodes.sn1.role, 'active');
    assert.equal(state.nodes.sn2.role, 'standby');
});

// ── 3. Standby with no shards is healthy, not degraded ───────────────────────
test('a standby node with no shards is healthy, never degraded', () => {
    const pulses = [pulse('sn1', { nodeName: 'NR0008' }), standbyPulse('sn2', { nodeName: 'NU3049' })];
    const state = statusWorker.evaluateState(pulses, { nodeName: 'NR0008', role: 'sn1' });
    assert.equal(state.nodes.sn2.status, 'operational');
    assert.equal(state.nodes.sn2.health, 'online');
    assert.notEqual(state.nodes.sn2.status, 'degraded');
    assert.notEqual(state.nodes.sn2.status, 'unavailable');
});

// ── 4. Standby with no gateway (unassigned) is healthy, not offline ──────────
test('a standby node with no gateway is ONLINE with gateway not_assigned', () => {
    const pulses = [pulse('sn1', { nodeName: 'NR0008' }), standbyPulse('sn2', { nodeName: 'NU3049' })];
    const state = statusWorker.evaluateState(pulses, { nodeName: 'NR0008', role: 'sn1' });
    assert.equal(state.nodes.sn2.gateway, 'not_assigned');
    assert.equal(state.nodes.sn2.health, 'online');
    assert.notEqual(state.nodes.sn2.status, 'unavailable');
});

// ── 5. Active node disconnected → real failure ───────────────────────────────
test('active node with a disconnected gateway is a real degradation', () => {
    const pulses = [pulse('sn1', { nodeName: 'NR0008', gatewayConnected: false, gatewayReady: false })];
    const state = statusWorker.evaluateState(pulses, { nodeName: 'NR0008', role: 'sn1' });
    assert.equal(state.nodes.sn1.status, 'degraded');
    assert.equal(state.nodes.sn1.gateway, 'disconnected');
    assert.equal(state.gateway.status, 'unavailable');
    assert.equal(state.bot.status, 'degraded');
    assert.notEqual(state.bot.status, 'operational');
});

// ── 6. Standby genuinely offline → redundancy incident, not service outage ───
test('a standby going offline does not take the bot down', () => {
    const pulses = [
        pulse('sn1', { nodeName: 'NR0008' }),
        standbyPulse('sn2', { nodeName: 'NU3049', ageMs: 99999999 }), // offline
    ];
    const state = statusWorker.evaluateState(pulses, { nodeName: 'NR0008', role: 'sn1' });
    assert.equal(state.nodes.sn2.status, 'unavailable');
    assert.equal(state.nodes.sn2.role, 'standby');
    // The active node is fine → the bot is still operational.
    assert.equal(state.bot.status, 'operational');
});

test('standby incidents are labelled as redundancy, severity minor', () => {
    const title = statusWorker.incidentTitle('sn3', 'unavailable', { role: 'standby' });
    assert.match(title, /standby/);
    assert.match(title, /failover capacity/i);
    assert.equal(statusWorker.incidentSeverity('sn3', 'unavailable', { role: 'standby' }), 'minor');
    // An active node outage keeps its normal label/severity.
    assert.equal(statusWorker.incidentTitle('sn1', 'unavailable', { role: 'active' }), 'Shard Node 1 down');
});

// ── 7/8. Repeated missed heartbeats → one incident; recovery resolves it ─────
function stubMonitor() {
    const incidents = [];
    const calls = { create: 0, resolve: 0, observations: [] };
    return {
        incidents, calls,
        async getOpenIncidents() { return incidents.filter(i => i.status !== 'resolved'); },
        async insertObservation(component, status, detail) { calls.observations.push({ component, status, detail }); },
        async createIncident(opts) {
            calls.create++;
            const inc = { id: incidents.length + 1, status: 'investigating', ...opts };
            incidents.push(inc);
            return inc;
        },
        async resolveIncident(id) {
            calls.resolve++;
            const inc = incidents.find(i => i.id === id);
            if (inc) inc.status = 'resolved';
            return inc;
        },
    };
}

test('a repeated standby outage creates exactly one incident', async () => {
    const mon = stubMonitor();
    const comps = { sn3: { status: 'unavailable', role: 'standby' } };
    for (let i = 0; i < 5; i++) await statusWorker.apply(comps, mon);
    assert.equal(mon.calls.create, 1);
    assert.equal(mon.calls.resolve, 0);
});

test('a standby node recovering resolves its incident', async () => {
    const mon = stubMonitor();
    await statusWorker.apply({ sn3: { status: 'unavailable', role: 'standby' } }, mon);
    await statusWorker.apply({ sn3: { status: 'operational', role: 'standby' } }, mon);
    await statusWorker.apply({ sn3: { status: 'operational', role: 'standby' } }, mon);
    assert.equal(mon.calls.resolve, 1);
    assert.equal(mon.incidents[0].status, 'resolved');
});

// ── 9. Missing monitoring history → NO DATA, not 100% ────────────────────────
test('a component with no monitoring history has no uptime (not 100%)', () => {
    const series = Array.from({ length: 30 }, (_, i) => ({
        day: `2026-01-${String(i + 1).padStart(2, '0')}`,
        hasData: false,
        monitoredMs: 0, operationalMs: 0, degradedMs: 0, downtimeMs: 0, maintenanceMs: 0,
        uptime: null, samples: 0,
    }));
    assert.equal(computeUptime30(series), null, 'no data must not fabricate an uptime');
});

test('no_data observations are never recorded (so they cannot count as monitored)', async () => {
    const mon = stubMonitor();
    await statusWorker.apply({ website: { status: 'no_data' }, api: { status: 'no_data' } }, mon);
    assert.equal(mon.calls.observations.length, 0);
    assert.equal(mon.calls.create, 0);
});

test('a partial window is flagged and reports real coverage', () => {
    const series = [];
    for (let i = 0; i < 30; i++) {
        series.push(i === 29
            ? { hasData: true, monitoredMs: 43200000, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 }
            : { hasData: false, monitoredMs: 0, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 });
    }
    const up = computeUptime30(series);
    assert.ok(up);
    assert.equal(up.daysWithData, 1);
    assert.equal(up.partial, true, 'a 12h window inside 30 days is partial');
});

// ── 10. Old heartbeat → stale/offline per configured thresholds ──────────────
test('stale then offline thresholds scale with the node\'s own cadence', () => {
    // Fast node (30s): stale > 90s, offline > 180s.
    assert.equal(statusWorker.classifyNode(pulse('sn1', { ageMs: 60000 }), { isActive: true }).status, 'operational');
    assert.equal(statusWorker.classifyNode(pulse('sn1', { ageMs: 120000 }), { isActive: true }).status, 'stale');
    assert.equal(statusWorker.classifyNode(pulse('sn1', { ageMs: 200000 }), { isActive: true }).status, 'unavailable');
    // Slow standby (5 min cadence): 3 min old is still fine.
    const slow = standbyPulse('sn3', { ageMs: 180000, resource: { pulseIntervalMs: 300000 } });
    assert.equal(statusWorker.classifyNode(slow, { isActive: false }).status, 'operational');
});

test('pulseStaleMs / pulseOfflineMs honour the published interval', () => {
    const fast = { resource: { pulseIntervalMs: 30000 } };
    const slow = { resource: { pulseIntervalMs: 300000 } };
    assert.equal(statusWorker.pulseStaleMs(fast), 90000);
    assert.equal(statusWorker.pulseStaleMs(slow), 900000);
    assert.equal(statusWorker.pulseOfflineMs(fast), 180000);
});

// ── 11. Multiple workers: no duplicate/conflicting records ───────────────────
test('a duplicate pulse for one role resolves to the ACTIVE node, not a stale row', () => {
    // A stale row from a renamed node shadows the live one — the active pulse wins.
    const stale = standbyPulse('sn1', { nodeName: 'OLD-NODE', ageMs: 99999999 });
    const live = pulse('sn1', { nodeName: 'NR0008' });
    const state = statusWorker.evaluateState([stale, live], { nodeName: 'NR0008', role: 'sn1' });
    assert.equal(state.nodes.sn1.health, 'online');
    assert.equal(state.nodes.sn1.role, 'active');
});

// ── 12. Uptime excludes unmonitored periods ──────────────────────────────────
test('uptime denominator only counts monitored time', () => {
    const series = [
        { hasData: true, monitoredMs: 86400000, downtimeMs: 8640000, degradedMs: 0, maintenanceMs: 0 },
        { hasData: false, monitoredMs: 0, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
        { hasData: true, monitoredMs: 86400000, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
    ];
    const up = computeUptime30(series);
    // (24h + 24h) monitored = 48h, 2.4h downtime → 45.6/48 = 95%
    assert.ok(Math.abs(up.pct - 95) < 0.01, `got ${up.pct}`);
    assert.equal(up.daysWithData, 2);
});

// ── Node identity: stable + unique ───────────────────────────────────────────
test('buildPulse reports a stable node identity from nodeFailover', () => {
    const p = monitorPulse.buildPulse({ user: { id: '1' }, ws: { status: 0 }, shards: [{ id: 0, status: 'ready' }] });
    // Falls back to the nodeFailover default name, never the literal 'local'.
    assert.ok(p.nodeName && p.nodeName !== 'local');
    assert.ok(['sn1', 'sn2', 'sn3'].includes(p.role));
    assert.deepEqual(p.shardIds, [0]);
    assert.equal(p.gatewayReady, true);
});

test('a standby (no client) reports no shards and an idle-aware cadence', () => {
    const p = monitorPulse.buildPulse(null);
    assert.equal(p.shardsTotal, 0);
    assert.equal(p.gatewayReady, false);
    assert.equal(p.processHealth, 'running');
    assert.ok(Number(p.resource.pulseIntervalMs) > 0);
});

// ── Infra counters via the server read-model ─────────────────────────────────
test('statusView infra counters are computed from node classifications', () => {
    // Exercise buildInfra indirectly through the exported helper path is not
    // possible, so assert the classification inputs it consumes are correct.
    const pulses = [
        pulse('sn1', { nodeName: 'NR0008' }),
        standbyPulse('sn2', { nodeName: 'NU3049' }),
        standbyPulse('sn3', { nodeName: 'NUKN09' }),
    ];
    const state = statusWorker.evaluateState(pulses, { nodeName: 'NR0008', role: 'sn1' });
    const nodes = ['sn1', 'sn2', 'sn3'].map(k => state.nodes[k]);
    const online = nodes.filter(n => n.health === 'online').length;
    const active = nodes.filter(n => n.role === 'active').length;
    const standby = nodes.filter(n => n.role === 'standby').length;
    const offline = nodes.filter(n => n.health === 'offline').length;
    const unhealthy = nodes.filter(n => !(n.health === 'online' && n.status !== 'degraded')).length;
    assert.equal(online, 3);
    assert.equal(active, 1);
    assert.equal(standby, 2);
    assert.equal(offline, 0);
    assert.equal(unhealthy, 0, 'healthy standby nodes are not unhealthy');
});

// ── Overall status derivation (dashboard/statusView.summarize) ───────────────
function comp(key, status, over = {}) {
    return { key, status, uptime30: null, ...over };
}

test('overall status: a healthy active node + dead standby is NOT a major outage', () => {
    const comps = {
        bot: comp('bot', 'operational'),
        gateway: comp('gateway', 'operational'),
        website: comp('website', 'operational'),
        api: comp('api', 'operational'),
        db: comp('db', 'operational'),
        sn1: comp('sn1', 'operational', { role: 'active' }),
        sn2: comp('sn2', 'unavailable', { role: 'standby' }),
        sn3: comp('sn3', 'operational', { role: 'standby' }),
    };
    const { overall } = statusView.summarize(comps, [{ id: 1 }]);
    assert.equal(overall.key, 'degraded', 'standby outage degrades, never major/critical');
});

test('overall status: service components still drive major/critical', () => {
    const base = () => ({
        bot: comp('bot', 'operational'), gateway: comp('gateway', 'operational'),
        website: comp('website', 'operational'), api: comp('api', 'operational'), db: comp('db', 'operational'),
        sn1: comp('sn1', 'operational', { role: 'active' }),
        sn2: comp('sn2', 'operational', { role: 'standby' }),
        sn3: comp('sn3', 'operational', { role: 'standby' }),
    });
    let c = base(); c.bot = comp('bot', 'unavailable');
    assert.equal(statusView.summarize(c, []).overall.key, 'major');
    c = base(); c.bot = comp('bot', 'unavailable'); c.db = comp('db', 'unavailable');
    assert.equal(statusView.summarize(c, []).overall.key, 'critical');
    c = base(); c.website = comp('website', 'degraded');
    assert.equal(statusView.summarize(c, []).overall.key, 'degraded');
});

test('overall status: everything operational reads All Systems Operational', () => {
    const comps = {
        bot: comp('bot', 'operational'), gateway: comp('gateway', 'operational'),
        website: comp('website', 'operational'), api: comp('api', 'operational'), db: comp('db', 'operational'),
        sn1: comp('sn1', 'operational', { role: 'active' }),
        sn2: comp('sn2', 'operational', { role: 'standby' }),
        sn3: comp('sn3', 'operational', { role: 'standby' }),
    };
    assert.equal(statusView.summarize(comps, []).overall.key, 'operational');
});

test('overall status: no observations at all reads Monitoring Data Unavailable', () => {
    const comps = {
        bot: comp('bot', 'unknown'), gateway: comp('gateway', 'unknown'),
        website: comp('website', 'unknown'), api: comp('api', 'unknown'), db: comp('db', 'unknown'),
        sn1: comp('sn1', 'unknown'), sn2: comp('sn2', 'unknown'), sn3: comp('sn3', 'unknown'),
    };
    assert.equal(statusView.summarize(comps, []).overall.key, 'no_data');
});

test('buildInfra reports real online/active/standby/healthy counts', () => {
    const nodeComps = {
        sn1: { key: 'sn1', role: 'active', health: 'online', status: 'operational', uptime30: { pct: 99.9, monitoredMs: 100, downtimeMs: 0.1 } },
        sn2: { key: 'sn2', role: 'standby', health: 'online', status: 'operational', uptime30: { pct: 100, monitoredMs: 100, downtimeMs: 0 } },
        sn3: { key: 'sn3', role: 'standby', health: 'offline', status: 'unavailable', uptime30: { pct: 90, monitoredMs: 100, downtimeMs: 10 } },
    };
    const infra = statusView.buildInfra(nodeComps);
    assert.equal(infra.total, 3);
    assert.equal(infra.online, 2);
    assert.equal(infra.offline, 1);
    assert.equal(infra.active, 1);
    assert.equal(infra.standby, 2);
    assert.equal(infra.healthy, 2);
    assert.equal(infra.unhealthy, 1);
    assert.equal(infra.mostReliable, 'sn2');
    assert.equal(infra.mostDown, 'sn3');
    // combined = (300 monitored - 10.1 downtime) / 300 = 96.63%
    assert.ok(Math.abs(infra.combinedPct - 96.633) < 0.01, `got ${infra.combinedPct}`);
});
