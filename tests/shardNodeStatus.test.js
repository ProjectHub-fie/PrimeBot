/**
 * Shard-node status: online state is reported separately from the active/standby
 * role, and every node keeps its own pulse row.
 *
 * Production symptom: the Stats page showed the two standby nodes as offline /
 * degraded while all three nodes were healthy. Two causes, both covered here:
 *
 *   1. `monitor_node_pulse` was keyed on `node_name` alone. Hosting panels give
 *      every node the SAME NODE_NAME (production: all three report
 *      "CloudeWave"), so all three upserted ONE row and overwrote each other —
 *      only whichever wrote last was visible and the other two had no data.
 *      The row is now keyed by (node_name, role).
 *   2. Node classification could judge a node by the shared name (every node
 *      matched the lease's activeNodeId and read as "active") and treat a
 *      standby's absent gateway / zero shards as a fault. The lease ROLE now
 *      decides who is active, and only the ACTIVE node is judged by its
 *      gateway.
 *
 * Pure (no DB, no network): the DB path is driven through a fake pool that
 * models the conflict target the real SQL uses.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const statusWorker = require('../utils/statusWorker');
const monitorPulse = require('../utils/monitorPulse');

// ── Pulse fixtures ───────────────────────────────────────────────────────────
// The production shape: every host reports the SAME node name.
const SHARED_NAME = 'CloudeWave';

function nodePulse(role, over = {}) {
    return {
        role,
        nodeName: SHARED_NAME,
        nodeId: SHARED_NAME,
        ageMs: 5000,
        processHealth: 'running',
        gatewayConnected: false,
        gatewayReady: false,
        shardsTotal: 0,
        shardsReady: 0,
        shardsActive: 0,
        startedAt: new Date('2026-01-01T00:00:00Z'),
        resource: { pulseIntervalMs: 30000 },
        ...over,
    };
}

const activePulse = (role = 'sn1', over = {}) => nodePulse(role, {
    processHealth: 'healthy',
    gatewayConnected: true,
    gatewayReady: true,
    shardsTotal: 5,
    shardsReady: 5,
    shardsActive: 5,
    ...over,
});

// The failover lease: the name is shared, the ROLE is what identifies the node.
const LEASE = { activeNodeId: SHARED_NAME, activeRole: 'sn1' };

// ── 1. Active + healthy → online + active ────────────────────────────────────
test('active + healthy node is online and labelled active', () => {
    const state = statusWorker.evaluateState([activePulse('sn1')], LEASE);
    const sn1 = state.nodes.sn1;
    assert.equal(sn1.online, true);
    assert.equal(sn1.healthy, true);
    assert.equal(sn1.isActive, true);
    assert.equal(sn1.status, 'operational');
    assert.equal(sn1.statusReason, 'serving');
});

// ── 2. Standby + healthy → online + standby ──────────────────────────────────
test('standby + healthy node is online and labelled standby (no gateway, no shards)', () => {
    const pulses = [activePulse('sn1'), nodePulse('sn2'), nodePulse('sn3')];
    const state = statusWorker.evaluateState(pulses, LEASE);

    for (const role of ['sn2', 'sn3']) {
        const n = state.nodes[role];
        assert.equal(n.online, true, `${role} is online`);
        assert.equal(n.healthy, true, `${role} is healthy`);
        assert.equal(n.isActive, false, `${role} is not the active node`);
        assert.equal(n.status, 'operational', `${role} is operational, not degraded`);
        assert.equal(n.statusReason, 'standby');
        // The absent gateway / zero shards are reported, never treated as faults.
        assert.equal(n.gateway.ready, false);
        assert.equal(n.shards.assigned, 0);
    }

    assert.deepEqual(
        { online: state.fleet.online, healthy: state.fleet.healthy, active: state.fleet.active, standby: state.fleet.standby, offline: state.fleet.offline },
        { online: 3, healthy: 3, active: 1, standby: 2, offline: 0 }
    );
    assert.equal(state.fleet.redundancyIntact, true);
});

// ── 2b. The shared NODE_NAME must not make every node "active" ────────────────
test('the lease ROLE decides the active node when every host shares one NODE_NAME', () => {
    const pulses = [activePulse('sn1'), nodePulse('sn2'), nodePulse('sn3')];
    const state = statusWorker.evaluateState(pulses, LEASE);
    assert.equal(state.nodes.sn1.isActive, true);
    assert.equal(state.nodes.sn2.isActive, false, 'a same-named peer is a standby');
    assert.equal(state.nodes.sn3.isActive, false, 'a same-named peer is a standby');
    assert.equal(state.fleet.active, 1);
    assert.equal(state.fleet.standby, 2);

    // Without a lease role the id fallback still works (legacy leases).
    const legacy = statusWorker.evaluateState(pulses, { holder: SHARED_NAME });
    assert.equal(legacy.nodes.sn1.isActive, true);
});

// ── 3. Unreachable node → offline ────────────────────────────────────────────
test('a node that never reported is "never", and a lapsed heartbeat is offline', () => {
    // No pulse row at all for sn3.
    const missing = statusWorker.evaluateState([activePulse('sn1'), nodePulse('sn2')], LEASE);
    assert.equal(missing.nodes.sn3.online, false);
    assert.equal(missing.nodes.sn3.status, 'never', 'a missing node is no-data, never a made-up outage');
    assert.equal(missing.fleet.unknown, 1);
    assert.equal(missing.fleet.offline, 0);

    // A genuinely unreachable node: heartbeat older than the outage window.
    const down = statusWorker.evaluateState(
        [activePulse('sn1'), nodePulse('sn2'), nodePulse('sn3', { ageMs: 10 * 60 * 1000 })],
        LEASE
    );
    assert.equal(down.nodes.sn3.online, false);
    assert.equal(down.nodes.sn3.status, 'unavailable');
    assert.equal(down.nodes.sn3.statusReason, 'stale');
    assert.equal(down.fleet.offline, 1);
    assert.equal(down.fleet.online, 2);
    // The service itself is unaffected — sn1 still serves.
    assert.equal(down.bot.status, 'operational');
});

// ── 3b. A late heartbeat is stale, not offline ──────────────────────────────
test('a briefly late heartbeat is stale (still online), not offline', () => {
    const state = statusWorker.evaluateState(
        [activePulse('sn1'), nodePulse('sn2'), nodePulse('sn3', { ageMs: 120000 })],
        LEASE
    );
    assert.equal(state.nodes.sn3.online, true);
    assert.equal(state.nodes.sn3.healthy, false);
    assert.equal(state.nodes.sn3.status, 'stale');
    assert.equal(state.fleet.offline, 0);
    assert.equal(state.fleet.stale, 1);
});

// ── 4. Actual health failure → degraded ─────────────────────────────────────
test('an active node with a broken gateway is degraded (online, not offline)', () => {
    const state = statusWorker.evaluateState(
        [activePulse('sn1', { gatewayReady: false, gatewayConnected: true }), nodePulse('sn2'), nodePulse('sn3')],
        LEASE
    );
    assert.equal(state.nodes.sn1.online, true);
    assert.equal(state.nodes.sn1.healthy, false);
    assert.equal(state.nodes.sn1.status, 'degraded');
    assert.equal(state.nodes.sn1.statusReason, 'gateway_not_ready');
    assert.equal(state.fleet.offline, 0);
    assert.equal(state.fleet.online, 3);
});

test('a node whose process reported dead is offline even with a fresh heartbeat', () => {
    const state = statusWorker.evaluateState(
        [activePulse('sn1'), nodePulse('sn2'), nodePulse('sn3', { processHealth: 'dead' })],
        LEASE
    );
    assert.equal(state.nodes.sn3.online, false);
    assert.equal(state.nodes.sn3.status, 'unavailable');
    assert.equal(state.nodes.sn3.statusReason, 'process_dead');
});

// ── 5. The pulse row is keyed by (node_name, role) ───────────────────────────
test('the pulse table is keyed by (node_name, role), never the name alone', () => {
    const src = fs.readFileSync(path.join(ROOT, 'server', 'monitorDb.js'), 'utf8');
    assert.match(src, /CREATE TABLE IF NOT EXISTS monitor_node_pulse[\s\S]*?PRIMARY KEY \(node_name, role\)/);
    assert.match(src, /ON CONFLICT \(node_name, role\) DO UPDATE SET/);
    assert.ok(!/ON CONFLICT \(node_name\) DO/.test(src), 'a name-only conflict target collapses the fleet into one row');
    // Existing deployments are migrated to the composite key.
    assert.match(src, /ADD PRIMARY KEY \(node_name, role\)/);
    assert.match(src, /pk_cols = 'node_name'/);
});

test('three nodes sharing one NODE_NAME keep three independent pulse rows', async () => {
    const seasonDbPath = require.resolve('../server/seasonDb');
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    const seasonDb = require(seasonDbPath);

    // Fake pool that models the upsert exactly as the SQL declares it: the row
    // is matched on whatever the ON CONFLICT target names. A regression back to
    // a name-only key therefore produces ONE row and fails this test.
    const rows = new Map();
    seasonDb.seasonPool = {
        async connect() { return { query: async () => ({ rows: [] }), release() {} }; },
        async query(sql, params) {
            if (/INSERT INTO monitor_node_pulse/i.test(sql)) {
                const composite = /ON CONFLICT \(node_name, role\)/.test(sql);
                const key = composite ? `${params[0]}|${params[2]}` : String(params[0]);
                rows.set(key, {
                    node_name: params[0], node_id: params[1], role: params[2],
                    ts: new Date().toISOString(), age_ms: 0,
                    process_health: params[3], gateway_connected: params[4], gateway_ready: params[5],
                    shards_total: params[6], shards_ready: params[7], shards_active: params[8],
                    pid: params[9], started_at: params[10], resource: params[11], detail: params[12],
                });
                return { rows: [] };
            }
            if (/FROM monitor_node_pulse/i.test(sql)) return { rows: [...rows.values()] };
            return { rows: [] };
        },
    };

    const monitorDb = require('../server/monitorDb');
    const client = { user: {}, ws: { status: 0 }, shards: null };
    for (const role of ['sn1', 'sn2', 'sn3']) {
        process.env.NODE_ROLE = role;
        process.env.NODE_NAME = SHARED_NAME;
        delete require.cache[require.resolve('../utils/nodeIdentity')];
        delete require.cache[require.resolve('../utils/monitorPulse')];
        const pulseModule = require('../utils/monitorPulse');
        const payload = pulseModule.buildPulse(client, { pulseIntervalMs: 30000 });
        await monitorDb.upsertNodePulse(payload);
    }

    const pulses = await monitorDb.getNodePulses();
    assert.equal(pulses.length, 3, 'all three nodes must have their own pulse row');
    assert.deepEqual(pulses.map(p => p.role).sort(), ['sn1', 'sn2', 'sn3']);

    const state = statusWorker.evaluateState(pulses, LEASE);
    assert.deepEqual(
        { online: state.fleet.online, active: state.fleet.active, standby: state.fleet.standby, offline: state.fleet.offline },
        { online: 3, active: 1, standby: 2, offline: 0 }
    );

    delete process.env.NODE_ROLE;
    delete process.env.NODE_NAME;
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    delete require.cache[require.resolve('../utils/nodeIdentity')];
    delete require.cache[require.resolve('../utils/monitorPulse')];
});

// ── 6. Restart detection is per (node_name, role) ────────────────────────────
test('restart detection never compares one role\'s startedAt against another\'s', async () => {
    const recorded = [];
    const fakeMonitor = { async recordNodeRestart(name, role) { recorded.push(`${name}|${role}`); } };
    const workerPath = require.resolve('../utils/statusWorker');
    const cached = require.cache[workerPath];
    // Drive the exported helper with an injected monitorDb by reloading the
    // module with a stubbed dependency (same technique the repo's other
    // monitoring tests use).
    delete require.cache[workerPath];
    const Module = require('node:module');
    const originalLoad = Module._load;
    Module._load = function (request, parent, isMain) {
        if (request === '../server/monitorDb' || request === './monitorDb') return fakeMonitor;
        return originalLoad.call(this, request, parent, isMain);
    };
    let worker;
    try {
        worker = require('../utils/statusWorker');
    } finally {
        Module._load = originalLoad;
    }

    const t1 = new Date('2026-01-01T00:00:00Z');
    const t2 = new Date('2026-01-02T00:00:00Z');
    // First sighting of all three nodes.
    await worker.applyRestartDetection([
        nodePulse('sn1', { startedAt: t2 }), nodePulse('sn2', { startedAt: t1 }), nodePulse('sn3', { startedAt: t1 }),
    ]);
    assert.deepEqual(recorded, [], 'a first sighting is a baseline, not a restart');
    // Only sn3 restarted; the older sn2 baseline must not fire.
    await worker.applyRestartDetection([
        nodePulse('sn1', { startedAt: t2 }), nodePulse('sn2', { startedAt: t1 }), nodePulse('sn3', { startedAt: t2 }),
    ]);
    assert.deepEqual(recorded, [`${SHARED_NAME}|sn3`]);

    delete require.cache[workerPath];
    if (cached) require.cache[workerPath] = cached;
});

// ── 7. Dashboard card: standby is online, never red ──────────────────────────
test('the stats page renders standby nodes as Online with a Standby chip (never offline)', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'dashboard', 'public', 'js', 'status.js'), 'utf8');
    const listeners = {};
    const elements = new Map();
    function makeEl(id) {
        return {
            id, innerHTML: '', dataset: {}, style: {},
            classList: { add() {}, remove() {}, contains() { return false; } },
            addEventListener(type, fn) { (listeners[id] = listeners[id] || {})[type] = fn; },
            querySelector() { return null; },
            querySelectorAll() { return []; },
            setAttribute() {}, getAttribute() { return null; },
        };
    }
    const doc = {
        readyState: 'complete',
        hidden: false,
        addEventListener() {},
        querySelector(sel) {
            if (!elements.has(sel)) elements.set(sel, makeEl(sel));
            return elements.get(sel);
        },
        querySelectorAll() { return []; },
    };
    const series = Array.from({ length: 30 }, (_, i) => ({
        day: `2026-01-${String(i + 1).padStart(2, '0')}`,
        hasData: true, dataStatus: 'complete', uptime: 100,
        downtimeMs: 0, degradedMs: 0, maintenanceMs: 0, monitoredMs: 86400000, coverage: 1,
    }));
    const node = (role, extra) => ({
        key: role, label: `Shard Node ${role.slice(2)}`, status: extra.status,
        uptime30: { pct: 100 }, series, lastObservedAt: new Date().toISOString(),
        // Exactly the shape dashboard/statusView.js emits for a node — note it
        // carries online/healthy/statusReason, NOT a status of its own.
        node: {
            role, nodeId: SHARED_NAME, isActive: extra.isActive, online: extra.online,
            healthy: extra.healthy, statusReason: extra.reason,
            process: { health: 'healthy', uptimeSeconds: 100 },
            heartbeat: { fresh: extra.online, stale: extra.reason === 'stale', ageMs: 5000, intervalMs: 30000 },
            gateway: { ready: !!extra.gateway, connected: !!extra.gateway },
            shards: { assigned: extra.shards || 0, ready: extra.shards || 0, active: extra.shards || 0, status: extra.shards ? 'all' : 'none' },
        },
    });
    const summary = {
        overall: { key: 'operational', label: 'All Systems Operational' },
        openIncidents: 0,
        lastCheckedAt: new Date().toISOString(),
        fleet: { online: 2, healthy: 2, active: 1, standby: 1, offline: 1, stale: 0, unknown: 0, total: 3 },
        components: [
            { key: 'bot', label: 'PrimeBot Bot', status: 'operational', uptime30: { pct: 100 }, series, lastObservedAt: new Date().toISOString() },
            node('sn1', { status: 'operational', isActive: true, online: true, healthy: true, gateway: true, shards: 5, reason: 'serving' }),
            node('sn2', { status: 'operational', isActive: false, online: true, healthy: true, gateway: false, shards: 0, reason: 'standby' }),
            node('sn3', { status: 'unavailable', isActive: false, online: false, healthy: false, gateway: false, shards: 0, reason: 'stale' }),
        ],
        activeIncidents: [], resolvedIncidents: [], measurement: { intervalMs: 60000 },
    };

    const ctx = {
        window: {},
        document: doc,
        fetch: async () => ({ ok: true, json: async () => summary }),
        setTimeout, clearTimeout,
        console, Date, Math, JSON, Number, Array, Object, String,
        location: { href: '' },
    };
    ctx.window.document = doc;
    ctx.window.fetch = ctx.fetch;
    vm.createContext(ctx);
    vm.runInContext(src, ctx);

    await new Promise(resolve => setTimeout(resolve, 30));
    const html = elements.get('#status-result').innerHTML;
    const cardOf = key => {
        const start = html.indexOf(`data-component="${key}"`);
        assert.ok(start > -1, `${key} card rendered`);
        const next = html.indexOf('data-component="', start + 1);
        return html.slice(start, next === -1 ? undefined : next);
    };

    const sn1 = cardOf('sn1');
    assert.match(sn1, /pill-ok[^>]*>Online/, 'the active node reads Online');
    assert.match(sn1, /role-active[^>]*>Active/);
    assert.ok(!/dot-down/.test(sn1) && !/pill-down/.test(sn1), 'an active node is never red');

    const sn2 = cardOf('sn2');
    assert.match(sn2, /pill-standby[^>]*>Online/, 'a healthy standby reads Online');
    assert.match(sn2, /role-standby[^>]*>Standby/);
    assert.ok(!/dot-down/.test(sn2), 'a healthy standby is never red');
    assert.ok(!/pill-down/.test(sn2), 'a healthy standby is never "Outage"');
    assert.match(sn2, /Gateway idle \(standby\)/);

    const sn3 = cardOf('sn3');
    assert.match(sn3, /pill-down[^>]*>Offline/, 'a genuinely unreachable node reads Offline');
    assert.match(sn3, /dot-down/);
});

// ── 8. Fleet summary from the API's own summarizer ───────────────────────────
test('statusView.summarize keeps a healthy standby fleet "operational" and flags a real outage', () => {
    const statusView = require('../dashboard/statusView');
    const componentsFor = (pulses) => {
        const state = statusWorker.evaluateState(pulses, LEASE);
        return {
            bot: { status: state.bot.status },
            gateway: { status: state.gateway.status },
            sn1: { status: state.nodes.sn1.status },
            sn2: { status: state.nodes.sn2.status },
            sn3: { status: state.nodes.sn3.status },
        };
    };

    const healthy = statusView.summarize(componentsFor([activePulse('sn1'), nodePulse('sn2'), nodePulse('sn3')]), []);
    assert.equal(healthy.overall.key, 'operational', 'two standbys are normal redundancy, not a degradation');

    const oneDown = statusView.summarize(
        componentsFor([activePulse('sn1'), nodePulse('sn2'), nodePulse('sn3', { ageMs: 10 * 60 * 1000 })]),
        []
    );
    assert.equal(oneDown.overall.key, 'degraded', 'a genuinely unreachable node still reduces redundancy');
    assert.match(oneDown.overall.label, /Redundancy Reduced/);
});
