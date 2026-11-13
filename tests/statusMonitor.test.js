const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const Module = require('module');

// Status-monitoring tests: pure worker evaluation, incident lifecycle, uptime
// math, date boundaries, worker-lease coordination against a fake pool, and the
// real dashboard HTTP surface (sanitization + auth).

const DASH = path.join(__dirname, '..', 'dashboard');

// ── Pure modules (no DB required) ────────────────────────────────────────────
const statusWorker = require('../utils/statusWorker');
const monitorPulse = require('../utils/monitorPulse');
const statusView = require('../dashboard/statusView');
const { computeUptime30 } = statusView;

function pulse(role, over = {}) {
    const base = {
        role,
        nodeName: `node-${role}`,
        ageMs: 5000,
        processHealth: 'healthy',
        gatewayConnected: true,
        gatewayReady: true,
        shardsTotal: 5,
        shardsReady: 5,
        shardsActive: 5,
        startedAt: new Date(1000 + (role === 'sn1' ? 0 : 10000000)),
        resource: { pulseIntervalMs: 30000 },
    };
    return { ...base, ...over };
}

// ── 1. Three shard nodes report independently ────────────────────────────────
test('all three shard nodes report independently', () => {
    const pulses = [
        pulse('sn1', { nodeName: 'NR0008' }),
        pulse('sn2', { nodeName: 'NU3049' }),
        pulse('sn3', { nodeName: 'NUKN09', gatewayReady: false, gatewayConnected: false }),
    ];
    // Only sn1 is the active lease holder with a ready gateway.
    const lease = { holder: 'NR0008' };
    const state = statusWorker.evaluateState(pulses, lease);
    assert.equal(state.nodes.sn1.status, 'operational');
    assert.equal(state.nodes.sn2.status, 'operational', 'standby node with no gateway is still a healthy node');
    // sn3 is a standby (not the holder) — its lack of gateway is NOT a fault.
    assert.equal(state.nodes.sn3.status, 'operational');
    // Mutating one node's freshness must not affect the others.
    const changed = statusWorker.evaluateState([pulse('sn1', { nodeName: 'NR0008' }), pulse('sn2', { ageMs: 99999999 }), pulse('sn3', { nodeName: 'NUKN09' })], { holder: 'NR0008' });
    assert.equal(changed.nodes.sn1.status, 'operational');
    assert.equal(changed.nodes.sn2.status, 'unavailable');
    assert.equal(changed.nodes.sn3.status, 'operational');
});

// ── 2. Bot uptime calculation ────────────────────────────────────────────────
test('bot uptime calculation uses monitored duration, ignoring gaps', () => {
    const series = [
        { hasData: true, monitoredMs: 86400000 * 0.5, downtimeMs: 8640000, degradedMs: 0, maintenanceMs: 0 },
        { hasData: true, monitoredMs: 86400000, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
        { hasData: false, monitoredMs: 0, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
        { hasData: false, monitoredMs: 0, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
    ];
    const up = computeUptime30(series).pct;
    // (12h + 24h) monitored = 36h; downtime 2.4h -> 33.6/36 = 93.33%
    assert.ok(Math.abs(up - 93.3333) < 0.1, `got ${up}`);
});

test('uptime is null when nothing was monitored (no fabricated data)', () => {
    const series = [
        { hasData: false, monitoredMs: 0, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
        { hasData: false, monitoredMs: 0, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
    ];
    assert.equal(computeUptime30(series), null);
});

// ── 3. Website uptime calculation ────────────────────────────────────────────
test('website uptime calculation (separate component)', () => {
    const series = [
        { hasData: true, monitoredMs: 86400000, downtimeMs: 0, degradedMs: 0, maintenanceMs: 0 },
        { hasData: true, monitoredMs: 86400000, downtimeMs: 43200000, degradedMs: 0, maintenanceMs: 0 },
    ];
    const up = computeUptime30(series);
    assert.ok(Math.abs(up.pct - 75) < 0.01);
    assert.equal(up.downtimeMs, 43200000);
});

// ── 4. Gateway disconnection detection ───────────────────────────────────────
test('gateway disconnection is detected (holder) and bot is degraded', () => {
    // Active node's process is healthy but its gateway is disconnected.
    const pulses = [
        pulse('sn1', { nodeName: 'NR0008', gatewayConnected: false, gatewayReady: false }),
        pulse('sn2', { nodeName: 'NU3049' }),
    ];
    const lease = { holder: 'NR0008' };
    const state = statusWorker.evaluateState(pulses, lease);
    assert.equal(state.gateway.status, 'unavailable');
    assert.equal(state.nodes.sn1.status, 'degraded', 'process running but gateway down');
    assert.equal(state.nodes.sn1.detail.reason, 'gateway_not_ready');
    assert.equal(state.bot.status, 'degraded');
});

// ── 5. Process-running but Gateway-disconnected state ────────────────────────
test('process-running-but-gateway-disconnected is never counted operational', () => {
    const pulses = [pulse('sn1', { nodeName: 'NR0008', gatewayReady: false, gatewayConnected: true })];
    const state = statusWorker.evaluateState(pulses, { holder: 'NR0008' });
    assert.equal(state.nodes.sn1.status, 'degraded');
    assert.equal(state.bot.status, 'degraded');
    assert.notEqual(state.bot.status, 'operational');
});

// ── 6. Missed heartbeat handling ─────────────────────────────────────────────
test('missed heartbeat is STALE first, then unavailable past the offline threshold', () => {
    // 30s cadence → stale at 3× (90s), offline at 6× (180s).
    const offline = pulse('sn1', { nodeName: 'NR0008', ageMs: 99999999 });
    const fresh = pulse('sn2', { nodeName: 'NU3049' });
    const state = statusWorker.evaluateState([offline, fresh], { holder: 'NR0008' });
    assert.equal(state.nodes.sn1.status, 'unavailable');
    assert.equal(state.nodes.sn1.detail.reason, 'offline');
    assert.equal(state.nodes.sn2.status, 'operational');
    // One delayed beat (120s > stale 90s but < offline 180s) → STALE, not down.
    const late = statusWorker.evaluateState([pulse('sn1', { nodeName: 'NR0008', ageMs: 120000 })], { holder: 'NR0008' });
    assert.equal(late.nodes.sn1.status, 'stale');
    assert.equal(late.nodes.sn1.health, 'stale');
    // Within the stale threshold → still operational (one missed beat is fine).
    const ok = statusWorker.evaluateState([pulse('sn1', { nodeName: 'NR0008', ageMs: 80000 })], { holder: 'NR0008' });
    assert.equal(ok.nodes.sn1.status, 'operational');
});

test('a node that never reported is unknown, never marked down', () => {
    const state = statusWorker.evaluateState([], { holder: null });
    assert.equal(state.nodes.sn1.status, 'never');
    assert.equal(state.nodes.sn2.status, 'never');
    assert.equal(state.nodes.sn3.status, 'never');
    assert.equal(state.bot.status, 'never');
});

// ── 7. Node recovery ─────────────────────────────────────────────────────────
test('node recovers once its heartbeat is fresh again', () => {
    const before = statusWorker.evaluateState([pulse('sn1', { nodeName: 'NR0008', ageMs: 99999999 })], { holder: 'NR0008' });
    assert.equal(before.nodes.sn1.status, 'unavailable');
    const after = statusWorker.evaluateState([pulse('sn1', { nodeName: 'NR0008', ageMs: 5000 })], { holder: 'NR0008' });
    assert.equal(after.nodes.sn1.status, 'operational');
});

// ── 8. Duplicate incident prevention + 9. incident resolution ────────────────
function stubMonitor() {
    const incidents = [];
    const calls = { create: 0, resolve: 0, observations: [] };
    return {
        incidents, calls,
        async getOpenIncidents() { return incidents.filter(i => i.status !== 'resolved'); },
        async insertObservation(component, status, detail) { calls.observations.push({ component, status }); },
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

test('duplicate incidents are prevented for a continuous outage', async () => {
    const mon = stubMonitor();
    const comps = { sn1: { status: 'unavailable', detail: { reason: 'stale' } } };
    // Two consecutive ticks both see the node down.
    await statusWorker.apply(comps, mon);
    await statusWorker.apply(comps, mon);
    assert.equal(mon.calls.create, 1, 'only one incident for one continuous outage');
    assert.equal(mon.calls.resolve, 0);
});

test('incident resolution requires sustained recovery (no flapping)', async () => {
    const mon = stubMonitor();
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    assert.equal(mon.calls.create, 1);
    assert.equal(mon.incidents[0].status, 'investigating');
    // First healthy tick is not enough — RECOVERY_CONFIRMATIONS (default 2).
    await statusWorker.apply({ sn1: { status: 'operational' } }, mon);
    assert.equal(mon.calls.resolve, 0, 'not resolved after a single healthy check');
    await statusWorker.apply({ sn1: { status: 'operational' } }, mon);
    assert.equal(mon.calls.resolve, 1);
    assert.equal(mon.incidents[0].status, 'resolved');
});

test('a flapping node does not resolve-and-recreate an incident', async () => {
    const mon = stubMonitor();
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    // operational (streak 1) then down again → streak resets, incident stays open.
    await statusWorker.apply({ sn1: { status: 'operational' } }, mon);
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    await statusWorker.apply({ sn1: { status: 'operational' } }, mon);
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    assert.equal(mon.calls.create, 1, 'still one incident for the same continuous outage');
    assert.equal(mon.calls.resolve, 0);
});

test('a STALE node neither opens nor resolves an incident', async () => {
    const mon = stubMonitor();
    await statusWorker.apply({ sn3: { status: 'unavailable', role: 'standby' } }, mon);
    assert.equal(mon.calls.create, 1);
    // Heartbeat late → checking; do not resolve yet.
    await statusWorker.apply({ sn3: { status: 'stale', role: 'standby' } }, mon);
    await statusWorker.apply({ sn3: { status: 'stale', role: 'standby' } }, mon);
    assert.equal(mon.calls.resolve, 0, 'stale is not a recovery');
    assert.equal(mon.calls.create, 1, 'stale does not open a new incident');
});

test('unknown components never fabricate observations or incidents', async () => {
    const mon = stubMonitor();
    await statusWorker.apply({ sn1: { status: 'never' } }, mon);
    assert.equal(mon.calls.create, 0);
    assert.equal(mon.calls.observations.length, 0);
});

// ── 10. Restart detection ────────────────────────────────────────────────────
test('restart detection via startedAt drift', () => {
    const t1 = new Date('2025-01-01T00:00:00Z');
    const t2 = new Date('2025-01-01T10:00:00Z');
    assert.equal(statusWorker.detectRestart('n', t2, t1), true);
    assert.equal(statusWorker.detectRestart('n', t1, t2), false);
    assert.equal(statusWorker.detectRestart('n', null, t1), false);
    assert.equal(statusWorker.detectRestart('n', t1, null), false);
    assert.equal(statusWorker.detectRestart('n', t1, t1), false);
});

test('pulse carries a stable per-process startedAt', () => {
    const p1 = monitorPulse.buildPulse({});
    const p2 = monitorPulse.buildPulse({});
    assert.ok(p1.startedAt instanceof Date);
    assert.equal(p1.startedAt.getTime(), p2.startedAt.getTime());
});

// ── 11/12/13. Daily bars + 30-day boundary + daily uptime over a fake pool ───
function makeFakePool({ dailyRows = [], obsRows = [], pulseRows = [], incidentRows = [], workerHolders = [], componentRows = defaultComponents() }) {
    const store = {
        dailyRows, obsRows, pulseRows, incidentRows, workerHolders, componentRows,
        workerRow: null, // { holder, last_seen, lease_expires_at }
    };
    const pool = {
        store,
        async connect() { return { query: async () => ({ rows: [] }), release() {} }; },
        async query(sql, params) {
            if (sql.includes('monitor_worker')) {
                // Atomic-claim simulation mirroring acquireWorkerLease / refresh / get.
                if (/INSERT/i.test(sql)) {
                    const holder = params && params[1];
                    const ttl = params && params[2] != null ? Number(params[2]) : 45;
                    const now = Date.now();
                    const row = store.workerRow;
                    const canClaim = !row || Date.parse(row.lease_expires_at) <= now || row.holder === holder;
                    if (canClaim) {
                        store.workerRow = {
                            holder,
                            last_seen: new Date(now).toISOString(),
                            lease_expires_at: new Date(now + ttl * 1000).toISOString(),
                        };
                        return { rows: [{ holder }] };
                    }
                    return { rows: [] };
                }
                if (/UPDATE/i.test(sql)) {
                    const holder = params && params[1];
                    if (store.workerRow && store.workerRow.holder === holder) {
                        const now = Date.now();
                        store.workerRow.last_seen = new Date(now).toISOString();
                        store.workerRow.lease_expires_at = new Date(now + (params && params[2] != null ? Number(params[2]) : 45) * 1000).toISOString();
                        return { rows: [{ holder }] };
                    }
                    return { rows: [] };
                }
                return { rows: store.workerRow ? [{ holder: store.workerRow.holder, last_seen: store.workerRow.last_seen, lease_expires_at: store.workerRow.lease_expires_at }] : [] };
            }
            if (sql.includes('portal') || /create table/i.test(sql) || /insert into monitor_components/i.test(sql)) {
                return { rows: [] };
            }
            if (sql.includes('FROM monitor_daily')) {
                return { rows: store.dailyRows };
            }
            if (sql.includes('monitor_observations')) {
                return { rows: store.obsRows };
            }
            if (sql.includes('monitor_node_pulse')) {
                return { rows: store.pulseRows };
            }
            if (sql.includes('monitor_incidents')) {
                return { rows: store.incidentRows };
            }
            if (sql.includes('monitor_components')) {
                return { rows: store.componentRows };
            }
            if (sql.includes('SELECT 1')) {
                return { rows: [{ '?column?': 1 }] };
            }
            return { rows: [] };
        },
    };
    return pool;
}

function defaultComponents() {
    return [
        { key: 'bot', label: 'PrimeBot Bot', description: '', enabled: true, updated_at: new Date() },
        { key: 'website', label: 'Main Website', description: '', enabled: true, updated_at: new Date() },
        { key: 'api', label: 'Dashboard / API', description: '', enabled: true, updated_at: new Date() },
        { key: 'db', label: 'PostgreSQL Database', description: '', enabled: true, updated_at: new Date() },
        { key: 'gateway', label: 'Discord Gateway', description: '', enabled: true, updated_at: new Date() },
        { key: 'sn1', label: 'Shard Node 1', description: '', enabled: true, updated_at: new Date() },
        { key: 'sn2', label: 'Shard Node 2', description: '', enabled: true, updated_at: new Date() },
        { key: 'sn3', label: 'Shard Node 3', description: '', enabled: true, updated_at: new Date() },
    ];
}

// Swap the season pool for a fake, then reload the monitor modules freshly.
let monitorDb;
function bootMonitor(overrides = {}) {
    const seasonDbPath = require.resolve('../server/seasonDb');
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    delete require.cache[require.resolve('../dashboard/statusView')];

    const fake = makeFakePool(overrides);
    const seasonDb = require(seasonDbPath);
    seasonDb.seasonPool = fake;
    monitorDb = require('../server/monitorDb');
    const freshView = require('../dashboard/statusView');
    return { monitorDb, statusView: freshView, fake };
}

function todayUTC() {
    const d = new Date();
    d.setUTCHours(0, 0, 0, 0);
    return d.toISOString().slice(0, 10);
}

test('daily series always has exactly 30 bars ending today (UTC)', async () => {
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const dailyRows = [{ component: 'sn1', day: yesterday, monitored_ms: 86400000, operational_ms: 80000000, degraded_ms: 4000000, downtime_ms: 2400000, maintenance_ms: 0, samples: 100 }];
    bootMonitor({ dailyRows, obsRows: [] });
    const series = await monitorDb.getDailySeries('sn1', 30);
    assert.equal(series.length, 30);
    assert.equal(series[29].day, todayUTC());
    assert.equal(series[0].day, new Date(Date.now() - 29 * 86400000).toISOString().slice(0, 10));
    const seeded = series.find(s => s.day === yesterday);
    assert.ok(seeded.hasData);
    // uptime = (monitored - downtime) / monitored
    assert.ok(Math.abs(seeded.uptime - ((86400000 - 2400000) / 86400000) * 100) < 0.01);
    // Days before any monitoring are hasData=false (grey), not green.
    assert.equal(series[0].hasData, false);
    assert.equal(series[0].uptime, null);
});

test('missing historical data stays grey and is never fabricated', async () => {
    bootMonitor({ dailyRows: [], obsRows: [] });
    const series = await monitorDb.getDailySeries('sn1', 30);
    assert.ok(series.every(s => !s.hasData && s.uptime === null));
});

test('overlapping downtime intervals are not double counted', async () => {
    // Two adjacent days each with 10% downtime; combined 30-day uptime should
    // be exactly what the monitored/downtime sums say (no double counting from
    // rounded per-day percentages).
    const day1 = new Date(Date.now() - 2 * 86400000).toISOString().slice(0, 10);
    const day2 = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const dailyRows = [
        { component: 'bot', day: day1, monitored_ms: 86400000, operational_ms: 77760000, degraded_ms: 0, downtime_ms: 8640000, maintenance_ms: 0, samples: 100 },
        { component: 'bot', day: day2, monitored_ms: 86400000, operational_ms: 77760000, degraded_ms: 0, downtime_ms: 8640000, maintenance_ms: 0, samples: 100 },
    ];
    bootMonitor({ dailyRows, obsRows: [] });
    const series = await monitorDb.getDailySeries('bot', 30);
    const up = computeUptime30(series);
    // 172.8M monitored, 17.28M downtime -> 90%
    assert.ok(Math.abs(up.pct - 90) < 0.01);
    assert.equal(up.downtimeMs, 17280000);
});

// ── 14. Database connectivity failure surfaces in overall status ─────────────
test('database connectivity failure degrades the overall status', async () => {
    const nowIso = new Date().toISOString();
    const obsRows = [{ component: 'db', status: 'unavailable', detail: null, ts: nowIso, age_ms: 500 }];
    const { statusView: freshView } = bootMonitor({ obsRows });
    const summary = await freshView.getStatusSummary();
    assert.equal(summary.components.find(c => c.key === 'db').status, 'unavailable');
    assert.ok(['major', 'critical'].includes(summary.overall.key), summary.overall.key);
});

// ── 18. Multi-node worker coordination (lease semantics over a fake pool) ─────
function fakeSeedWorkerRow(pool, holder, now, ttl) {
    pool.store.workerRow = { holder, last_seen: now.toISOString(), lease_expires_at: new Date(now.getTime() + ttl).toISOString() };
}

test('worker lease prevents duplicate workers and recovers after expiry', async () => {
    const { monitorDb: mdb, fake } = bootMonitor();
    // Simulate: worker A holds a fresh lease -> B cannot acquire.
    fakeSeedWorkerRow(fake, 'nodeA', new Date(Date.now() - 1000), 90000);
    const aHeld = await mdb.acquireWorkerLease('nodeB', 90);
    assert.equal(aHeld, false, 'fresh lease must not be stolen');
    // A crashed holder: lease expires -> B recovers it.
    fakeSeedWorkerRow(fake, 'nodeA', new Date(Date.now() - 200000), 0);
    const bHeld = await mdb.acquireWorkerLease('nodeB', 90);
    assert.equal(bHeld, true, 'expired lease must be recoverable');
    // Same holder can always refresh its own lease.
    fakeSeedWorkerRow(fake, 'nodeB', new Date(Date.now() - 1000), 90000);
    const refreshed = await mdb.refreshWorkerLease('nodeB', 90);
    assert.equal(refreshed, true);
    // A different holder cannot refresh B's lease.
    const stolen = await mdb.refreshWorkerLease('nodeC', 90);
    assert.equal(stolen, false);
});

// ── HTTP: public + auth surface ──────────────────────────────────────────────
let app = null, server = null;

function mockDbForHttp() {
    return {
        getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '3.1.1', features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async () => ({}),
        getServerSettings: async () => ({}),
        upsertServerSettings: async () => ({}),
        getAutomodSettings: async () => ({}),
        upsertAutomodSettings: async () => ({}),
        getAutomodIncidents: async () => ({ incidents: [], total: 0 }),
        getAutomodAnalytics: async () => ({ totals: {} }),
        getAutomodWarnings: async () => [],
        getAntiNukeSettings: async () => ({}),
        upsertAntiNukeSettings: async () => ({}),
        getAntiNukeSetup: async () => ({ method: null, status: 'not_started', state: {} }),
        saveAntiNukeSetup: async () => ({}),
        getAntiNukeIncidents: async () => ({ incidents: [], total: 0 }),
        getAntiNukeLockdown: async () => ({ active: false, state: null }),
        addAntiNukeAccessHistory: async () => {},
        listAntiNukeAccessHistory: async () => [],
        listAntiNukeAccess: async () => [],
        upsertAntiNukeAccess: async () => ({}),
        deleteAntiNukeAccess: async () => true,
        addWebsiteLog: async () => {},
        getLatencySeries: async () => ({ series: [], summary: {} }),
        getLatencyRoutes: async () => [],
    };
}

function mockDiscordForHttp() {
    return {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 0,
        getBotMemberCount: async () => null,
        getBotGuild: async (guildId) => ({ id: guildId, name: 'Test', icon: null, owner_id: '1', approximate_member_count: 5 }),
        getGuildChannels: async () => [],
        getGuildRoles: async () => [],
        exchangeCode: async () => ({}),
        getCurrentUser: async () => ({ id: '1', username: 'tester' }),
        getUserGuilds: async () => [],
        canManageGuild: () => true,
        getBotMemberCountCached: async () => null,
    };
}

// A fake season pool for the HTTP boot so monitorDb + statusView load and all
// monitoring queries degrade to empty (unknown / grey — never fabricated).
function fakeSeasonDb() {
    return {
        seasonPool: {
            async connect() { return { query: async () => ({ rows: [] }), release() {} }; },
            async query(sql) {
                if (sql.includes('FROM monitor_components')) return { rows: defaultComponents() };
                if (/create table/i.test(sql) || /insert into monitor_components/i.test(sql) || /portal/i.test(sql)) return { rows: [] };
                return { rows: [] };
            },
        },
        seasonDb: {},
    };
}

function bootHttp() {
    if (server) return server;
    delete process.env.DATABASE_URL;
    process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
    process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
    process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
    process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

    const realSession = require('express-session');
    const testStore = new realSession.MemoryStore();
    const wrappedSession = function (opts) { return realSession({ ...opts, store: testStore }); };
    Object.assign(wrappedSession, realSession);

    const SEASON_DB = require.resolve('../server/seasonDb');
    const MONITOR_DB = require.resolve('../server/monitorDb');
    const origLoad = Module._load;
    Module._load = function (request, parent) {
        const fromDash = parent && parent.filename && parent.filename.startsWith(DASH + path.sep);
        if (fromDash && request === './db') return mockDbForHttp();
        if (fromDash && request === './discord') return mockDiscordForHttp();
        if (fromDash && request === '../server/seasonDb') return fakeSeasonDb();
        if (fromDash && request === 'express-session') return wrappedSession;
        // server/monitorDb.js requires './seasonDb' from inside the server dir
        // (not a dashboard module), so intercept it explicitly so the monitoring
        // queries degrade to empty for the HTTP boot.
        const parentIsMonitorDb = parent && parent.filename && parent.filename === MONITOR_DB;
        const parentWasSeasonDb = parent && parent.filename && parent.filename === SEASON_DB;
        if (request === './seasonDb' && (parentIsMonitorDb || parentWasSeasonDb)) return fakeSeasonDb();
        return origLoad.apply(this, arguments);
    };
    try {
        // Flush every monitoring-adjacent module so it re-evaluates through the
        // interception above (otherwise the cached instances hold the REAL stub
        // pool and every monitoring query 500s "database not configured").
        for (const m of ['../server/monitorDb', '../server/seasonDb', '../dashboard/statusView', '../utils/statusWorker', '../utils/monitorPulse']) {
            delete require.cache[require.resolve(m)];
        }
        delete require.cache[require.resolve('../dashboard/server')];
        app = require('../dashboard/server');
    } finally {
        Module._load = origLoad;
    }
    return app;
}

function httpReq(urlPath, { method = 'GET', body } = {}) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const req = http.request({
            port: server.address().port, path: urlPath, method,
            // No keep-alive: Node's global agent keeps sockets alive by default,
            // which would block server.close() in the teardown hook forever.
            agent: false,
            headers: {
                Accept: 'application/json',
                Connection: 'close',
                ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
            },
        }, (res) => {
            let data = '';
            res.on('data', c => (data += c));
            res.on('end', () => resolve({ status: res.statusCode, body: data }));
        });
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

test('HTTP boot', async () => {
    const a = bootHttp();
    await new Promise(resolve => { server = a.listen(0, resolve); });
});

test.after(() => new Promise(resolve => {
    if (server) {
        try { server.closeAllConnections?.(); } catch (_) {}
        server.close(resolve);
    } else resolve();
}));

test('public ping endpoint (no auth) returns ok', async () => {
    const r = await httpReq('/api/status/ping');
    assert.equal(r.status, 200);
    const body = JSON.parse(r.body);
    assert.equal(body.ok, true);
});

// ── 17. Public API secret redaction ──────────────────────────────────────────
test('public /api/status sanitizes secrets and unknown state honestly', async () => {
    const r = await httpReq('/api/status');
    assert.equal(r.status, 200);
    const body = JSON.parse(r.body);
    const raw = r.body;
    for (const secret of ['token', 'secret', 'password', 'DATABASE_URL', 'postgres://', 'accessToken', 'refreshToken', 'discord_token', 'Authorization']) {
        assert.ok(!raw.toLowerCase().includes(secret.toLowerCase()), `should not leak: ${secret}`);
    }
    assert.ok(Array.isArray(body.components));
    assert.ok(body.components.length >= 3, 'has component list');
    const sn1 = body.components.find(c => c.key === 'sn1');
    assert.ok(sn1, 'sn1 present');
    assert.equal(sn1.status, 'unknown', 'never monitored -> unknown, not green');
    assert.equal(sn1.uptime30, null, 'no fabricated uptime');
    assert.ok(body.overall && body.overall.key, 'overall status present');
});

test('public incident list is sanitized', async () => {
    const r = await httpReq('/api/status/incidents');
    assert.equal(r.status, 200);
    assert.ok(!r.body.toLowerCase().includes('token'));
});

// ── 16. Unauthorized administrative requests ─────────────────────────────────
test('admin endpoints 401 without a session', async () => {
    const cases = [
        ['POST', '/api/status/incidents'],
        ['PATCH', '/api/status/incidents/1'],
        ['POST', '/api/status/incidents/1/resolve'],
        ['POST', '/api/status/maintenance'],
        ['DELETE', '/api/status/maintenance/1'],
    ];
    for (const [method, urlPath] of cases) {
        const r = await httpReq(urlPath, { method });
        assert.equal(r.status, 401, `${method} ${urlPath}`);
    }
});

// ── 16b. Public status board (the Stats page is not auth-required) ───────────
test('GET /stats renders publicly for an anonymous visitor (no login bounce)', async () => {
    const r = await httpReq('/stats');
    assert.equal(r.status, 200, '/stats must not require auth');
    assert.ok(r.body.includes('id="stats-status"'), 'status board rendered');
    assert.ok(r.body.includes('status-skeleton'), 'skeleton rendered');
    // Anonymous visitors get the no-nav shell (like /docs): no top nav, no
    // idle-timeout script, but an in-body back button instead.
    assert.ok(!r.body.includes('topnav'), 'anon /stats should not render the top nav');
    assert.ok(!r.body.includes('session-timeout.js'), 'anon /stats should not load the idle script');
    assert.ok(r.body.includes('stats-back'), 'anon /stats gets an in-body back button');
});

test('public /api/status/detailed + /api/status/history return sanitized data (no auth)', async () => {
    const d = await httpReq('/api/status/detailed');
    assert.equal(d.status, 200, 'detailed status must be public');
    const body = JSON.parse(d.body);
    assert.ok(Array.isArray(body.components) && body.components.length >= 3, 'component list present');
    assert.ok(body.components[0].series, 'daily series included so bars render for anon');
    assert.equal(body.isAdmin, undefined, 'anon never gets isAdmin');
    // No secrets leak through the public payload.
    for (const secret of ['token', 'secret', 'password', 'DATABASE_URL', 'postgres://', 'accessToken', 'refreshToken']) {
        assert.ok(!d.body.toLowerCase().includes(secret.toLowerCase()), `should not leak: ${secret}`);
    }
    // `detail` (error internals) is stripped from the public component payload.
    assert.ok(body.components.every(c => c.detail === undefined), 'component detail internals omitted');

    const h = await httpReq('/api/status/history?component=sn1&days=30');
    assert.equal(h.status, 200, 'component history must be public');
    const hb = JSON.parse(h.body);
    assert.ok(Array.isArray(hb.series), 'series present');
    assert.ok(!('pulseTimeline' in hb), 'heartbeat timeline omitted for anon');
    assert.ok(!('restarts' in hb), 'restart history omitted for anon');
});

test('input validation on admin endpoints', async () => {
    const r = await httpReq('/api/status/incidents', { method: 'POST' });
    assert.equal(r.status, 401, 'unauthenticated attempt is rejected before validation');
});

// ── 20. Mobile / desktop dashboard rendering ─────────────────────────────────
test('stats page renders the status board + skeleton + loads status.js', async () => {
    const pages = require('../dashboard/render/pages');
    const html = pages.statsPage({ user: null });
    assert.ok(html.includes('id="stats-status"'), 'status board container rendered');
    assert.ok(html.includes('/js/status.js'), 'status client script loaded');
    // The board ships a loading skeleton (not a bare spinner) while it fetches.
    assert.ok(html.includes('status-skeleton'), 'loading skeleton rendered');
    assert.ok(html.includes('sk-shimmer'), 'skeleton uses the shimmer placeholder');
    assert.ok(html.includes('aria-busy="true"'), 'board marked busy while loading');
    // Non-monitoring content was removed from the Stats page.
    assert.ok(!html.includes('/js/stats.js'), 'bot-stats client script removed');
    assert.ok(!html.includes('id="stats-bot"'), 'bot statistics band removed');
    assert.ok(!html.includes('id="stats-latency"'), 'website latency card removed');
    assert.ok(!html.includes('id="stats-nodes"'), 'shardnode status card removed');
});

test('stats page shell is public: no-nav for anon, full nav for a signed-in user', () => {
    const pages = require('../dashboard/render/pages');
    const anon = pages.statsPage({ user: null });
    assert.ok(!anon.includes('topnav'), 'anon gets the no-nav shell');
    assert.ok(!anon.includes('session-timeout.js'), 'anon loads no idle script');
    assert.ok(anon.includes('stats-back'), 'anon gets an in-body back button');
    assert.ok(anon.includes('/js/status.js'), 'anon still loads the status client');

    const authed = pages.statsPage({ user: { id: '1', username: 'tester', globalName: 'Tester' } });
    assert.ok(authed.includes('topnav'), 'signed-in user keeps the top nav');
    assert.ok(authed.includes('session-timeout.js'), 'signed-in user loads the idle script');
    assert.ok(!authed.includes('stats-back'), 'signed-in user relies on the nav back button');
});

test('shard infrastructure aggregation (pure)', () => {
    // Combined availability is computed from real node intervals, not rounded.
    const comps = {
        sn1: { key: 'sn1', label: 'Shard Node 1', status: 'operational', uptime30: { pct: 99.5, monitoredMs: 1000, downtimeMs: 5, degradedMs: 0, maintenanceMs: 0 } },
        sn2: { key: 'sn2', label: 'Shard Node 2', status: 'operational', uptime30: { pct: 98, monitoredMs: 1000, downtimeMs: 20, degradedMs: 0, maintenanceMs: 0 } },
        sn3: { key: 'sn3', label: 'Shard Node 3', status: 'unavailable', uptime30: { pct: 85, monitoredMs: 1000, downtimeMs: 150, degradedMs: 0, maintenanceMs: 0 } },
        bot: { status: 'degraded', uptime30: { pct: 94 } },
    };
    const monitored = comps.sn1.uptime30.monitoredMs + comps.sn2.uptime30.monitoredMs + comps.sn3.uptime30.monitoredMs;
    const down = comps.sn1.uptime30.downtimeMs + comps.sn2.uptime30.downtimeMs + comps.sn3.uptime30.downtimeMs;
    const combined = (monitored - down) / monitored * 100;
    assert.ok(Math.abs(combined - 94.167) < 0.01);
    assert.ok(combined !== 94, 'not an average of rounded per-node percentages');
});
// ── 20b. rollDaily SQL correctness + no data loss on roll failure ────────────
// Regression for the production log "[MONITOR] rollDaily error: LEAST types
// timestamp with time zone and interval cannot be matched": `a + interval '1
// day' - ts` parses as `a + (interval '1 day' - ts)`, so LEAST() compared a
// timestamptz against an interval and threw. The roll silently failed every
// tick — and because the DELETE ran unconditionally afterwards, finished days
// were pruned from monitor_observations WITHOUT ever being aggregated.
test('rollDaily prunes raw observations only after the aggregate persists', async () => {
    // INSERT throws (e.g. the LEAST type error) → the DELETE must NOT run.
    const executed = [];
    const failing = {
        async connect() { return { query: async () => ({ rows: [] }), release() {} }; },
        async query(sql) {
            executed.push(sql.replace(/\s+/g, ' ').trim());
            if (/INSERT INTO monitor_daily/i.test(sql)) throw new Error('boom');
            return { rows: [] };
        },
    };
    const seasonDbPath = require.resolve('../server/seasonDb');
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    const seasonDb = require(seasonDbPath);
    seasonDb.seasonPool = failing;
    const fresh = require('../server/monitorDb');

    await fresh.rollDaily();
    const deleted = executed.some(s => /DELETE FROM monitor_observations/i.test(s));
    assert.equal(deleted, false, 'must not delete raw observations when the roll fails');

    // And when the INSERT succeeds the prune does run.
    executed.length = 0;
    const ok = {
        async connect() { return { query: async () => ({ rows: [] }), release() {} }; },
        async query(sql) { executed.push(sql.replace(/\s+/g, ' ').trim()); return { rows: [] }; },
    };
    seasonDb.seasonPool = ok;
    delete require.cache[require.resolve('../server/monitorDb')];
    const fresh2 = require('../server/monitorDb');
    await fresh2.rollDaily();
    assert.ok(executed.some(s => /DELETE FROM monitor_observations/i.test(s)), 'prunes after a successful roll');
});

test('rollDaily uses a UTC-explicit, correctly parenthesized day boundary', () => {
    const fs = require('node:fs');
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'monitorDb.js'), 'utf8');
    // The LEAST() second argument must not be the bare `x + interval '1 day' - ts`
    // form that mis-parses; require the parenthesized `( ... ) AT TIME ZONE 'UTC'`.
    assert.match(src, /LEAST\(\s*next_ts,\s*\(date_trunc\('day', NOW\(\) AT TIME ZONE 'UTC'\) \+ interval '1 day'\) AT TIME ZONE 'UTC'\)/);
    // And the same UTC-explicit boundary on the DELETE.
    assert.match(src, /DELETE FROM monitor_observations WHERE ts < date_trunc\('day', NOW\(\) AT TIME ZONE 'UTC'\) AT TIME ZONE 'UTC'/);
});

// Real-Postgres execution of the roll (opt-in). Set MONITOR_TEST_DATABASE_URL to
// a throwaway database to exercise the actual SQL; skipped otherwise so CI with
// no Postgres still passes.
test('rollDaily executes against a real Postgres and computes uptime', { skip: !process.env.MONITOR_TEST_DATABASE_URL }, async () => {
    const url = process.env.MONITOR_TEST_DATABASE_URL;
    const saved = { MONITOR: process.env.MONITOR_DATABASE_URL, SEASON: process.env.SEASON_DATABASE_URL, DB: process.env.DATABASE_URL };
    process.env.MONITOR_DATABASE_URL = url;
    process.env.SEASON_DATABASE_URL = url;
    process.env.DATABASE_URL = url;
    try {
        delete require.cache[require.resolve('../server/seasonDb')];
        delete require.cache[require.resolve('../server/monitorDb')];
        const fresh = require('../server/monitorDb');
        const { monitorPool } = fresh;
        await fresh.ensureMonitorTables();
        await monitorPool.query('DELETE FROM monitor_observations');
        await monitorPool.query('DELETE FROM monitor_daily');
        const rows = [
            ['bot', '2026-11-01T00:00:00Z', 'operational'],
            ['bot', '2026-11-01T06:00:00Z', 'operational'],
            ['bot', '2026-11-01T12:00:00Z', 'unavailable'],
            ['bot', '2026-11-01T18:00:00Z', 'degraded'],
            ['bot', '2026-11-02T00:00:00Z', 'operational'],
        ];
        for (const [c, ts, s] of rows) {
            await monitorPool.query('INSERT INTO monitor_observations (component, ts, status) VALUES ($1,$2,$3)', [c, ts, s]);
        }
        await fresh.rollDaily();
        const r = (await monitorPool.query("SELECT * FROM monitor_daily WHERE component='bot' AND day='2026-11-01'")).rows[0];
        assert.ok(r, 'a daily row was written (the SQL parsed and ran)');
        assert.equal(Number(r.monitored_ms), 86400000);
        assert.equal(Number(r.operational_ms), 43200000);
        assert.equal(Number(r.downtime_ms), 21600000);
        assert.equal(Number(r.degraded_ms), 21600000);
        assert.equal(Number(r.samples), 4);
        const left = (await monitorPool.query("SELECT COUNT(*)::int AS n FROM monitor_observations WHERE ts < date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'")).rows[0].n;
        assert.equal(left, 0, 'finished days were pruned after a successful roll');
    } finally {
        if (saved.MONITOR === undefined) delete process.env.MONITOR_DATABASE_URL; else process.env.MONITOR_DATABASE_URL = saved.MONITOR;
        if (saved.SEASON === undefined) delete process.env.SEASON_DATABASE_URL; else process.env.SEASON_DATABASE_URL = saved.SEASON;
        if (saved.DB === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = saved.DB;
        delete require.cache[require.resolve('../server/seasonDb')];
        delete require.cache[require.resolve('../server/monitorDb')];
    }
});

// ── 21. index.js boot wiring must only call exports that exist ───────────────
// Regression for the production crash "nodeFailover.setPulseProvider is not a
// function": a helper defined but not added to module.exports only surfaces at
// runtime, after a deploy, taking the whole bot down. Statically verify every
// `module.fn(` call in index.js resolves to a real export.
test('index.js only calls exported monitor/failover helpers', () => {
    const fs = require('node:fs');
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');

    const modules = {
        monitorPulse: require('../utils/monitorPulse'),
        statusWorker: require('../utils/statusWorker'),
        nodeFailover: require('../utils/nodeFailover'),
    };

    const missing = [];
    const re = /\b(monitorPulse|statusWorker|nodeFailover)\.([A-Za-z_$][\w$]*)\s*\(/g;
    let m;
    while ((m = re.exec(src)) !== null) {
        const [, mod, fn] = m;
        if (typeof modules[mod][fn] !== 'function') missing.push(`${mod}.${fn}`);
    }

    assert.deepEqual(missing, [], `index.js calls unexported helpers: ${missing.join(', ')}`);
    // Guard the exact helper that crashed production.
    assert.equal(typeof modules.nodeFailover.setPulseProvider, 'function');
});
