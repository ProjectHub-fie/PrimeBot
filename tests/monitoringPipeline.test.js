/**
 * Regression tests for the two production monitoring bugs.
 *
 * BUG 1 — standby nodes shown as OFFLINE/DEGRADED: all three nodes wrote the
 *   same pulse identity (the literal 'local'), so `monitor_node_pulse` held one
 *   row instead of three; and node health was judged on the gateway/active
 *   lease, so a healthy standby looked broken.
 *
 * BUG 2 — the 30-day graph showed only ONE illuminated bar: `rollDaily()`'s
 *   INSERT failed (a `LEAST(timestamptz, interval)` precedence error) while its
 *   unconditional DELETE still consumed every prior day's raw observations, so
 *   `monitor_daily` stayed empty and only today (never rolled) had data.
 *
 * These tests are pure (no DB, no network). The DB-touching helpers are driven
 * through a fake pg pool, matching the pattern already used by
 * tests/statusMonitor.test.js.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const statusWorker = require('../utils/statusWorker');
const monitorPulse = require('../utils/monitorPulse');
const { resolveNodeIdentity, normalizeNodeRole } = require('../utils/nodeIdentity');

// ── Shared pulse builder ─────────────────────────────────────────────────────
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

// ── 1-9. Node classification ─────────────────────────────────────────────────

// 1 + 2 + 3 + 4: the exact production shape — one active node, two standbys,
// the standbys with NO gateway and NO assigned shards.
test('1-4: one active node + two healthy standbys without gateway or shards', () => {
    const pulses = [
        activeNode('sn1', { nodeName: 'NR0008', nodeId: 'NR0008' }),
        pulse('sn2', { nodeName: 'NU3049', nodeId: 'NU3049' }),
        pulse('sn3', { nodeName: 'NUKN09', nodeId: 'NUKN09' }),
    ];
    const state = statusWorker.evaluateState(pulses, { activeNodeId: 'NR0008', activeRole: 'sn1' });

    assert.equal(state.nodes.sn1.status, 'operational');
    assert.equal(state.nodes.sn1.isActive, true);
    assert.equal(state.nodes.sn2.status, 'operational', 'healthy standby is operational');
    assert.equal(state.nodes.sn2.isActive, false);
    assert.equal(state.nodes.sn3.status, 'operational', 'healthy standby with no gateway/shards is operational');

    // Standby independent signals are reported but never treated as faults.
    assert.equal(state.nodes.sn2.online, true);
    assert.equal(state.nodes.sn2.healthy, true);
    assert.equal(state.nodes.sn2.gateway.ready, false);
    assert.equal(state.nodes.sn2.shards.assigned, 0);

    // The required headline numbers.
    assert.deepEqual(
        { online: state.fleet.online, healthy: state.fleet.healthy, active: state.fleet.active, standby: state.fleet.standby, offline: state.fleet.offline },
        { online: 3, healthy: 3, active: 1, standby: 2, offline: 0 }
    );
    assert.equal(state.fleet.redundancyIntact, true);
    assert.equal(state.bot.status, 'operational');
});

// 5: a standby genuinely failing (stale heartbeat) is reported, and redundancy
// drops — but the reason is the heartbeat, never the absent gateway.
test('5: genuine standby-node failure reduces redundancy with the real reason', () => {
    const pulses = [
        activeNode('sn1', { nodeName: 'NR0008', nodeId: 'NR0008' }),
        pulse('sn2', { nodeName: 'NU3049', nodeId: 'NU3049' }),
        pulse('sn3', { nodeName: 'NUKN09', nodeId: 'NUKN09', ageMs: 999999 }),
    ];
    const state = statusWorker.evaluateState(pulses, { activeNodeId: 'NR0008', activeRole: 'sn1' });
    assert.equal(state.nodes.sn3.status, 'unavailable');
    assert.equal(state.nodes.sn3.statusReason, 'stale');
    assert.equal(state.fleet.offline, 1);
    assert.equal(state.fleet.online, 2);
    assert.equal(state.fleet.redundancyIntact, false);
    // Service is unaffected: the active node still serves.
    assert.equal(state.bot.status, 'operational');
});

// 6: the ACTIVE node failing is a service impact (bot degraded), not a
// standby-redundancy event.
test('6: active-node failure degrades the bot service', () => {
    const pulses = [
        activeNode('sn1', { nodeName: 'NR0008', nodeId: 'NR0008', ageMs: 999999 }),
        pulse('sn2', { nodeName: 'NU3049', nodeId: 'NU3049' }),
        pulse('sn3', { nodeName: 'NUKN09', nodeId: 'NUKN09' }),
    ];
    const state = statusWorker.evaluateState(pulses, { activeNodeId: 'NR0008', activeRole: 'sn1' });
    assert.equal(state.nodes.sn1.status, 'unavailable');
    assert.equal(state.fleet.active, 0);
    assert.equal(state.fleet.standby, 2);
    assert.equal(state.fleet.redundancyIntact, false);
    // No active node serving → the bot is degraded (not "operational").
    assert.notEqual(state.bot.status, 'operational');
});

// 6b: an active node whose process is up but gateway is down is DEGRADED
// (still online), which is distinct from offline.
test('6b: active node with a broken gateway is degraded, still online', () => {
    const pulses = [activeNode('sn1', { nodeName: 'NR0008', nodeId: 'NR0008', gatewayReady: false, gatewayConnected: true })];
    const state = statusWorker.evaluateState(pulses, { activeNodeId: 'NR0008', activeRole: 'sn1' });
    assert.equal(state.nodes.sn1.status, 'degraded');
    assert.equal(state.nodes.sn1.online, true);
    assert.equal(state.nodes.sn1.healthy, false);
    assert.equal(state.nodes.sn1.statusReason, 'gateway_not_ready');
});

// 7: a late heartbeat is STALE (needs verification) — only a heartbeat missing
// long enough to confirm the process stopped is an OUTAGE. The stale/outage
// thresholds scale with the cadence each writer publishes.
test('7: a late heartbeat is STALE, a long-missing one is unavailable; a slower published cadence is honoured', () => {
    // 80s old with a 30s cadence (90s stale window) → still fresh/operational.
    assert.equal(statusWorker.evaluateState([pulse('sn1', { ageMs: 80000 })], {}).nodes.sn1.status, 'operational');
    // 100s old with a 30s cadence → past the 90s stale window but well inside
    // the 180s outage window → STALE, NOT a confirmed outage.
    const late = statusWorker.evaluateState([pulse('sn1', { ageMs: 100000 })], {});
    assert.equal(late.nodes.sn1.status, 'stale');
    assert.equal(late.nodes.sn1.online, true, 'a stale node is still online');
    assert.equal(late.nodes.sn1.healthy, false);
    assert.equal(late.nodes.sn1.statusReason, 'heartbeat_stale');
    // 250s old with a 30s cadence → past the 180s outage window → unavailable.
    assert.equal(statusWorker.evaluateState([pulse('sn1', { ageMs: 250000 })], {}).nodes.sn1.status, 'unavailable');
    // 100s old but the writer publishes a 5-minute cadence → fresh.
    const slow = pulse('sn1', { ageMs: 100000, resource: { pulseIntervalMs: 300000 } });
    assert.equal(statusWorker.evaluateState([slow], {}).nodes.sn1.status, 'operational');
});

// 8: recovery — a stale node becomes operational again on a fresh heartbeat.
test('8: recovery after an outage', () => {
    const down = statusWorker.evaluateState([pulse('sn2', { ageMs: 999999 })], {});
    assert.equal(down.nodes.sn2.status, 'unavailable');
    const up = statusWorker.evaluateState([pulse('sn2', { ageMs: 4000 })], {});
    assert.equal(up.nodes.sn2.status, 'operational');
});

// 9: repeated heartbeats (same state, many ticks) produce no duplicate incident.
test('9: repeated heartbeats without duplicate incidents', async () => {
    const incidents = [];
    let creates = 0;
    const mon = {
        async getOpenIncidents() { return incidents.filter(i => i.status !== 'resolved'); },
        async insertObservation() {},
        async createIncident(o) { creates++; const inc = { id: incidents.length + 1, status: 'investigating', ...o }; incidents.push(inc); return inc; },
        async resolveIncident(id) { const i = incidents.find(x => x.id === id); if (i) i.status = 'resolved'; return i; },
        async updateIncident() { return null; },
    };
    const down = { sn3: { status: 'unavailable', detail: {} } };
    for (let i = 0; i < 10; i++) await statusWorker.apply(down, mon);
    assert.equal(creates, 1, '10 consecutive down ticks → exactly one incident');
});

// 9b: a node status change (degraded → unavailable) UPDATES the open incident
// rather than stacking a duplicate.
test('9b: a status change updates the existing incident instead of duplicating', async () => {
    const incidents = [];
    let creates = 0;
    let updates = 0;
    const mon = {
        async getOpenIncidents() { return incidents.filter(i => i.status !== 'resolved'); },
        async insertObservation() {},
        async createIncident(o) { creates++; const inc = { id: incidents.length + 1, status: 'investigating', ...o }; incidents.push(inc); return inc; },
        async updateIncident(id, patch) { updates++; Object.assign(incidents.find(x => x.id === id), patch); return incidents.find(x => x.id === id); },
        async resolveIncident() { return null; },
    };
    await statusWorker.apply({ sn1: { status: 'degraded', detail: {} } }, mon);
    await statusWorker.apply({ sn1: { status: 'unavailable', detail: {} } }, mon);
    assert.equal(creates, 1, 'no second incident for the same continuous outage');
    assert.equal(updates, 1, 'the open incident was updated in place');
});

// 9c: standby vs active incident wording (node failure ≠ service outage).
test('9c: node incident descriptions distinguish active vs standby', () => {
    const standbySnap = { nodes: { sn2: { isActive: false } } };
    const activeSnap = { nodes: { sn1: { isActive: true } } };
    assert.match(statusWorker.incidentDescription('sn2', 'unavailable', standbySnap), /standby cluster/);
    assert.match(statusWorker.incidentDescription('sn2', 'unavailable', standbySnap), /redundancy is reduced/);
    assert.match(statusWorker.incidentDescription('sn1', 'unavailable', activeSnap), /active cluster/);
    assert.match(statusWorker.incidentDescription('sn1', 'unavailable', activeSnap), /the shards it serves are affected/);
});

// 9d: confirmed recovery — a single healthy blip does not resolve an incident.
test('9d: recovery must be confirmed across consecutive healthy readings', async () => {
    const incidents = [];
    let resolves = 0;
    const mon = {
        async getOpenIncidents() { return incidents.filter(i => i.status !== 'resolved'); },
        async insertObservation() {},
        async createIncident(o) { const inc = { id: incidents.length + 1, status: 'investigating', ...o }; incidents.push(inc); return inc; },
        async resolveIncident(id) { resolves++; const i = incidents.find(x => x.id === id); if (i) i.status = 'resolved'; return i; },
        async updateIncident() { return null; },
    };
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    await statusWorker.apply({ sn1: { status: 'operational' } }, mon); // blip
    assert.equal(resolves, 0, 'a single healthy reading must not resolve the incident');
    // Now stay down again, then recover for good.
    await statusWorker.apply({ sn1: { status: 'unavailable' } }, mon);
    for (let i = 0; i < statusWorker.RECOVERY_CONFIRMATIONS; i++) {
        await statusWorker.apply({ sn1: { status: 'operational' } }, mon);
    }
    assert.equal(resolves, 1, 'confirmed recovery resolves exactly once');
});

// ── 18. Multiple workers writing monitoring records ──────────────────────────

test('18: only one worker holds the monitoring lease at a time', async () => {
    // Drive the real acquireWorkerLease/refreshWorkerLease over a fake pool that
    // models the atomic conditional upsert.
    const seasonDbPath = require.resolve('../server/seasonDb');
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    const seasonDb = require(seasonDbPath);
    let row = null;
    seasonDb.seasonPool = {
        async connect() { return { query: async () => ({ rows: [] }), release() {} }; },
        async query(sql, params) {
            if (/create table/i.test(sql) || /insert into monitor_components/i.test(sql) || /alter table/i.test(sql) || /delete from monitor_node_pulse/i.test(sql) || /create index/i.test(sql)) return { rows: [] };
            if (sql.includes('monitor_worker')) {
                if (/INSERT/i.test(sql)) {
                    const holder = params[1];
                    const ttl = Number(params[2] || 45);
                    const now = Date.now();
                    const canClaim = !row || Date.parse(row.lease_expires_at) <= now || row.holder === holder;
                    if (!canClaim) return { rows: [] };
                    row = { holder, last_seen: new Date(now).toISOString(), lease_expires_at: new Date(now + ttl * 1000).toISOString() };
                    return { rows: [{ holder }] };
                }
                if (/UPDATE/i.test(sql)) {
                    if (row && row.holder === params[1]) { row.last_seen = new Date().toISOString(); return { rows: [{ holder: row.holder }] }; }
                    return { rows: [] };
                }
                return { rows: row ? [row] : [] };
            }
            return { rows: [] };
        },
    };
    const mdb = require('../server/monitorDb');
    assert.equal(await mdb.acquireWorkerLease('workerA', 90), true);
    assert.equal(await mdb.acquireWorkerLease('workerB', 90), false, 'a second worker cannot steal a fresh lease');
    // The holder can refresh; a non-holder cannot.
    assert.equal(await mdb.refreshWorkerLease('workerA', 90), true);
    assert.equal(await mdb.refreshWorkerLease('workerB', 90), false);
    // A crashed holder's expired lease is recoverable.
    row = { holder: 'workerA', last_seen: new Date(Date.now() - 300000).toISOString(), lease_expires_at: new Date(Date.now() - 200000).toISOString() };
    assert.equal(await mdb.acquireWorkerLease('workerB', 90), true, 'an expired lease is recoverable');
});

// ── BUG 2 root cause: rollDaily must not destroy raw rows when it fails ──────

test('rollDaily wraps the aggregate + prune in one transaction and preserves raw rows on failure', async () => {
    const seasonDbPath = require.resolve('../server/seasonDb');
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    const seasonDb = require(seasonDbPath);
    const calls = { begin: 0, commit: 0, rollback: 0, deleteRan: false, insertSql: null };
    seasonDb.seasonPool = {
        async connect() {
            return {
                async query(sql) {
                    if (sql === 'BEGIN') calls.begin++;
                    else if (sql === 'COMMIT') calls.commit++;
                    else if (sql === 'ROLLBACK') calls.rollback++;
                    else if (/INSERT INTO monitor_daily/i.test(sql)) {
                        calls.insertSql = sql;
                        throw new Error('LEAST types timestamp with time zone and interval cannot be matched');
                    } else if (/DELETE FROM monitor_observations/i.test(sql)) {
                        calls.deleteRan = true;
                    }
                    return { rows: [], rowCount: 0 };
                },
                release() {},
            };
        },
        async query(sql) {
            if (/create table/i.test(sql) || /alter table/i.test(sql) || /create index/i.test(sql) || /delete from monitor_node_pulse/i.test(sql) || /insert into monitor_components/i.test(sql)) return { rows: [] };
            return { rows: [] };
        },
    };
    const mdb = require('../server/monitorDb');
    const result = await mdb.rollDaily();
    assert.equal(result, null, 'a failed roll returns null (signals failure)');
    assert.equal(calls.begin, 1);
    assert.equal(calls.rollback, 1, 'the transaction is rolled back');
    assert.equal(calls.commit, 0);
    assert.equal(calls.deleteRan, false, 'the destructive prune must NOT run when the aggregate failed');
    // The corrected SQL must not contain the buggy unparenthesised expression.
    assert.ok(calls.insertSql, 'the roll ran an INSERT');
    assert.match(calls.insertSql, /LEAST\(next_ts, date_trunc\('day', NOW\(\)\) \+ interval '1 day'\) - ts/,
        'the LEAST is clamped to the day boundary with the subtraction OUTSIDE the LEAST');
    assert.ok(!/interval '1 day' - ts\)\)/.test(calls.insertSql), 'no precedence bug');
});

test('rollDaily succeeds in one transaction (BEGIN → INSERT → DELETE → COMMIT)', async () => {
    const seasonDbPath = require.resolve('../server/seasonDb');
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    const seasonDb = require(seasonDbPath);
    const order = [];
    seasonDb.seasonPool = {
        async connect() {
            return {
                async query(sql) {
                    if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') order.push(sql);
                    else if (/INSERT INTO monitor_daily/i.test(sql)) { order.push('INSERT'); return { rowCount: 3 }; }
                    else if (/DELETE FROM monitor_observations/i.test(sql)) order.push('DELETE');
                    return { rows: [], rowCount: 0 };
                },
                release() {},
            };
        },
        async query(sql) {
            if (/create table/i.test(sql) || /alter table/i.test(sql) || /create index/i.test(sql) || /delete from monitor_node_pulse/i.test(sql) || /insert into monitor_components/i.test(sql)) return { rows: [] };
            return { rows: [] };
        },
    };
    const mdb = require('../server/monitorDb');
    const result = await mdb.rollDaily();
    assert.equal(result, 3);
    assert.deepEqual(order, ['BEGIN', 'INSERT', 'DELETE', 'COMMIT']);
});

// ── BUG 2: 30 graph positions + data status ──────────────────────────────────

function bootMonitorWithDaily(dailyRows, obsRows = []) {
    const seasonDbPath = require.resolve('../server/seasonDb');
    delete require.cache[seasonDbPath];
    delete require.cache[require.resolve('../server/monitorDb')];
    const seasonDb = require(seasonDbPath);
    seasonDb.seasonPool = {
        async connect() { return { query: async () => ({ rows: [] }), release() {} }; },
        async query(sql, params) {
            if (/create table/i.test(sql) || /alter table/i.test(sql) || /create index/i.test(sql) || /delete from monitor_node_pulse/i.test(sql) || /insert into monitor_components/i.test(sql)) return { rows: [] };
            if (sql.includes('FROM monitor_daily')) return { rows: dailyRows };
            if (sql.includes('monitor_observations')) return { rows: obsRows };
            return { rows: [] };
        },
    };
    return require('../server/monitorDb');
}

const utcDay = (offset) => {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() + offset);
    d.setUTCHours(0, 0, 0, 0);
    return d.toISOString().slice(0, 10);
};

// 10: exactly 30 positions.
test('10: the series always has exactly 30 positions ending today (UTC)', async () => {
    const mdb = bootMonitorWithDaily([]);
    const series = await mdb.getDailySeries('bot', 30);
    assert.equal(series.length, 30);
    assert.equal(series[29].day, utcDay(0));
    assert.equal(series[0].day, utcDay(-29));
    // Consecutive, no gaps, no duplicate keys.
    const days = series.map(s => s.day);
    assert.equal(new Set(days).size, 30, 'no duplicate day keys');
});

// 11: only one day of history → still 30 positions, 29 grey.
test('11: one day of history still renders 30 positions (29 no-data)', async () => {
    const mdb = bootMonitorWithDaily([
        { component: 'bot', day: utcDay(-1), monitored_ms: 86400000, operational_ms: 86400000, degraded_ms: 0, downtime_ms: 0, maintenance_ms: 0, samples: 100 },
    ]);
    const series = await mdb.getDailySeries('bot', 30);
    assert.equal(series.length, 30);
    assert.equal(series.filter(s => s.hasData).length, 1);
    assert.equal(series.filter(s => !s.hasData).length, 29);
    assert.equal(series.filter(s => s.dataStatus === 'no_data').length, 29);
    const withData = series.find(s => s.hasData);
    assert.equal(withData.dataStatus, 'complete');
    assert.ok(withData.coverage > 0.98);
});

// 12: multiple days of history.
test('12: multiple days of history each get their own position', async () => {
    const mdb = bootMonitorWithDaily([
        { component: 'bot', day: utcDay(-3), monitored_ms: 86400000, operational_ms: 80000000, degraded_ms: 0, downtime_ms: 6400000, maintenance_ms: 0, samples: 100 },
        { component: 'bot', day: utcDay(-2), monitored_ms: 86400000, operational_ms: 86400000, degraded_ms: 0, downtime_ms: 0, maintenance_ms: 0, samples: 100 },
        { component: 'bot', day: utcDay(-1), monitored_ms: 86400000, operational_ms: 50000000, degraded_ms: 0, downtime_ms: 36400000, maintenance_ms: 0, samples: 100 },
    ]);
    const series = await mdb.getDailySeries('bot', 30);
    const withData = series.filter(s => s.hasData);
    assert.equal(withData.length, 3);
    for (const s of withData) {
        assert.equal(s.dataStatus, 'complete');
        assert.ok(s.uptime != null);
        assert.ok(s.downtimePct != null);
    }
});

// 13: missing historical dates stay grey (never fabricated to 100%).
test('13: missing historical dates remain NO DATA and are never 100%', async () => {
    const mdb = bootMonitorWithDaily([
        { component: 'bot', day: utcDay(-10), monitored_ms: 86400000, operational_ms: 86400000, degraded_ms: 0, downtime_ms: 0, maintenance_ms: 0, samples: 100 },
        { component: 'bot', day: utcDay(-2), monitored_ms: 86400000, operational_ms: 86400000, degraded_ms: 0, downtime_ms: 0, maintenance_ms: 0, samples: 100 },
    ]);
    const series = await mdb.getDailySeries('bot', 30);
    const gap = series.find(s => s.day === utcDay(-6));
    assert.equal(gap.hasData, false);
    assert.equal(gap.uptime, null, 'a missing day is null uptime, never fabricated 100%');
    assert.equal(gap.coverage, 0);
    assert.equal(gap.dataStatus, 'no_data');
});

// 14: partial-day monitoring → dataStatus 'partial'.
test('14: partial-day monitoring is flagged as partial', async () => {
    const mdb = bootMonitorWithDaily([
        { component: 'bot', day: utcDay(-1), monitored_ms: 3600000, operational_ms: 3600000, degraded_ms: 0, downtime_ms: 0, maintenance_ms: 0, samples: 10 },
    ]);
    const series = await mdb.getDailySeries('bot', 30);
    const day = series.find(s => s.day === utcDay(-1));
    assert.equal(day.hasData, true);
    assert.equal(day.dataStatus, 'partial');
    assert.ok(day.coverage > 0 && day.coverage < 0.5);
});

// 15: UTC date-boundary handling — today's bucket is the UTC day, and the
// series is anchored to UTC midnight.
test('15: the series is anchored to UTC day boundaries', async () => {
    const mdb = bootMonitorWithDaily([]);
    const series = await mdb.getDailySeries('bot', 30);
    const today = series[series.length - 1];
    assert.equal(today.isToday, true);
    assert.equal(today.day, new Date().toISOString().slice(0, 10));
    // Every position is a valid UTC YYYY-MM-DD.
    for (const s of series) assert.match(s.day, /^\d{4}-\d{2}-\d{2}$/);
});

// 16 + 17: API returns 30 correctly ordered records (via the real statusView).
test('17: getStatusSummary exposes a 30-position series per component', async () => {
    const mdb = bootMonitorWithDaily([]);
    const seasonDbPath = require.resolve('../server/seasonDb');
    const seasonDb = require(seasonDbPath);
    // Provide components so the summary loops over them.
    seasonDb.seasonPool.query = async (sql) => {
        if (/create table/i.test(sql) || /alter table/i.test(sql) || /create index/i.test(sql) || /delete from monitor_node_pulse/i.test(sql) || /insert into monitor_components/i.test(sql)) return { rows: [] };
        if (sql.includes('monitor_components')) return { rows: [{ key: 'bot', label: 'PrimeBot Bot', description: '', enabled: true, updated_at: new Date() }] };
        if (sql.includes('monitor_node_pulse')) return { rows: [] };
        if (sql.includes('bot_failover_lock')) return { rows: [] };
        if (sql.includes('monitor_incidents')) return { rows: [] };
        if (sql.includes('monitor_maintenance')) return { rows: [] };
        if (sql.includes('monitor_observations')) return { rows: [] };
        if (sql.includes('FROM monitor_daily')) return { rows: [] };
        return { rows: [] };
    };
    delete require.cache[require.resolve('../dashboard/statusView')];
    const statusView = require('../dashboard/statusView');
    const summary = await statusView.getStatusSummary();
    const bot = summary.components.find(c => c.key === 'bot');
    assert.equal(bot.series.length, 30);
    // Ordered ascending by day.
    const days = bot.series.map(s => s.day);
    assert.deepEqual(days, [...days].sort());
    assert.ok(summary.fleet, 'fleet summary is present');
});

// ── BUG 1 root cause: pulse identity is stable and per-node ──────────────────

test('the pulse identity is stable per role and never the literal "local"', () => {
    const sn1 = resolveNodeIdentity({ NODE_ROLE: 'sn1' });
    const sn2 = resolveNodeIdentity({ NODE_ROLE: 'sn2' });
    const sn3 = resolveNodeIdentity({ NODE_ROLE: 'sn3' });
    assert.equal(sn1.nodeId, 'NR0008');
    assert.equal(sn2.nodeId, 'NU3049');
    assert.equal(sn3.nodeId, 'NUKN09');
    assert.equal(new Set([sn1.nodeId, sn2.nodeId, sn3.nodeId]).size, 3, 'three distinct identities');
    for (const n of [sn1, sn2, sn3]) assert.notEqual(n.nodeId, 'local');
    // NODE_ID / NODE_NAME override wins.
    assert.equal(resolveNodeIdentity({ NODE_ROLE: 'sn2', NODE_ID: 'custom-1' }).nodeId, 'custom-1');
    assert.equal(resolveNodeIdentity({ NODE_ROLE: 'sn2', NODE_NAME: 'custom-2' }).nodeId, 'custom-2');
    // Role aliases.
    assert.equal(normalizeNodeRole('primary'), 'sn1');
    assert.equal(normalizeNodeRole('secondary'), 'sn2');
    assert.equal(normalizeNodeRole('tertiary'), 'sn3');
});

test('buildPulse publishes the node id + role + its own cadence', () => {
    const p = monitorPulse.buildPulse({});
    assert.ok(p.nodeName && p.nodeName !== 'local');
    assert.equal(p.nodeId, p.nodeName);
    assert.ok(['sn1', 'sn2', 'sn3'].includes(p.role));
    assert.equal(typeof p.resource.pulseIntervalMs, 'number');
    assert.ok(p.resource.pulseIntervalMs > 0);
    // A standby pulse (no client) is 'running', not 'dead'.
    assert.equal(p.processHealth, 'running');
    assert.equal(p.gatewayReady, false);
    assert.equal(p.shardsTotal, 0);
});

// ── Frontend rendering of all 30 bars (vm sandbox, no jsdom) ─────────────────

test('16: the client renders all 30 bar elements for a 30-position series', () => {
    const fs = require('node:fs');
    const vm = require('node:vm');
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'status.js'), 'utf8');

    // Minimal DOM: the script builds the shell then paints the summary.
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
        hasData: i === 29,
        dataStatus: i === 29 ? 'complete' : 'no_data',
        uptime: i === 29 ? 100 : null,
        downtimeMs: 0, degradedMs: 0, maintenanceMs: 0, monitoredMs: i === 29 ? 86400000 : 0, coverage: i === 29 ? 1 : 0,
    }));
    const summary = {
        overall: { key: 'operational', label: 'All Systems Operational' },
        openIncidents: 0,
        lastCheckedAt: new Date().toISOString(),
        fleet: { online: 3, healthy: 3, active: 1, standby: 2, offline: 0 },
        components: [
            { key: 'bot', label: 'PrimeBot Bot', status: 'operational', uptime30: { pct: 100 }, series, lastObservedAt: new Date().toISOString() },
            { key: 'sn1', label: 'Shard Node 1', status: 'operational', uptime30: { pct: 100 }, series, node: { role: 'sn1', isActive: true, online: true, healthy: true, gateway: { ready: true }, shards: { assigned: 5, ready: 5 } } },
            { key: 'sn2', label: 'Shard Node 2', status: 'operational', uptime30: { pct: 100 }, series, node: { role: 'sn2', isActive: false, online: true, healthy: true, gateway: { ready: false }, shards: { assigned: 0, ready: 0 } } },
            { key: 'sn3', label: 'Shard Node 3', status: 'operational', uptime30: { pct: 100 }, series, node: { role: 'sn3', isActive: false, online: true, healthy: true, gateway: { ready: false }, shards: { assigned: 0, ready: 0 } } },
        ],
        activeIncidents: [], resolvedIncidents: [], measurement: { intervalMs: 60000 },
    };

    const ctx = {
        window: {},
        document: doc,
        fetch: async () => ({ ok: true, json: async () => summary }),
        setTimeout, clearTimeout,
        console,
        Date, Math, JSON, Number, Array, Object, String,
        location: { href: '' },
    };
    ctx.window.document = doc;
    ctx.window.fetch = ctx.fetch;
    vm.createContext(ctx);
    vm.runInContext(src, ctx);

    // Flush the async init.
    return new Promise(resolve => setTimeout(() => {
        const result = elements.get('#status-result');
        assert.ok(result && result.innerHTML, 'the board rendered');
        const bars = (result.innerHTML.match(/class="uptime-bar bar-/g) || []).length;
        // 4 components × 30 positions = 120 bars (never a single lit bar).
        assert.equal(bars, 120, `expected 120 bars, got ${bars}`);
        assert.ok(result.innerHTML.includes('role-standby'), 'standby chip rendered');
        assert.ok(result.innerHTML.includes('role-active'), 'active chip rendered');
        assert.ok(result.innerHTML.includes('No shards assigned'), 'standby shard chip rendered');
        assert.ok(result.innerHTML.includes('Standby clusters'), 'fleet standby count rendered');
        resolve();
    }, 20));
});
