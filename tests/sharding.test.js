/**
 * Active-active sharding tests.
 *
 * Everything here runs against the real coordinator/assignment/status modules
 * with an in-memory store (MemoryShardStore) and a stubbed season pool — no
 * Discord credentials, no network, no Postgres.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const { resolveShardConfig } = require('../utils/sharding/config');
const { planAssignment, validatePlan, shardsFor } = require('../utils/sharding/assignment');
const { ShardCoordinator, MemoryShardStore } = require('../utils/sharding/coordinator');
const { describeFleet, clusterLabel } = require('../utils/sharding/status');

const CFG = resolveShardConfig({ SHARD_COUNT: '6', SHARD_NODES: 'sn1,sn2,sn3' }, { role: 'sn1' });

function newStore(clock) {
    const store = new MemoryShardStore({ now: () => clock.now });
    for (const role of ['sn1', 'sn2', 'sn3']) store.setNode(role, { nodeName: role, ageMs: 1000 });
    return store;
}

function coordinator(store, role, cfg = CFG) {
    return new ShardCoordinator({ store, role, nodeName: role, config: cfg, logger: { log() {}, warn() {}, error() {} } });
}

// ── assignment planning ──────────────────────────────────────────────────
test('balanced plan covers every shard exactly once', () => {
    const { plan } = planAssignment({ shardCount: 6, nodes: ['sn1', 'sn2', 'sn3'] });
    assert.deepEqual(plan, { sn1: [0, 3], sn2: [1, 4], sn3: [2, 5] });
    const check = validatePlan(plan, 6);
    assert.equal(check.ok, true);
    assert.deepEqual(check.missing, []);
    assert.deepEqual(check.duplicates, []);

    // Uneven counts stay within one shard of each other.
    const seven = planAssignment({ shardCount: 7, nodes: ['sn1', 'sn2', 'sn3'] }).plan;
    const counts = Object.values(seven).map(s => s.length).sort((a, b) => a - b);
    assert.deepEqual(counts, [2, 2, 3]);
});

test('an unknown strategy falls back to balanced instead of throwing', () => {
    const plan = planAssignment({ shardCount: 3, nodes: ['sn1'], strategy: 'nonsense' });
    assert.equal(plan.strategy, 'balanced');
    assert.deepEqual(plan.plan.sn1, [0, 1, 2]);
});

// ── 1 + 2: three healthy nodes, distinct sets, no duplicate ownership ────
test('three healthy nodes concurrently own distinct shard sets', async () => {
    const clock = { now: 1_000_000 };
    const store = newStore(clock);
    const claims = {};
    for (const role of ['sn1', 'sn2', 'sn3']) {
        claims[role] = (await coordinator(store, role).claim()).shardIds;
    }
    assert.deepEqual(claims.sn1, [0, 3]);
    assert.deepEqual(claims.sn2, [1, 4]);
    assert.deepEqual(claims.sn3, [2, 5]);

    const all = [...claims.sn1, ...claims.sn2, ...claims.sn3].sort((a, b) => a - b);
    assert.deepEqual(all, [0, 1, 2, 3, 4, 5], 'every shard is served exactly once');
    assert.equal(new Set(all).size, all.length, 'no shard is owned by two nodes');

    const assignments = await store.listAssignments();
    assert.equal(assignments.length, 6);
    const byShard = new Map();
    for (const a of assignments) byShard.set(a.shardId, (byShard.get(a.shardId) || 0) + 1);
    assert.ok([...byShard.values()].every(n => n === 1));
});

test('a live owner is never preempted by a peer re-claiming', async () => {
    const clock = { now: 1_000_000 };
    const store = newStore(clock);
    const sn1 = coordinator(store, 'sn1');
    await sn1.claim();
    await coordinator(store, 'sn2').claim();

    // sn1 re-claims while sn2 is still fresh: it must keep only its own shards.
    clock.now += 5_000;
    const again = await sn1.claim();
    assert.deepEqual(again.shardIds, [0, 3]);
    const sn2Rows = (await store.listAssignments()).filter(a => a.ownerRole === 'sn2');
    assert.deepEqual(sn2Rows.map(a => a.shardId).sort((a, b) => a - b), [1, 4]);
});

// ── 4: restart + heartbeat timeout ───────────────────────────────────────
test('a dead node\'s shards are taken over only after its lease lapses', async () => {
    const clock = { now: 1_000_000 };
    const store = newStore(clock);
    const sn1 = coordinator(store, 'sn1');
    await sn1.claim();
    await coordinator(store, 'sn2').claim();
    await coordinator(store, 'sn3').claim();

    // sn2 stops heartbeating but its lease has not lapsed yet.
    store.setNode('sn2', { nodeName: 'sn2', ageMs: 1_000 });
    clock.now += CFG.staleAfterMs - 1_000;
    let claim = await sn1.claim();
    assert.deepEqual(claim.shardIds, [0, 3], 'nothing is stolen while the owner is alive');

    // ...and now it lapses. Keep sn3 fresh so only sn2 is considered dead.
    clock.now += CFG.staleAfterMs + 1_000;
    store.removeNode('sn2');
    store.setNode('sn3', { nodeName: 'sn3', ageMs: 1_000 });
    claim = await sn1.claim();
    assert.deepEqual(claim.shardIds, [0, 1, 3, 4], 'the survivor absorbs the dead peer\'s shards');
    assert.deepEqual(claim.takenOver.sort((a, b) => a - b), [1, 4]);

    // sn3 keeps its own shards untouched.
    const sn3Rows = (await store.listAssignments()).filter(a => a.ownerRole === 'sn3');
    assert.deepEqual(sn3Rows.map(a => a.shardId).sort((a, b) => a - b), [2, 5]);
});

test('a restarted node recovers its own assignment from the coordinator', async () => {
    const clock = { now: 1_000_000 };
    const store = newStore(clock);
    for (const role of ['sn1', 'sn2', 'sn3']) await coordinator(store, role).claim();

    // Process restart: a brand-new coordinator instance with empty memory, same
    // shared store. It must get exactly its previous shards back and release
    // nothing belonging to a peer.
    clock.now += 10_000;
    const restarted = coordinator(store, 'sn2');
    const claim = await restarted.claim();
    assert.deepEqual(claim.shardIds, [1, 4]);

    const rows = await store.listAssignments();
    assert.equal(rows.length, 6, 'no shard is dropped by a restart');
    assert.equal(rows.filter(r => r.ownerRole === 'sn1').length, 2);
    assert.equal(rows.filter(r => r.ownerRole === 'sn3').length, 2);
});

test('a node outside the plan owns nothing and reports standby', async () => {
    const clock = { now: 1_000_000 };
    const store = newStore(clock);
    for (const role of ['sn1', 'sn2', 'sn3']) await coordinator(store, role).claim();

    const cfg = resolveShardConfig({ SHARD_COUNT: '6', SHARD_NODES: 'sn1,sn2,sn3' }, { role: 'sn4' });
    const extra = coordinator(store, 'sn4', cfg);
    const claim = await extra.claim();
    assert.deepEqual(claim.shardIds, []);
    assert.equal(claim.reason, 'not_in_plan');
});

// ── 5: coordinator restart / recovery ────────────────────────────────────
test('a coordinator restart does not disturb existing ownership', async () => {
    const clock = { now: 1_000_000 };
    const store = newStore(clock);
    for (const role of ['sn1', 'sn2', 'sn3']) await coordinator(store, role).claim();
    const before = (await store.listAssignments()).map(a => `${a.shardId}:${a.ownerRole}:${a.epoch}`).sort();

    // Every node re-runs claim() from scratch (as it would after a deploy).
    for (const role of ['sn1', 'sn2', 'sn3']) await coordinator(store, role).claim();
    const after = (await store.listAssignments()).map(a => `${a.shardId}:${a.ownerRole}:${a.epoch}`).sort();
    assert.deepEqual(after, before, 'same owners, same epochs — no churn');
});

// ── 3: fleet status vocabulary ───────────────────────────────────────────
function nodeRow(overrides = {}) {
    return {
        role: 'sn1',
        nodeName: 'NR0008',
        ageMs: 2_000,
        shardIds: [0, 3],
        shardReady: 2,
        shardTotal: 2,
        guildCount: 20,
        memberCount: 2000,
        uptimeSeconds: 7200,
        ramMB: 210,
        cpuPercent: 12.5,
        lastHeartbeat: '2026-01-01T00:00:00Z',
        ...overrides,
    };
}

function fleet(rows, extra = {}) {
    return describeFleet({
        nodes: rows,
        assignments: rows.flatMap(r => (r.shardIds || []).map(id => ({ shardId: id, ownerRole: r.role, ageMs: r.ageMs }))),
        shardCount: 6,
        staleAfterMs: 90_000,
        ...extra,
    });
}

test('three healthy clusters are all active — never standby, never offline', () => {
    const result = fleet([
        nodeRow(),
        nodeRow({ role: 'sn2', nodeName: 'NU3049', shardIds: [1, 4] }),
        nodeRow({ role: 'sn3', nodeName: 'NUKN09', shardIds: [2, 5] }),
    ]);

    assert.deepEqual(result.clusters.map(c => c.label), ['Cluster 1', 'Cluster 2', 'Cluster 3']);
    assert.ok(result.clusters.every(c => c.health === 'online'));
    assert.ok(result.clusters.every(c => c.servingRole === 'active'));
    assert.ok(result.clusters.every(c => c.roleLabel === 'Active'));
    assert.equal(result.totals.clustersActive, 3);
    assert.equal(result.totals.clustersStandby, 0);
    assert.equal(result.totals.clustersOffline, 0);
    assert.equal(result.totals.shardsAssigned, 6);
    assert.equal(result.totals.shardsReady, 6);
    assert.equal(result.healthy, true);
    // Totals are sums of disjoint shard sets — no double counting.
    assert.equal(result.totals.guilds, 60);
    assert.equal(result.totals.guildsReliable, true);
});

test('one unreachable cluster is offline while the other two stay active', () => {
    const result = fleet([
        nodeRow(),
        nodeRow({ role: 'sn2', shardIds: [1, 4], ageMs: 5 * 60_000 }),
        nodeRow({ role: 'sn3', shardIds: [2, 5] }),
    ]);
    const byRole = Object.fromEntries(result.clusters.map(c => [c.role, c]));
    assert.equal(byRole.sn2.health, 'offline');
    assert.equal(byRole.sn2.healthLabel, 'Offline');
    assert.equal(byRole.sn1.health, 'online');
    assert.equal(byRole.sn3.health, 'online');
    assert.equal(result.totals.clustersOffline, 1);
    assert.equal(result.totals.clustersActive, 3, 'role stays active — it still owns shards');
    assert.equal(result.healthy, false);
});

test('degraded and stale telemetry are reported honestly', () => {
    const degraded = fleet([nodeRow({ shardReady: 1, shardTotal: 2 })]);
    assert.equal(degraded.clusters[0].health, 'degraded');
    assert.equal(degraded.clusters[0].servingRole, 'active', 'degraded is not standby');

    const stale = fleet([nodeRow({ ageMs: 60_000 })]); // between stale/2 and stale
    assert.equal(stale.clusters[0].health, 'stale');
    assert.equal(stale.clusters[0].healthLabel, 'Stale data');

    const never = fleet([nodeRow({ ageMs: null })]);
    assert.equal(never.clusters[0].health, 'never');
    assert.equal(never.clusters[0].healthLabel, 'No data');
    assert.equal(never.healthy, false, 'missing data is never healthy');
});

test('a cluster with no shards is the only genuine standby', () => {
    const result = fleet([
        nodeRow(),
        nodeRow({ role: 'sn2', shardIds: [], shardReady: 0, shardTotal: 0 }),
    ]);
    const byRole = Object.fromEntries(result.clusters.map(c => [c.role, c]));
    assert.equal(byRole.sn1.servingRole, 'active');
    assert.equal(byRole.sn2.servingRole, 'standby');
    assert.equal(byRole.sn2.roleLabel, 'Standby');
    assert.equal(byRole.sn2.health, 'online', 'idle but alive is online');
    assert.equal(result.totals.clustersActive, 1);
    assert.equal(result.totals.clustersStandby, 1);
});

test('missing RAM/CPU metrics degrade to null instead of zero', () => {
    const result = fleet([nodeRow({ ramMB: null, cpuPercent: null })]);
    assert.equal(result.clusters[0].ramMB, null);
    assert.equal(result.clusters[0].cpuPercent, null);
    assert.equal(result.clusters[0].health, 'online');
});

test('a shard owned twice is flagged and the guild total is not trusted', () => {
    const result = fleet([
        nodeRow(),
        nodeRow({ role: 'sn2', shardIds: [0, 4] }), // 0 duplicated
    ]);
    assert.equal(result.duplicates.length, 1);
    assert.equal(result.duplicates[0].shardId, 0);
    assert.equal(result.totals.duplicates, 1);
    assert.equal(result.totals.guildsReliable, false);
    assert.equal(result.healthy, false);
});

test('clusterLabel maps roles to Cluster 1..3 and keeps unknown roles stable', () => {
    assert.equal(clusterLabel('sn1'), 'Cluster 1');
    assert.equal(clusterLabel('sn2'), 'Cluster 2');
    assert.equal(clusterLabel('sn3'), 'Cluster 3');
    assert.equal(clusterLabel('sn9'), 'sn9');
    assert.equal(clusterLabel(null, 3), 'Cluster 4');
});

// ── dashboard API (same aggregation as the command) ──────────────────────
test('getNodeStats returns the shared fleet shape from the season pool', async () => {
    const rows = [
        { role: 'sn1', node_name: 'NR0008', age_ms: 1500, shard_ids: [0, 3], shard_ready: 2, shard_total: 2, guild_count: 18, member_count: 900, uptime_s: 3600, cpu_pct: 8.2, ram_mb: 190, ram_total_mb: 512, pid: 11, version: '3.2.0', last_heartbeat: '2026-01-01T00:00:00Z', heartbeat_interval_ms: 30000 },
        { role: 'sn2', node_name: 'NU3049', age_ms: 2000, shard_ids: [1, 4], shard_ready: 2, shard_total: 2, guild_count: 17, member_count: 850, uptime_s: 3500, cpu_pct: null, ram_mb: null, ram_total_mb: 512, pid: 12, version: '3.2.0', last_heartbeat: '2026-01-01T00:00:00Z', heartbeat_interval_ms: 30000 },
        { role: 'sn3', node_name: 'NUKN09', age_ms: 2100, shard_ids: [2, 5], shard_ready: 2, shard_total: 2, guild_count: 16, member_count: 800, uptime_s: 3400, cpu_pct: 5.1, ram_mb: 205, ram_total_mb: 512, pid: 13, version: '3.2.0', last_heartbeat: '2026-01-01T00:00:00Z', heartbeat_interval_ms: 30000 },
    ];
    const assignments = [0, 1, 2, 3, 4, 5].map(id => ({ shard_id: id, owner_role: ['sn1', 'sn2', 'sn3'][id % 3], owner_node: 'n', epoch: 2, age_ms: 1500 }));
    const calls = [];
    const fakePool = {
        query: async (sql) => {
            calls.push(sql);
            if (/FROM bot_node_status/.test(sql)) return { rows };
            if (/FROM bot_shard_assignment/.test(sql)) return { rows: assignments };
            return { rows: [] };
        },
    };
    const seasonPath = require.resolve('../server/seasonDb');
    const previous = require.cache[seasonPath];
    require.cache[seasonPath] = {
        id: seasonPath, filename: seasonPath, loaded: true, exports: { seasonPool: fakePool, seasonDb: {}, testSeasonConnection: async () => {} },
    };
    try {
        const dbPath = require.resolve('../dashboard/db');
        delete require.cache[dbPath];
        const db = require('../dashboard/db');
        const stats = await db.getNodeStats();

        assert.equal(stats.nodes.length, 3);
        assert.deepEqual(stats.nodes.map(n => n.label), ['Cluster 1', 'Cluster 2', 'Cluster 3']);
        assert.ok(stats.nodes.every(n => n.servingRole === 'active'));
        assert.deepEqual(stats.nodes[0].shardIds, [0, 3]);
        assert.equal(stats.totals.guilds, 51);
        assert.equal(stats.totals.shardsAssigned, 6);
        assert.equal(stats.shardCount, 6);
        assert.equal(stats.healthy, true);
        assert.equal(stats.nodes[1].ramMB, null, 'a missing metric is null, not zero');
        assert.ok(calls.some(sql => /bot_shard_assignment/.test(sql)));
    } finally {
        if (previous) require.cache[seasonPath] = previous; else delete require.cache[seasonPath];
        delete require.cache[require.resolve('../dashboard/db')];
    }
});

// ── 6: wiring — command, dashboard and bot agree ─────────────────────────
test('the stats command and the dashboard share one aggregation module', () => {
    const command = fs.readFileSync(path.join(ROOT, 'events/messageCreate.js'), 'utf8');
    const dashboard = fs.readFileSync(path.join(ROOT, 'dashboard/db.js'), 'utf8');

    assert.match(command, /require\('\.\.\/utils\/sharding\/status'\)/, 'the command uses the shared fleet module');
    assert.match(dashboard, /require\('\.\.\/utils\/sharding\/status'\)/, 'the dashboard uses the same module');
    assert.match(command, /describeFleet\(/, 'the command aggregates with describeFleet');
    assert.match(dashboard, /describeFleet\(/, 'the dashboard aggregates with describeFleet');
});

test('the bot claims shards before login and limits the client to them', () => {
    const index = fs.readFileSync(path.join(ROOT, 'index.js'), 'utf8');
    assert.match(index, /createShardRuntime/, 'index.js creates the shard runtime');
    assert.match(index, /shardRuntime\.claim\(\)/, 'shards are claimed before connecting');
    assert.match(index, /shardRuntime\.applyToClient\(client\)/, 'the claimed set is applied to the client');
    assert.match(index, /startShardHeartbeatLoop/, 'the shard heartbeat publishes telemetry');
    assert.match(index, /startShardStandby/, 'a shardless node stands by instead of crashing');
    assert.ok(
        index.indexOf('shardRuntime.applyToClient(client)') < index.indexOf('await client.login(resolvedToken)'),
        'the shard list is set BEFORE login',
    );
});

test('node role is derived from shard ownership, not from a single-active lease', () => {
    const worker = fs.readFileSync(path.join(ROOT, 'utils/statusWorker.js'), 'utf8');
    assert.match(worker, /if \(Number\(p\.shardsTotal\) > 0\) return true;/, 'a node with shards is active');
    assert.match(worker, /sn1: 'Cluster 1'/, 'user-facing labels say Cluster');
    assert.doesNotMatch(worker, /'Shard Node 1'/, 'the old Node wording is gone');
});

test('the dashboard status page uses Cluster wording and never labels a serving node standby', () => {
    const page = fs.readFileSync(path.join(ROOT, 'dashboard/public/js/status.js'), 'utf8');
    assert.match(page, /Clusters online/);
    assert.doesNotMatch(page, /Nodes online/);
    assert.match(page, /Most reliable cluster/);
    assert.match(page, /n\.isActive \? 'Active' : 'Standby'/);
    assert.match(page, /n\.shardIds/, 'the card shows the owned shard ids');
});

test('the shared status module keeps Node.js out of its user-facing labels', () => {
    const status = fs.readFileSync(path.join(ROOT, 'utils/sharding/status.js'), 'utf8');
    assert.match(status, /Cluster \$\{/);
    assert.doesNotMatch(status, /'Node ' \+/);
});
