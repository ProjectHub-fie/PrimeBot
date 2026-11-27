/**
 * Active-active fleet convergence.
 *
 * The three hosting panels give every host the SAME `NODE_NAME` and, unless
 * `NODE_ROLE` is set, the same default role (sn1). Three nodes that all think
 * they are sn1 plan the same shards, so only one of them can ever come online
 * and the other two stand by forever — the "all nodes aren't going online"
 * symptom. These tests pin the convergence rules:
 *
 *  - a node without `NODE_ROLE` adopts a free role instead of duplicating sn1;
 *  - a node that restarted with a smaller share releases its old shards;
 *  - a peer reclaims shards whose lease lapsed, even though the owner process
 *    is still alive (it is not serving them);
 *  - a live owner that never published its shard list is never preempted.
 */

const { test } = require('node:test');
const assert = require('node:assert');

const { ShardCoordinator, MemoryShardStore } = require('../utils/sharding/coordinator');
const { createShardRuntime } = require('../utils/sharding/runtime');

const BASE_ENV = {
    SHARD_COUNT: '6',
    SHARD_NODES: 'sn1,sn2,sn3',
    SHARD_LEASE_MS: '90000',
    SHARD_HEARTBEAT_INTERVAL_MS: '30000',
};

function makeEnv(extra = {}) {
    return { ...BASE_ENV, ...extra };
}

function makeStore(clock) {
    const store = new MemoryShardStore({ now: () => clock.now });
    return store;
}

function config(role, env = makeEnv()) {
    const { resolveShardConfig } = require('../utils/sharding/config');
    return resolveShardConfig(env, { role });
}

test('three hosts with no NODE_ROLE converge on sn1/sn2/sn3 and all serve', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv();
    const cfg = config('sn1', env);
    const stale = cfg.staleAfterMs;

    // All three boot as sn1 (NODE_ROLE unset) and heartbeat on the shared row.
    const runtimes = ['a', 'b', 'c'].map(() => createShardRuntime({
        env,
        store,
        logger: { log() {}, warn() {}, error() {} },
    }));

    // Simulate three separate processes: each has its own pid.
    const pids = [101, 202, 303];
    const claimed = [];
    for (let i = 0; i < runtimes.length; i++) {
        const runtime = runtimes[i];
        // Every process sees only the heartbeats written so far.
        const claim = await runtime.claim();
        claimed.push({ role: runtime.identity.role, shards: claim.shardIds });
        // Publish this node's heartbeat the way nodeFailover does.
        store.setNode(runtime.identity.role, {
            nodeName: 'CloudeWave',
            pid: pids[i],
            ageMs: 0,
            shardIds: claim.shardIds,
        });
        clock.now += 1_000;
    }

    assert.deepEqual(claimed.map(c => c.role), ['sn1', 'sn2', 'sn3'], 'each node adopts a distinct role');
    const served = claimed.flatMap(c => c.shards).sort((a, b) => a - b);
    assert.deepEqual(served, [0, 1, 2, 3, 4, 5], 'the whole shard set is served by the fleet');

    // And no shard is owned twice.
    const rows = await store.listAssignments();
    const owners = new Map();
    for (const row of rows) {
        assert.ok(!owners.has(row.shardId), `shard ${row.shardId} claimed twice`);
        owners.set(row.shardId, row.ownerRole);
    }
    assert.equal(stale, cfg.staleAfterMs);
});

test('a node that restarted with a smaller share releases its old shards', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv();
    const cfg = config('sn1', env);

    // sn1 booted while its peers were down and absorbed every shard.
    store.setNode('sn1', { nodeName: 'sn1', pid: 1, shardIds: null });
    for (let shardId = 0; shardId < 6; shardId++) {
        await store.claim(shardId, { role: 'sn1', nodeName: 'sn1', staleAfterMs: cfg.staleAfterMs });
    }
    assert.equal((await store.listAssignments()).length, 6);

    // It restarts (fresh process, no in-memory `_owned`) and its lease lapses.
    clock.now += cfg.staleAfterMs + 1_000;
    const restarted = new ShardCoordinator({
        store,
        role: 'sn1',
        nodeName: 'sn1',
        config: { ...cfg, role: 'sn1' },
        logger: { log() {}, warn() {}, error() {} },
    });
    store.setNode('sn1', { nodeName: 'sn1', pid: 2, shardIds: [0, 3] });
    const after = await restarted.claim();
    assert.deepEqual(after.shardIds, [0, 3], 'the restarted node only serves its planned share');

    // The shards it no longer serves are released, so peers do not wait.
    const rows = await store.listAssignments();
    assert.deepEqual(rows.map(r => r.shardId).sort((a, b) => a - b), [0, 3]);
});

test('a peer reclaims shards whose owner is alive but no longer serving them', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv();
    const cfg = config('sn2', env);

    // sn1 holds shard 1 but its heartbeat says it serves only [0].
    store.setNode('sn1', { nodeName: 'sn1', pid: 11, ageMs: 0, shardIds: [0] });
    store.setNode('sn2', { nodeName: 'sn2', pid: 22, ageMs: 0, shardIds: null });
    store.setNode('sn3', { nodeName: 'sn3', pid: 33, ageMs: 0, shardIds: null });
    await store.claim(1, { role: 'sn1', nodeName: 'sn1', staleAfterMs: cfg.staleAfterMs });

    const sn2 = new ShardCoordinator({
        store, role: 'sn2', nodeName: 'sn2',
        config: { ...cfg, role: 'sn2' },
        logger: { log() {}, warn() {}, error() {} },
    });

    // Fresh lease: nothing is stolen, even though sn1 does not serve it.
    let claim = await sn2.claim();
    assert.ok(!claim.shardIds.includes(1), 'a renewed lease is never preempted');

    // Lease lapses while sn1 keeps heartbeating → the shard is not being served.
    clock.now += cfg.staleAfterMs + 1_000;
    store.setNode('sn1', { nodeName: 'sn1', pid: 11, ageMs: 0, shardIds: [0] });
    claim = await sn2.claim();
    assert.ok(claim.shardIds.includes(1), 'an unserved shard is reclaimed from a live peer');
});

test('a live owner that never published its shard list is never preempted', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv();
    const cfg = config('sn2', env);

    store.setNode('sn1', { nodeName: 'sn1', pid: 11, ageMs: 0, shardIds: null });
    store.setNode('sn2', { nodeName: 'sn2', pid: 22, ageMs: 0, shardIds: null });
    store.setNode('sn3', { nodeName: 'sn3', pid: 33, ageMs: 0, shardIds: null });
    await store.claim(1, { role: 'sn1', nodeName: 'sn1', staleAfterMs: cfg.staleAfterMs });

    const sn2 = new ShardCoordinator({
        store, role: 'sn2', nodeName: 'sn2',
        config: { ...cfg, role: 'sn2' },
        logger: { log() {}, warn() {}, error() {} },
    });
    // The lease lapses, but sn1 is still alive and we cannot see what it
    // serves — so its shards must be left alone.
    clock.now += cfg.staleAfterMs + 1_000;
    store.setNode('sn1', { nodeName: 'sn1', pid: 11, ageMs: 0, shardIds: null });
    const claim = await sn2.claim();
    assert.ok(!claim.shardIds.includes(1), 'unknown shard telemetry must never cause a steal');
});

test('an explicit NODE_ROLE is authoritative — no silent role adoption', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv({ NODE_ROLE: 'sn1' });
    const runtime = createShardRuntime({
        env, store, logger: { log() {}, warn() {}, error() {} },
    });

    // Another live process already owns sn1.
    store.setNode('sn1', { nodeName: 'CloudeWave', pid: 999, ageMs: 0, shardIds: [0, 3] });
    await runtime.claim();
    assert.equal(runtime.identity.role, 'sn1', 'an explicit role is never rewritten');
    assert.equal(runtime.explicitRole, true);
});

test('the operator is warned when a multi-node fleet runs without SHARD_COUNT', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    assert.match(src, /Active-active is OFF \(SHARD_COUNT is not set\)/);
    assert.match(src, /SHARD_COUNT=<total shards>/);
});

test('the standby loop re-negotiates the role on every tick', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const standby = src.slice(src.indexOf('function startShardStandby'));
    assert.match(standby, /shardRuntime\.claim\(\)/, 'the standby tick claims (and negotiates) again');
    assert.match(standby, /startShardHeartbeat\(\)/, 'the heartbeat follows the adopted role');
});

test('the adopted role is published to the environment and to the pulse', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv();
    const runtime = createShardRuntime({ env, store, logger: { log() {}, warn() {}, error() {} } });

    // Another live process already owns sn1 (different pid → a peer).
    store.setNode('sn1', { nodeName: 'CloudeWave', pid: 999, ageMs: 0, shardIds: [0, 3] });
    await runtime.claim();
    assert.equal(runtime.identity.role, 'sn2');
    assert.equal(env.NODE_ROLE, 'sn2', 'the environment follows the adopted role');

    const { buildPulse } = require('../utils/monitorPulse');
    const prev = process.env.NODE_ROLE;
    process.env.NODE_ROLE = 'sn2';
    try {
        assert.equal(buildPulse({ user: null }).role, 'sn2', 'the pulse reports the served role');
    } finally {
        if (prev === undefined) delete process.env.NODE_ROLE;
        else process.env.NODE_ROLE = prev;
    }
});

test('a duplicate explicit NODE_ROLE is reported once, with the fix', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv({ NODE_ROLE: 'sn1' });
    const warnings = [];
    const runtime = createShardRuntime({
        env, store,
        logger: { log() {}, warn: (msg) => warnings.push(msg), error() {} },
    });
    store.setNode('sn1', { nodeName: 'CloudeWave', pid: 999, ageMs: 0, shardIds: [0, 3] });

    await runtime.claim();
    await runtime.claim();
    const collisions = warnings.filter(w => w.includes('already served by another node'));
    assert.equal(collisions.length, 1, 'warned once, not on every tick');
    assert.match(collisions[0], /NODE_ROLE=sn1/);
    assert.match(collisions[0], /sn1\/sn2\/sn3/);
});

test('.env.example documents the sharding contract', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const env = fs.readFileSync(path.join(__dirname, '..', '.env.example'), 'utf8');
    for (const key of ['SHARD_COUNT', 'SHARD_NODES', 'NODE_ROLE', 'LAVALINK_NAME']) {
        assert.match(env, new RegExp(`# ${key}=`), `${key} must be documented`);
    }
    assert.match(env, /NODES CANNOT EXCEED SHARD_COUNT/);
    assert.match(env, /SINGLE-ACTIVE/);
});

test('serveAllShards() covers every shard so a broken store cannot black out the bot', async () => {
    const clock = { now: 1_000_000 };
    const store = makeStore(clock);
    const env = makeEnv({ SHARD_COUNT: '3' });
    const runtime = createShardRuntime({ env, store, logger: { log() {}, warn() {}, error() {} } });
    const client = { options: {} };

    assert.equal(runtime.serveAllShards(client), true);
    assert.deepEqual(runtime.shardIds, [0, 1, 2]);
    assert.deepEqual(client.options.shards, [0, 1, 2]);
    assert.equal(client.options.shardCount, 3);

    // Disabled (no SHARD_COUNT) stays inert.
    const off = createShardRuntime({ env: { ...BASE_ENV, SHARD_COUNT: '' }, store, logger: { log() {}, warn() {}, error() {} } });
    assert.equal(off.serveAllShards({ options: {} }), false);
});

test('a claim that cannot reach the store reports coordinator_error, not a crash', async () => {
    const broken = {
        async ensureTables() { throw new Error('ECONNREFUSED 5432'); },
        async listNodes() { throw new Error('ECONNREFUSED 5432'); },
        async listAssignments() { throw new Error('ECONNREFUSED 5432'); },
        async claim() { throw new Error('ECONNREFUSED 5432'); },
        async renew() { throw new Error('ECONNREFUSED 5432'); },
        async release() { throw new Error('ECONNREFUSED 5432'); },
    };
    const env = makeEnv({ SHARD_COUNT: '3' });
    const runtime = createShardRuntime({ env, store: broken, logger: { log() {}, warn() {}, error() {} } });

    const claim = await runtime.claim();
    assert.deepEqual(claim.shardIds, []);
    assert.equal(claim.reason, 'coordinator_error');
    assert.match(claim.error, /ECONNREFUSED/);

    const check = await runtime.checkStore();
    assert.equal(check.ok, false);
    assert.match(check.error, /ECONNREFUSED/);
});

test('index.js fails open on the primary role only', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');

    assert.match(src, /const primaryRole = shardRuntime\.config\.nodes\[0\];/);
    assert.match(src, /isPrimary && \(claim\.reason === 'coordinator_error' \|\| forced\)/);
    assert.match(src, /shardRuntime\.serveAllShards\(client\);/);
    assert.match(src, /SHARD_FAIL_OPEN/, 'a manual override exists');
    // The fail-open path must not also start the standby loop (it is serving).
    const block = src.slice(src.indexOf('const primaryRole = shardRuntime.config.nodes[0];'));
    const failOpen = block.slice(0, block.indexOf('shardRuntime.applyToClient(client);'));
    assert.ok(!/startShardStandby\(/.test(failOpen.replace(/} else \{[\s\S]*?\n                \}/, '')),
        'the serving branch must not stand by');
    assert.match(src, /shardRuntime\.checkStore\(\)/, 'boot logs whether the store is usable');
});
