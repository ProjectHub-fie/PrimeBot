// Static shard assignment (the default).
//
// Every host derives its shard set from SHARD_COUNT + SHARD_NODES + NODE_ROLE,
// so no shared table has to be reachable for a node to serve. That removes the
// whole class of "all nodes standing by because the coordinator is down".

const test = require('node:test');
const assert = require('node:assert/strict');

const { createShardRuntime } = require('../utils/sharding/runtime');
const { resolveShardConfig } = require('../utils/sharding/config');

const SILENT = { log() {}, warn() {}, error() {} };
const ENV = {
    SHARD_COUNT: '3',
    SHARD_NODES: 'sn1,sn2,sn3',
    SHARD_HEARTBEAT_INTERVAL_MS: '30000',
    SHARD_LEASE_MS: '90000',
};

function explodingStore() {
    const boom = async () => { throw new Error('shard table unreachable'); };
    return {
        ensureTables: boom, listNodes: boom, listAssignments: boom,
        claim: boom, renew: boom, release: boom,
    };
}

function runtime(env, store) {
    return createShardRuntime({ env, store, logger: SILENT, client: { options: {} } });
}

test('static is the default mode', () => {
    const cfg = resolveShardConfig({ ...ENV, NODE_ROLE: 'sn2' }, { role: 'sn2' });
    assert.equal(cfg.mode, 'static');
    assert.equal(cfg.isStatic, true);
    // Opting into the coordinator is explicit.
    const dynamic = resolveShardConfig({ ...ENV, NODE_ROLE: 'sn2', SHARD_MODE: 'dynamic' }, { role: 'sn2' });
    assert.equal(dynamic.mode, 'dynamic');
    assert.equal(dynamic.isStatic, false);
});

test('each role serves its own shard without touching the shard table', async () => {
    for (const [role, expected] of [['sn1', [0]], ['sn2', [1]], ['sn3', [2]]]) {
        const rt = runtime({ ...ENV, NODE_ROLE: role }, explodingStore());
        const claim = await rt.claim();
        assert.deepEqual(claim.shardIds, expected, role);
        assert.equal(claim.reason, 'static');
        assert.equal(rt.config.isStatic, true);
    }
});

test('static mode never creates a coordinator or a renew timer', async () => {
    const rt = runtime({ ...ENV, NODE_ROLE: 'sn1' }, explodingStore());
    assert.equal(rt.coordinator, null);
    assert.equal(rt.startLoop(), null);
    assert.deepEqual(await rt.release(), []);
    const snap = await rt.snapshot();
    assert.equal(snap.mode, 'static');
    assert.deepEqual(snap.owned, []);
    const check = await rt.checkStore();
    assert.equal(check.ok, true, 'no store needed');
    assert.equal(check.reason, 'static');
});

test('a role outside SHARD_NODES owns nothing and says so', async () => {
    const warnings = [];
    const rt = createShardRuntime({
        env: { ...ENV, NODE_ROLE: 'sn4' },
        store: explodingStore(),
        logger: { log() {}, warn: (m) => warnings.push(m), error() {} },
        client: { options: {} },
    });
    const claim = await rt.claim();
    assert.deepEqual(claim.shardIds, []);
    assert.equal(claim.reason, 'static');
    assert.ok(warnings.some(w => /no shards in the static plan/.test(w)));
});

test('a larger fleet splits deterministically', async () => {
    const env = { ...ENV, SHARD_COUNT: '6', NODE_ROLE: 'sn2' };
    const rt = runtime(env, explodingStore());
    assert.deepEqual((await rt.claim()).shardIds, [1, 4]);
});

test('applyToClient hands discord.js the static shards', async () => {
    const client = { options: {} };
    const rt = createShardRuntime({ env: { ...ENV, NODE_ROLE: 'sn3' }, store: explodingStore(), logger: SILENT, client });
    await rt.claim();
    assert.equal(rt.applyToClient(), true);
    assert.deepEqual(client.options.shards, [2]);
    assert.equal(client.options.shardCount, 3);
});

test('dynamic mode still uses the coordinator when asked', async () => {
    const calls = [];
    const store = {
        ensureTables: async () => {},
        listNodes: async () => [],
        listAssignments: async () => [],
        claim: async (shardId, { role }) => { calls.push({ shardId, role }); return true; },
        renew: async () => [],
        release: async () => [],
    };
    const rt = createShardRuntime({ env: { ...ENV, NODE_ROLE: 'sn2', SHARD_MODE: 'dynamic' }, store, logger: SILENT, client: { options: {} } });
    assert.ok(rt.coordinator, 'coordinator exists in dynamic mode');
    const claim = await rt.claim();
    assert.notEqual(claim.reason, 'static');
});
