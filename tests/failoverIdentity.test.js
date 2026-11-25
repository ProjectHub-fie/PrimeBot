// Failover identity: a node owns the lease / is "the other active node" only
// when BOTH node name and role match. Hosting panels give every node the same
// NODE_NAME ("CloudeWave" in production), which made sn3 believe it already
// held sn1's lease and never notice sn1 — "sn3 online while sn1 is online".

const { test } = require('node:test');
const assert = require('node:assert/strict');

// Stub the season pool before utils/nodeFailover captures it.
const seasonDb = { execute: async () => ({ rows: [], rowCount: 0 }) };
const seasonDbPath = require.resolve('../server/seasonDb');
require.cache[seasonDbPath] = {
    id: seasonDbPath,
    filename: seasonDbPath,
    loaded: true,
    exports: { seasonDb },
};

const nodeFailover = require('../utils/nodeFailover');

function sqlText(query) {
    if (!query) return '';
    // Nested `sql` fragments (e.g. sql`${select} AND role != ...`) are SQL
    // instances with their own queryChunks, so recurse instead of printing '?'.
    if (!Array.isArray(query.queryChunks)) return String(query);
    const chunks = query.queryChunks;
    return chunks
        .map((chunk) => {
            if (typeof chunk === 'string') return chunk;
            if (chunk && Array.isArray(chunk.value)) return chunk.value.join('');
            if (chunk && chunk.queryChunks) return sqlText(chunk);
            return '?';
        })
        .join('');
}

function stubDb(routes) {
    const calls = [];
    seasonDb.execute = async (query) => {
        const text = sqlText(query);
        calls.push(text);
        for (const route of routes) {
            if (route.match(text)) return route.result(text, query);
        }
        return { rows: [], rowCount: 0 };
    };
    return calls;
}

const HOLDER_SN1 = {
    match: (t) => t.includes('FROM bot_failover_lock') && t.includes('SELECT'),
    result: () => ({
        rows: [{ owner_node_name: 'CloudeWave', owner_role: 'sn1', age_ms: 1000 }],
    }),
};

const FRESH_SN1_HEARTBEAT = {
    match: (t) => t.includes('FROM bot_node_status'),
    result: () => ({
        rows: [{
            node_name: 'CloudeWave',
            active: true,
            age_ms: 5000,
            heartbeat_interval_ms: 30000,
        }],
    }),
};

test('sn3 with the same node name does not adopt sn1\'s lease', async () => {
    const calls = stubDb([
        { match: (t) => t.includes('INSERT INTO bot_failover_lock'), result: () => ({ rowCount: 0 }) },
        HOLDER_SN1,
        FRESH_SN1_HEARTBEAT,
    ]);

    const result = await nodeFailover.acquireLease('sn3', 'CloudeWave');

    assert.equal(result.acquired, false, 'sn3 must stand by, not reuse sn1\'s lease');
    assert.equal(result.ownerRole, 'sn1');
    assert.ok(
        !calls.some((c) => c.includes('UPDATE bot_failover_lock')),
        'sn3 must not touch a lease it does not own'
    );
});

test('a node reuses the lease only when name AND role match', async () => {
    stubDb([
        { match: (t) => t.includes('INSERT INTO bot_failover_lock'), result: () => ({ rowCount: 0 }) },
        {
            match: (t) => t.includes('FROM bot_failover_lock') && t.includes('SELECT'),
            result: () => ({
                rows: [{ owner_node_name: 'CloudeWave', owner_role: 'sn3', age_ms: 1000 }],
            }),
        },
        FRESH_SN1_HEARTBEAT,
    ]);

    const result = await nodeFailover.acquireLease('sn3', 'CloudeWave');
    assert.equal(result.acquired, true);
    assert.equal(result.stolen, false);
});

test('a returning sn1 reclaims the lease from sn3 even with a shared node name', async () => {
    stubDb([
        { match: (t) => t.includes('INSERT INTO bot_failover_lock'), result: () => ({ rowCount: 0 }) },
        {
            match: (t) => t.includes('FROM bot_failover_lock') && t.includes('SELECT'),
            result: () => ({
                rows: [{ owner_node_name: 'CloudeWave', owner_role: 'sn3', age_ms: 1000 }],
            }),
        },
        FRESH_SN1_HEARTBEAT,
    ]);

    const result = await nodeFailover.acquireLease('sn1', 'CloudeWave');
    assert.equal(result.acquired, true);
    assert.equal(result.stolen, true);
});

test('getOtherActiveNode finds a live higher-priority node that shares our name', async () => {
    stubDb([{
        match: (t) => t.includes('FROM bot_node_status'),
        result: () => ({
            rows: [{
                role: 'sn1',
                node_name: 'CloudeWave',
                active: true,
                age_ms: 4000,
                heartbeat_interval_ms: 30000,
            }],
        }),
    }]);

    const other = await nodeFailover.getOtherActiveNode('CloudeWave', 'sn3');
    assert.ok(other, 'sn3 must see sn1 as an active node despite the shared name');
    assert.equal(other.role, 'sn1');
});

test('getOtherActiveNode ignores a lower-priority node', async () => {
    stubDb([{
        match: (t) => t.includes('FROM bot_node_status'),
        result: () => ({
            rows: [{
                role: 'sn3',
                node_name: 'CloudeWave',
                active: true,
                age_ms: 4000,
                heartbeat_interval_ms: 30000,
            }],
        }),
    }]);

    assert.equal(await nodeFailover.getOtherActiveNode('CloudeWave', 'sn1'), null);
});

test('isLeaseHeldByHigherPriority ignores a lease that shares our name but not our role', async () => {
    stubDb([{
        match: (t) => t.includes('FROM bot_failover_lock') && t.includes('SELECT'),
        result: () => ({
            rows: [{ owner_node_name: 'CloudeWave', owner_role: 'sn1', age_ms: 1000 }],
        }),
    }]);

    assert.equal(
        await nodeFailover.isLeaseHeldByHigherPriority('sn3', 'CloudeWave'),
        true,
        'sn1 holding the lease must make sn3 step down'
    );
});

test('isLeaseHeldByHigherPriority treats our own name+role as ours', async () => {
    stubDb([{
        match: (t) => t.includes('FROM bot_failover_lock') && t.includes('SELECT'),
        result: () => ({
            rows: [{ owner_node_name: 'CloudeWave', owner_role: 'sn3', age_ms: 1000 }],
        }),
    }]);

    assert.equal(await nodeFailover.isLeaseHeldByHigherPriority('sn3', 'CloudeWave'), false);
});

test('a reclaim reports who it took the lease from', async () => {
    stubDb([
        { match: (t) => t.includes('INSERT INTO bot_failover_lock'), result: () => ({ rowCount: 0 }) },
        {
            match: (t) => t.includes('FROM bot_failover_lock') && t.includes('SELECT'),
            result: () => ({
                rows: [{ owner_node_name: 'CloudeWave', owner_role: 'sn3', age_ms: 1000 }],
            }),
        },
        FRESH_SN1_HEARTBEAT,
    ]);

    const result = await nodeFailover.acquireLease('sn1', 'CloudeWave');
    assert.deepEqual(result.previousOwner, { nodeName: 'CloudeWave', role: 'sn3' });
});

test('waitForNodeInactive returns as soon as the peer reports inactive', async () => {
    stubDb([{
        match: (t) => t.includes('FROM bot_node_status'),
        result: () => ({ rows: [{ role: 'sn3', active: false, age_ms: 1000, heartbeat_interval_ms: 30000 }] }),
    }]);

    assert.equal(await nodeFailover.waitForNodeInactive('sn3', { timeoutMs: 1000 }), true);
});

test('waitForNodeInactive treats a stale heartbeat as gone', async () => {
    stubDb([{
        match: (t) => t.includes('FROM bot_node_status'),
        result: () => ({ rows: [{ role: 'sn3', active: true, age_ms: 120000, heartbeat_interval_ms: 30000 }] }),
    }]);

    assert.equal(await nodeFailover.waitForNodeInactive('sn3', { timeoutMs: 1000 }), true);
});

test('waitForNodeInactive times out while the peer is still active', async () => {
    stubDb([{
        match: (t) => t.includes('FROM bot_node_status'),
        result: () => ({ rows: [{ role: 'sn3', active: true, age_ms: 1000, heartbeat_interval_ms: 30000 }] }),
    }]);

    assert.equal(
        await nodeFailover.waitForNodeInactive('sn3', { timeoutMs: 120, intervalMs: 20 }),
        false,
        'a live peer must keep the taker waiting (bounded)'
    );
});

test('waitForNodeInactive never blocks a takeover on a status read failure', async () => {
    seasonDb.execute = async () => { throw new Error('db down'); };
    assert.equal(await nodeFailover.waitForNodeInactive('sn3', { timeoutMs: 100 }), true);
});
