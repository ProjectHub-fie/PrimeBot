// Fleet server/member counts under active-active sharding.
//
// Each node serves a DISJOINT shard set, so its heartbeat `guild_count` is only
// its share. The dashboard must SUM the serving nodes — reading one row (or
// summing a node that has stepped down) reports a fraction of the bot, which is
// what "24 servers instead of 63" looked like in production.
//
// The season pool is stubbed (same justified-mock pattern as
// liveMemberCount.test.js — there is no Postgres in CI).

const test = require('node:test');
const assert = require('node:assert/strict');

function stubModule(relPath, exports) {
    const p = require.resolve(relPath);
    require.cache[p] = { id: p, filename: p, loaded: true, exports };
}

function loadDbWithRows(rows) {
    const queries = [];
    stubModule('../server/seasonDb', {
        seasonPool: {
            query: async (text) => {
                queries.push(String(text));
                if (String(text).includes('FROM bot_node_status')) return { rows };
                return { rows: [] };
            },
        },
        seasonDb: { execute: async () => ({ rows: [] }) },
    });
    for (const mod of ['../dashboard/db']) delete require.cache[require.resolve(mod)];
    return { db: require('../dashboard/db'), queries };
}

const node = (role, guildCount, memberCount, extra = {}) => ({
    role,
    node_name: 'CloudeWave',
    guild_count: guildCount,
    member_count: memberCount,
    active: true,
    age_ms: 1200,
    ...extra,
});

test('the fleet total is the SUM of every serving node', async () => {
    const { db } = loadDbWithRows([
        node('sn1', 23, 3000),
        node('sn2', 17, 2000),
        node('sn3', 23, 2500),
    ]);
    const stats = await db.getPlatformStats(null, null);
    assert.equal(stats.servers, 63);
    assert.equal(stats.serversSource, 'bot');
    assert.equal(stats.totalUsers, 7500);
    assert.equal(stats.liveNodes.length, 3);
    assert.deepEqual(stats.liveNodes.map(n => n.role), ['sn1', 'sn2', 'sn3']);
    assert.deepEqual(stats.liveNodes.map(n => n.guildCount), [23, 17, 23]);
});

test('a node that has stepped down never contributes its stale count', async () => {
    const { db } = loadDbWithRows([
        node('sn1', 63, 7500),                      // serving everything
        node('sn2', 17, 2000, { active: false }),   // stood down, cached count
        node('sn3', 0, 0, { active: false }),
    ]);
    const stats = await db.getPlatformStats(null, null);
    assert.equal(stats.servers, 63, 'only the serving node counts');
    assert.equal(stats.totalUsers, 7500);
    assert.equal(stats.liveNodes.find(n => n.role === 'sn2').guildCount, null);
});

test('a single active node still reports its own total (no sharding)', async () => {
    const { db } = loadDbWithRows([node('sn1', 63, 7500)]);
    const stats = await db.getPlatformStats(null, null);
    assert.equal(stats.servers, 63);
    assert.equal(stats.serversSource, 'bot');
    assert.equal(stats.liveNodes.length, 1);
});

test('no fresh heartbeat falls back to the DB row count and says so', async () => {
    const { db } = loadDbWithRows([]);
    const stats = await db.getPlatformStats(null, null);
    assert.equal(stats.serversSource, 'db');
    assert.deepEqual(stats.liveNodes, []);
});

test('the REST count still wins for SERVERS, the live heartbeat for members', async () => {
    const { db } = loadDbWithRows([node('sn1', 23, 3000)]);
    const stats = await db.getPlatformStats(63, 7500);
    assert.equal(stats.servers, 63, 'Discord REST is authoritative for guilds');
    assert.equal(stats.serversSource, 'rest');
    // The heartbeat is fresher than a REST member sum, so it keeps precedence.
    assert.equal(stats.totalUsers, 3000);
    assert.equal(stats.totalUsersSource, 'bot');
});
