// Fleet-wide counts in the bot's own surfaces.
//
// `client.guilds.cache.size` is only this shard's share, so the ready log,
// presence, /about, /stats and the mention card must read the fleet total from
// utils/fleetStats.js (Discord REST `/users/@me/guilds`, cached).
//
// No network: `client.rest.get` is stubbed with a paged guild list.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function freshFleetStats() {
    const p = require.resolve('../utils/fleetStats');
    delete require.cache[p];
    return require('../utils/fleetStats');
}

function shardedClient(pages, { shards = [1], shardCount = 3 } = {}) {
    const calls = [];
    return {
        calls,
        token: 'test-token',
        options: { shards, shardCount },
        guilds: { cache: new Map([['local-1', { memberCount: 10 }]]) },
        rest: {
            get: async (_route, opts) => {
                calls.push(String(opts?.query || ''));
                const after = opts?.query?.get?.('after') || '0';
                const page = pages[after] || [];
                return page;
            },
        },
    };
}

const guildRow = (id, members) => ({ id, approximate_member_count: members });

test('unsharded clients read the cache and never call REST', async () => {
    const { getFleetCounts } = freshFleetStats();
    const client = shardedClient({}, { shards: [0], shardCount: 1 });
    const counts = await getFleetCounts(client, { force: true });
    assert.equal(counts.guilds, 1);
    assert.equal(counts.members, 10);
    assert.equal(counts.source, 'cache');
    assert.equal(client.calls.length, 0);
});

test('a sharded client sums every page of /users/@me/guilds', async () => {
    const { getFleetCounts } = freshFleetStats();
    const fullPage = Array.from({ length: 200 }, (_, i) => guildRow(String(1000 + i), 2));
    const client = shardedClient({ 0: fullPage, 1199: [guildRow('2000', 5)] });
    const counts = await getFleetCounts(client, { force: true });
    assert.equal(counts.guilds, 201);
    assert.equal(counts.members, 200 * 2 + 5);
    assert.equal(counts.source, 'rest');
    assert.equal(client.calls.length, 2, 'paginates with the `after` cursor');
});

test('the fleet value is cached and the sync accessor never blocks', async () => {
    const { getFleetGuildCount, getFleetCounts } = freshFleetStats();
    const client = shardedClient({ 0: [guildRow('1', 1), guildRow('2', 1)] });
    await getFleetCounts(client, { force: true });
    const before = client.calls.length;
    assert.equal(getFleetGuildCount(client), 2);
    assert.equal(client.calls.length, before, 'a fresh cache issues no request');
});

test('a REST failure keeps the previous fleet value instead of reporting the shard', async () => {
    const { getFleetCounts } = freshFleetStats();
    const client = shardedClient({ 0: [guildRow('1', 1), guildRow('2', 1), guildRow('3', 1)] });
    assert.equal((await getFleetCounts(client, { force: true })).guilds, 3);
    client.rest.get = async () => { throw new Error('ECONNRESET'); };
    const after = await getFleetCounts(client, { force: true });
    assert.equal(after.guilds, 3, 'stale-but-known beats a wrong low number');
});

test('every count surface uses the fleet helper', () => {
    const files = {
        'events/ready.js': [/getFleetGuildCount\(client\)/, /getFleetCounts\(client, \{ force: true \}\)/],
        'commands/about.js': [/getFleetGuildCount\(interaction\.client\)/],
        'utils/mentionReply.js': [/getFleetGuildCount\(client\)/, /getFleetMemberCount\(client\)/],
        'events/messageCreate.js': [/getFleetGuildCount\(client\)\.toLocaleString\(\)/, /getFleetMemberCount\(client\)/],
        'utils/prefixHelp.js': [/fleetGuildCount\(client\)/],
        'index.js': [/getFleetGuildCount\(client\)\} servers \| \$help/],
    };
    for (const [file, patterns] of Object.entries(files)) {
        const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
        for (const re of patterns) assert.match(src, re, `${file} must use the fleet count`);
        assert.ok(!/guilds\.cache\.size\.toLocaleString/.test(src), `${file} must not print the shard share`);
    }
});

test('$stats never renders "NaN users"', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events/messageCreate.js'), 'utf8');
    assert.ok(!/reduce\(\(a, g\) => a \+ g\.memberCount, 0\)/.test(src), 'member sum must guard undefined');
    assert.match(src, /const localUsers = client\.guilds\.cache\.reduce\(\(a, g\) => a \+ \(g\.memberCount \|\| 0\), 0\);/);
});
