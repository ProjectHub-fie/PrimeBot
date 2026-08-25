// Live member-count bridge tests.
//
// The dashboard runs as a separate process and can't read the bot's
// client.guilds.cache, so the bot publishes its live guild/member counts on
// the failover heartbeat row (bot_node_status.guild_count / member_count) and
// the dashboard's getPlatformStats prefers those over the leveling-tracked
// distinct user count. These tests stub the season DB (same justified-mock
// pattern as serverSettingsInit.test.js / botRoles.test.js — no Postgres in CI)
// and assert both ends of the bridge.

const test = require('node:test');
const assert = require('node:assert/strict');
const { PgDialect } = require('drizzle-orm/pg-core');

const dialect = new PgDialect();

function stubModule(relPath, exports) {
    const p = require.resolve(relPath);
    require.cache[p] = { id: p, filename: p, loaded: true, exports };
}

function makeFakeSeasonDb() {
    const statements = [];
    return {
        statements,
        seasonDb: {
            execute: async (q) => {
                const { sql, params } = dialect.sqlToQuery(q);
                statements.push({ sql, params });
                return { rows: [], rowCount: 1 };
            },
        },
        seasonPool: { query: async () => ({ rows: [] }) },
    };
}

function freshNodeFailover(fake) {
    stubModule('../server/seasonDb', fake);
    delete require.cache[require.resolve('../utils/nodeFailover')];
    return require('../utils/nodeFailover');
}

test('writeHeartbeat stores live guild/member counts from the stats provider', async () => {
    const fake = makeFakeSeasonDb();
    const nodeFailover = freshNodeFailover(fake);
    nodeFailover.setStatsProvider(() => ({ guildCount: 7, memberCount: 1234 }));

    await nodeFailover.writeHeartbeat('sn1', true);

    const insert = fake.statements.find((s) => s.sql.includes('INSERT INTO bot_node_status'));
    assert.ok(insert, 'heartbeat upsert executed');
    assert.ok(insert.sql.includes('guild_count'), 'upsert covers guild_count');
    assert.ok(insert.sql.includes('member_count'), 'upsert covers member_count');
    assert.ok(insert.params.includes(7), 'upsert params include the guild count');
    assert.ok(insert.params.includes(1234), 'upsert params include the member count');

    // ensureTable self-migrates the live-stats columns onto older tables.
    assert.ok(
        fake.statements.some((s) => s.sql.includes('ADD COLUMN IF NOT EXISTS member_count')),
        'member_count column self-migrated'
    );

    nodeFailover.setStatsProvider(null);
});

test('a failing stats provider never breaks the heartbeat (counts stored as NULL)', async () => {
    const fake = makeFakeSeasonDb();
    const nodeFailover = freshNodeFailover(fake);
    nodeFailover.setStatsProvider(() => { throw new Error('client cache gone'); });

    await nodeFailover.writeHeartbeat('sn2', true);

    const insert = fake.statements.find((s) => s.sql.includes('INSERT INTO bot_node_status'));
    assert.ok(insert, 'heartbeat upsert still executed');
    // params: role, nodeName, active, guildCount, memberCount
    assert.equal(insert.params[3], null);
    assert.equal(insert.params[4], null);

    nodeFailover.setStatsProvider(null);
});

// ── dashboard side: getPlatformStats prefers the live counts ────────────────

function countPool(count) {
    return { query: async () => ({ rows: [{ count }] }) };
}

function stubDashboardPools({ liveRow }) {
    stubModule('../server/db', { pool: countPool(5) });
    stubModule('../server/welcomeDb', { welcomePool: countPool(1) });
    stubModule('../server/automodDb', { automodPool: countPool(1) });
    stubModule('../server/ticketDb', { ticketPool: countPool(1) });
    stubModule('../server/levelingDb', { levelingPool: countPool(42) });
    stubModule('../server/seasonDb', {
        seasonPool: {
            query: async (q) => {
                const text = String(q);
                if (text.includes('bot_node_status') && text.includes('member_count')) {
                    return { rows: liveRow ? [liveRow] : [] };
                }
                return { rows: [] };
            },
        },
    });
    delete require.cache[require.resolve('../dashboard/db')];
    return require('../dashboard/db');
}

test('getPlatformStats uses the live member count from the active bot node', async () => {
    const db = stubDashboardPools({ liveRow: { guild_count: 3, member_count: 9876 } });

    const stats = await db.getPlatformStats(null);

    assert.equal(stats.totalUsers, 9876, 'real member count wins over the leveling fallback');
    assert.equal(stats.totalUsersSource, 'bot');
    assert.equal(stats.servers, 3, 'live guild count beats the lazy server_settings row count');
});

test('getPlatformStats falls back to the leveling user count when the bot is not reporting', async () => {
    const db = stubDashboardPools({ liveRow: null });

    const stats = await db.getPlatformStats(null);

    assert.equal(stats.totalUsers, 42);
    assert.equal(stats.totalUsersSource, 'leveling');
    assert.equal(stats.servers, 5, 'falls back to the server_settings row count');
});

test('an explicit server-count override (Discord REST) still wins', async () => {
    const db = stubDashboardPools({ liveRow: { guild_count: 3, member_count: 9876 } });

    const stats = await db.getPlatformStats(9);

    assert.equal(stats.servers, 9);
    assert.equal(stats.totalUsers, 9876);
});
