// Member-count fallback: the dashboard stats "Total members" card previously
// fell straight to the leveling distinct-user count when the bot's heartbeat
// wasn't reporting (e.g. showed 320 instead of the real 4318). Now the REST
// fallback (getBotMemberCount — sums guild.approximate_member_count, the REST
// equivalent of discord.js `guild.memberCount`) sits between the heartbeat and
// the leveling fallback.
//
// The season DB is stubbed (same justified-mock pattern as
// liveMemberCount.test.js) so no real Postgres/env DB leaks into the tests.

const test = require('node:test');
const assert = require('node:assert/strict');

function stubModule(relPath, exports) {
    const p = require.resolve(relPath);
    require.cache[p] = { id: p, filename: p, loaded: true, exports };
}

// Block any live heartbeat answer: season pool queries always fail → _liveBotCounts → null.
stubModule('../server/seasonDb', {
    seasonDb: { execute: async () => { throw new Error('no db'); } },
    seasonPool: { query: async () => { throw new Error('no db'); } },
});

const dashboardDb = require('../dashboard/db');
const discord = require('../dashboard/discord');

// ── getPlatformStats source selection ───────────────────────────────────────

test('REST member-count override wins over any fallback', async () => {
    const stats = await dashboardDb.getPlatformStats(null, 4318);
    assert.equal(stats.totalUsers, 4318);
    assert.equal(stats.totalUsersSource, 'rest');
});

test('without any Discord count totalUsers is null (never the leveling count)', async () => {
    const stats = await dashboardDb.getPlatformStats(null, null);
    assert.equal(stats.totalUsers, null);
    assert.equal(stats.totalUsersSource, null);
});

test('an explicit server-count override (Discord REST) still wins', async () => {
    const db = stubDashboardWithLiveRow({ guild_count: 3, member_count: 9876 });
    const stats = await db.getPlatformStats(9);
    assert.equal(stats.servers, 9);
    assert.equal(stats.totalUsers, 9876);
});

// ── guild_count is independent of member_count ─────────────────────────────
//
// The heartbeat row carries guild_count + member_count, but they are written
// independently: a node can report a guild count while member_count is NULL
// (pre-upgrade row, or the member half of the provider failed). The old query
// required member_count IS NOT NULL, which discarded a perfectly good guild
// count and silently dropped the server number to the lazy server_settings row
// count — the dashboard then showed fewer servers than Discord does.

function stubDashboardWithLiveRow(liveRow) {
    const countPool = (count) => ({ query: async () => ({ rows: [{ count }] }) });
    // The main pool serves the server_settings adoption aggregate (one row with
    // four FILTERed counts). `_platformCounts` also reads totalServers from it.
    stubModule('../server/db', { pool: { query: async () => ({ rows: [{ total: 5, leveling: 5, auto_reactions: 0, broadcasts: 0 }] }) } });
    stubModule('../server/welcomeDb', { welcomePool: countPool(1) });
    stubModule('../server/automodDb', { automodPool: countPool(1) });
    stubModule('../server/ticketDb', { ticketPool: countPool(1) });
    stubModule('../server/levelingDb', { levelingPool: countPool(42) });
    stubModule('../server/seasonDb', {
        seasonPool: {
            query: async (q) => {
                const text = String(q);
                if (text.includes('bot_node_status')) return { rows: liveRow ? [liveRow] : [] };
                return { rows: [{ count: 5 }] };
            },
        },
    });
    delete require.cache[require.resolve('../dashboard/db')];
    return require('../dashboard/db');
}

test('a heartbeat with a guild count but no member count still reports servers', async () => {
    const db = stubDashboardWithLiveRow({ guild_count: 51, member_count: null });

    const stats = await db.getPlatformStats(null, null);

    assert.equal(stats.servers, 51, 'the live server count is used even without a member count');
    assert.equal(stats.serversSource, 'bot');
    // No Discord member count on this row → totalUsers is null (never leveling).
    assert.equal(stats.totalUsers, null);
    assert.equal(stats.totalUsersSource, null);
});

test('serversSource labels a DB-row fallback so a configured count is never passed off as the total', async () => {
    const db = stubDashboardWithLiveRow(null);

    const stats = await db.getPlatformStats(null, null);

    assert.equal(stats.serversSource, 'db');
    assert.equal(stats.servers, 5);
});

test('serversSource is rest when the Discord REST count was supplied', async () => {
    const db = stubDashboardWithLiveRow({ guild_count: 3, member_count: 9876 });

    const stats = await db.getPlatformStats(49, null);

    assert.equal(stats.servers, 49);
    assert.equal(stats.serversSource, 'rest');
});

// ── getBotMemberCount (global fetch mocked) ─────────────────────────────────

test('getBotMemberCount sums approximate_member_count across guild pages', async () => {
    // Page 1 = a full 200-guild page (paging continues), page 2 = short page (stops).
    const page1 = Array.from({ length: 200 }, (_, i) => ({ id: String(i + 1), approximate_member_count: 20 }));
    const page2 = [{ id: '201', approximate_member_count: 318 }, { id: '202', approximate_member_count: 7 }];
    const pages = [page1, page2];
    const origFetch = global.fetch;
    let calls = 0;
    global.fetch = async (url) => {
        const idx = url.includes('after=') ? 1 : 0;
        calls++;
        return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify(pages[idx]),
        };
    };
    try {
        delete require.cache[require.resolve('../dashboard/discord')];
        const fresh = require('../dashboard/discord');
        process.env.DISCORD_TOKEN = 'x';
        const total = await fresh.getBotMemberCount();
        assert.equal(total, 4325);
        assert.equal(calls, 2, 'paginated exactly twice then stopped on the short page');
    } finally {
        global.fetch = origFetch;
    }
});

test('getBotMemberCount returns null when Discord errors (callers fall back)', async () => {
    const origFetch = global.fetch;
    global.fetch = async () => ({ ok: false, status: 401, text: async () => '{}' });
    try {
        // Bust the module cache to force a fresh fetch (60s TTL).
        delete require.cache[require.resolve('../dashboard/discord')];
        const fresh = require('../dashboard/discord');
        const total = await fresh.getBotMemberCount();
        assert.equal(total, null);
    } finally {
        global.fetch = origFetch;
    }
});
