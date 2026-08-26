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

test('REST member-count override wins over the leveling fallback', async () => {
    const stats = await dashboardDb.getPlatformStats(null, 4318);
    assert.equal(stats.totalUsers, 4318);
    assert.equal(stats.totalUsersSource, 'rest');
});

test('without an override it degrades to the leveling count', async () => {
    const stats = await dashboardDb.getPlatformStats(null, null);
    assert.equal(stats.totalUsersSource, 'leveling');
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
