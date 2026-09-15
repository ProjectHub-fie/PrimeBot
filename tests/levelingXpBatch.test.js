// Regression tests for the batched XP writer.
//
// XP used to be a SELECT + UPDATE per message — the highest-frequency write in
// the bot and the biggest driver of Neon compute. Gains now accumulate in
// memory and are flushed with a constant number of set-based statements.
//
// These tests use an in-memory fake of `levelingPool.query` (a real Postgres
// is not available in CI). The fake interprets the two statements the flush
// issues against a plain table object, so the assertions cover the real SQL
// semantics that matter: counters are INCREMENTED (never overwritten), rows
// that do not exist yet are inserted, and no pending delta is lost.

const { test } = require('node:test');
const assert = require('node:assert');
const Module = require('module');

// ── Fake leveling pool ──────────────────────────────────────────────────────

function makeFakePool() {
    const rows = new Map(); // `${guildId}:${userId}` -> { xp, level, messages }
    const calls = [];       // { sql, params }

    return {
        rows,
        calls,
        query: async (sql, params) => {
            calls.push({ sql, params });
            const text = String(sql);

            if (text.includes('INSERT INTO user_levels')) {
                // The real statement inserts literal 0 for xp and messages and
                // takes only the level from the VALUES list; the delta lands via
                // the UPDATE below. params are groups of 5:
                // (guild_id, user_id, xp_delta, level, messages_delta).
                for (let i = 0; i < params.length; i += 5) {
                    const [guildId, userId, , level] = params.slice(i, i + 5);
                    const key = `${guildId}:${userId}`;
                    if (!rows.has(key)) rows.set(key, { xp: 0, level, messages: 0 });
                }
                return { rows: [] };
            }

            if (text.includes('UPDATE user_levels')) {
                for (let i = 0; i < params.length; i += 5) {
                    const [guildId, userId, xp, level, messages] = params.slice(i, i + 5);
                    const key = `${guildId}:${userId}`;
                    const row = rows.get(key);
                    if (!row) continue;
                    row.xp += xp;
                    row.messages += messages;
                    row.level = level;
                }
                return { rows: [] };
            }

            return { rows: [] };
        },
    };
}

// Load LevelingManager with its DB deps stubbed so no real connection is made.
function loadManager({ dbRows = new Map() } = {}) {
    const fakePool = makeFakePool();
    for (const [k, v] of dbRows.entries()) fakePool.rows.set(k, { ...v });

    // Seed the module cache: flushXp() requires '../server/levelingDb' lazily at
    // call time, so intercepting Module._load is not enough — the resolved entry
    // has to stay in require.cache for the lifetime of the test.
    const levelingDbPath = require.resolve('../server/levelingDb');
    const cached = require.cache[levelingDbPath];
    require.cache[levelingDbPath] = {
        id: levelingDbPath,
        filename: levelingDbPath,
        loaded: true,
        exports: { levelingPool: fakePool, levelingDb: {}, levelingSchema: {} },
    };

    delete require.cache[require.resolve('../utils/levelingManager')];
    const LevelingManager = require('../utils/levelingManager');

    if (cached) require.cache[levelingDbPath] = cached;
    else delete require.cache[levelingDbPath];

    // Neutralise auto-init + interval loops.
    const realInit = LevelingManager.prototype.initializeDatabase;
    LevelingManager.prototype.initializeDatabase = async function () {};
    const mgr = new LevelingManager({});
    LevelingManager.prototype.initializeDatabase = realInit;
    clearInterval(mgr.cooldownCleanupInterval);
    if (mgr._roleRewardsTimer?.stop) mgr._roleRewardsTimer.stop();

    // flushXp() re-requires the module at call time, so re-seed inside a helper
    // that the tests call via mgr.flushXp's wrapper.
    mgr.dbReady = true;
    mgr.db = { select: () => ({ from: () => ({ where: () => ({ limit: () => [] }) }) }) };
    mgr.schema = { userLevels: {} };

    const realFlush = mgr.flushXp.bind(mgr);
    mgr.flushXp = async function () {
        require.cache[levelingDbPath] = {
            id: levelingDbPath,
            filename: levelingDbPath,
            loaded: true,
            exports: { levelingPool: fakePool, levelingDb: {}, levelingSchema: {} },
        };
        try {
            return await realFlush();
        } finally {
            if (cached) require.cache[levelingDbPath] = cached;
            else delete require.cache[levelingDbPath];
        }
    };

    return { mgr, fakePool };
}

const key = (g, u) => `${g}:${u}`;

// ── Tests ───────────────────────────────────────────────────────────────────

test('a burst of messages produces one set-based flush, not one write per message', async () => {
    const { mgr, fakePool } = loadManager();

    // 40 messages from the same user, all within one flush window.
    for (let i = 0; i < 40; i++) {
        mgr._accumulateXp('g1', 'u1', 10);
    }
    await mgr.flushXp();

    // Exactly two statements (insert-missing + increment-existing), regardless
    // of how many messages were accumulated.
    assert.equal(fakePool.calls.length, 2, 'flush must be two set-based statements');
    assert.equal(fakePool.rows.get(key('g1', 'u1')).xp, 400, 'all 40 gains must be persisted');
    assert.equal(fakePool.rows.get(key('g1', 'u1')).messages, 40);
});

test('multiple users are flushed in the same two statements', async () => {
    const { mgr, fakePool } = loadManager();

    for (let u = 1; u <= 25; u++) mgr._accumulateXp('g1', `u${u}`, 5);
    await mgr.flushXp();

    assert.equal(fakePool.calls.length, 2, '25 users must not cost 25 statements');
    for (let u = 1; u <= 25; u++) {
        assert.equal(fakePool.rows.get(key('g1', `u${u}`)).xp, 5);
    }
});

test('flushing twice does not double-count', async () => {
    const { mgr, fakePool } = loadManager();

    mgr._accumulateXp('g1', 'u1', 7);
    await mgr.flushXp();
    const afterFirst = fakePool.rows.get(key('g1', 'u1')).xp;

    await mgr.flushXp(); // nothing pending

    assert.equal(afterFirst, 7);
    assert.equal(fakePool.rows.get(key('g1', 'u1')).xp, 7, 'an empty flush must not add XP');
});

test('a second flush adds only the new gain', async () => {
    const { mgr, fakePool } = loadManager();

    mgr._accumulateXp('g1', 'u1', 10);
    await mgr.flushXp();
    mgr._accumulateXp('g1', 'u1', 3);
    await mgr.flushXp();

    assert.equal(fakePool.rows.get(key('g1', 'u1')).xp, 13);
    assert.equal(fakePool.rows.get(key('g1', 'u1')).messages, 2);
});

test('an existing row is incremented, not overwritten', async () => {
    const { mgr, fakePool } = loadManager({
        dbRows: new Map([[key('g1', 'u1'), { xp: 1000, level: 5, messages: 500 }]]),
    });

    mgr._accumulateXp('g1', 'u1', 15);
    await mgr.flushXp();

    const row = fakePool.rows.get(key('g1', 'u1'));
    assert.equal(row.xp, 1015, 'pre-existing XP must be preserved');
    assert.equal(row.messages, 501);
});

test('level is computed from total messages', async () => {
    const { mgr, fakePool } = loadManager();

    for (let i = 0; i < 10; i++) mgr._accumulateXp('g1', 'u1', 1);
    await mgr.flushXp();

    const row = fakePool.rows.get(key('g1', 'u1'));
    assert.equal(row.level, mgr.calculateLevel(10), 'level must match the message count');
});

test('a failed flush keeps deltas pending for the next attempt', async () => {
    const { mgr, fakePool } = loadManager();

    mgr._accumulateXp('g1', 'u1', 9);

    const realQuery = fakePool.query;
    fakePool.query = async () => { throw new Error('Neon unavailable'); };
    const written = await mgr.flushXp();
    assert.equal(written, 0, 'a failed flush reports nothing written');
    assert.ok(mgr._xpPending.size > 0, 'pending XP must survive a failed flush');

    // Recover: the delta must still be there and land on the next flush.
    fakePool.query = realQuery;
    await mgr.flushXp();
    assert.equal(fakePool.rows.get(key('g1', 'u1')).xp, 9, 'no XP may be lost across a failure');
});

test('batching can be disabled with LEVELING_FLUSH_INTERVAL_MS=0', () => {
    const prev = process.env.LEVELING_FLUSH_INTERVAL_MS;
    process.env.LEVELING_FLUSH_INTERVAL_MS = '0';
    const { mgr } = loadManager();
    mgr._startXpFlushTimer();
    assert.equal(mgr._xpFlushTimer, null, 'interval 0 must not start a timer');
    if (prev === undefined) delete process.env.LEVELING_FLUSH_INTERVAL_MS;
    else process.env.LEVELING_FLUSH_INTERVAL_MS = prev;
});

test('a very long session still only writes in constant-size batches', async () => {
    const { mgr, fakePool } = loadManager();

    // 5 flush windows × 100 messages each = 500 messages.
    for (let window = 0; window < 5; window++) {
        for (let i = 0; i < 100; i++) mgr._accumulateXp('g1', 'u1', 2);
        await mgr.flushXp();
    }

    assert.equal(fakePool.rows.get(key('g1', 'u1')).xp, 1000, 'all 500 gains persisted');
    assert.equal(fakePool.calls.length, 10, '5 windows × 2 set-based statements');
});