const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const Module = require('node:module');
const fs = require('node:fs');
const vm = require('node:vm');

const { LatencyRecorder } = require('../dashboard/latency');
const { summarizeLatency, percentileLatency } = require('../dashboard/db');

const DASH = path.join(__dirname, '..', 'dashboard');

// A fake pg pool that records queries so we can assert on what gets written.
function fakePool({ failQuery = false } = {}) {
    const queries = [];
    return {
        queries,
        async query(sql, params) {
            if (failQuery) throw new Error('mock pool down');
            queries.push({ sql, params });
            // The aggregation query returns a single empty row-set placeholder.
            if (sql.includes('date_trunc')) return { rows: [] };
            return { rows: [] };
        },
    };
}

// ── LatencyRecorder unit tests (no DB — a fake pool) ───────────────────────

test('recorder buffers samples and never throws', () => {
    const pool = fakePool();
    const r = new LatencyRecorder({
        poolFn: async () => pool,
        flushIntervalMs: 100000,
        minFlushGap: Infinity,   // disable traffic-driven coalescing for this test
        maxBuffer: 10,
        nowFn: () => 1000000,
    });
    r.record(120, 'GET /');          // below maxBuffer → buffered, no immediate flush
    r.record(300, 'GET /guild/:guildId');
    assert.equal(r.counts().buffered, 2);
    assert.equal(r._buffer.length, 2);
    assert.equal(r._buffer[0].ms, 120);
    assert.equal(r._buffer[0].route, 'GET /');
});

test('recorder discards invalid durations and caps the bound window', () => {
    const pool = fakePool();
    const r = new LatencyRecorder({ poolFn: async () => pool, maxBuffer: 100, maxBound: 5, nowFn: () => 0 });
    r.record('nope', 'x');
    r.record(-5, 'x');
    r.record(1.9, 'x');
    assert.equal(r._buffer.length, 1);
    assert.equal(r._buffer[0].ms, 2);
    for (let i = 0; i < 20; i++) r.record(i, 'x');
    assert.ok(r._bound.length <= 5, 'bound window must stay capped');
});

test('recorder flushes to the pool in one batched INSERT', async () => {
    const pool = fakePool();
    const r = new LatencyRecorder({
        poolFn: async () => pool,
        flushIntervalMs: 100000,
        maxBuffer: 5,           // every 5th sample forces a flush
        nowFn: () => 5,
    });
    for (let i = 0; i < 5; i++) r.record(100 + i, 'GET /docs');
    // maxBuffer reached → record() triggers an async flush; await a tick.
    await new Promise(res => setImmediate(res));
    assert.equal(r._buffer.length, 0, 'buffer should be drained by the flush');
    assert.ok(pool.queries.length >= 1, 'a flush should have hit the pool');
    const insert = pool.queries.find(q => q.sql.startsWith('INSERT INTO latency_samples'));
    assert.ok(insert, 'INSERT should be present');
    // 5 samples × 3 placeholders each.
    assert.equal(insert.params.length, 15);
    assert.equal(insert.params[1], 100);
});

test('recorder retries the batch on a failed flush (re-buffers)', async () => {
    const pool = fakePool({ failQuery: true });
    const r = new LatencyRecorder({
        poolFn: async () => pool,
        flushIntervalMs: 100000,
        maxBuffer: 100,
        nowFn: () => 1,
    });
    r.record(50, 'GET /stats');
    await r.flush();
    assert.equal(r._buffer.length, 1, 'failed flush must put the sample back');
});

// ── Pure aggregation helpers ─────────────────────────────────────────────

test('percentileLatency computes quantiles on unsorted input', () => {
    assert.equal(percentileLatency([], 0.5), null);
    assert.equal(percentileLatency([1, 2, 3, 4, 5], 0.5), 3);
    assert.equal(percentileLatency([5, 3, 1, 4, 2], 0.5), 3);
    assert.equal(percentileLatency([1, 2, 3, 4, 5], 0.95), 5);
    assert.equal(percentileLatency([100], 0.9), 100);
});

test('summarizeLatency handles empty and populated series', () => {
    assert.deepEqual(summarizeLatency([]), { sampleCount: 0, avg: null, p95: null, max: null, bucketsWithData: 0 });
    const s = summarizeLatency([
        { count: 10, avg: 100, p95: 150, max: 220 },
        { count: 5, avg: 300, p95: 400, max: 950 },
    ]);
    assert.equal(s.sampleCount, 15);
    assert.equal(s.avg, Math.round((100 + 300) / 2)); // avg of bucket averages
    assert.equal(s.avg, 200);
    assert.equal(s.max, 950);
    assert.equal(s.bucketsWithData, 2);
});

// ── getLatencyRoutes DB aggregation (stubbed season pool) ───────────────────

test('getLatencyRoutes aggregates per-route rows worst-first and folds in-flight samples', async () => {
    const DASH = path.join(__dirname, '..', 'dashboard');
    const queries = [];
    const fakeSeasonPool = {
        async query(sql, params) {
            queries.push({ sql, params });
            if (sql.includes('CREATE TABLE')) return { rows: [] };
            if (sql.includes('GROUP BY route')) {
                return {
                    rows: [
                        { route: 'GET /guild/:guildId', n: '40', avg_ms: 820, p50_ms: 700, p95_ms: 1600, max_ms: 2400 },
                        { route: 'GET /api/stats/latency', n: '12', avg_ms: 310, p50_ms: 250, p95_ms: 600, max_ms: 900 },
                    ],
                };
            }
            return { rows: [] };
        },
    };
    // Seed the shared recorder with a fresh in-flight sample for a route that is
    // NOT in the DB result, to prove the fold-in path adds it.
    const { getLatencyRecorder } = require('../dashboard/latency');
    getLatencyRecorder({ force: true, poolFn: async () => ({ query: async () => ({ rows: [] }) }) })
        .record(5000, 'GET /api/guilds/:guildId/slow');

    const origLoad = Module._load;
    Module._load = function (request, parent, isMain) {
        if (parent && parent.filename && parent.filename.startsWith(DASH + path.sep + 'db.js') && request === '../server/seasonDb') {
            return { seasonPool: fakeSeasonPool };
        }
        return origLoad.apply(this, arguments);
    };
    let db;
    try {
        delete require.cache[require.resolve('../dashboard/db')];
        db = require('../dashboard/db');
        const routes = await db.getLatencyRoutes({ days: 7, limit: 10 });
        assert.ok(Array.isArray(routes));
        // The fresh in-flight route (5000ms) should sort to the top.
        assert.equal(routes[0].route, 'GET /api/guilds/:guildId/slow');
        assert.equal(routes[0].avg, 5000);
        const guild = routes.find(r => r.route === 'GET /guild/:guildId');
        assert.ok(guild, 'DB route should still be present');
        assert.equal(guild.avg, 820);
        assert.equal(guild.count, 40);
        // The aggregate query asked for the 7-day window with the limit.
        const agg = queries.find(q => q.sql.includes('GROUP BY route'));
        assert.ok(agg);
        assert.equal(agg.params[1], 10);
    } finally {
        Module._load = origLoad;
        delete require.cache[require.resolve('../dashboard/db')];
    }
});

test('getLatencyRoutes degrades to [] when the season pool is unreachable', async () => {
    const DASH = path.join(__dirname, '..', 'dashboard');
    const origLoad = Module._load;
    Module._load = function (request, parent, isMain) {
        if (parent && parent.filename && parent.filename.startsWith(DASH + path.sep + 'db.js') && request === '../server/seasonDb') {
            return { seasonPool: { query: async () => { throw new Error('boom'); } } };
        }
        return origLoad.apply(this, arguments);
    };
    try {
        delete require.cache[require.resolve('../dashboard/db')];
        const db = require('../dashboard/db');
        const routes = await db.getLatencyRoutes({ days: 30 });
        assert.ok(Array.isArray(routes));
    } finally {
        Module._load = origLoad;
        delete require.cache[require.resolve('../dashboard/db')];
    }
});


// ── HTTP route guard + happy path (real dashboard/server.js boot) ───────────

function mockDb() {
    return {
        getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '1.0.0', features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async () => ({ server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [] }),
        getServerSettings: async () => ({}),
        upsertServerSettings: async (gid, patch) => patch,
        getLatencySeries: async ({ days }) => ({
            days,
            granularityMs: 3600000,
            summary: { sampleCount: 10, avg: 120, p95: 190, max: 400, bucketsWithData: 3 },
            series: [
                { ts: new Date(Date.now() - 3 * 3600000), count: 4, avg: 100, p50: 90, p95: 140, max: 220 },
                { ts: new Date(Date.now() - 2 * 3600000), count: 3, avg: 180, p50: 160, p95: 300, max: 400 },
                { ts: new Date(Date.now() - 1 * 3600000), count: 3, avg: 90, p50: 80, p95: 120, max: 160 },
            ],
        }),
        getLatencyRoutes: async ({ days }) => ([
            { route: 'GET /guild/:guildId', count: 40, avg: 820, p50: 700, p95: 1600, max: 2400 },
            { route: 'GET /api/stats/latency', count: 12, avg: 310, p50: 250, p95: 600, max: 900 },
        ]),
    };
}

function mockDiscord() {
    return {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 0,
        getBotGuild: async () => ({ id: '1', name: 'Test', approximate_member_count: 1 }),
        getGuildChannels: async () => [],
        getGuildRoles: async () => [],
        exchangeCode: async () => ({ access_token: 'fake-access', refresh_token: 'fake-refresh', expires_in: 3600 }),
        getCurrentUser: async () => ({ id: '1', username: 'tester', discriminator: '0', global_name: 'Tester', avatar: null }),
        getUserGuilds: async () => [],
    };
}

let app;
function bootApp() {
    const savedDbUrl = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
    process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
    process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
    process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

    const origLoad = Module._load;
    Module._load = function (request, parent, isMain) {
        const fromServer = parent && parent.filename && parent.filename.startsWith(DASH + path.sep + 'server.js');
        if (fromServer && request === './db') return mockDb();
        if (fromServer && request === './discord') return mockDiscord();
        if (fromServer && request === '../server/seasonDb') throw new Error('mock: no season pool');
        return origLoad.apply(this, arguments);
    };
    try {
        delete require.cache[require.resolve('../dashboard/server')];
        app = require('../dashboard/server');
    } finally {
        Module._load = origLoad;
        if (savedDbUrl !== undefined) process.env.DATABASE_URL = savedDbUrl;
    }
    return app;
}

function startServer(appInstance) {
    return new Promise((resolve) => {
        const server = appInstance.listen(0, () => resolve(server));
    });
}
function closeServer(server) {
    return new Promise((resolve) => server.close(resolve));
}

async function fetchOnce(server, urlPath, opts = {}) {
    const { method = 'GET', headers = {}, body } = opts;
    return new Promise((resolve, reject) => {
        const req = http.request(
            { port: server.address().port, path: urlPath, method, headers: { ...headers } },
            (res) => {
                let data = '';
                res.on('data', (c) => (data += c));
                res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
            }
        );
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

function makeSession(server) {
    // Perform a login via the real OAuth callback with mocked discord to obtain
    // a valid signed session cookie.
    const clientId = process.env.DISCORD_CLIENT_ID || '999';
    const fakeCode = 'code-latency';
    return new Promise((resolve) => {
        const req = http.get(
            { port: server.address().port, path: `/auth/callback?code=${fakeCode}` },
            (res) => {
                resolve(res.headers['set-cookie'] || []);
                res.resume();
            }
        );
        req.on('error', () => resolve([]));
    });
}

test('HTTP: /api/stats/latency is 401 unauthenticated and 200 with a session (7d default clamp)', async () => {
    const a = bootApp();
    const server = await startServer(a);
    try {
        const anon = await fetchOnce(server, '/api/stats/latency', { headers: { Accept: 'application/json' } });
        assert.equal(anon.status, 401);

        const cookies = await makeSession(server);
        assert.ok(cookies.length, 'expected a session cookie from the OAuth callback');
        const cookieHeader = cookies.map(c => c.split(';')[0]).join('; ');
        const authed = await fetchOnce(server, '/api/stats/latency?days=30', { headers: { Accept: 'application/json', Cookie: cookieHeader } });
        assert.equal(authed.status, 200);
        const body = JSON.parse(authed.body);
        assert.equal(body.days, 30);
        assert.ok(Array.isArray(body.series));
        assert.equal(body.summary.sampleCount, 10);
        // The route breakdown ships in the same response (one round-trip).
        assert.ok(Array.isArray(body.routes));
        assert.equal(body.routes[0].route, 'GET /guild/:guildId');
        assert.equal(body.routes[0].avg, 820);
    } finally {
        await closeServer(server);
    }
});

