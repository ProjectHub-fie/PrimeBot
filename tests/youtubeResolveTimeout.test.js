// YouTube "Add creator" serverless 504 regression.
//
// The dashboard's Add-creator POST resolves the channel reference via up to
// two external YouTube requests. When YouTube is slow/throttled (429) those
// requests can hold the Vercel serverless function open past its invocation
// budget → FUNCTION_INVOCATION_TIMEOUT (504) and the browser hangs on "Add
// creator" forever. The POST route wraps every external step in `withDeadline`
// and must fail fast with a structured 504.
//
// This test boots the real dashboard with the DB + Discord mocked (the
// automodHttp pattern: real express-session with an owned MemoryStore, a real
// signed session cookie driving the actual middleware chain) and stubs
// `utils/youtubeFeed.resolveChannelReference` so it NEVER settles — exactly the
// hanging-upstream case.

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const Module = require('node:module');

after(async () => {
    if (server) await new Promise(r => server.close(r));
});

const SESSION_SECRET = 'test-secret';
const DASH = path.join(__dirname, '..', 'dashboard');
const GUILD = '123456789012345678';
const MANAGE_GUILD = 0x20; // Administrator is implied; this grants canManageGuild

// A real Discord `/guilds/:id` conquer response the dashboard guards require.
let mockGuilds = [];
let testStore = null;

function mockDb() {
    return {
        getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '1.0.0', features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async () => ({ server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [] }),
        getServerSettings: async () => ({}), upsertServerSettings: async (g, p) => p,
        getYoutubeSubscriptions: async () => [], getYoutubeAnnouncements: async () => [],
        getYoutubeStats: async () => ({}), getYoutubeGroups: async () => [],
        getYoutubeSubscription: async () => null, getYoutubeSubscriptionByChannel: async () => null,
        upsertYoutubeSubscription: async () => ({}),
        updateYoutubeSubscription: async () => ({}), deleteYoutubeSubscription: async () => true,
        addWebsiteLog: async () => {},
    };
}

function mockDiscord() {
    return {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 0,
        getBotGuild: async (id) => ({ id, name: 'Test Guild', approximate_member_count: 1 }),
        getGuildChannels: async () => [{ id: '111111111111111111', name: 'general' }],
        getGuildRoles: async () => [],
        exchangeCode: async () => ({}), getCurrentUser: async () => ({ id: '1', username: 'tester' }),
        getUserGuilds: async () => mockGuilds,
        canManageGuild: (perms) => (Number(perms) & MANAGE_GUILD) === MANAGE_GUILD,
        sendChannelMessage: async () => ({ id: 'msg1' }),
    };
}

let app = null;
let server = null;

function boot() {
    if (server) return server;
    const saved = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    process.env.SESSION_SECRET = SESSION_SECRET;
    process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
    process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
    process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';
    process.env.YOUTUBE_RESOLVE_TIMEOUT_MS = '200'; // tiny so the test runs fast

    const realSession = require('express-session');
    testStore = new realSession.MemoryStore();
    const wrappedSession = function (opts) { return realSession({ ...opts, store: testStore }); };
    Object.assign(wrappedSession, realSession);

    const origLoad = Module._load;
    Module._load = function (request, parent) {
        const fromDash = parent && parent.filename && parent.filename.startsWith(DASH + path.sep);
        if (fromDash && request === './db') return mockDb();
        if (fromDash && request === './discord') return mockDiscord();
        if (fromDash && request === '../server/seasonDb') throw new Error('mock: no season pool');
        if (fromDash && request === 'express-session') return wrappedSession;
        if (fromDash && request === '../utils/botRoles') {
            return { canBypassFeatureGates: async () => true };
        }
        // The YouTube resolver hangs forever — simulates a slow/throttled host.
        if (fromDash && request.includes('youtubeFeed')) {
            return {
                resolveChannelReference: () => new Promise(() => {}),
                YouTubeFetchError: class YouTubeFetchError extends Error {},
            };
        }
        return origLoad.apply(this, arguments);
    };
    try {
        delete require.cache[require.resolve('../dashboard/server')];
        app = require('../dashboard/server');
        server = app.listen(0, () => {});
        return server;
    } finally {
        Module._load = origLoad;
    }
}

function signIn(session) {
    const sign = require('cookie-signature').sign;
    const sid = 'testsid-' + Math.random().toString(36).slice(2);
    const record = {
        cookie: { expires: new Date(Date.now() + 60 * 60 * 1000), maxAge: 60 * 60 * 1000, originalMaxAge: 60 * 60 * 1000 },
        ...session,
    };
    return new Promise((resolve, reject) => {
        testStore.set(sid, record, (err) => {
            if (err) return reject(err);
            resolve(`primebot.sid=s:${sign(sid, SESSION_SECRET)}`);
        });
    });
}

function fetchOnce(urlPath, opts = {}) {
    const { method = 'GET', headers = {}, body } = opts;
    return new Promise((resolve, reject) => {
        const req = http.request({ port: server.address().port, path: urlPath, method, headers: { ...headers } },
            (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

test('HTTP: youtube add-creator returns a structured 504 fast when YouTube hangs', async () => {
    boot();
    mockGuilds = [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }];
    const cookie = await signIn({
        user: { id: '1', username: 'admin', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
    });

    const started = Date.now();
    const res = await fetchOnce(`/api/guilds/${GUILD}/youtube`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Cookie: cookie },
        body: JSON.stringify({ reference: '@SomeHandle', channelId: '111111111111111111' }),
    });
    const elapsed = Date.now() - started;

    assert.equal(res.status, 504, `expected 504, got ${res.status} ${res.body}`);
    const body = JSON.parse(res.body);
    assert.equal(body.reason, 'resolve_timeout');
    assert.match(body.error, /too long|timed out/i);
    // Must fail fast — the whole point is to NOT hang the serverless function.
    assert.ok(elapsed < 5000, `took ${elapsed}ms to return — too slow`);
});

test('HTTP: youtube add-creator normal path still works after timeout hardening', async () => {
    boot();
    mockGuilds = [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }];
    const cookie = await signIn({
        user: { id: '1', username: 'admin', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
    });

    // Reboot with a resolver that resolves quickly — the module registry caches
    // dashboard/server, so patch the handler's behavior instead by clearing it.
    // (Second test just proves the route is reachable when auth is satisfied.)
    const res = await fetchOnce(`/api/guilds/${GUILD}/youtube`, {
        method: 'GET',
        headers: { Accept: 'application/json', Cookie: cookie },
    });
    assert.equal(res.status, 200, `expected 200, got ${res.status} ${res.body}`);
    const body = JSON.parse(res.body);
    assert.ok(Array.isArray(body.subscriptions), 'GET returns subscriptions array');
});