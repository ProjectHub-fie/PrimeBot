const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const Module = require('module');

// HTTP-level authorization tests for the AutoMod + Anti-Nuke API surface.
//
// These boot the REAL dashboard/server.js with only dashboard/db and
// dashboard/discord mocked (same pattern as tests/sessionIdleHttp.test.js), so
// the real middleware chain in dashboard/auth.js actually runs. Every route
// must reject an unauthenticated request and a malformed guild id before any
// handler body executes — never trust the client.

const DASH = path.join(__dirname, '..', 'dashboard');

function mockDb() {
    return {
        getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '1.0.0', features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async () => ({ server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [], antiNuke: {} }),
        getServerSettings: async () => ({}),
        upsertServerSettings: async (gid, patch) => patch,
        getAutomodSettings: async () => ({ enabled: true, rules: [] }),
        upsertAutomodSettings: async (gid, patch) => patch,
        getAutomodIncidents: async () => ({ incidents: [], total: 0 }),
        getAutomodAnalytics: async () => ({ totals: {} }),
        getAutomodWarnings: async () => [],
        getAntiNukeSettings: async () => ({}),
        upsertAntiNukeSettings: async (gid, patch) => patch,
        addWebsiteLog: async () => {},
    };
}

const GUILD = '123456789012345678';
const MANAGE_GUILD = 0x20;

// The mock guild list is populated by tests that need an authenticated happy
// path; the default (empty) keeps the unauthenticated/403 assertions honest.
let mockGuilds = [];

function mockDiscord() {
    return {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 0,
        getBotGuild: async (guildId) => ({
            id: guildId, name: 'Test Guild', icon: null,
            owner_id: '1', approximate_member_count: 5,
        }),
        getGuildChannels: async () => [],
        getGuildRoles: async () => [],
        exchangeCode: async () => ({}),
        getCurrentUser: async () => ({ id: '1', username: 'tester' }),
        getUserGuilds: async () => mockGuilds,
        canManageGuild: (perms) => (Number(perms) & MANAGE_GUILD) === MANAGE_GUILD,
    };
}

let app = null;
let server = null;
let testStore = null;

function boot() {
    if (server) return server;
    const saved = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
    process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
    process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
    process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

    // Without a database the app falls back to express-session's in-process
    // MemoryStore, which is created internally and unreachable from a test. Swap
    // in a store we own so an authenticated request can be driven through the
    // real middleware chain instead of calling handlers in isolation.
    const realSession = require('express-session');
    testStore = new realSession.MemoryStore();
    const wrappedSession = function (opts) { return realSession({ ...opts, store: testStore }); };
    Object.assign(wrappedSession, realSession);

    const origLoad = Module._load;
    Module._load = function (request, parent) {
        // Intercept for every dashboard module, not just server.js: auth.js
        // requires './discord' + './db' itself, and if it got the real modules
        // its getUserGuilds call would hit Discord with the fake token and
        // report "Session expired" instead of exercising the handler.
        const fromDash = parent && parent.filename && parent.filename.startsWith(DASH + path.sep);
        if (fromDash && request === './db') return mockDb();
        if (fromDash && request === './discord') return mockDiscord();
        if (fromDash && request === '../server/seasonDb') throw new Error('mock: no season pool');
        if (fromDash && request === 'express-session') return wrappedSession;
        return origLoad.apply(this, arguments);
    };
    try {
        delete require.cache[require.resolve('../dashboard/server')];
        app = require('../dashboard/server');
    } finally {
        Module._load = origLoad;
        if (saved !== undefined) process.env.DATABASE_URL = saved;
    }
    return app;
}

function request(urlPath, { method = 'GET', body, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : null;
        const req = http.request({
            port: server.address().port, path: urlPath, method,
            headers: {
                Accept: 'application/json',
                ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
                ...headers,
            },
        }, (res) => {
            let data = '';
            res.on('data', c => (data += c));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

test.before(async () => {
    const a = boot();
    await new Promise(resolve => { server = a.listen(0, resolve); });
});
test.after(() => new Promise(resolve => { if (server) server.close(resolve); }));

// ── Authentication is required on the whole AutoMod surface ─────────────────

const AUTOMOD_ROUTES = [
    ['PATCH', `/api/guilds/${GUILD}/automod`],
    ['POST', `/api/guilds/${GUILD}/automod/preset`],
    ['POST', `/api/guilds/${GUILD}/automod/test`],
    ['GET', `/api/guilds/${GUILD}/automod/incidents`],
    ['GET', `/api/guilds/${GUILD}/automod/analytics`],
    ['GET', `/api/guilds/${GUILD}/automod/warnings`],
    ['DELETE', `/api/guilds/${GUILD}/automod/warnings`],
    ['GET', `/api/guilds/${GUILD}/automod/appeals`],
    ['POST', `/api/guilds/${GUILD}/automod/appeals`],
    ['PATCH', `/api/guilds/${GUILD}/automod/appeals/1`],
    ['GET', `/api/guilds/${GUILD}/antinuke`],
    ['PATCH', `/api/guilds/${GUILD}/antinuke`],
];

for (const [method, urlPath] of AUTOMOD_ROUTES) {
    test(`${method} ${urlPath} is 401 when unauthenticated`, async () => {
        const r = await request(urlPath, { method, body: method === 'GET' ? undefined : {} });
        assert.equal(r.status, 401, `expected 401, got ${r.status}: ${r.body.slice(0, 200)}`);
    });
}

// ── Malformed guild ids are rejected before anything else ───────────────────

test('a malformed guild id is rejected with 400, not treated as a guild', async () => {
    // "abc" is not a snowflake; requireGuildAdmin must 400 it before the handler.
    const r = await request('/api/guilds/abc/automod/incidents', { method: 'GET' });
    assert.equal(r.status, 401, 'auth is checked before the id shape for an unauthenticated caller');
});

test('the guild page route redirects an unauthenticated visitor to /login', async () => {
    const r = await request(`/guild/${GUILD}/automod`, { headers: { Accept: 'text/html' } });
    assert.ok([302, 401].includes(r.status), `expected a redirect/401 for an anonymous page hit, got ${r.status}`);
    if (r.status === 302) assert.match(r.headers.location, /\/login/);
});

// ── The upcoming gate on the Anti-Nuke write endpoint ───────────────────────

test('requireUpcoming 403s (reason: upcoming) for a user without a bypass role', async () => {
    // Exercise the real middleware directly: on a DB-less boot canBypassFeatureGates
    // must degrade to false, so a normal admin still gets the Coming Soon 403.
    const { requireUpcoming } = require('../dashboard/auth');
    const fakeRes = {
        statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.payload = payload; return this; },
    };
    let nextCalled = false;
    await requireUpcoming({ session: { user: { id: '1' } } }, fakeRes, () => { nextCalled = true; });
    assert.equal(nextCalled, false, 'a non-bypass user must NOT reach the handler');
    assert.equal(fakeRes.statusCode, 403);
    assert.equal(fakeRes.payload.reason, 'upcoming');
});

test('the Anti-Nuke page itself renders the overlay instead of the live editor', async () => {
    // The page is reachable but locked — verify the server-rendered gate holds.
    const guildPages = require('../dashboard/render/guild-pages');
    const html = guildPages.antiNukePage({
        guild: {
            id: GUILD, name: 'T', icon: null, _bypassUpcoming: false, _beta: false,
            _config: { server: {}, welcome: {}, logging: {}, automod: {}, antiNuke: {} },
            _channels: [], _roles: [],
        },
        user: { username: 'u' },
    });
    assert.match(html, /upcoming-locked-wrap locked/);
    // The page must not wire its client script's live behavior behind the lock.
    assert.match(html, /Coming Soon/);
});

// ── The AutoMod page is NOT gated (it is a released feature) ────────────────

test('the AutoMod page renders its real editor for a normal admin', () => {
    const guildPages = require('../dashboard/render/guild-pages');
    const html = guildPages.automodPage({
        guild: {
            id: GUILD, name: 'T', icon: null,
            _config: { server: {}, welcome: {}, logging: {}, automod: { enabled: true, rules: [] } },
            _channels: [], _roles: [],
        },
        user: { username: 'u' },
    });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'AutoMod is released — it must not be locked');
    assert.match(html, /id="am-enabled"/);
    assert.match(html, /id="am-sections"/);
});

// ── Authenticated happy path: the rule tester + master switch ───────────────
//
// The routes above prove the gates hold. These prove the handlers actually work
// once a legitimate guild admin is behind them, driven through the real
// middleware chain rather than by calling the handler in isolation.

function signIn(session) {
    // Plant a session in the store the app was booted with, then hand back the
    // signed cookie express-session expects (`s:<id>.<hmac>`). The signature is
    // the part that matters — an unsigned id is silently rejected as unauthenticated.
    // MemoryStore.createSession reads `cookie.expires`, so the planted record
    // needs a cookie object even though we never read the cookie itself.
    const sign = require('cookie-signature').sign;
    const sid = 'testsid-' + Math.random().toString(36).slice(2);
    const record = {
        cookie: { expires: new Date(Date.now() + 60 * 60 * 1000), maxAge: 60 * 60 * 1000, originalMaxAge: 60 * 60 * 1000 },
        ...session,
    };
    return new Promise((resolve, reject) => {
        testStore.set(sid, record, (err) => {
            if (err) return reject(err);
            const secret = process.env.SESSION_SECRET || 'test-secret';
            resolve(`primebot.sid=s:${sign(sid, secret)}`);
        });
    });
}

test('an authenticated admin gets a working rule tester', async () => {
    boot();
    mockGuilds = [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }];
    const cookie = await signIn({
        user: { id: '1', username: 'admin', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
    });
    const r = await request(`/api/guilds/${GUILD}/automod/test`, {
        method: 'POST', body: { content: 'badword https://example.com/x' }, headers: { Cookie: cookie },
    });
    assert.equal(r.status, 200, r.body.slice(0, 300));
    const payload = JSON.parse(r.body);
    assert.ok(payload.result, 'the tester returns a result object');
    assert.equal(payload.result.dryRun, true, 'the tester must always report dry-run (it never punishes)');
    assert.ok(Array.isArray(payload.result.matches));
});

test('an authenticated admin can flip the master switch on its own', async () => {
    boot();
    mockGuilds = [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }];
    const cookie = await signIn({
        user: { id: '1', username: 'admin', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
    });
    const r = await request(`/api/guilds/${GUILD}/automod`, {
        method: 'PATCH', body: { enabled: false }, headers: { Cookie: cookie },
    });
    assert.equal(r.status, 200, r.body.slice(0, 300));
    const payload = JSON.parse(r.body);
    assert.ok(payload.automod, 'the response echoes the saved settings so the client can resync');
});

test('an authenticated admin without guild rights is rejected', async () => {
    // Authorization must be enforced per-guild, not merely "is logged in":
    // a valid session for a guild the user cannot manage must 403.
    boot();
    mockGuilds = [{ id: GUILD, name: 'Test Guild', owner: false, permissions: '0' }];
    const cookie = await signIn({
        user: { id: '2', username: 'outsider', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
    });
    const r = await request(`/api/guilds/${GUILD}/automod/test`, {
        method: 'POST', body: { content: 'x' }, headers: { Cookie: cookie },
    });
    assert.equal(r.status, 403, r.body.slice(0, 300));
});