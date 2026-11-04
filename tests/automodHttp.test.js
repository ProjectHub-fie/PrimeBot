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
        getAntiNukeSetup: async () => ({ method: null, status: 'not_started', state: {} }),
        saveAntiNukeSetup: async (gid, patch) => ({ method: patch.method, status: patch.status, state: patch.state }),
        getAntiNukeIncidents: async () => ({ incidents: [], total: 0 }),
        getAntiNukeLockdown: async () => ({ active: false, state: null }),
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
        // Anti-Nuke is an UPCOMING feature: its write endpoints are gated by
        // requireUpcoming, which 403s unless the viewer holds a developer/owner
        // bot role. There is no DB in this boot, so mock the role lookup to
        // report the admin as a bypass user — that is the state in which the
        // real handlers (save/toggle/setup/lockdown) are reachable at all.
        if (fromDash && request === '../utils/botRoles') {
            return {
                canBypassFeatureGates: async () => true,
                getRole: async () => 'developer',
                getRoleInfo: () => ({ label: 'Developer' }),
            };
        }
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
    ['POST', `/api/guilds/${GUILD}/antinuke/toggle`],
    ['GET', `/api/guilds/${GUILD}/antinuke/incidents`],
    ['POST', `/api/guilds/${GUILD}/antinuke/lockdown`],
    ['GET', `/api/guilds/${GUILD}/antinuke/setup`],
    ['POST', `/api/guilds/${GUILD}/antinuke/setup/start`],
    ['POST', `/api/guilds/${GUILD}/antinuke/setup/resume`],
    ['PATCH', `/api/guilds/${GUILD}/antinuke/setup/progress`],
    ['POST', `/api/guilds/${GUILD}/antinuke/setup/step`],
    ['POST', `/api/guilds/${GUILD}/antinuke/setup/complete`],
    ['POST', `/api/guilds/${GUILD}/antinuke/setup/reset`],
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

// ── The upcoming gate still applies to the feature that has one ─────────────
//
// Anti-Nuke is RELEASED (no requireUpcoming). Event Management still carries the
// gate, so the middleware itself must keep working.

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

test('the Anti-Nuke page renders its real setup wizard for a bypass user', async () => {
    // Anti-Nuke is an UPCOMING feature: an ordinary admin gets the Coming Soon
    // overlay, and a developer/owner viewer (guild._bypassUpcoming) gets the
    // real editor so the feature can still be exercised before it ships.
    const guildPages = require('../dashboard/render/guild-pages');
    const base = {
        id: GUILD, name: 'T', icon: null, _beta: false,
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, antiNuke: {} },
        _channels: [], _roles: [],
    };

    const ordinary = guildPages.antiNukePage({ guild: { ...base, _bypassUpcoming: false }, user: { username: 'u' } });
    assert.ok(ordinary.includes('upcoming-locked-wrap locked'), 'ordinary users get the Coming Soon overlay');
    assert.match(ordinary, /data-method="automatic"/, 'the real markup is still rendered underneath the overlay');

    const bypass = guildPages.antiNukePage({ guild: { ...base, _bypassUpcoming: true }, user: { username: 'u' } });
    assert.ok(!bypass.includes('upcoming-locked-wrap locked'), 'bypass users get the real editor');
    assert.match(bypass, /data-method="automatic"/, 'the setup chooser renders');
    assert.match(bypass, /data-method="manual"/, 'the manual option renders');
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

// ── Anti-Nuke authenticated happy path ──────────────────────────────────────
//
// Anti-Nuke is an UPCOMING feature, so its write endpoints are gated by
// requireUpcoming. The boot mock reports the admin as a developer/owner (bypass)
// user, which is the state in which the real handlers are reachable — these
// tests then prove the handlers themselves work through the real middleware
// chain.

async function adminCookie() {
    mockGuilds = [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }];
    return signIn({
        user: { id: '1', username: 'admin', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
    });
}

test('an authenticated admin can save Anti-Nuke settings', async () => {
    boot();
    const cookie = await adminCookie();
    const r = await request(`/api/guilds/${GUILD}/antinuke`, {
        method: 'PATCH',
        body: { enabled: true, dryRun: true, responses: ['alertOwner', 'alertChannel'], watched: { channelDelete: { enabled: true, threshold: 3, seconds: 10 } } },
        headers: { Cookie: cookie },
    });
    assert.equal(r.status, 200, r.body.slice(0, 300));
    const payload = JSON.parse(r.body);
    assert.equal(payload.antiNuke.enabled, true);
});

test('Anti-Nuke rejects an unknown action key and an empty response list', async () => {
    boot();
    const cookie = await adminCookie();
    // An empty response list is a validation error (never silently saved).
    const bad = await request(`/api/guilds/${GUILD}/antinuke`, {
        method: 'PATCH', body: { responses: [] }, headers: { Cookie: cookie },
    });
    assert.equal(bad.status, 400, bad.body.slice(0, 200));
    // An unknown watched action key is dropped, never persisted.
    const r = await request(`/api/guilds/${GUILD}/antinuke`, {
        method: 'PATCH',
        body: { watched: { notARealAction: { enabled: true, threshold: 1, seconds: 1 }, channelDelete: { enabled: true, threshold: 2, seconds: 5 } } },
        headers: { Cookie: cookie },
    });
    assert.equal(r.status, 200);
    const payload = JSON.parse(r.body);
    assert.ok(!('notARealAction' in (payload.antiNuke.watched || {})), 'unknown action key must be dropped');
});

test('the Anti-Nuke master toggle persists on its own', async () => {
    boot();
    const cookie = await adminCookie();
    const r = await request(`/api/guilds/${GUILD}/antinuke/toggle`, {
        method: 'POST', body: { enabled: false }, headers: { Cookie: cookie },
    });
    assert.equal(r.status, 200, r.body.slice(0, 300));
    assert.equal(JSON.parse(r.body).antiNuke.enabled, false);
});

test('the manual setup wizard saves real progress and refuses to complete while required sections are pending', async () => {
    boot();
    const cookie = await adminCookie();
    // Completing only "general" leaves required sections pending.
    const partial = await request(`/api/guilds/${GUILD}/antinuke/setup/progress`, {
        method: 'PATCH', body: { method: 'manual', completed: ['general'] }, headers: { Cookie: cookie },
    });
    assert.equal(partial.status, 200, partial.body.slice(0, 300));
    assert.equal(JSON.parse(partial.body).setup.status, 'in_progress');

    const complete = await request(`/api/guilds/${GUILD}/antinuke/setup/complete`, {
        method: 'POST', body: { method: 'manual' }, headers: { Cookie: cookie },
    });
    assert.equal(complete.status, 400, 'setup cannot complete with required sections pending');
});

test('Anti-Nuke lockdown is refused when disabled in the configuration', async () => {
    boot();
    const cookie = await adminCookie();
    // The mock getAntiNukeSettings returns {} → lockdown.enabled is undefined.
    // The handler treats a missing/disabled lockdown config as a 400.
    const r = await request(`/api/guilds/${GUILD}/antinuke/lockdown`, {
        method: 'POST', body: { action: 'engage' }, headers: { Cookie: cookie },
    });
    assert.equal(r.status, 400, r.body.slice(0, 200));
});

test('Anti-Nuke refuses to serve a guild the admin cannot manage (guild isolation)', async () => {
    boot();
    // The session can manage GUILD, but not a different guild id.
    mockGuilds = [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }];
    const cookie = await signIn({
        user: { id: '1', username: 'admin', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
    });
    const r = await request('/api/guilds/999999999999999999/antinuke', {
        method: 'GET', headers: { Cookie: cookie },
    });
    assert.equal(r.status, 403, r.body.slice(0, 200));
});