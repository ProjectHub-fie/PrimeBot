const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const Module = require('module');

// HTTP-level authorization tests for the 24/7 Radio dashboard API.
//
// Boots the REAL dashboard/server.js with dashboard/db + dashboard/discord
// mocked (the tests/automodHttp.test.js pattern), so the real middleware chain
// in dashboard/auth.js runs. Every radio route must reject an unauthenticated
// request before any handler body executes, and the page route must bounce an
// anonymous visitor to /login.

const DASH = path.join(__dirname, '..', 'dashboard');

function mockDb() {
    return {
        getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '1.0.0', features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async () => ({ server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [], antiNuke: {}, radioSession: null, radioStations: [] }),
        getRadioSession: async () => null,
        getRadioStations: async () => [],
        upsertRadioStation: async (gid, station) => ({ ...station, guildId: gid }),
        deleteRadioStation: async () => true,
        upsertRadioSession: async (gid, patch) => ({ guildId: gid, ...patch }),
        setRadioEnabled: async (gid, enabled) => ({ guildId: gid, enabled }),
        addWebsiteLog: async () => {},
    };
}

const GUILD = '123456789012345678';
const MANAGE_GUILD = 0x20;

function mockDiscord() {
    return {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 0,
        getBotGuild: async (guildId) => ({ id: guildId, name: 'Test Guild', icon: null, owner_id: '1', approximate_member_count: 5 }),
        getGuildChannels: async () => [],
        getGuildRoles: async () => [],
        exchangeCode: async () => ({}),
        getCurrentUser: async () => ({ id: '1', username: 'tester' }),
        getUserGuilds: async () => [],
        canManageGuild: (perms) => (Number(perms) & MANAGE_GUILD) === MANAGE_GUILD,
    };
}

let app = null;
let server = null;

function boot() {
    if (server) return server;
    const saved = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
    process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
    process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
    process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

    const realSession = require('express-session');
    const testStore = new realSession.MemoryStore();
    const wrappedSession = function (opts) { return realSession({ ...opts, store: testStore }); };
    Object.assign(wrappedSession, realSession);

    const origLoad = Module._load;
    Module._load = function (request, parent) {
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

const RADIO_ROUTES = [
    ['GET', `/api/guilds/${GUILD}/radio`],
    ['PATCH', `/api/guilds/${GUILD}/radio`],
    ['POST', `/api/guilds/${GUILD}/radio/station`],
    ['DELETE', `/api/guilds/${GUILD}/radio/station/my-station`],
];

for (const [method, urlPath] of RADIO_ROUTES) {
    test(`${method} ${urlPath} is 401 when unauthenticated`, async () => {
        const r = await request(urlPath, { method, body: method === 'GET' ? undefined : {} });
        assert.equal(r.status, 401, `expected 401, got ${r.status}: ${r.body.slice(0, 200)}`);
    });
}

test('the radio page route redirects an unauthenticated visitor to /login', async () => {
    const r = await request(`/guild/${GUILD}/radio`, { headers: { Accept: 'text/html' } });
    assert.ok([302, 401].includes(r.status), `expected a redirect/401 for an anonymous page hit, got ${r.status}`);
    if (r.status === 302) assert.match(r.headers.location, /\/login/);
});

// ── station validation is a pure function (no DB needed) ────────────────────

test('normalizeStation rejects a non-soundcloud URL and a URL-as-genre', () => {
    const { normalizeStation, STATION_SOURCES } = require('../shared/radioConstants');
    assert.equal(normalizeStation({ name: 'X', source: STATION_SOURCES.PLAYLIST, reference: 'https://evil.example/x' }).ok, false);
    assert.equal(normalizeStation({ name: 'X', source: STATION_SOURCES.GENRE, reference: 'https://soundcloud.com/x' }).ok, false);
    assert.equal(normalizeStation({ name: 'X', source: STATION_SOURCES.PLAYLIST, reference: 'https://soundcloud.com/x/sets/y' }).ok, true);
    assert.equal(normalizeStation({ name: 'X', source: STATION_SOURCES.GENRE, reference: 'deep house' }).ok, true);
});
