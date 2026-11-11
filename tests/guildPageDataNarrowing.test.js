// Regression test: a guild settings page must only load the data it renders.
//
// Every tab used to run one monolithic guard that fetched the guild channels,
// the roles, EVERY feature's settings slice and the Anti-Nuke extras. A tab
// like /prefix renders a single field, so that work was pure latency — and on
// a serverless host a single slow pool or Discord call stalls the render until
// the function is killed (browsers report ERR_CONNECTION_ABORTED).
//
// The tests below boot the real dashboard (mocking only the DB + Discord
// boundary) and assert what each tab actually asks for.

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');
const Module = require('module');

const DASH = path.join(__dirname, '..', 'dashboard');
const GUILD = '123456789012345678';
const MANAGE_GUILD = 0x20;

// ── Mocked DB / Discord boundary (records everything it is asked for) ──────
const calls = {
    getGuildConfig: [],
    getGuildChannels: 0,
    getGuildRoles: 0,
    computeBotPermissions: 0,
    getAntiNukeLockdown: 0,
    getAntiNukeIncidentSummary: 0,
    canAccess: 0,
    canBypassFeatureGates: 0,
};

function resetCalls() {
    calls.getGuildConfig = [];
    calls.getGuildChannels = 0;
    calls.getGuildRoles = 0;
    calls.computeBotPermissions = 0;
    calls.getAntiNukeLockdown = 0;
    calls.getAntiNukeIncidentSummary = 0;
    calls.canAccess = 0;
    calls.canBypassFeatureGates = 0;
}

function defaultConfig() {
    return {
        server: { prefix: '!', leveling: { roleRewards: [] } },
        welcome: {},
        logging: {},
        reactionRoles: [],
        automod: {},
        antiNuke: {},
        ticketPanels: [],
        birthdaySettings: { channelId: null, roleId: null, imageUrl: null },
        birthdays: [],
        youtubeSubscriptions: [],
        youtubeAnnouncements: [],
        youtubeStats: {},
    };
}

function mockDb() {
    return {
        getPlatformStats: async () => ({ servers: 0, features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async (guildId, opts) => {
            calls.getGuildConfig.push(opts || {});
            return defaultConfig();
        },
        getGuildConfigSummaries: async () => new Map(),
        getServerSettings: async () => ({}),
        upsertServerSettings: async (gid, patch) => patch,
        getAntiNukeLockdown: async () => { calls.getAntiNukeLockdown++; return { active: false }; },
        getAntiNukeIncidentSummary: async () => { calls.getAntiNukeIncidentSummary++; return { total: 0, byAction: [] }; },
        addWebsiteLog: async () => {},
    };
}

function mockDiscord() {
    return {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 1,
        getBotGuild: async (guildId) => ({
            id: guildId, name: 'Test Guild', icon: null, owner_id: '1', approximate_member_count: 5,
        }),
        getGuildChannels: async () => { calls.getGuildChannels++; return [{ id: '111', name: 'general', type: 0 }]; },
        getGuildRoles: async () => { calls.getGuildRoles++; return [{ id: '222', name: 'Member', position: 1 }]; },
        computeBotPermissions: async () => { calls.computeBotPermissions++; return 0n; },
        getUserGuilds: async () => [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }],
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
        // No DB in this boot — keep the role/beta lookups deterministic.
        if (fromDash && request === '../utils/botRoles') {
            return {
                canBypassFeatureGates: async () => { calls.canBypassFeatureGates++; return false; },
                getRole: async () => 'user',
                getRoleInfo: () => ({ label: 'User' }),
            };
        }
        if (fromDash && request === '../utils/betaManager') {
            return {
                canAccess: async () => { calls.canAccess++; return false; },
                isAllowed: async () => false,
                isEnabled: async () => false,
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

function get(urlPath, cookie) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            port: server.address().port, path: urlPath, method: 'GET',
            headers: { Accept: 'text/html', ...(cookie ? { Cookie: cookie } : {}) },
        }, (res) => {
            let data = '';
            res.on('data', c => (data += c));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        req.end();
    });
}

function signIn() {
    const sign = require('cookie-signature').sign;
    const sid = 'page-data-' + Math.random().toString(36).slice(2);
    const record = {
        cookie: { expires: new Date(Date.now() + 60 * 60 * 1000), maxAge: 60 * 60 * 1000, originalMaxAge: 60 * 60 * 1000 },
        user: { id: '1', username: 'admin', avatar: null },
        accessToken: 'tok',
        idleExpiresAt: Date.now() + 60 * 60 * 1000,
        // Pre-seed the guild list so the guard never calls Discord for it.
        guilds: [{ id: GUILD, name: 'Test Guild', owner: true, permissions: String(MANAGE_GUILD) }],
        guildsFetchedAt: Date.now(),
    };
    return new Promise((resolve, reject) => {
        testStore.set(sid, record, (err) => {
            if (err) return reject(err);
            const secret = process.env.SESSION_SECRET || 'test-secret';
            resolve(`primebot.sid=s:${sign(sid, secret)}`);
        });
    });
}

test.before(async () => {
    const a = boot();
    await new Promise(resolve => { server = a.listen(0, resolve); });
});
test.after(() => new Promise(resolve => { if (server) server.close(resolve); }));

test('the General (prefix) tab loads only the server settings slice', async () => {
    resetCalls();
    const cookie = await signIn();
    const r = await get(`/guild/${GUILD}/prefix`, cookie);

    assert.equal(r.status, 200, r.body.slice(0, 300));
    assert.match(r.body, /id="prefix-value"/);
    assert.equal(calls.getGuildConfig.length, 1, 'one config read');
    assert.deepEqual(calls.getGuildConfig[0], { only: ['server'] },
        'the prefix page must not load every feature slice');
    assert.equal(calls.getGuildChannels, 0, 'the prefix page renders no channel select');
    assert.equal(calls.getGuildRoles, 0, 'the prefix page renders no role select');
    assert.equal(calls.computeBotPermissions, 0, 'anti-nuke extras are not needed here');
    assert.equal(calls.getAntiNukeLockdown, 0);
    assert.equal(calls.getAntiNukeIncidentSummary, 0);
    assert.equal(calls.canAccess, 0, 'the prefix page renders no beta overlay');
    assert.equal(calls.canBypassFeatureGates, 0);
});

test('a beta-gated tab loads the beta flags', async () => {
    resetCalls();
    const cookie = await signIn();
    const r = await get(`/guild/${GUILD}/badges`, cookie);

    assert.equal(r.status, 200, r.body.slice(0, 300));
    assert.deepEqual(calls.getGuildConfig[0], { only: [] });
    assert.equal(calls.canAccess, 1);
    assert.equal(calls.canBypassFeatureGates, 1);
});

test('the AutoMod tab loads its own slice and the channel/role selectors', async () => {
    resetCalls();
    const cookie = await signIn();
    const r = await get(`/guild/${GUILD}/automod`, cookie);

    assert.equal(r.status, 200, r.body.slice(0, 300));
    assert.deepEqual(calls.getGuildConfig[0], { only: ['automod'] });
    assert.equal(calls.getGuildChannels, 1);
    assert.equal(calls.getGuildRoles, 1);
    assert.equal(calls.computeBotPermissions, 0, 'anti-nuke extras stay on the Anti-Nuke page');
});

test('the Anti-Nuke tab is the only one that loads the anti-nuke extras', async () => {
    resetCalls();
    const cookie = await signIn();
    const r = await get(`/guild/${GUILD}/antinuke`, cookie);

    assert.equal(r.status, 200, r.body.slice(0, 300));
    assert.deepEqual(calls.getGuildConfig[0], { only: ['antiNuke'] });
    assert.equal(calls.computeBotPermissions, 1);
    assert.equal(calls.getAntiNukeLockdown, 1);
    assert.equal(calls.getAntiNukeIncidentSummary, 1);
});

test('a light tab (Embed builder) skips the channel/role lookups entirely', async () => {
    resetCalls();
    const cookie = await signIn();
    const r = await get(`/guild/${GUILD}/embed`, cookie);

    assert.equal(r.status, 200, r.body.slice(0, 300));
    assert.deepEqual(calls.getGuildConfig[0], { only: [] });
    assert.equal(calls.getGuildChannels, 0);
    assert.equal(calls.getGuildRoles, 0);
});

// ── getGuildConfig honours `only` (real DB layer, no DB configured) ─────────

test('getGuildConfig loads only the requested slices', async () => {
    const db = require('../dashboard/db');
    const configMod = require('../config');

    // No database in this process: any slice loader that RUNS would log a
    // "read failed" warning. Silence + count them to prove none are attempted.
    const captured = [];
    const originalError = console.error;
    const capture = async (fn) => {
        const start = captured.length;
        console.error = (...args) => { captured.push(args.join(' ')); };
        try {
            await fn();
        } finally {
            console.error = originalError;
        }
        return captured.slice(start);
    };

    let empty;
    let serverOnly;
    const emptyErrors = await capture(async () => { empty = await db.getGuildConfig('1', { only: [] }); });
    const errors = await capture(async () => { serverOnly = await db.getGuildConfig('1', { only: ['server'] }); });

    // `only: []` issues no query at all.
    assert.deepEqual(emptyErrors.filter(e => e.includes('read failed')), [], 'no slice may be read when none is requested');
    assert.equal(empty.server.prefix, configMod.prefix, 'unrequested slices keep their defaults');
    assert.equal(empty.youtubeStats.totalSubscriptions, 0);
    assert.deepEqual(empty.ticketPanels, []);

    // `only: ['server']` reads server settings (+ the role rewards that ride on
    // them) — and nothing else, so the other pools are never touched.
    const failed = errors.filter(e => e.includes('read failed'));
    assert.ok(failed.every(e => /server_settings|leveling_role_rewards/.test(e)),
        `unexpected slice read: ${failed.join(' | ')}`);
    assert.equal(serverOnly.antiNuke, null, 'anti-nuke is not loaded');
    assert.deepEqual(serverOnly.youtubeSubscriptions, []);
});
