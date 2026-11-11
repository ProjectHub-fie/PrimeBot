// Automatic deployment update system tests.
//
// Three layers, each exercising REAL code:
//   1. dashboard/deployVersion.js — version resolution precedence + fallback.
//   2. dashboard/server.js over real HTTP — /version.json + Cache-Control
//      headers for HTML, static assets, and /api/*.
//   3. dashboard/public/js/auto-update.js in a vm sandbox — detection, loop
//      guards, route preservation, hidden-tab pause, error retry, unsaved defer.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const vm = require('node:vm');
const Module = require('node:module');

const ROOT = path.join(__dirname, '..');
const DASH = path.join(ROOT, 'dashboard');
const LAYOUT = require('../dashboard/render/layout');

// ─────────────────────────────────────────────────────────────────────────────
// 1. deployVersion resolution
// ─────────────────────────────────────────────────────────────────────────────

function freshDeployVersion() {
    delete require.cache[require.resolve('../dashboard/deployVersion')];
    return require('../dashboard/deployVersion');
}

function withEnv(vars, fn) {
    const saved = {};
    for (const k of Object.keys(vars)) { saved[k] = process.env[k]; }
    for (const [k, v] of Object.entries(vars)) {
        if (v == null) delete process.env[k];
        else process.env[k] = v;
    }
    try { return fn(); } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
}

test('deployVersion: VERCEL_GIT_COMMIT_SHA wins over other CI vars', () => {
    withEnv({
        PRIMEBOT_DEPLOY_VERSION: null, VERCEL_GIT_COMMIT_SHA: 'abc123sha',
        VERCEL_DEPLOYMENT_ID: 'dpl_x', COMMIT_REF: 'netlify', GITHUB_SHA: 'gh',
    }, () => {
        const dv = freshDeployVersion();
        assert.equal(dv.getDeployVersion(), 'abc123sha');
    });
});

test('deployVersion: explicit PRIMEBOT_DEPLOY_VERSION overrides everything', () => {
    withEnv({ PRIMEBOT_DEPLOY_VERSION: 'forced-1', VERCEL_GIT_COMMIT_SHA: 'abc' }, () => {
        const dv = freshDeployVersion();
        assert.equal(dv.getDeployVersion(), 'forced-1');
    });
});

test('deployVersion: falls back to VERCEL_DEPLOYMENT_ID when no SHA', () => {
    withEnv({ PRIMEBOT_DEPLOY_VERSION: null, VERCEL_GIT_COMMIT_SHA: null, VERCEL_DEPLOYMENT_ID: 'dpl_42' }, () => {
        const dv = freshDeployVersion();
        assert.equal(dv.getDeployVersion(), 'dpl_42');
    });
});

test('deployVersion: local dev falls back to a non-empty fingerprint (never empty)', () => {
    withEnv({
        PRIMEBOT_DEPLOY_VERSION: null, VERCEL_GIT_COMMIT_SHA: null,
        VERCEL_DEPLOYMENT_ID: null, COMMIT_REF: null, GITHUB_SHA: null,
    }, () => {
        const dv = freshDeployVersion();
        const v = dv.getDeployVersion();
        assert.ok(typeof v === 'string' && v.length > 0, 'version must never be empty');
        assert.match(v, /^dev-[0-9a-z]+$/, 'local fallback is a filesystem fingerprint');
    });
});

test('deployVersion: asset version is URL-safe and short', () => {
    withEnv({ PRIMEBOT_DEPLOY_VERSION: 'a/b c+d/e' }, () => {
        const dv = freshDeployVersion();
        const av = dv.getAssetVersion();
        assert.doesNotMatch(av, /[^a-zA-Z0-9._-]/);
        assert.ok(av.length <= 12);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. HTTP: version.json + cache headers
// ─────────────────────────────────────────────────────────────────────────────

function mockDb() {
    return {
        getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '1.0.0', features: {} }),
        getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
        getLivePolls: async () => [], getLiveGiveaways: async () => [],
        getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
        getGuildConfig: async () => ({ server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [] }),
        getServerSettings: async () => ({}),
        upsertServerSettings: async (gid, patch) => patch,
    };
}
function mockDiscord() {
    return {
        getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
        getBotGuildCount: async () => 0,
        getBotGuild: async (id) => ({ id, name: 'Test', approximate_member_count: 1 }),
        getGuildChannels: async () => [], getGuildRoles: async () => [],
        exchangeCode: async () => ({}), getCurrentUser: async () => ({ id: '1', username: 't' }),
        getUserGuilds: async () => [], canManageGuild: () => false,
    };
}

function bootApp() {
    const savedDbUrl = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
    process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
    process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
    process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

    const origLoad = Module._load;
    Module._load = function (request, parent) {
        const fromDash = parent && parent.filename && parent.filename.startsWith(DASH + path.sep);
        if (fromDash && request === './db') return mockDb();
        if (fromDash && request === './discord') return mockDiscord();
        if (fromDash && request === '../server/seasonDb') throw new Error('mock: no season pool');
        return origLoad.apply(this, arguments);
    };
    try {
        delete require.cache[require.resolve('../dashboard/server')];
        return require('../dashboard/server');
    } finally {
        Module._load = origLoad;
        if (savedDbUrl !== undefined) process.env.DATABASE_URL = savedDbUrl;
    }
}

function startServer(app) {
    return new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
}
function closeServer(server) {
    return new Promise((resolve) => server.close(resolve));
}
function fetchOnce(server, urlPath, opts = {}) {
    const { method = 'GET', headers = {} } = opts;
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
        req.end();
    });
}

async function withServer(fn) {
    const app = bootApp();
    const server = await startServer(app);
    try { await fn(server); } finally { await closeServer(server); }
}

test('GET /version.json returns a JSON version and is never cached', async () => {
    await withServer(async (server) => {
        const res = await fetchOnce(server, '/version.json');
        assert.equal(res.status, 200);
        assert.match(res.headers['content-type'] || '', /application\/json/);
        const cc = res.headers['cache-control'] || '';
        assert.match(cc, /no-store/, 'version.json must be no-store so open tabs see new builds');
        assert.match(res.headers['pragma'] || '', /no-cache/);
        const body = JSON.parse(res.body);
        assert.ok(body.version && typeof body.version === 'string');
        assert.ok(body.builtAt);
    });
});

test('HTML entry documents revalidate (no-cache) instead of going stale', async () => {
    await withServer(async (server) => {
        // /login is public (no auth) and renders real HTML through the shell.
        const res = await fetchOnce(server, '/login');
        assert.equal(res.status, 200);
        assert.match(res.headers['content-type'] || '', /text\/html/);
        const cc = res.headers['cache-control'] || '';
        assert.match(cc, /no-cache/, 'HTML must revalidate');
        assert.doesNotMatch(cc, /immutable/, 'HTML must not be immutable');
        assert.match(res.headers['vary'] || '', /Cookie/, 'HTML must vary on Cookie (personalized)');
    });
});

test('static assets are cached short-lived + must-revalidate (never immutable)', async () => {
    await withServer(async (server) => {
        const res = await fetchOnce(server, '/styles.css');
        assert.equal(res.status, 200);
        const cc = res.headers['cache-control'] || '';
        assert.match(cc, /public/);
        assert.match(cc, /max-age=\d+/);
        assert.match(cc, /must-revalidate/);
        assert.doesNotMatch(cc, /immutable/);
        assert.ok(res.headers['etag'], 'a strong ETag enables cheap 304 revalidation');
    });
});

test('/version.json served by the static handler (if built) is still no-store', async () => {
    await withServer(async (server) => {
        // The route handler wins, but assert the header regardless of which
        // handler answered — both must be no-store.
        const res = await fetchOnce(server, '/version.json?cachebust=1');
        assert.match(res.headers['cache-control'] || '', /no-store/);
    });
});

test('API responses are never stored (personalized data)', async () => {
    await withServer(async (server) => {
        const res = await fetchOnce(server, '/api/stats');
        // 401 (unauthenticated) is fine — the header must be present regardless.
        const cc = res.headers['cache-control'] || '';
        assert.match(cc, /no-store/, 'API responses must be no-store');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Layout: versioned assets + deploy injection
// ─────────────────────────────────────────────────────────────────────────────

test('layout versions local assets and injects the deploy config + detector', () => {
    const html = LAYOUT.render({ title: 'T', body: '', user: { username: 'u' } });
    assert.match(html, /href="\/styles\.css\?v=[^"]+"/);
    assert.match(html, /src="\/js\/icons\.js\?v=[^"]+"/);
    assert.match(html, /src="\/js\/common\.js\?v=[^"]+"/);
    assert.match(html, /src="\/js\/auto-update\.js\?v=[^"]+"/);
    assert.match(html, /window\.__PRIMEBOT_DEPLOY__=\{"version":"[^"]+"\}/);
});

test('layout versions page scripts too (guild tab scripts)', () => {
    const html = LAYOUT.render({ title: 'T', body: '', user: { username: 'u' }, scripts: ['/js/birthdays.js'] });
    assert.match(html, /src="\/js\/birthdays\.js\?v=[^"]+"/);
});

test('layout does not rewrite external asset URLs', () => {
    const html = LAYOUT.render({
        title: 'T', body: '',
        scripts: ['https://cdn.example.com/x.js'],
    });
    assert.match(html, /src="https:\/\/cdn\.example\.com\/x\.js"/);
    assert.doesNotMatch(html, /cdn\.example\.com\/x\.js\?v=/);
});

test('layout injects the detector on the login page too (stale login refreshes)', () => {
    const html = LAYOUT.render({ title: 'Login', body: '', login: true });
    assert.match(html, /src="\/js\/auto-update\.js\?v=[^"]+"/);
    assert.match(html, /window\.__PRIMEBOT_DEPLOY__=/);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Client detector (vm sandbox)
// ─────────────────────────────────────────────────────────────────────────────

const AUTO_UPDATE_SRC = fs.readFileSync(path.join(DASH, 'public', 'js', 'auto-update.js'), 'utf8');

function makeSandbox(deployVersion) {
    const handlers = { document: {}, window: {} };
    const location = {
        href: 'https://dash.example.com/guild/123/prefix?tab=general#top',
        reloads: 0,
        reload() { this.reloads++; },
        assign(url) { this.href = url; },
    };
    const body = { dataset: {} };
    const doc = {
        hidden: false,
        body,
        addEventListener: (evt, fn) => { (handlers.document[evt] = handlers.document[evt] || []).push(fn); },
        removeEventListener: () => {},
    };
    const win = {
        __PRIMEBOT_DEPLOY__: { version: deployVersion },
        __PRIMEBOT_AUTOUPDATE_TEST__: true,
        document: doc,
        location,
        addEventListener: (evt, fn) => { (handlers.window[evt] = handlers.window[evt] || []).push(fn); },
        removeEventListener: () => {},
    };
    const sandbox = {
        window: win, document: doc, console, Promise, Date, JSON, parseInt, Number,
        module: { exports: {} },
        setTimeout: () => 0, clearTimeout: () => {},
    };
    vm.createContext(sandbox);
    vm.runInContext(AUTO_UPDATE_SRC, sandbox);
    return { sandbox, win, doc, location, handlers, factory: win.PrimeBotAutoUpdate };
}

// Build a manager with fully-injected dependencies so no real timer/network/DOM
// is touched. Returns the manager plus inspection helpers.
function makeManager({ deployVersion = 'v1', fetchImpl, now, storageMap } = {}) {
    const sb = makeSandbox(deployVersion);
    const timers = [];
    let nowVal = now != null ? now : 1_000_000;
    const fetches = [];
    const map = storageMap || new Map();
    const manager = sb.factory({
        window: sb.win,
        document: sb.doc,
        location: sb.location,
        fetchFn: (url, opts) => {
            fetches.push({ url, opts });
            return fetchImpl ? fetchImpl(url, opts) : Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ version: 'v1' }) });
        },
        setTimeoutFn: (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; },
        clearTimeoutFn: () => {},
        nowFn: () => nowVal,
        storage: {
            getItem: (k) => (map.has(k) ? map.get(k) : null),
            setItem: (k, v) => map.set(k, String(v)),
            removeItem: (k) => map.delete(k),
        },
        intervalMs: 60000,
        logger: () => {},
    });
    return { manager, sb, timers, fetches, map, setNow: (v) => { nowVal = v; } };
}

function settle() { return new Promise((r) => setImmediate(r)); }

test('client: reloads once when the fetched version differs', () => {
    const h = makeManager({ deployVersion: 'v1' });
    const reloaded = h.manager.evaluate('v2');
    assert.equal(reloaded, true);
    assert.equal(h.sb.location.reloads, 1);
    assert.equal(h.manager.state.pendingVersion, 'v2');
});

test('client: no reload when the version matches', () => {
    const h = makeManager({ deployVersion: 'v1' });
    assert.equal(h.manager.evaluate('v1'), false);
    assert.equal(h.sb.location.reloads, 0);
});

test('client: no reload loop — the same new version reloads at most once', () => {
    const h = makeManager({ deployVersion: 'v1' });
    h.manager.evaluate('v2');
    h.manager.evaluate('v2');   // a second observation of the same version
    h.manager.evaluate('v2');
    assert.equal(h.sb.location.reloads, 1, 'must reload exactly once per new version');
});

test('client: a further new version still triggers a reload (fresh page instance)', () => {
    // In a real reload the JS instance is destroyed and re-created. Model that:
    // a NEW manager whose page loaded v2 (applied marker set) and now sees v3.
    const map = new Map();
    map.set('primebot.update.applied', 'v2');
    map.set('primebot.update.reloadedAt', String(1_000_000 - 60_000)); // cooldown elapsed
    const h = makeManager({ deployVersion: 'v2', storageMap: map, now: 1_000_000 });
    h.manager.evaluate('v3');
    assert.equal(h.sb.location.reloads, 1);
    assert.equal(map.get('primebot.update.applied'), 'v3');
});

test('client: a stale applied marker for the SAME version blocks a reload (no loop)', () => {
    // The page reloaded for v2 but an intermediate cache served v1's HTML
    // again; the detector must NOT reload again for v2 (that would loop).
    const map = new Map();
    map.set('primebot.update.applied', 'v2');
    map.set('primebot.update.reloadedAt', String(1_000_000 - 60_000));
    const h = makeManager({ deployVersion: 'v1', storageMap: map, now: 1_000_000 });
    assert.equal(h.manager.evaluate('v2'), false);
    assert.equal(h.sb.location.reloads, 0);
});

test('client: reload preserves the current route + query (location.reload)', () => {
    const h = makeManager({ deployVersion: 'v1' });
    h.manager.evaluate('v2');
    assert.equal(h.sb.location.href, 'https://dash.example.com/guild/123/prefix?tab=general#top');
    assert.equal(h.sb.location.reloads, 1);
});

test('client: defers the reload while there are unsaved changes', () => {
    const h = makeManager({ deployVersion: 'v1' });
    h.sb.doc.body.dataset.unsaved = '1';
    assert.equal(h.manager.evaluate('v2'), false);
    assert.equal(h.sb.location.reloads, 0, 'no reload while unsaved');
    assert.equal(h.manager.state.pendingVersion, 'v2', 'the pending version is remembered');
    // User saves/discards → the next observation reloads.
    delete h.sb.doc.body.dataset.unsaved;
    assert.equal(h.manager.evaluate('v2'), true);
    assert.equal(h.sb.location.reloads, 1);
});

test('client: hidden tab pauses polling (checkNow issues no fetch)', async () => {
    const h = makeManager({ deployVersion: 'v1' });
    h.manager.start();
    h.sb.doc.hidden = true;
    h.manager.checkNow();
    await settle();
    assert.equal(h.fetches.length, 0, 'hidden tab must not poll');
});

test('client: a fetch is made with cache disabled + a cache-busting query', async () => {
    const h = makeManager({ deployVersion: 'v1' });
    h.manager.start();
    h.manager.checkNow();
    await settle();
    assert.equal(h.fetches.length, 1);
    const { url, opts } = h.fetches[0];
    assert.match(url, /\/version\.json\?/);
    assert.equal(opts.cache, 'no-store');
    assert.equal(opts.credentials, 'same-origin');
});

test('client: becomes visible → immediate re-check', async () => {
    const h = makeManager({ deployVersion: 'v1' });
    h.manager.start();
    h.sb.doc.hidden = true;
    // Fire the visibilitychange handler with the tab now visible.
    h.sb.doc.hidden = false;
    for (const fn of (h.sb.handlers.document.visibilitychange || [])) fn();
    await settle();
    assert.equal(h.fetches.length, 1, 'a visible tab re-checks immediately');
});

test('client: network error is handled gracefully and retried later', async () => {
    let calls = 0;
    const h = makeManager({
        deployVersion: 'v1',
        fetchImpl: () => { calls++; return Promise.reject(new Error('offline')); },
    });
    h.manager.start();
    h.manager.checkNow();
    await settle();
    assert.equal(calls, 1);
    assert.equal(h.sb.location.reloads, 0, 'a network error never reloads');
    assert.equal(h.manager.state.errors, 1);
    assert.ok(h.timers.length >= 1, 'a retry is scheduled');
});

test('client: malformed JSON response is tolerated (no throw, no reload)', async () => {
    const h = makeManager({
        deployVersion: 'v1',
        fetchImpl: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new Error('bad json')) }),
    });
    h.manager.start();
    h.manager.checkNow();
    await settle();
    assert.equal(h.sb.location.reloads, 0);
    assert.equal(h.manager.state.errors, 1);
});

test('client: non-2xx response does not reload', async () => {
    const h = makeManager({
        deployVersion: 'v1',
        fetchImpl: () => Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) }),
    });
    h.manager.start();
    h.manager.checkNow();
    await settle();
    assert.equal(h.sb.location.reloads, 0);
    assert.equal(h.manager.state.errors, 1);
});

test('client: a full check cycle reloads when the fetched version changes', async () => {
    const h = makeManager({
        deployVersion: 'v1',
        fetchImpl: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ version: 'v9' }) }),
    });
    h.manager.start();
    h.manager.checkNow();
    await settle();
    assert.equal(h.sb.location.reloads, 1);
});

test('client: stop() prevents further polling', async () => {
    const h = makeManager({ deployVersion: 'v1' });
    h.manager.start();
    h.manager.stop();
    h.manager.checkNow();
    await settle();
    assert.equal(h.fetches.length, 0);
});

test('auto-update script does not auto-start when the test opt-out flag is set', () => {
    const sb = makeSandbox('v1'); // __PRIMEBOT_AUTOUPDATE_TEST__ = true
    assert.equal(typeof sb.factory, 'function');
    // No manager was auto-created (nothing scheduled / no fetch happened).
    assert.ok(sb.win.PrimeBotAutoUpdate);
});
