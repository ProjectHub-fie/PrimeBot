// Tests for the invisible Cloudflare Turnstile login gate:
//   - loginPage renders the widget + api.js only when a site key is provided
//   - turnstile_failed surfaces a friendly login error
//   - verifyTurnstile skips when no secret, rejects missing tokens, and
//     round-trips Cloudflare's siteverify response (fetch mocked)
//   - HTTP: /auth/discord bounces to /login?error=turnstile_failed without a
//     valid token and proceeds to the Discord OAuth redirect with one
// Pure except the HTTP section, which boots the real dashboard server with
// db/discord mocked (same pattern as sessionIdleHttp.test.js) and global.fetch
// stubbed — no network.

process.env.TURNSTILE_SITE_KEY = 'test-site-key'; // read by constants at require time

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('path');
const Module = require('module');

const pages = require('../dashboard/render/pages');
const turnstile = require('../dashboard/turnstile');

const DASH = path.join(__dirname, '..', 'dashboard');

// ── Render ──────────────────────────────────────────────────────────────────

test('login page without a site key renders no Turnstile widget', () => {
    const html = pages.loginPage({});
    assert.doesNotMatch(html, /challenges\.cloudflare\.com\/turnstile/);
    assert.doesNotMatch(html, /cf-turnstile-widget/);
    assert.doesNotMatch(html, /__TURNSTILE_SITE_KEY__/);
    assert.match(html, /href="\/auth\/discord"/);
});

test('login page with a site key renders the invisible widget + api.js', () => {
    const html = pages.loginPage({ turnstileSiteKey: 'site-key-123' });
    assert.match(html, /id="cf-turnstile-widget"/);
    assert.match(html, /challenges\.cloudflare\.com\/turnstile\/v0\/api\.js\?render=explicit/);
    assert.match(html, /window\.__TURNSTILE_SITE_KEY__="site-key-123"/);
    assert.match(html, /id="login-discord-btn"/);
});

test('login page surfaces the turnstile_failed error', () => {
    const html = pages.loginPage({ errorKey: 'turnstile_failed' });
    assert.match(html, /security check could not be verified/i);
});

// ── verifyTurnstile helper ──────────────────────────────────────────────────

test('verifyTurnstile skips verification when no secret is configured', async () => {
    const saved = process.env.TURNSTILE_SECRET_KEY;
    delete process.env.TURNSTILE_SECRET_KEY;
    try {
        const res = await turnstile.verifyTurnstile(undefined);
        assert.equal(res.success, true);
        assert.equal(res.skipped, true);
    } finally {
        if (saved !== undefined) process.env.TURNSTILE_SECRET_KEY = saved;
    }
});

test('verifyTurnstile rejects a missing token when a secret is configured', async () => {
    const saved = process.env.TURNSTILE_SECRET_KEY;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    try {
        const res = await turnstile.verifyTurnstile(undefined);
        assert.equal(res.success, false);
        assert.deepEqual(res['error-codes'], ['missing-input-response']);
    } finally {
        if (saved === undefined) delete process.env.TURNSTILE_SECRET_KEY;
        else process.env.TURNSTILE_SECRET_KEY = saved;
    }
});

test('verifyTurnstile posts the token to siteverify and returns the verdict', async () => {
    const saved = process.env.TURNSTILE_SECRET_KEY;
    const savedFetch = global.fetch;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    let seenBody;
    global.fetch = async (url, opts) => {
        assert.equal(url, turnstile.SITEVERIFY_URL);
        seenBody = new URLSearchParams(opts.body);
        return { ok: true, json: async () => ({ success: true, 'error-codes': [] }) };
    };
    try {
        const res = await turnstile.verifyTurnstile('tok-abc', '1.2.3.4');
        assert.equal(res.success, true);
        assert.equal(seenBody.get('secret'), 'secret');
        assert.equal(seenBody.get('response'), 'tok-abc');
        assert.equal(seenBody.get('remoteip'), '1.2.3.4');
    } finally {
        global.fetch = savedFetch;
        if (saved === undefined) delete process.env.TURNSTILE_SECRET_KEY;
        else process.env.TURNSTILE_SECRET_KEY = saved;
    }
});

// ── HTTP: /auth/discord gate ────────────────────────────────────────────────

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
        getGuildChannels: async () => [],
        getGuildRoles: async () => [],
        exchangeCode: async () => ({ access_token: 'fake-access', refresh_token: 'fake-refresh', expires_in: 3600 }),
        getCurrentUser: async () => ({ id: '1', username: 'tester', discriminator: '0', global_name: 'Tester', avatar: null }),
        getUserGuilds: async () => [],
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
    Module._load = function (request, parent, isMain) {
        const fromServer = parent && parent.filename && parent.filename.startsWith(DASH + path.sep + 'server.js');
        if (fromServer && request === './db') return mockDb();
        if (fromServer && request === './discord') return mockDiscord();
        if (fromServer && request === '../server/seasonDb') throw new Error('mock: no season db pool');
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

function fetchOnce(server, urlPath) {
    return new Promise((resolve, reject) => {
        const req = http.request({ port: server.address().port, path: urlPath, method: 'GET' }, (res) => {
            let data = '';
            res.on('data', (c) => (data += c));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        req.end();
    });
}

test('HTTP: /auth/discord requires a valid Turnstile token when configured', async () => {
    const savedSecret = process.env.TURNSTILE_SECRET_KEY;
    const savedFetch = global.fetch;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    global.fetch = async () => ({ ok: true, json: async () => ({ success: true }) });

    const app = bootApp();
    const server = await new Promise((resolve) => {
        const s = app.listen(0, () => resolve(s));
    });
    try {
        // The login page advertises the widget.
        const login = await fetchOnce(server, '/login');
        assert.equal(login.status, 200);
        assert.match(login.body, /cf-turnstile-widget/);
        assert.match(login.body, /__TURNSTILE_SITE_KEY__="test-site-key"/);

        // No token → bounced back to the login page with the error.
        const noToken = await fetchOnce(server, '/auth/discord');
        assert.equal(noToken.status, 302);
        assert.equal(noToken.headers.location, '/login?error=turnstile_failed');

        // Valid token (fetch stubbed to success) → Discord OAuth redirect.
        const ok = await fetchOnce(server, '/auth/discord?cf-turnstile-response=tok');
        assert.equal(ok.status, 302);
        assert.match(ok.headers.location, /^https:\/\/discord\.com\/api\/oauth2\/authorize\?/);
    } finally {
        await new Promise((resolve) => server.close(resolve));
        global.fetch = savedFetch;
        if (savedSecret === undefined) delete process.env.TURNSTILE_SECRET_KEY;
        else process.env.TURNSTILE_SECRET_KEY = savedSecret;
    }
});

test('HTTP: /auth/discord bounces when Cloudflare rejects the token', async () => {
    const savedSecret = process.env.TURNSTILE_SECRET_KEY;
    const savedFetch = global.fetch;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    global.fetch = async () => ({ ok: true, json: async () => ({ success: false, 'error-codes': ['invalid-input-response'] }) });

    const app = bootApp();
    const server = await new Promise((resolve) => {
        const s = app.listen(0, () => resolve(s));
    });
    try {
        const res = await fetchOnce(server, '/auth/discord?cf-turnstile-response=bad');
        assert.equal(res.status, 302);
        assert.equal(res.headers.location, '/login?error=turnstile_failed');
    } finally {
        await new Promise((resolve) => server.close(resolve));
        global.fetch = savedFetch;
        if (savedSecret === undefined) delete process.env.TURNSTILE_SECRET_KEY;
        else process.env.TURNSTILE_SECRET_KEY = savedSecret;
    }
});

// ── Client behavior (login.js in a vm sandbox) ──────────────────────────────
// The invisible widget must start on PAGE LOAD (not on click) and cache the
// token, so clicking Login navigates instantly. login.js is plain browser JS;
// run it in a vm with a minimal DOM + turnstile stub (same trick the icons
// test uses for window-global exposure).
const vm = require('node:vm');
const fs = require('fs');

const LOGIN_JS = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'login.js'), 'utf8');

function makeLoginSandbox({ executeBehavior } = {}) {
    const els = {};
    const rendered = [];
    const executed = [];
    const listeners = {};
    const fakeEl = (id) => ({
        id,
        textContent: '',
        hidden: true,
        style: {},
        addEventListener(type, fn) { listeners[type] = fn; },
        querySelector() { return { textContent: '' }; },
    });
    const sandboxWindow = {
        __TURNSTILE_SITE_KEY__: 'site-key',
        location: { href: '' },
        turnstile: {
            render(sel, opts) { rendered.push(opts); return rendered.length - 1; },
            execute(widgetId) {
                executed.push(widgetId);
                if (executeBehavior === 'resolve') rendered[widgetId].callback('tok-page-load');
                // default: leave the challenge in-flight (no token yet)
            },
            reset() {},
        },
    };
    const sandbox = {
        window: sandboxWindow,
        document: { getElementById: (id) => (els[id] = els[id] || fakeEl(id)) },
        performance,
        requestAnimationFrame: () => {},
        api: async () => ({}),
        esc: (s) => String(s),
        setInterval, clearInterval, setTimeout, clearTimeout,
        console,
    };
    vm.createContext(sandbox);
    vm.runInContext(LOGIN_JS, sandbox);
    return { sandboxWindow, rendered, executed, listeners };
}

test('client: the widget executes on page load (eager warm-up)', () => {
    const { rendered, executed } = makeLoginSandbox();
    assert.equal(rendered.length, 1, 'widget rendered exactly once');
    assert.ok(executed.length >= 1, 'widget executed without waiting for a click');
});

test('client: a cached token makes Login navigate instantly on click', () => {
    const { sandboxWindow, rendered, listeners } = makeLoginSandbox({ executeBehavior: 'resolve' });
    assert.equal(sandboxWindow.location.href, '', 'no navigation before the click');
    listeners.click({ preventDefault() {} });
    assert.equal(sandboxWindow.location.href, '/auth/discord?cf-turnstile-response=tok-page-load');
    assert.equal(rendered.length, 1, 'no second widget render');
});

test('client: a click while the challenge is still in flight waits, then navigates from the callback', () => {
    const { sandboxWindow, rendered, executed, listeners } = makeLoginSandbox();
    listeners.click({ preventDefault() {} }); // token not ready yet
    assert.equal(sandboxWindow.location.href, '', 'click did not navigate without a token');
    rendered[rendered.length - 1].callback('tok-after-wait');
    assert.equal(sandboxWindow.location.href, '/auth/discord?cf-turnstile-response=tok-after-wait');
    // Expiry refreshes the cached token in the background.
    const before = executed.length;
    rendered[rendered.length - 1]['expired-callback']();
    assert.equal(executed.length, before + 1, 'expiry re-executes the challenge');
});
