// Tests for the invisible Cloudflare Turnstile login gate:
//   - loginPage renders the widget + api.js only when a site key is provided,
//     keeps the "Login with Discord" label, and adds a Status link next to the
//     Documentation link
//   - turnstile_failed surfaces a friendly login error
//   - verifyTurnstile skips when no secret, rejects missing/oversized tokens,
//     bounds the request with a timeout and round-trips Cloudflare's verdict
//   - HTTP: /auth/discord bounces to /login?error=turnstile_failed without a
//     valid token (including a Cloudflare network failure) and proceeds to the
//     Discord OAuth redirect with one
//   - client (vm): one challenge per tap, inline spinner + "Verifying…", ✓ +
//     "Verified" then the OAuth redirect, failure/timeout/unavailable → error +
//     retry, rapid taps, unmount safety
// Pure except the HTTP section, which boots the real dashboard server with
// db/discord mocked (same pattern as sessionIdleHttp.test.js) and global.fetch
// stubbed — no network.

process.env.TURNSTILE_SITE_KEY = 'test-site-key'; // read by constants at require time

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
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

test('the Login button keeps its label and carries the inline indicator slot', () => {
    const html = pages.loginPage({ turnstileSiteKey: 'site-key-123' });
    const button = /<a[^>]*id="login-discord-btn"[^>]*>([\s\S]*?)<\/a>/.exec(html);
    assert.ok(button, 'login button missing');
    const inner = button[1];
    // The label text is never replaced by the flow.
    assert.match(inner, /<span class="login-auth-label">Login with Discord<\/span>/);
    // Spinner + ✓ live in one fixed-size slot beside the label.
    assert.match(inner, /<span class="login-auth-slot" aria-hidden="true">/);
    assert.match(inner, /<span class="login-spinner"><\/span>/);
    assert.match(inner, /class="ico login-check"/);
});

test('the login page renders a status line region for the flow', () => {
    const html = pages.loginPage({ turnstileSiteKey: 'site-key-123' });
    assert.match(html, /<p id="login-status"[^>]*role="status"[^>]*aria-live="polite"[^>]*hidden><\/p>/);
    assert.match(html, /<p id="turnstile-error"[^>]*role="alert"[^>]*hidden><\/p>/);
    assert.match(html, /class="login-auth-status"/);
});

test('a Status link with an SVG icon sits beside Documentation on the login page', () => {
    const html = pages.loginPage({});
    const links = /<div class="login-links">([\s\S]*?)<\/div>/.exec(html);
    assert.ok(links, 'login-links container missing');
    assert.match(links[1], /href="\/docs"[^>]*class="btn btn-secondary"/);
    const statusLink = /<a href="\/stats"[^>]*>([\s\S]*?)<\/a>/.exec(links[1]);
    assert.ok(statusLink, 'Status link missing next to Documentation');
    assert.match(statusLink[1], /<svg class="ico"[^>]*viewBox="0 0 24 24"/, 'Status link needs an SVG icon');
    assert.match(statusLink[1], /Status/);
});

test('Documentation and Status form one row of two equal halves', () => {
    const css = fs.readFileSync(path.join(DASH, 'public', 'styles.css'), 'utf8');
    const rule = /\.login-links \{([\s\S]*?)\}/.exec(css);
    assert.ok(rule, '.login-links rule missing');
    assert.match(rule[1], /display: grid/);
    assert.match(rule[1], /grid-template-columns: 1fr 1fr/);
    assert.match(rule[1], /max-width/);
});

test('the login page surfaces the turnstile_failed error', () => {
    const html = pages.loginPage({ errorKey: 'turnstile_failed' });
    assert.match(html, /security check could not be verified/i);
});

test('reduced-motion users get no spinner rotation or check pop', () => {
    const css = fs.readFileSync(path.join(DASH, 'public', 'styles.css'), 'utf8');
    const block = /@media \(prefers-reduced-motion: reduce\) \{([\s\S]*?)\n\}/.exec(css);
    assert.ok(block, 'reduced-motion block missing');
    assert.match(block[1], /\.login-auth-btn\.is-verifying \.login-spinner/);
    assert.match(block[1], /animation: none/);
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

test('verifyTurnstile rejects an oversized token without calling Cloudflare', async () => {
    const savedSecret = process.env.TURNSTILE_SECRET_KEY;
    const savedFetch = global.fetch;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    let called = false;
    global.fetch = async () => { called = true; return { ok: true, json: async () => ({ success: true }) }; };
    try {
        const res = await turnstile.verifyTurnstile('x'.repeat(turnstile.MAX_TOKEN_LENGTH + 1));
        assert.equal(res.success, false);
        assert.deepEqual(res['error-codes'], ['invalid-input-response']);
        assert.equal(called, false, 'no request is sent for a bogus token');
    } finally {
        global.fetch = savedFetch;
        if (savedSecret === undefined) delete process.env.TURNSTILE_SECRET_KEY;
        else process.env.TURNSTILE_SECRET_KEY = savedSecret;
    }
});

test('verifyTurnstile posts the token to siteverify and returns the verdict', async () => {
    const saved = process.env.TURNSTILE_SECRET_KEY;
    const savedFetch = global.fetch;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    let seenBody;
    let seenSignal;
    global.fetch = async (url, opts) => {
        assert.equal(url, turnstile.SITEVERIFY_URL);
        seenBody = new URLSearchParams(opts.body);
        seenSignal = opts.signal;
        return { ok: true, json: async () => ({ success: true, 'error-codes': [] }) };
    };
    try {
        const res = await turnstile.verifyTurnstile('tok-abc', '1.2.3.4');
        assert.equal(res.success, true);
        assert.equal(seenBody.get('secret'), 'secret');
        assert.equal(seenBody.get('response'), 'tok-abc');
        assert.equal(seenBody.get('remoteip'), '1.2.3.4');
        // A stuck siteverify call can never hang the login request.
        assert.ok(seenSignal, 'the siteverify request must be abortable');
        assert.ok(turnstile.VERIFY_TIMEOUT_MS > 0 && turnstile.VERIFY_TIMEOUT_MS <= 30000);
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

async function withServer(fn) {
    const app = bootApp();
    const server = await new Promise((resolve) => {
        const s = app.listen(0, () => resolve(s));
    });
    try {
        return await fn(server);
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
}

test('HTTP: /auth/discord requires a valid Turnstile token when configured', async () => {
    const savedSecret = process.env.TURNSTILE_SECRET_KEY;
    const savedFetch = global.fetch;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    global.fetch = async () => ({ ok: true, json: async () => ({ success: true }) });

    try {
        await withServer(async (server) => {
            const login = await fetchOnce(server, '/login');
            assert.equal(login.status, 200);
            assert.match(login.body, /cf-turnstile-widget/);
            assert.match(login.body, /__TURNSTILE_SITE_KEY__="test-site-key"/);

            // A client that skips the challenge never reaches Discord.
            const noToken = await fetchOnce(server, '/auth/discord');
            assert.equal(noToken.status, 302);
            assert.equal(noToken.headers.location, '/login?error=turnstile_failed');

            // A token Cloudflare accepts → Discord OAuth redirect.
            const ok = await fetchOnce(server, '/auth/discord?cf-turnstile-response=tok');
            assert.equal(ok.status, 302);
            assert.match(ok.headers.location, /^https:\/\/discord\.com\/api\/oauth2\/authorize\?/);
        });
    } finally {
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

    try {
        await withServer(async (server) => {
            const res = await fetchOnce(server, '/auth/discord?cf-turnstile-response=bad');
            assert.equal(res.status, 302);
            assert.equal(res.headers.location, '/login?error=turnstile_failed');
        });
    } finally {
        global.fetch = savedFetch;
        if (savedSecret === undefined) delete process.env.TURNSTILE_SECRET_KEY;
        else process.env.TURNSTILE_SECRET_KEY = savedSecret;
    }
});

test('HTTP: /auth/discord bounces when Cloudflare is unreachable (no OAuth redirect)', async () => {
    const savedSecret = process.env.TURNSTILE_SECRET_KEY;
    const savedFetch = global.fetch;
    process.env.TURNSTILE_SECRET_KEY = 'secret';
    global.fetch = async () => { throw new Error('network down'); };

    try {
        await withServer(async (server) => {
            const res = await fetchOnce(server, '/auth/discord?cf-turnstile-response=tok');
            assert.equal(res.status, 302);
            assert.equal(res.headers.location, '/login?error=turnstile_failed');
        });
    } finally {
        global.fetch = savedFetch;
        if (savedSecret === undefined) delete process.env.TURNSTILE_SECRET_KEY;
        else process.env.TURNSTILE_SECRET_KEY = savedSecret;
    }
});

// ── Client behavior (login.js in a vm sandbox) ──────────────────────────────
// login.js is plain browser JS; run it in a vm with a minimal DOM, a fake clock
// and a Turnstile stub so the whole tap → verify → ✓ → redirect flow (and its
// failure/retry paths) is exercised without a browser or the network.

const LOGIN_JS = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'login.js'), 'utf8');

function makeClock() {
    let now = 0;
    let seq = 0;
    const timers = new Map();
    return {
        now: () => now,
        setTimeout(fn, ms = 0) {
            const id = ++seq;
            timers.set(id, { at: now + ms, fn });
            return id;
        },
        clearTimeout(id) { timers.delete(id); },
        tick(ms) {
            now += ms;
            for (let guard = 0; guard < 500; guard++) {
                const due = [...timers.entries()]
                    .filter(([, t]) => t.at <= now)
                    .sort((a, b) => a[1].at - b[1].at)[0];
                if (!due) return;
                timers.delete(due[0]);
                due[1].fn();
            }
        },
        pending: () => timers.size,
    };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

function makeLoginSandbox({ siteKey, execute = 'hang', noApi = false } = {}) {
    const clock = makeClock();
    const calls = { rendered: [], executed: [], resets: [], removed: [], assigned: [], prevented: 0 };
    const listeners = {};
    const winListeners = {};
    const els = new Map();

    function el(id) {
        if (!els.has(id)) {
            const classes = new Set();
            els.set(id, {
                id,
                textContent: '',
                hidden: false,
                dataset: {},
                style: {},
                classList: {
                    add: (...c) => c.forEach((x) => classes.add(x)),
                    remove: (...c) => c.forEach((x) => classes.delete(x)),
                    contains: (c) => classes.has(c),
                },
                attributes: {},
                setAttribute(k, v) { this.attributes[k] = String(v); },
                removeAttribute(k) { delete this.attributes[k]; },
                getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; },
                addEventListener(type, fn) { listeners[type] = fn; },
                querySelector() { return { textContent: '' }; },
            });
        }
        return els.get(id);
    }

    const behaviour = () => (Array.isArray(execute) ? execute.shift() : execute);
    const turnstileStub = {
        render(sel, opts) {
            calls.rendered.push({ sel, opts });
            return calls.rendered.length - 1;
        },
        execute(id) {
            calls.executed.push(id);
            const opts = calls.rendered[id].opts;
            const mode = behaviour();
            if (mode === 'success') opts.callback('tok-' + calls.executed.length);
            if (mode === 'error') opts['error-callback']('bad');
            if (mode === 'reject') return Promise.reject(new Error('cannot start'));
            return undefined;
        },
        reset(id) { calls.resets.push(id); },
        remove(id) { calls.removed.push(id); },
    };

    const win = {
        __TURNSTILE_SITE_KEY__: siteKey === undefined ? 'site-key' : siteKey,
        turnstile: noApi ? undefined : turnstileStub,
        location: {
            href: '',
            assign(url) { calls.assigned.push(url); win.location.href = url; },
        },
        addEventListener(type, fn) { winListeners[type] = fn; },
    };

    const FakeDate = class extends Date {
        static now() { return clock.now(); }
    };
    const sandbox = {
        window: win,
        document: { getElementById: (id) => el(id) },
        performance,
        requestAnimationFrame: () => {},
        api: async () => ({}),
        esc: (s) => String(s),
        setTimeout: clock.setTimeout,
        clearTimeout: clock.clearTimeout,
        setInterval: () => 0,
        clearInterval: () => {},
        console,
        Date: FakeDate,
    };
    vm.createContext(sandbox);
    vm.runInContext(LOGIN_JS, sandbox);

    const click = () => {
        if (!listeners.click) return false;
        listeners.click({ preventDefault() { calls.prevented += 1; } });
        return true;
    };
    return {
        clock, calls, listeners, winListeners, click,
        btn: el('login-discord-btn'),
        status: el('login-status'),
        error: el('turnstile-error'),
        opts: () => calls.rendered[calls.rendered.length - 1].opts,
        fire: (type) => winListeners[type] && winListeners[type]({ persisted: type === 'pageshow' }),
    };
}

test('client: tapping Login runs one invisible challenge and shows Verifying…', async () => {
    const sb = makeLoginSandbox();
    sb.click();
    await flush();

    assert.equal(sb.calls.prevented, 1, 'the plain link navigation is prevented');
    assert.equal(sb.calls.executed.length, 1, 'exactly one challenge');
    assert.equal(sb.calls.rendered[0].opts.size, 'invisible', 'never a visible checkbox');
    assert.equal(sb.calls.rendered[0].opts.sitekey, 'site-key');
    assert.equal(sb.btn.classList.contains('is-busy'), true);
    assert.equal(sb.btn.classList.contains('is-verifying'), true);
    assert.equal(sb.btn.getAttribute('aria-busy'), 'true');
    assert.equal(sb.btn.getAttribute('aria-disabled'), 'true');
    assert.equal(sb.status.textContent, 'Verifying…');
    assert.equal(sb.status.hidden, false);
    assert.equal(sb.calls.assigned.length, 0, 'no redirect while verifying');
});

test('client: the button label is never rewritten by the flow', () => {
    const src = fs.readFileSync(path.join(DASH, 'public', 'js', 'login.js'), 'utf8');
    assert.doesNotMatch(src, /btn\.textContent\s*=/, 'the label must stay "Login with Discord"');
    assert.doesNotMatch(src, /login-auth-label['"]?\)?\s*\.\s*textContent\s*=/, 'label text must not be swapped');
    // ...it only toggles the inline indicator classes + the status text.
    assert.match(src, /is-verifying/);
    assert.match(src, /is-verified/);
    assert.match(src, /aria-busy/);
});

test('client: rapid taps only ever run one challenge', async () => {
    const sb = makeLoginSandbox();
    sb.click();
    sb.click();
    sb.click();
    await flush();
    sb.click();
    await flush();
    assert.equal(sb.calls.prevented, 4, 'every tap is intercepted');
    assert.equal(sb.calls.executed.length, 1, 'but only one challenge runs');
});

test('client: success shows ✓ + Verified, then continues to Discord OAuth', async () => {
    const sb = makeLoginSandbox({ execute: 'success' });
    sb.click();
    await flush();

    assert.equal(sb.btn.classList.contains('is-verified'), true);
    assert.equal(sb.btn.classList.contains('is-verifying'), false, 'the spinner is replaced by the ✓');
    assert.equal(sb.status.textContent, 'Verified — continuing to Discord…');
    assert.equal(sb.calls.assigned.length, 0, 'the ✓ is held before redirecting');

    sb.clock.tick(699);
    assert.equal(sb.calls.assigned.length, 0);
    sb.clock.tick(1);
    assert.deepEqual(sb.calls.assigned, ['/auth/discord?cf-turnstile-response=tok-1']);
    // Still the existing OAuth entry point — same route the server verifies.
    assert.match(sb.calls.assigned[0], /^\/auth\/discord\?cf-turnstile-response=/);
});

test('client: a failed challenge shows an error, re-enables the button and never redirects', async () => {
    const sb = makeLoginSandbox({ execute: 'error' });
    sb.click();
    await flush();

    assert.match(sb.error.textContent, /could not be verified/i);
    assert.equal(sb.error.hidden, false);
    assert.equal(sb.status.textContent, '', 'the loading text is cleared');
    assert.equal(sb.btn.classList.contains('is-busy'), false);
    assert.equal(sb.btn.getAttribute('aria-disabled'), null, 'the button is usable again');
    assert.equal(sb.calls.resets.length, 1, 'the widget is reset for the next attempt');
    sb.clock.tick(5000);
    assert.equal(sb.calls.assigned.length, 0);
});

test('client: a hung challenge times out with a clear error and no redirect', async () => {
    const sb = makeLoginSandbox({ execute: 'hang' });
    sb.click();
    await flush();
    sb.clock.tick(14999);
    assert.equal(sb.error.hidden, true, 'still waiting just before the limit');
    sb.clock.tick(1);
    assert.match(sb.error.textContent, /timed out/i);
    assert.equal(sb.btn.classList.contains('is-busy'), false);
    assert.equal(sb.calls.assigned.length, 0);
});

test('client: an unavailable widget fails fast with an error (no redirect)', async () => {
    const sb = makeLoginSandbox({ noApi: true });
    sb.click();
    await flush();
    assert.equal(sb.status.textContent, 'Verifying…', 'waits for api.js before failing');
    sb.clock.tick(8000);
    await flush();
    assert.match(sb.error.textContent, /unavailable/i);
    assert.equal(sb.btn.classList.contains('is-busy'), false);
    assert.equal(sb.calls.assigned.length, 0);
});

test('client: retrying after a failure resets the widget and then succeeds', async () => {
    const sb = makeLoginSandbox({ execute: ['error', 'success'] });
    sb.click();
    await flush();
    assert.match(sb.error.textContent, /could not be verified/i);

    sb.click();
    await flush();
    assert.equal(sb.calls.executed.length, 2, 'the retry runs a second challenge');
    assert.equal(sb.calls.resets.length, 2, 'reset() before the retry challenge');
    assert.equal(sb.error.hidden, true, 'the old error is cleared on retry');
    assert.equal(sb.status.textContent, 'Verified — continuing to Discord…');
    sb.clock.tick(700);
    assert.deepEqual(sb.calls.assigned, ['/auth/discord?cf-turnstile-response=tok-2']);
});

test('client: an expired challenge during verification is reported as a retryable error', async () => {
    const sb = makeLoginSandbox({ execute: 'hang' });
    sb.click();
    await flush();
    sb.opts()['expired-callback']();
    assert.match(sb.error.textContent, /timed out/i);
    assert.equal(sb.btn.classList.contains('is-busy'), false);
    assert.equal(sb.calls.assigned.length, 0);
});

test('client: leaving the page cancels timers and can never redirect mid-flight', async () => {
    const sb = makeLoginSandbox({ execute: 'success' });
    sb.click();
    await flush();
    assert.equal(sb.status.textContent, 'Verified — continuing to Discord…');
    sb.fire('pagehide');
    assert.equal(sb.calls.removed.length, 1, 'the widget is removed on unmount');
    sb.clock.tick(5000);
    assert.equal(sb.calls.assigned.length, 0, 'no redirect after the page is gone');
});

test('client: without a site key the button stays a plain link', async () => {
    const sb = makeLoginSandbox({ siteKey: null });
    assert.equal(sb.click(), false, 'no click handler is installed');
    assert.equal(sb.calls.executed.length, 0);
    assert.equal(sb.calls.rendered.length, 0);
});
