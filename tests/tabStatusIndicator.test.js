/**
 * Live browser-tab status indicator (/stats favicon dot + tab title).
 *
 * The mapping tests drive the REAL monitoring classifier
 * (utils/statusWorker.evaluateState) and the REAL banner summary
 * (dashboard/statusView.summarize), so the tab colour is derived from the same
 * health definitions the Stats board renders — standby shard nodes are
 * operational there and can never be read as offline.
 *
 * The client tests run dashboard/public/js/tab-status.js in a vm sandbox with
 * injected document/location/fetch/timers: no real DOM, no network, no clock.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const statusWorker = require('../utils/statusWorker');
const { summarize } = require('../dashboard/statusView');

const ROOT = path.join(__dirname, '..');
const DASH = path.join(ROOT, 'dashboard');
const SRC = fs.readFileSync(path.join(DASH, 'public', 'js', 'tab-status.js'), 'utf8');
const STATUS_SRC = fs.readFileSync(path.join(DASH, 'public', 'js', 'status.js'), 'utf8');

const GREEN = '#23a55a';
const YELLOW = '#f0b232';
const RED = '#f23f43';

// ── Real monitoring fixtures ─────────────────────────────────────────────────

const NODE_IDS = { sn1: 'NR0008', sn2: 'NU3049', sn3: 'NUKN09' };

function pulse(role, over = {}) {
    return {
        role,
        nodeName: NODE_IDS[role],
        nodeId: NODE_IDS[role],
        ageMs: 5000,
        processHealth: 'healthy',
        gatewayConnected: false,
        gatewayReady: false,
        shardsTotal: 0,
        shardsReady: 0,
        shardsActive: 0,
        startedAt: new Date('2025-01-01T00:00:00Z'),
        resource: { pulseIntervalMs: 30000 },
        ...over,
    };
}

const activePulse = (role = 'sn1', over = {}) => pulse(role, {
    gatewayConnected: true, gatewayReady: true,
    shardsTotal: 5, shardsReady: 5, shardsActive: 5, ...over,
});
const standbyPulse = (role) => pulse(role);

const leaseFor = (role) => ({ activeNodeId: NODE_IDS[role], activeRole: role });

/**
 * Build the same shape `/api/status/detailed` returns: the live node/gateway/
 * bot classification plus the banner summary, with website/api/db healthy
 * unless overridden.
 */
function summaryFrom(pulses, lease, overrides = {}) {
    const state = statusWorker.evaluateState(pulses, lease);
    const keys = ['bot', 'website', 'api', 'db', 'gateway', 'sn1', 'sn2', 'sn3'];
    const components = keys.map((key) => {
        const live = state.nodes[key] || state[key] || { status: 'never' };
        const status = overrides[key] || (live.status === 'never' ? 'unknown' : live.status);
        return { key, status };
    });
    const byKey = {};
    for (const c of components) byKey[c.key] = c;
    const { overall } = summarize(byKey, []);
    return { overall, fleet: state.fleet, components };
}

const healthySummary = () => summaryFrom(
    [activePulse('sn1'), standbyPulse('sn2'), standbyPulse('sn3')],
    leaseFor('sn1'),
    { website: 'operational', api: 'operational', db: 'operational' }
);

// ── Module loading ───────────────────────────────────────────────────────────

function loadApi() {
    const sandbox = {
        window: {},
        console,
        Promise,
        Date,
        JSON,
        Math,
        Number,
        String,
        Array,
        encodeURIComponent,
    };
    sandbox.window = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(SRC, sandbox);
    return sandbox.PrimeBotTabStatus;
}

// ── DOM / timer / fetch harness ──────────────────────────────────────────────

function makeDoc({ title = 'PrimeBot · Stats', favicon = 'ORIGINAL-FAVICON', canvas = null } = {}) {
    const writes = { title: 0, favicon: 0 };
    const link = {
        _href: favicon,
        getAttribute(name) { return name === 'href' ? this._href : null; },
        setAttribute(name, value) {
            if (name !== 'href') return;
            this._href = value;
            writes.favicon++;
        },
    };
    const listeners = {};
    let currentTitle = title;
    const doc = {
        hidden: false,
        head: { appendChild() {} },
        querySelector(sel) { return /^link\[rel=/.test(sel) ? link : null; },
        createElement(tag) { return tag === 'canvas' ? canvas : { setAttribute() {} }; },
        addEventListener(evt, fn) { (listeners[evt] = listeners[evt] || []).push(fn); },
        removeEventListener(evt, fn) { listeners[evt] = (listeners[evt] || []).filter((f) => f !== fn); },
    };
    Object.defineProperty(doc, 'title', {
        configurable: true,
        get() { return currentTitle; },
        set(value) {
            if (value !== currentTitle) writes.title++;
            currentTitle = value;
        },
    });
    return { doc, link, writes, listeners, getTitle: () => currentTitle };
}

function makeTimers() {
    let nextId = 0;
    const timers = new Map();
    const setTimeoutFn = (fn, ms) => {
        const id = ++nextId;
        timers.set(id, { id, fn, ms });
        return id;
    };
    const clearTimeoutFn = (id) => { timers.delete(id); };
    return {
        timers,
        setTimeoutFn,
        clearTimeoutFn,
        pending(ms) { return [...timers.values()].filter((t) => t.ms === ms).length; },
        run(ms) {
            const due = [...timers.values()].filter((t) => t.ms === ms);
            for (const t of due) { timers.delete(t.id); t.fn(); }
            return due.length;
        },
        clearAll() { timers.clear(); },
    };
}

function makeWindow() {
    const listeners = {};
    return {
        listeners,
        location: { pathname: '/stats' },
        addEventListener(evt, fn) { (listeners[evt] = listeners[evt] || []).push(fn); },
        removeEventListener(evt, fn) { listeners[evt] = (listeners[evt] || []).filter((f) => f !== fn); },
    };
}

function makeClient({ pathname = '/stats', canvas = null, intervalMs = 45000, timeoutMs = 12000 } = {}) {
    const api = loadApi();
    const dom = makeDoc({ canvas });
    const win = makeWindow();
    const timers = makeTimers();
    const fetches = [];
    const updates = [];
    const clock = { now: 1000000 };
    let next = () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(healthySummary()) });

    const client = api.create({
        document: dom.doc,
        window: win,
        location: { pathname, href: `https://dash.example.com${pathname}` },
        fetchFn: (url, opts) => { fetches.push({ url, opts }); return next(url, opts); },
        setTimeoutFn: timers.setTimeoutFn,
        clearTimeoutFn: timers.clearTimeoutFn,
        nowFn: () => clock.now,
        intervalMs,
        timeoutMs,
        onUpdate: (s) => updates.push(s),
        logger: () => {},
    });

    return {
        api, client, dom, win, timers, fetches, updates, clock,
        advance(ms) { clock.now += ms; },
        setFetch: (fn) => { next = fn; },
    };
}

async function settle(ticks = 6) {
    for (let i = 0; i < ticks; i++) await new Promise((r) => setImmediate(r));
}

const okResponse = (summary) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(summary) });

// ── 1. Health → colour mapping (existing health definitions) ─────────────────

test('all three nodes online with two standbys is GREEN', () => {
    const summary = healthySummary();
    assert.equal(summary.fleet.online, 3, 'all three nodes online');
    assert.equal(summary.fleet.standby, 2, 'two standbys — never counted offline');
    assert.equal(summary.fleet.offline, 0);
    assert.equal(summary.overall.key, 'operational');
    assert.equal(loadApi().levelForSummary(summary), 'operational');
});

test('a genuinely offline standby node is YELLOW (redundancy reduced, not an outage)', () => {
    const summary = summaryFrom(
        [activePulse('sn1'), standbyPulse('sn2'), pulse('sn3', { ageMs: 99999999 })],
        leaseFor('sn1'),
        { website: 'operational', api: 'operational', db: 'operational' }
    );
    assert.equal(summary.fleet.offline, 1);
    assert.equal(summary.overall.key, 'degraded');
    assert.equal(loadApi().levelForSummary(summary), 'degraded');
});

test('the ACTIVE node going offline is a bot outage → RED', () => {
    const summary = summaryFrom(
        [activePulse('sn1', { ageMs: 99999999 }), standbyPulse('sn2'), standbyPulse('sn3')],
        leaseFor('sn1'),
        { website: 'operational', api: 'operational', db: 'operational' }
    );
    const bot = summary.components.find((c) => c.key === 'bot');
    assert.equal(bot.status, 'unavailable');
    assert.equal(summary.overall.key, 'major');
    assert.equal(loadApi().levelForSummary(summary), 'outage');
});

test('bot offline is RED even if the banner claims operational', () => {
    const summary = healthySummary();
    summary.components = summary.components.map((c) => (c.key === 'bot' ? { ...c, status: 'unavailable' } : c));
    assert.equal(loadApi().levelForSummary(summary), 'outage');
});

test('a stale active node (outdated data) is YELLOW, never GREEN', () => {
    // 100s > 3 × 30s stale band, still inside the 6 × 30s outage band.
    const summary = summaryFrom(
        [activePulse('sn1', { ageMs: 100000 }), standbyPulse('sn2'), standbyPulse('sn3')],
        leaseFor('sn1'),
        { website: 'operational', api: 'operational', db: 'operational' }
    );
    const bot = summary.components.find((c) => c.key === 'bot');
    assert.equal(bot.status, 'stale');
    assert.equal(loadApi().levelForSummary(summary), 'degraded');
});

test('no monitoring data at all is YELLOW', () => {
    const summary = summaryFrom([], {}, { website: 'unknown', api: 'unknown', db: 'unknown' });
    assert.equal(summary.overall.key, 'no_data');
    assert.equal(loadApi().levelForSummary(summary), 'degraded');
});

test('missing / malformed summaries are YELLOW, never GREEN', () => {
    const api = loadApi();
    for (const bad of [null, undefined, {}, [], 'nope', 42, { overall: null }, { overall: {} }, { overall: { key: 'weird' } }]) {
        assert.equal(api.levelForSummary(bad), 'degraded', `expected degraded for ${JSON.stringify(bad)}`);
    }
});

test('title text matches the required labels', () => {
    const api = loadApi();
    assert.equal(api.titleForLevel('operational'), '🟢 PrimeBot — Operational');
    assert.equal(api.titleForLevel('degraded'), '🟡 PrimeBot — Degraded');
    assert.equal(api.titleForLevel('outage'), '🔴 PrimeBot — Outage');
});

test('favicon keeps the PrimeBot bolt and adds the status dot', () => {
    const api = loadApi();
    const href = api.buildFaviconHref('operational', null);
    assert.match(href, /^data:image\/svg\+xml,/);
    const svg = decodeURIComponent(href.replace('data:image/svg+xml,', ''));
    assert.match(svg, /M13 2 L3 14 L12 14 L11 22 L21 10 L12 10 Z/, 'existing bolt logo is the base');
    assert.match(svg, /#5865f2/, 'brand stroke colour preserved');
    assert.match(svg, new RegExp(GREEN));
    assert.match(api.buildFaviconHref('degraded', null), new RegExp(encodeURIComponent(YELLOW)));
    assert.match(api.buildFaviconHref('outage', null), new RegExp(encodeURIComponent(RED)));
});

test('favicon is rasterized to PNG when a canvas is available', () => {
    const calls = [];
    const ctx = {
        clearRect() {}, beginPath() {}, moveTo() {}, lineTo() {}, closePath() {},
        stroke() {}, fill() {}, arc() {},
        set fillStyle(v) { calls.push(['fillStyle', v]); },
        set strokeStyle(v) { calls.push(['strokeStyle', v]); },
    };
    const canvas = {
        width: 0,
        height: 0,
        getContext: (kind) => (kind === '2d' ? ctx : null),
        toDataURL: (type) => (type === 'image/png' ? 'data:image/png;base64,AAAA' : ''),
    };
    const api = loadApi();
    const href = api.buildFaviconHref('outage', { createElement: () => canvas });
    assert.equal(href, 'data:image/png;base64,AAAA');
    assert.equal(canvas.width, 64);
    assert.ok(calls.some(([k, v]) => k === 'fillStyle' && v === RED), 'dot painted with the outage colour');
});

test('/stats page loads tab-status.js before status.js', () => {
    const pages = require('../dashboard/render/pages');
    const html = pages.statsPage({ user: null });
    const tabIdx = html.indexOf('/js/tab-status.js');
    const boardIdx = html.indexOf('/js/status.js');
    assert.ok(tabIdx > -1, 'tab-status.js is loaded on the stats page');
    assert.ok(boardIdx > -1, 'status.js is still loaded');
    assert.ok(tabIdx < boardIdx, 'the indicator module must load first');
    assert.match(html, /<title>PrimeBot · Stats<\/title>/, 'server-rendered title stays the original');
});

test('status.js boots the indicator with the summary it already fetched', () => {
    assert.match(STATUS_SRC, /window\.PrimeBotTabStatus\.create/);
    assert.match(STATUS_SRC, /bootTabStatus\(summary\)/, 'seeded with the board summary (no extra request)');
    assert.match(STATUS_SRC, /bootTabStatus\(null\)/, 'still polls when the API is unavailable');
    // The error state must stay inside #status-result so a later successful
    // poll can repaint the board without a reload.
    assert.match(STATUS_SRC, /function showBoardError\(\)/);
    assert.match(STATUS_SRC, /\$\('#status-result'\)/);
    assert.match(STATUS_SRC, /render\(summary\);\n\s+window\.__statusSummary = summary;/, 'onUpdate repaints the board');
});

// ── 2. Client behaviour (vm sandbox) ─────────────────────────────────────────

test('client: start() polls the existing endpoint and paints green', async () => {
    const h = makeClient();
    h.client.start();
    await settle();
    assert.equal(h.fetches.length, 1);
    assert.equal(h.fetches[0].url, '/api/status/detailed');
    assert.equal(h.dom.getTitle(), '🟢 PrimeBot — Operational');
    assert.match(h.dom.link._href, new RegExp(encodeURIComponent(GREEN)));
    assert.equal(h.client.state.level, 'operational');
    assert.equal(h.updates.length, 1);
});

test('client: the favicon/title are written only when the status changes', async () => {
    const h = makeClient();
    h.client.start();
    await settle();
    assert.equal(h.dom.writes.title, 1);
    assert.equal(h.dom.writes.favicon, 1);

    // Next scheduled poll with the same health — no DOM churn.
    h.timers.run(45000);
    await settle();
    assert.equal(h.fetches.length, 2);
    assert.equal(h.dom.writes.title, 1);
    assert.equal(h.dom.writes.favicon, 1);

    // Health changes → exactly one more write.
    h.setFetch(() => okResponse(summaryFrom(
        [activePulse('sn1'), standbyPulse('sn2'), pulse('sn3', { ageMs: 99999999 })],
        leaseFor('sn1'),
        { website: 'operational', api: 'operational', db: 'operational' }
    )));
    h.timers.run(45000);
    await settle();
    assert.equal(h.dom.getTitle(), '🟡 PrimeBot — Degraded');
    assert.equal(h.dom.writes.title, 2);
    assert.equal(h.dom.writes.favicon, 2);
});

test('client: polls every 45s (30–60s window) with one poll chain', async () => {
    const h = makeClient();
    h.client.start();
    await settle();
    assert.equal(h.timers.pending(45000), 1, 'next poll scheduled after the first settles');
    h.timers.run(45000);
    await settle();
    assert.equal(h.fetches.length, 2);
    assert.equal(h.timers.pending(45000), 1, 'exactly one pending poll — never a second chain');
});

test('client: overlapping polls are impossible', async () => {
    const h = makeClient();
    let release;
    h.setFetch(() => new Promise((r) => { release = r; }));
    h.client.start();
    await settle();
    assert.equal(h.fetches.length, 1);

    // A timer tick / visibility event while the request is in flight must not
    // start a second request.
    h.dom.listeners.visibilitychange[0]();
    h.client.start();
    await settle();
    assert.equal(h.fetches.length, 1);

    release({ ok: true, status: 200, json: () => Promise.resolve(healthySummary()) });
    await settle();
    assert.equal(h.fetches.length, 1);
    assert.equal(h.timers.pending(45000), 1);
});

test('client: network error, HTTP error and invalid JSON all paint YELLOW', async () => {
    const cases = [
        () => Promise.reject(new Error('ECONNRESET')),
        () => Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) }),
        () => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new Error('bad json')) }),
        () => okResponse({ nope: true }),
        () => okResponse(null),
    ];
    for (const impl of cases) {
        const h = makeClient();
        h.setFetch(impl);
        h.client.start();
        await settle();
        assert.equal(h.client.state.level, 'degraded', 'unavailable monitoring data is never green');
        assert.equal(h.dom.getTitle(), '🟡 PrimeBot — Degraded');
        assert.match(h.dom.link._href, new RegExp(encodeURIComponent(YELLOW)));
        assert.ok(h.client.state.lastError, 'the failure reason is recorded');
        h.client.stop();
    }
});

test('client: a timed-out request paints YELLOW', async () => {
    const h = makeClient({ timeoutMs: 12000 });
    h.setFetch(() => new Promise(() => {})); // never settles
    h.client.start();
    await settle();
    assert.equal(h.client.state.level, null, 'still waiting');

    h.timers.run(12000); // the request timeout
    await settle();
    assert.equal(h.client.state.level, 'degraded');
    assert.equal(h.client.state.lastError, 'timeout');
    assert.equal(h.dom.getTitle(), '🟡 PrimeBot — Degraded');
});

test('client: recovers to GREEN once the API is back', async () => {
    const h = makeClient();
    h.setFetch(() => Promise.reject(new Error('offline')));
    h.client.start();
    await settle();
    assert.equal(h.dom.getTitle(), '🟡 PrimeBot — Degraded');

    h.setFetch(() => okResponse(healthySummary()));
    h.timers.run(45000);
    await settle();
    assert.equal(h.dom.getTitle(), '🟢 PrimeBot — Operational');
    assert.match(h.dom.link._href, new RegExp(encodeURIComponent(GREEN)));
    assert.equal(h.client.state.failures, 0);
});

test('client: leaving the page restores the original title and favicon', async () => {
    const h = makeClient();
    h.client.start();
    await settle();
    assert.notEqual(h.dom.getTitle(), 'PrimeBot · Stats');

    h.win.listeners.pagehide[0]();
    assert.equal(h.dom.getTitle(), 'PrimeBot · Stats');
    assert.equal(h.dom.link._href, 'ORIGINAL-FAVICON');
    assert.equal(h.client.state.level, null);
});

test('client: stop() restores the chrome, clears the poll and detaches listeners', async () => {
    const h = makeClient();
    h.client.start();
    await settle();
    h.client.stop();
    assert.equal(h.dom.getTitle(), 'PrimeBot · Stats');
    assert.equal(h.dom.link._href, 'ORIGINAL-FAVICON');
    assert.equal(h.timers.timers.size, 0, 'no timer left behind');
    assert.equal((h.dom.listeners.visibilitychange || []).length, 0);
    assert.equal((h.win.listeners.pagehide || []).length, 0);

    const orphaned = (h.dom.listeners.visibilitychange || [])[0];
    if (orphaned) orphaned();
    await settle();
    assert.equal(h.fetches.length, 1, 'no polling after unmount');
});

test('client: bfcache restore re-arms the indicator', async () => {
    const h = makeClient();
    h.client.start();
    await settle();
    h.win.listeners.pagehide[0]();
    assert.equal(h.dom.getTitle(), 'PrimeBot · Stats');

    h.win.listeners.pageshow[0]({ persisted: true });
    await settle();
    assert.equal(h.fetches.length, 2, 'a fresh poll after a bfcache restore');
    assert.equal(h.dom.getTitle(), '🟢 PrimeBot — Operational');
    assert.equal(h.timers.pending(45000), 1);
});

test('client: background tab keeps polling and refreshes on return', async () => {
    const h = makeClient();
    h.client.start();
    await settle();
    // Hidden tab: timers still fire (browsers throttle, they do not stop).
    h.dom.doc.hidden = true;
    h.timers.run(45000);
    await settle();
    assert.equal(h.fetches.length, 2, 'polling continues while the tab is in the background');

    // Becoming visible refreshes immediately (and only once).
    h.dom.doc.hidden = false;
    h.advance(6000);
    h.dom.listeners.visibilitychange[0]();
    await settle();
    assert.equal(h.timers.pending(0), 1, 'an immediate refresh was scheduled');
    h.timers.run(0);
    await settle();
    assert.equal(h.fetches.length, 3);
});

test('client: a seed summary paints instantly without an extra request', async () => {
    const h = makeClient();
    h.client.start({ summary: healthySummary() });
    await settle();
    assert.equal(h.fetches.length, 0, 'no request: the board already fetched the summary');
    assert.equal(h.dom.getTitle(), '🟢 PrimeBot — Operational');
    assert.equal(h.timers.pending(45000), 1, 'polling still scheduled');
});

test('client: does not run outside /stats', async () => {
    for (const pathname of ['/', '/dashboard', '/guild/1/prefix', '/stats-extra']) {
        const h = makeClient({ pathname });
        h.client.start();
        await settle();
        assert.equal(h.fetches.length, 0, `no polling on ${pathname}`);
        assert.equal(h.dom.getTitle(), 'PrimeBot · Stats');
        assert.equal(h.dom.writes.favicon, 0);
    }
    const stats = makeClient({ pathname: '/stats/' });
    stats.client.start();
    await settle();
    assert.equal(stats.fetches.length, 1, '/stats/ (trailing slash) is supported');
});
