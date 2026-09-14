const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

// Client-side inactivity manager tests (dashboard/public/js/session-timeout.js).
//
// The client is the UX layer: timestamps drive the warning (25 min), the
// countdown, and the 30-minute logout. The test sandbox runs the REAL script in
// a vm with a fake clock, a stub fetch, and a stub BroadcastChannel — no DOM,
// no timers, no network — so every timing/throttle/multi-tab invariant is
// deterministic and NO Postgres is involved.

const SRC = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'session-timeout.js'), 'utf8');

const IDLE = 30 * 60 * 1000;
const WARN = 25 * 60 * 1000;
const REFRESH = 10 * 60 * 1000;

// Build a fresh vm sandbox running the REAL script. `wire` receives the window
// object so a test can attach a fake BroadcastChannel BEFORE the manager is
// created. Returns { window, sandbox }.
function makeSandbox({ idle = IDLE, warn = WARN, refresh = REFRESH } = {}) {
  const windowListeners = new Map();
  const location = { href: '', assign(url) { this.href = url; } };
  const windowObj = {
    __PRIMEBOT_SESSION_CONFIG__: {
      idleTimeoutMs: idle,
      warningMs: warn,
      refreshIntervalMs: refresh,
    },
    __PRIMEBOT_IDLE_TIMEOUT_MS__: idle,
    location,
    addEventListener: (evt, fn) => {
      if (!windowListeners.has(evt)) windowListeners.set(evt, []);
      windowListeners.get(evt).push(fn);
    },
    removeEventListener: () => {},
  };
  const sandbox = {
    window: windowObj,
    Date,
    Math,
    JSON,
    parseInt,
    Promise,
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox);
  return { window: windowObj, sandbox, windowListeners, location };
}

// Boot the manager from a sandbox with a fake clock + stub fetch. Returns:
//   { manager, clock, location, fetches, storageMap, windowListeners, channels }
function makeManager({ sandbox, fetches, storageMap, fetchStatus = 200, nowFn } = {}) {
  let clock = nowFn ? null : 0;
  const fetchLog = fetches || [];
  const manager = sandbox.window.PrimeBotInactivityManager({
    nowFn: nowFn || (() => clock),
    window: sandbox.window,
    fetchFn: (url, opts) => {
      fetchLog.push({ url, opts });
      const status = typeof fetchStatus !== 'function' ? fetchStatus : fetchStatus(fetchLog.length);
      return Promise.resolve({ status, ok: status === 200, json: () => Promise.resolve({}) });
    },
    storage: {
      setItem: (k, v) => { storageMap.set(k, v); },
      getItem: (k) => storageMap.get(k),
    },
  });
  return {
    manager,
    clock: { set(v) { clock = v; }, advance(ms) { clock += ms; }, get() { return clock; } },
    location: sandbox.window.location,
    fetches: fetchLog,
    storageMap,
    windowListeners: sandbox.windowListeners,
  };
}

function makeHarness({ idle = IDLE, warn = WARN, refresh = REFRESH } = {}) {
  const sb = makeSandbox({ idle, warn, refresh });
  const h = makeManager({
    sandbox: sb.sandbox,
    fetches: [],
    storageMap: new Map(),
  });
  h.windowListeners = sb.windowListeners;
  return h;
}

function settle() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('warning appears after 25 min idle with a 5-minute countdown (client-only)', () => {
  const h = makeHarness();
  const m = h.manager;
  // 24 minutes idle → nothing.
  h.clock.set(24 * 60 * 1000);
  m.evaluate();
  assert.equal(m.state.warningVisible, false);
  assert.equal(m.state.logouts, 0);

  // 25 minutes → warning with 5:00 remaining.
  h.clock.set(25 * 60 * 1000);
  m.evaluate();
  assert.equal(m.state.warningVisible, true, 'warning starts at 25 min');
  assert.ok(m.state.warningRemainingMs <= 5 * 60 * 1000 + 1);
  assert.ok(m.state.countdownSeconds > 4 * 60, 'countdown starts near 5:00');

  // Countdown ticks down — computed from timestamps, no network involved.
  h.clock.set(28 * 60 * 1000);
  m.evaluate();
  assert.equal(m.state.warningVisible, true);
  assert.ok(m.state.countdownSeconds <= 2 * 60 + 1, 'countdown is near 2:00');
  assert.equal(h.fetches.length, 0, 'the countdown issues ZERO server requests');
});

test('logout occurs exactly at 30 minutes and only fires once', () => {
  const h = makeHarness();
  const m = h.manager;
  // 29 minutes → warning, still logged in.
  h.clock.set(29 * 60 * 1000);
  m.evaluate();
  assert.equal(m.state.logouts, 0);

  // 30 minutes → logout with exactly one navigation.
  h.clock.set(30 * 60 * 1000);
  m.evaluate();
  assert.equal(m.state.logouts, 1);
  assert.equal(h.location.href, '/logout?reason=idle_timeout');

  // Further evaluations must not double-logout.
  h.clock.set(40 * 60 * 1000);
  m.evaluate();
  m.evaluate();
  m.notifyActivity();
  assert.equal(m.state.logouts, 1);
  assert.equal(h.location.href, '/logout?reason=idle_timeout');
});

test('user activity resets the clock; no activity for 30 min after that logs out', () => {
  const h = makeHarness();
  const m = h.manager;

  h.clock.set(10 * 60 * 1000);
  m.notifyActivity();               // genuine interaction at t=10min
  h.clock.set(25 * 60 * 1000);       // 15 min later
  m.evaluate();
  assert.equal(m.state.warningVisible, false, 'no warning 15 min after activity');
  assert.equal(m.state.logouts, 0);

  h.clock.set(10 * 60 * 1000 + 25 * 60 * 1000); // 25 min after activity
  m.evaluate();
  assert.equal(m.state.warningVisible, true);

  h.clock.set(10 * 60 * 1000 + 30 * 60 * 1000); // 30 min after activity
  m.evaluate();
  assert.equal(m.state.logouts, 1, 'logged out 30 min after the last interaction');
});

test('stay logged in performs ONE authenticated refresh and resets the timer', async () => {
  const h = makeHarness();
  const m = h.manager;

  // Warn the user.
  h.clock.set(26 * 60 * 1000);
  m.evaluate();
  assert.equal(m.state.warningVisible, true);

  const before = h.fetches.length;
  m.stayLoggedIn();
  await settle();

  assert.equal(h.fetches.length, before + 1, 'exactly one refresh request');
  assert.equal(h.fetches[h.fetches.length - 1].url, '/api/session/heartbeat');
  assert.equal(h.fetches[h.fetches.length - 1].opts.method, 'POST');
  assert.equal(h.fetches[h.fetches.length - 1].opts.credentials, 'same-origin');

  assert.equal(m.state.warningVisible, false, 'warning hidden after stay-logged-in');
  h.clock.set(26 * 60 * 1000 + 10 * 1000);
  m.evaluate();
  assert.equal(m.state.warningVisible, false, 'timer reset to a fresh window');
  assert.equal(m.state.logouts, 0);

  // A second immediate stay-logged-in must not issue another refresh (the
  // server deadline is already fresh → sync throttled).
  m.stayLoggedIn();
  await settle();
  assert.equal(h.fetches.length, before + 1, 'no repeated refresh requests');
});

test('session activity sync is throttled: bursts of activity send at most one request per interval', async () => {
  const h = makeHarness();
  const m = h.manager;

  // Simulate heavy mousemove/scroll for 30 seconds (many events, timestamps
  // bumping). Only the first may sync; the throttle holds the rest back.
  for (let i = 0; i < 200; i += 1) {
    h.clock.advance(150); // ~150ms — realistic mousemove cadence
    m.notifyActivity();
  }
  await settle();
  assert.ok(h.fetches.length <= 2, 'a 30s burst issues at most ~1 sync');

  // After REFRESH_MS (10 min) of continued activity, ONE more sync is allowed.
  h.clock.advance(REFRESH + 1000);
  m.notifyActivity();
  await settle();
  assert.equal(h.fetches.length, 2, 'one new sync per 10-minute interval');

  // And again inside the interval → held back.
  h.clock.advance(60 * 1000);
  m.notifyActivity();
  await settle();
  assert.equal(h.fetches.length, 2, 'activity inside the interval never syncs');
});

test('a backgrounded tab past 30 minutes logs out on return (timestamps, not timers)', () => {
  const h = makeHarness();
  const m = h.manager;

  h.clock.set(5 * 60 * 1000);
  m.evaluate(); // page loaded / focused at t=5min, no syncs due yet

  // The tab is backgrounded for 40 minutes; browser timers are throttled.
  h.clock.advance(40 * 60 * 1000);

  // The user returns → visibilitychange/focus runs evaluate() from timestamps.
  m.evaluate();
  assert.equal(m.state.logouts, 1, 'session expired while the tab was hidden');
  assert.equal(h.location.href, '/logout?reason=idle_timeout');
  assert.equal(h.fetches.length, 0, 'no heartbeat requests were needed');
});

test('a server 401 during the activity sync (rejecting harness) logs out once', async () => {
  const sb = makeSandbox();
  const h = makeManager({ sandbox: sb.sandbox, fetches: [], storageMap: new Map(), fetchStatus: 401 });
  const m = h.manager;

  m.notifyActivity();
  await settle();
  await settle();
  assert.equal(h.fetches.length, 1, 'one sync call was made');
  assert.equal(m.state.logouts, 1, '401 during sync logs out');
  assert.equal(h.location.href, '/logout?reason=idle_timeout');
});

test('multi-tab: a logout in one tab propagates to another via BroadcastChannel', () => {
  // Tab A logs out and posts to the shared channel; tab B has registered its
  // onmessage handler on the same fake channel and must follow.
  const sbA = makeSandbox();
  const sbB = makeSandbox();
  const channelsA = [];
  const channelsB = [];
  sbA.window.BroadcastChannel = function (name) {
    const ch = { name, onmessage: null, postMessage(data) { /* A posts to B */ if (channelsB[0]) channelsB[0].onmessage({ data }); }, close() {} };
    channelsA.push(ch);
    return ch;
  };
  sbB.window.BroadcastChannel = function (name) {
    const ch = { name, onmessage: null, postMessage() {}, close() {} };
    channelsB.push(ch);
    return ch;
  };

  const hA = makeManager({ sandbox: sbA.sandbox, fetches: [], storageMap: new Map() });
  const hB = makeManager({ sandbox: sbB.sandbox, fetches: [], storageMap: new Map() });

  hA.manager.performIdleLogout(); // A logs out → broadcastLogout posts to channel
  assert.equal(hA.location.href, '/logout?reason=idle_timeout');
  assert.equal(hB.manager.state.logouts, 1, 'tab B logs out when tab A posts logout');
  assert.equal(hB.manager.state.expired, true);
});

test('multi-tab: a storage event (fallback) also logs the other tabs out', () => {
  const h = makeHarness();
  const m = h.manager;
  const listeners = h.windowListeners.get('storage') || [];
  assert.ok(listeners.length >= 1, 'manager registered a storage listener');
  listeners.forEach((fn) => fn({ key: 'primebot.session.idleLogout', newValue: '1' }));
  assert.equal(m.state.logouts, 1);
  assert.equal(h.location.href, '/logout?reason=idle_timeout');
});

test('no per-second heartbeat exists in the client script', () => {
  const src = SRC;
  // The old implementation had setInterval(fetch(.../heartbeat)) — that must be
  // gone. The only intervals left are the local countdown re-render and the
  // visible-tab safety eval, neither of which performs a fetch.
  assert.ok(!/setInterval\([^)]*heartbeat[^;]*\);/i.test(src), 'no heartbeat setInterval');
  assert.ok(!/setInterval\(sendHeartbeat/.test(src));
  // No request may be fired from a timer — all fetches happen in event
  // handlers (activity/stay/visibility), none inside setInterval callbacks.
  assert.ok(!/setInterval\([^)]*\)[\s\S]*fetch\(/m.test(src), 'no timer fetches');
  // No loop that posts every second.
  assert.ok(!/1000\);\s*$/.test(src), 'no 1s interval driving requests');
  assert.equal((src.match(/\/api\/session\/heartbeat/g) || []).length >= 1, true, 'endpoint still used');
});

test('the logout URL never contains session ids or tokens', () => {
  const h = makeHarness();
  h.clock.set(40 * 60 * 1000);
  h.manager.evaluate();
  assert.match(h.location.href, /^\/logout\?reason=idle_timeout$/);
  assert.doesNotMatch(h.location.href, /sid=|token=|session=/);
});