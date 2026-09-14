const test = require('node:test');
const assert = require('node:assert/strict');

// Idle auto-logout logic. We test the pure auth helpers (throttled deadline
// refresh + expiry decision) and the layout injection of the client
// script/config, which are the deterministic core of the feature. The full HTTP
// path (heartbeat endpoint, /logout?reason redirect, requireAuth expiry,
// server-side sync throttling) is exercised in sessionIdleHttp.test.js and the
// client behavior in sessionIdleClient.test.js.

const { touchIdleDeadline, isIdleExpired, IDLE_TIMEOUT_MS } = require('../dashboard/auth');
const constants = require('../dashboard/constants');
const layout = require('../dashboard/render/layout');

function fakeReq(session) {
  return { session };
}

test('constants expose a sane default idle policy (30 min idle / 10 min refresh)', () => {
  // Default policy: 30-minute idle timeout with a 5-minute warning and a
  // 10-minute server-refresh throttle (see SESSION_WARNING_MS). All must be
  // >= the documented clamps. These envs could be overridden in the process,
  // but the defaults must match the spec.
  assert.ok(constants.SESSION_IDLE_TIMEOUT_MS >= 1000);
  assert.ok(constants.SESSION_WARNING_MS >= 0);
  assert.ok(constants.SESSION_WARNING_MS < constants.SESSION_IDLE_TIMEOUT_MS,
    'warning window must start before the idle deadline');
  assert.ok(constants.SESSION_ACTIVITY_REFRESH_INTERVAL_MS >= 5000);
  // Defaults: 30 min idle, 25 min warning, 10 min refresh.
  assert.equal(constants.SESSION_IDLE_TIMEOUT_MS, 30 * 60 * 1000);
  assert.equal(constants.SESSION_WARNING_MS, 25 * 60 * 1000);
  assert.equal(constants.SESSION_ACTIVITY_REFRESH_INTERVAL_MS, 10 * 60 * 1000);
  // The exported auth constant must match the single source of truth.
  assert.equal(IDLE_TIMEOUT_MS, constants.SESSION_IDLE_TIMEOUT_MS);
});

test('touchIdleDeadline sets a future idleExpiresAt on the session', () => {
  const req = fakeReq({});
  const before = Date.now();
  assert.equal(touchIdleDeadline(req), true, 'first touch always refreshes');
  const after = Date.now();
  assert.equal(typeof req.session.idleExpiresAt, 'number');
  // Deadline is now + IDLE_TIMEOUT_MS (allow the clock tick between calls).
  assert.ok(req.session.idleExpiresAt >= before + IDLE_TIMEOUT_MS - 5);
  assert.ok(req.session.idleExpiresAt <= after + IDLE_TIMEOUT_MS + 5);
});

test('touchIdleDeadline is THROTTLED: repeated touches within the refresh interval do nothing (no Neon write)', () => {
  const req = fakeReq({});
  const deadline = Date.now() + IDLE_TIMEOUT_MS;
  req.session.idleExpiresAt = deadline; // freshly touched a moment ago
  const stale = touchIdleDeadline(req);
  assert.equal(stale, false, 'a second touch inside the interval must be a no-op');
  assert.equal(req.session.idleExpiresAt, deadline, 'deadline stays untouched when throttled');
});

test('touchIdleDeadline refreshes once the refresh interval has elapsed', () => {
  const req = fakeReq({});
  // Last persisted a full interval + a bit ago.
  const REFRESH = constants.SESSION_ACTIVITY_REFRESH_INTERVAL_MS;
  req.session.idleExpiresAt = Date.now() - REFRESH - 1000 + IDLE_TIMEOUT_MS;
  const refreshed = touchIdleDeadline(req);
  assert.equal(refreshed, true);
  assert.ok(req.session.idleExpiresAt > Date.now(), 'deadline rolled forward to a future value');
});

test('isIdleExpired is false for a freshly-touched session', () => {
  const req = fakeReq({});
  touchIdleDeadline(req);
  assert.equal(isIdleExpired(req), false);
});

test('isIdleExpired is true once the deadline has lapsed', () => {
  const req = fakeReq({});
  touchIdleDeadline(req);
  // Rewind the deadline into the past.
  req.session.idleExpiresAt = Date.now() - 1;
  assert.equal(isIdleExpired(req), true);
});

test('a session without a deadline (legacy/debug) is NOT considered expired', () => {
  // We intentionally don't surprise-logout sessions created before this feature
  // shipped or debug sessions that never set idleExpiresAt.
  assert.equal(isIdleExpired(fakeReq({})), false);
  assert.equal(isIdleExpired(fakeReq({ idleExpiresAt: undefined })), false);
  assert.equal(isIdleExpired(fakeReq({ idleExpiresAt: 'oops' })), false);
  assert.equal(isIdleExpired(fakeReq(null)), false);
});

test('touchIdleDeadline is a no-op when there is no session', () => {
  const req = fakeReq(null);
  assert.doesNotThrow(() => touchIdleDeadline(req));
  assert.equal(req.session, null);
});

test('layout injects the idle timeout script + full session config on authenticated pages', () => {
  const html = layout.render({ title: 'T', body: '', user: { username: 'u' } });
  assert.match(html, /<script src="\/js\/session-timeout\.js"><\/script>/);
  assert.match(html, /window\.__PRIMEBOT_IDLE_TIMEOUT_MS__=\d+;/);
  // The client needs the full policy (idle + warning + refresh throttle).
  assert.match(html, /__PRIMEBOT_SESSION_CONFIG__/);
  assert.match(html, /"idleTimeoutMs":\d+/);
  assert.match(html, /"warningMs":\d+/);
  assert.match(html, /"refreshIntervalMs":\d+/);
});

test('layout does NOT inject the idle timeout script on the login page', () => {
  // The login page has no session, so the countdown/heartbeat must not run.
  const html = layout.render({ title: 'Login', body: '', login: true });
  assert.doesNotMatch(html, /session-timeout\.js/);
  assert.doesNotMatch(html, /__PRIMEBOT_IDLE_TIMEOUT_MS__/);
});

test('layout respects explicit idle locals (env override path)', () => {
  const html = layout.render({
    title: 'T', body: '', user: { username: 'u' },
    locals: { idleTimeoutMs: 99999, idleWarningMs: 50000, idleRefreshIntervalMs: 20000 },
  });
  assert.match(html, /window\.__PRIMEBOT_IDLE_TIMEOUT_MS__=99999;/);
  assert.match(html, /"idleTimeoutMs":99999/);
  assert.match(html, /"warningMs":50000/);
  assert.match(html, /"refreshIntervalMs":20000/);
  // No secrets are injected with the client config.
  assert.doesNotMatch(html, /SESSION_SECRET|secret/);
});
