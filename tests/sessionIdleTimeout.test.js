const test = require('node:test');
const assert = require('node:assert/strict');

// Idle auto-logout logic. We test the pure auth helpers (deadline refresh +
// expiry decision) and the layout injection of the client script/config, which
// are the deterministic core of the feature. The full HTTP path (heartbeat
// endpoint, /logout?reason redirect, requireAuth expiry) is exercised via the
// mock-dashboard boot in manual QA; here we cover the unit-level invariants.

const { touchIdleDeadline, isIdleExpired, IDLE_TIMEOUT_MS } = require('../dashboard/auth');
const constants = require('../dashboard/constants');
const layout = require('../dashboard/render/layout');

function fakeReq(session) {
  return { session };
}

test('constants expose a sane default idle timeout (120s) and env override', () => {
  // Default is 120000ms unless SESSION_IDLE_TIMEOUT_MS is set in the env this
  // process was launched with. Either way it must be >= 1000 (clamped).
  assert.ok(constants.SESSION_IDLE_TIMEOUT_MS >= 1000);
  // The exported auth constant must match the single source of truth.
  assert.equal(IDLE_TIMEOUT_MS, constants.SESSION_IDLE_TIMEOUT_MS);
});

test('touchIdleDeadline sets a future idleExpiresAt on the session', () => {
  const req = fakeReq({});
  const before = Date.now();
  touchIdleDeadline(req);
  const after = Date.now();
  assert.equal(typeof req.session.idleExpiresAt, 'number');
  // Deadline is now + IDLE_TIMEOUT_MS (allow the clock tick between calls).
  assert.ok(req.session.idleExpiresAt >= before + IDLE_TIMEOUT_MS - 5);
  assert.ok(req.session.idleExpiresAt <= after + IDLE_TIMEOUT_MS + 5);
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

test('layout injects the idle timeout script + config on authenticated pages', () => {
  const html = layout.render({ title: 'T', body: '', user: { username: 'u' } });
  assert.match(html, /<script src="\/js\/session-timeout\.js"><\/script>/);
  assert.match(html, /window\.__PRIMEBOT_IDLE_TIMEOUT_MS__=\d+;/);
});

test('layout does NOT inject the idle timeout script on the login page', () => {
  // The login page has no session, so the countdown/heartbeat must not run.
  const html = layout.render({ title: 'Login', body: '', login: true });
  assert.doesNotMatch(html, /session-timeout\.js/);
  assert.doesNotMatch(html, /__PRIMEBOT_IDLE_TIMEOUT_MS__/);
});

test('layout respects an explicit idleTimeoutMs local (env override path)', () => {
  const html = layout.render({ title: 'T', body: '', user: { username: 'u' }, locals: { idleTimeoutMs: 99999 } });
  assert.match(html, /window\.__PRIMEBOT_IDLE_TIMEOUT_MS__=99999;/);
});
