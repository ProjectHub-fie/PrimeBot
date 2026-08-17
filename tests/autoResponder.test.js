// Unit tests for the Auto-Responder logic in ServerSettingsManager.
// These exercise the in-memory matching/normalisation helpers without a DB:
// we construct a manager, stub the fire-and-forget DB saver, and assert
// trigger matching (contains vs exact), case sensitivity, and add/remove.

const { test } = require('node:test');
const assert = require('node:assert');

const ServerSettingsManager = require('../utils/serverSettingsManager');

// Neutralise async DB init/reload so tests run pure in-memory. The constructor
// calls _init() (which connects to Postgres + starts a reload interval); stub
// it on the prototype BEFORE constructing so the in-memory Map is the only state.
ServerSettingsManager.prototype._init = async function () { this._tableReady = true; };
ServerSettingsManager.prototype.loadSettings = async function () {};

function makeManager() {
    const mgr = new ServerSettingsManager({});
    if (mgr._refreshTimer) { clearInterval(mgr._refreshTimer); mgr._refreshTimer = null; }
    mgr._tableReady = true;
    // No-op the fire-and-forget DB saver; add/remove still update the in-memory Map.
    mgr._saveGuildSettings = () => {};
    return mgr;
}

// Helper: add a response AND enable the auto-responder (mirrors how the bot's
// /autoresponder add + the dashboard both leave the master switch to the user,
// so tests that want matches must enable explicitly).
function addAndEnable(mgr, gid, trigger, response, opts) {
    mgr.addAutoResponse(gid, trigger, response, opts);
    mgr.getAutoResponder(gid).enabled = true;
}

test('getAutoResponder returns a default {enabled:false, responses:[]}', () => {
    const m = makeManager();
    const ar = m.getAutoResponder('g1');
    assert.strictEqual(ar.enabled, false);
    assert.deepStrictEqual(ar.responses, []);
});

test('toggleAutoResponder flips the master switch', () => {
    const m = makeManager();
    assert.strictEqual(m.toggleAutoResponder('g1'), true);
    assert.strictEqual(m.getAutoResponder('g1').enabled, true);
    assert.strictEqual(m.toggleAutoResponder('g1'), false);
    assert.strictEqual(m.getAutoResponder('g1').enabled, false);
});

test('addAutoResponse stores a contains-match entry and getTriggeredResponses matches substrings', () => {
    const m = makeManager();
    addAndEnable(m, 'g1', 'hello', 'Hi there!');
    const ar = m.getAutoResponder('g1');
    assert.strictEqual(ar.responses.length, 1);
    assert.strictEqual(ar.responses[0].trigger, 'hello');
    assert.strictEqual(ar.responses[0].response, 'Hi there!');
    assert.strictEqual(ar.responses[0].exactMatch, false);

    // contains match (case-insensitive by default)
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'Hello everyone!'), ['Hi there!']);
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'say hello world'), ['Hi there!']);
    // not present
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'goodbye'), []);
});

test('exactMatch only fires when the message equals the trigger (trimmed)', () => {
    const m = makeManager();
    addAndEnable(m, 'g1', 'ping', 'pong', { exactMatch: true });
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'ping'), ['pong']);
    assert.deepStrictEqual(m.getTriggeredResponses('g1', '  ping  '), ['pong']);
    // substring but not exact -> no match
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'ping me'), []);
});

test('caseSensitive respects letter case', () => {
    const m = makeManager();
    addAndEnable(m, 'g1', 'PrimeBot', 'is great', { caseSensitive: true });
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'PrimeBot'), ['is great']);
    // lowercase 'primebot' must NOT match when caseSensitive
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'primebot'), []);
});

test('disabled auto-responder returns no responses even when a trigger matches', () => {
    const m = makeManager();
    m.addAutoResponse('g1', 'hi', 'hey');
    // ensure disabled (add doesn't auto-enable in this unit path)
    const ar = m.getAutoResponder('g1');
    ar.enabled = false;
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'hi'), []);
    ar.enabled = true;
    assert.deepStrictEqual(m.getTriggeredResponses('g1', 'hi'), ['hey']);
});

test('addAutoResponse with the same trigger (case-insensitive) updates the existing entry', () => {
    const m = makeManager();
    m.addAutoResponse('g1', 'hello', 'first');
    m.addAutoResponse('g1', 'HELLO', 'second');
    const ar = m.getAutoResponder('g1');
    assert.strictEqual(ar.responses.length, 1);
    assert.strictEqual(ar.responses[0].response, 'second');
});

test('removeAutoResponse removes by trigger (case-insensitive) and returns false when absent', () => {
    const m = makeManager();
    m.addAutoResponse('g1', 'hello', 'hi');
    assert.strictEqual(m.removeAutoResponse('g1', 'HELLO'), true);
    assert.strictEqual(m.getAutoResponder('g1').responses.length, 0);
    assert.strictEqual(m.removeAutoResponse('g1', 'hello'), false);
});

test('multiple matching rules each contribute a response', () => {
    const m = makeManager();
    addAndEnable(m, 'g1', 'a', 'A-resp');
    m.addAutoResponse('g1', 'b', 'B-resp');
    m.getAutoResponder('g1').enabled = true;
    // message contains both a and b
    const out = m.getTriggeredResponses('g1', 'a and b together');
    assert.deepStrictEqual(out, ['A-resp', 'B-resp']);
});
