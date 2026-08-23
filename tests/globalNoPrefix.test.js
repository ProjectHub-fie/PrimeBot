// Regression tests for two fixes:
//
// 1. No-prefix grants are GLOBAL — a grant made in one server must work in
//    every server without re-granting. Grants live in a sentinel bucket
//    (guild_id 'global') inside server_settings.no_prefix_users, and legacy
//    per-guild grants are folded into it on load.
// 2. BirthdayManager.formatDate existed on neither the manager nor its
//    prototype, so the prefix `$birthday set` path crashed with
//    "client.birthdayManager.formatDate is not a function".
//
// Manager DB calls are stubbed (no Postgres in CI) — the same justified-stub
// pattern as serverSettingsInit.test.js / birthdaysDashboard.test.js; all
// no-prefix/birthday logic exercised is the real code path.

const { test } = require('node:test');
const assert = require('node:assert');

const ServerSettingsManager = require('../utils/serverSettingsManager');
const BirthdayManager = require('../utils/birthdayManager');

const realInit = ServerSettingsManager.prototype._init;
const realLoad = BirthdayManager.prototype.loadBirthdays;

function freshSettingsManager() {
    ServerSettingsManager.prototype._init = async function () { /* skip constructor init */ };
    const mgr = new ServerSettingsManager({ guilds: { cache: new Map() } });
    ServerSettingsManager.prototype._init = realInit;
    mgr._saveGuildSettings = () => {}; // stub DB writes
    return mgr;
}

function freshBirthdayManager() {
    BirthdayManager.prototype.loadBirthdays = async function () {};
    const mgr = new BirthdayManager({ guilds: { cache: new Map() } });
    BirthdayManager.prototype.loadBirthdays = realLoad;
    clearInterval(mgr._reloadTimer);
    return mgr;
}

const GLOBAL = ServerSettingsManager.GLOBAL_NO_PREFIX_GUILD_ID;
const LIFETIME = ServerSettingsManager.NO_PREFIX_LIFETIME;

// ── Global no-prefix grants ──────────────────────────────────────────────────

test('enableNoPrefixMode stores the grant in the global bucket, not the guild', () => {
    const mgr = freshSettingsManager();
    const result = mgr.enableNoPrefixMode('guild-A', 'user-1', null);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.lifetime, true);
    assert.strictEqual(mgr.serverSettings.get(GLOBAL).noPrefixUsers['user-1'], LIFETIME);
    assert.strictEqual(mgr.serverSettings.get('guild-A'), undefined, 'grant must not be stored per-guild');
});

test('a grant made in one server is honored in every other server', () => {
    const mgr = freshSettingsManager();
    mgr.enableNoPrefixMode('guild-A', 'user-1', null);

    assert.strictEqual(mgr.hasNoPrefixMode('guild-A', 'user-1'), true);
    assert.strictEqual(mgr.hasNoPrefixMode('guild-B', 'user-1'), true);
    assert.strictEqual(mgr.hasNoPrefixMode('guild-C', 'user-1'), true);
    assert.strictEqual(mgr.hasNoPrefixMode('guild-B', 'user-2'), false, 'other users unaffected');
});

test('timed grants expire globally regardless of the querying guild', () => {
    const mgr = freshSettingsManager();
    const result = mgr.enableNoPrefixMode('guild-A', 'user-1', 60);

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.lifetime, false);
    assert.strictEqual(mgr.hasNoPrefixMode('guild-B', 'user-1'), true);

    // Force expiry by backdating the stored timestamp.
    mgr.serverSettings.get(GLOBAL).noPrefixUsers['user-1'] = Date.now() - 1000;
    assert.strictEqual(mgr.hasNoPrefixMode('guild-B', 'user-1'), false);
    assert.strictEqual(mgr.serverSettings.get(GLOBAL).noPrefixUsers['user-1'], undefined, 'expired grant removed');
});

test('disableNoPrefixMode revokes the grant everywhere', () => {
    const mgr = freshSettingsManager();
    mgr.enableNoPrefixMode('guild-A', 'user-1', null);

    assert.strictEqual(mgr.disableNoPrefixMode('guild-A', 'user-1'), true);
    assert.strictEqual(mgr.hasNoPrefixMode('guild-A', 'user-1'), false);
    assert.strictEqual(mgr.hasNoPrefixMode('guild-B', 'user-1'), false);
    assert.strictEqual(mgr.disableNoPrefixMode('guild-A', 'user-1'), false, 'second revoke is a no-op');
});

test('getNoPrefixExpiration returns the same value from any guild', () => {
    const mgr = freshSettingsManager();
    mgr.enableNoPrefixMode('guild-A', 'user-1', null);

    assert.strictEqual(mgr.getNoPrefixExpiration('guild-A', 'user-1'), LIFETIME);
    assert.strictEqual(mgr.getNoPrefixExpiration('guild-B', 'user-1'), LIFETIME);
    assert.strictEqual(mgr.getNoPrefixExpiration('guild-B', 'user-2'), null);
});

test('legacy per-guild grants are folded into the global bucket on load', () => {
    const mgr = freshSettingsManager();
    const saves = [];
    mgr._saveGuildSettings = (guildId) => saves.push(guildId);

    // Simulate rows loaded from the DB with old-style per-guild grants.
    mgr.serverSettings.set('guild-A', { ...mgr._defaultSettings(), noPrefixUsers: { 'user-1': LIFETIME } });
    mgr.serverSettings.set('guild-B', { ...mgr._defaultSettings(), noPrefixUsers: { 'user-1': Date.now() + 60000, 'user-2': Date.now() + 120000 } });
    mgr.serverSettings.set('guild-C', { ...mgr._defaultSettings(), noPrefixUsers: { 'user-3': Date.now() - 1000 } }); // expired

    mgr._migrateLegacyNoPrefixGrants();

    const globalUsers = mgr.serverSettings.get(GLOBAL).noPrefixUsers;
    assert.strictEqual(globalUsers['user-1'], LIFETIME, 'lifetime wins over timed');
    assert.ok(globalUsers['user-2'] > Date.now(), 'timed grant migrated');
    assert.strictEqual(globalUsers['user-3'], undefined, 'expired grant dropped');

    assert.deepStrictEqual(mgr.serverSettings.get('guild-A').noPrefixUsers, {});
    assert.deepStrictEqual(mgr.serverSettings.get('guild-B').noPrefixUsers, {});
    assert.ok(saves.includes(GLOBAL), 'global bucket persisted');
    assert.ok(saves.includes('guild-A') && saves.includes('guild-B'), 'cleared guilds persisted');

    // And the migrated grants are honored everywhere.
    assert.strictEqual(mgr.hasNoPrefixMode('guild-Z', 'user-1'), true);
    assert.strictEqual(mgr.hasNoPrefixMode('guild-Z', 'user-2'), true);
});

test('the global sentinel row is excluded from broadcast helpers', () => {
    const mgr = freshSettingsManager();
    mgr.enableNoPrefixMode('guild-A', 'user-1', null);
    mgr.serverSettings.set('guild-A', { ...mgr._defaultSettings(), receiveBroadcasts: false });

    assert.deepStrictEqual(mgr.getOptedOutServers(), ['guild-A'], 'sentinel must not appear as an opted-out server');
    assert.strictEqual(mgr.getBroadcastReceptionCount(), 0, 'sentinel must not count as a broadcast-receiving server');
});

// ── BirthdayManager.formatDate ───────────────────────────────────────────────

test('formatDate renders "Month D" labels', () => {
    const mgr = freshBirthdayManager();
    assert.strictEqual(mgr.formatDate(9, 5), 'September 5');
    assert.strictEqual(mgr.formatDate(1, 31), 'January 31');
    assert.strictEqual(mgr.formatDate(12, 25), 'December 25');
});

test('formatDate rejects out-of-range input instead of crashing', () => {
    const mgr = freshBirthdayManager();
    assert.strictEqual(mgr.formatDate(0, 5), 'Invalid date');
    assert.strictEqual(mgr.formatDate(13, 5), 'Invalid date');
    assert.strictEqual(mgr.formatDate(5, 0), 'Invalid date');
    assert.strictEqual(mgr.formatDate(5, 32), 'Invalid date');
    assert.strictEqual(mgr.formatDate('x', 'y'), 'Invalid date');
});

test('waitForReady resolves to the boot promise', async () => {
    const mgr = freshBirthdayManager();
    await assert.doesNotReject(() => mgr.waitForReady());
});
