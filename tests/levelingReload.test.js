// Regression test for "Cannot access 'refreshMs' before initialization".
// _startRoleRewardsReload() used to reference `refreshMs` (a `const`
// declared later in the same scope) in the first `setInterval` — a JS
// temporal-dead-zone ReferenceErrorthat made LevelingManager's
// initializeDatabase() retry forever. The `const` declarations must come
// before any use.

const { test } = require('node:test');
const assert = require('node:assert');

const LevelingManager = require('../utils/levelingManager');

// Neutralise the constructor's auto-init so we can drive the reload method manually.
const realInitialize = LevelingManager.prototype.initializeDatabase;

function freshManager() {
    LevelingManager.prototype.initializeDatabase = async function () { /* skip constructor init */ };
    const mgr = new LevelingManager({});
    LevelingManager.prototype.initializeDatabase = realInitialize;
    clearInterval(mgr.cooldownCleanupInterval); // constructor keeps event loop alive
    return mgr;
}

test('_startRoleRewardsReload starts both timers without TDZ ReferenceError', () => {
    const mgr = freshManager();
    mgr._loadRoleRewards = async () => {};

    assert.doesNotThrow(() => mgr._startRoleRewardsReload());
    assert.ok(mgr._roleRewardsTimer, '5s refresh timer must be running');
    assert.ok(mgr._roleRewardsReloadTimer, 'background reload timer must be running');
    assert.notStrictEqual(mgr._roleRewardsTimer, mgr._roleRewardsReloadTimer);

    clearInterval(mgr._roleRewardsTimer);
    clearInterval(mgr._roleRewardsReloadTimer);
});

test('_startRoleRewardsReload is idempotent (no double timers)', () => {
    const mgr = freshManager();
    mgr._loadRoleRewards = async () => {};

    mgr._startRoleRewardsReload();
    const first = mgr._roleRewardsTimer;
    mgr._startRoleRewardsReload();
    assert.strictEqual(mgr._roleRewardsTimer, first);

    clearInterval(mgr._roleRewardsTimer);
    clearInterval(mgr._roleRewardsReloadTimer);
});
