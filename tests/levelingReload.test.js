// Regression test for "Cannot access 'refreshMs' before initialization".
// _startRoleRewardsReload() used to reference `refreshMs` (a `const`
// declared later in the same scope) in the first `setInterval` — a JS
// temporal-dead-zone ReferenceError that made LevelingManager's
// initializeDatabase() retry forever.
//
// That bug is structurally impossible now: a single adaptive poller replaced
// the two fixed timers, so there is no `refreshMs` const to reference and the
// manager must never throw while wiring up the reload loop.

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

test('_startRoleRewardsReload starts a single poller without TDZ ReferenceError', () => {
    const mgr = freshManager();
    mgr._loadRoleRewards = async () => {};

    assert.doesNotThrow(() => mgr._startRoleRewardsReload());
    assert.ok(mgr._roleRewardsTimer, 'role rewards poller must be running');

    mgr._roleRewardsTimer.stop();
});

test('_startRoleRewardsReload is idempotent (no double timers)', () => {
    const mgr = freshManager();
    mgr._loadRoleRewards = async () => {};

    mgr._startRoleRewardsReload();
    const first = mgr._roleRewardsTimer;
    mgr._startRoleRewardsReload();
    assert.strictEqual(mgr._roleRewardsTimer, first);

    mgr._roleRewardsTimer.stop();
});
