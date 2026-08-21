// Regression test for the "dashboard saved but bot never reacts" failure mode:
// if the DB is briefly unreachable while the bot boots, ServerSettingsManager's
// old _init() aborted before _startReloadInterval() — so the settings reload
// loop NEVER started and dashboard saves (auto-reactions / auto-responder)
// never reached the bot until a full restart.
//
// _init() must now isolate each boot step and ALWAYS start the reload loop, so
// the manager recovers on the next 5s/30s tick once the DB comes back.

const { test } = require('node:test');
const assert = require('node:assert');

const ServerSettingsManager = require('../utils/serverSettingsManager');

// Neutralise the constructor's auto-init so we can drive _init manually.
const realInit = ServerSettingsManager.prototype._init;

function freshManager() {
    ServerSettingsManager.prototype._init = async function () { /* skip constructor init */ };
    const mgr = new ServerSettingsManager({});
    ServerSettingsManager.prototype._init = realInit;
    return mgr;
}

test('_init still starts the reload loop when every boot step throws', async () => {
    const mgr = freshManager();
    mgr._ensureTable = async () => { throw new Error('DB not ready'); };
    mgr._migrateFromJson = async () => { throw new Error('fs gone'); };
    mgr.loadSettings = async () => { throw new Error('DB not ready'); };

    await mgr._init();

    assert.ok(mgr._reloadTimer, 'reload interval must be running');
    assert.ok(mgr._refreshTimer, 'refresh loop must be running');
    clearInterval(mgr._reloadTimer);
    clearInterval(mgr._refreshTimer);
});

test('_startReloadInterval is idempotent (no double timers)', async () => {
    const mgr = freshManager();
    mgr._startReloadInterval();
    const first = mgr._reloadTimer;
    mgr._startReloadInterval();
    assert.strictEqual(mgr._reloadTimer, first);
    clearInterval(mgr._reloadTimer);
    clearInterval(mgr._refreshTimer);
});
