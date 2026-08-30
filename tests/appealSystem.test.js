// Appeal / Ban-DM subsystem — pure unit tests (no Postgres in CI).
const { test } = require('node:test');
const assert = require('node:assert');
const { AppealManager } = require('../utils/appealManager');
const realInit = AppealManager.prototype._init;
function fresh(automod) {
    AppealManager.prototype._init = async function () { /* skip constructor init */ };
    const mgr = new AppealManager({ automodManager: { getSettings: () => automod || {} } });
    AppealManager.prototype._init = realInit;
    return mgr;
}
test('sendBanDm sends nothing when "DM user" is off', async () => {
    const mgr = fresh({ dmUser: false, useAppeal: false, appealChannelId: null });
    let sent = false;
    const ok = await mgr.sendBanDm({
        guild: { id: 'G1', name: 'Test Server' },
        user: { id: 'U1', tag: 'tester#1234', send: async () => { sent = true; } },
    });
    assert.strictEqual(ok, false);
    assert.strictEqual(sent, false);
});
test('sendBanDm attaches an Appeal button when "Use appeal" is on', async () => {
    const mgr = fresh({ dmUser: true, useAppeal: true, appealChannelId: 'CH' });
    let payload = null;
    const ok = await mgr.sendBanDm({
        guild: { id: 'G1', name: 'Test Server' },
        user: { id: 'U1', tag: 'tester#1234', send: async (p) => { payload = p; } },
        reason: 'spam',
        action: 'ban',
        cid: 7,
    });
    assert.strictEqual(ok, true);
    assert.ok(payload, 'DM must be sent');
    assert.ok(Array.isArray(payload.components), 'must carry components');
    const row = payload.components[0];
    const btn = row.components[0];
    assert.strictEqual(btn.data.custom_id, 'appeal:open:G1:ban:7');
    assert.strictEqual(btn.data.label, 'Appeal ban');
    assert.ok(payload.embeds?.[0]?.data?.fields?.some(f => f.name === 'CID' && f.value === '7'), 'embed must include the CID field');
});
test('sendBanDm sends a plain embed (no button) when "Use appeal" is off', async () => {
    const mgr = fresh({ dmUser: true, useAppeal: false, appealChannelId: null });
    let payload = null;
    const ok = await mgr.sendBanDm({
        guild: { id: 'G1', name: 'Test Server' },
        user: { id: 'U1', username: 'tester', send: async (p) => { payload = p; } },
    });
    assert.strictEqual(ok, true);
    assert.ok(payload?.embeds, 'must include an embed');
    assert.ok(!payload.components || payload.components.length === 0, 'no button when appeals are off');
});
test('getSettings mirrors the Automod tab switches', async () => {
    const mgr = fresh({ dmUser: true, useAppeal: true, appealChannelId: 'CH' });
    const s = mgr.getSettings('G1');
    assert.strictEqual(s.dmUser, true);
    assert.strictEqual(s.useAppeal, true);
    assert.strictEqual(s.appealChannelId,'CH');
});
test('handleAppealButton submits a modal with guild + action + CID in the custom id', async () => {
    const mgr = fresh({ dmUser: true, useAppeal: true, appealChannelId: null });
    let showed = null;
    const interaction = {
        client: {},
        showModal: async (m) => { showed = m; },
    };
    await mgr.handleAppealButton(interaction, 'G1', 'ban', 42);
    assert.ok(showed);
    assert.ok(showed.data.custom_id.startsWith('appeal_modal:G1'));
});

test('AppealManager module parses and sendBanDm builds ban-embed fields from banEmbedFields', async () => {
    // Regression: commit 19a2c71 corrupted this loop into `for ( (constk ...` which
    // threw a SyntaxError killingthe whole module, so NO ban DM/appeal button
    // was ever sent (the runtime fallback stub returned false) regardless of the
    // dashboard's "DM user" / "Use appeal" switches.o
    const mgr = fresh({ dmUser: true, useAppeal: true, appealChannelId: 'CH', banEmbedFields: ['server', 'user', 'reason'] });
    let payload = null;
    const ok = await mgr.sendBanDm({
        guild: { id: 'G1', name: 'Test Server' },
        user: { id: 'U1', tag: 'tester#1234', send: async (p) => { payload = p; } },
        reason: 'spam',
        action: 'ban',
        cid: 7,
    });
    assert.strictEqual(ok, true);
    assert.ok(payload, 'DM must be sent');
    const fieldNames = payload.embeds?.[0]?.data?.fields?.map(f => f.name) || [];
    assert.deepStrictEqual(fieldNames, ['Server', 'User', 'Responsible moderator', 'Action', 'Reason', 'Rule', 'CID', 'Time']);
});
