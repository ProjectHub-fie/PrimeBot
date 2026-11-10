/* Anti-Nuke automatic-setup step changes.
 *
 * Covers the requested autosetup flow:
 *   • `restore` is gone from the walkthrough (step 8 removed).
 *   • step 2 (`permissions`) is a hard gate on the bot being in the top 3 roles.
 *   • step 3 (`alert`) asks for a log channel — "Make automatically" creates
 *     #primebot-antinuke-log.
 *   • step 7 (`isolation`) asks for an isolation role — "Make automatically"
 *     creates a role named `isolated` just below the bot's role.
 */
const { test } = require('node:test');
const assert = require('node:assert');

const setup = require('../utils/antiNukeSetup');
const {
    stepsForMethod, botRolePositionCheck,
    ALERT_CHANNEL_NAME, ISOLATION_ROLE_NAME, AUTO_WALKTHROUGH_STEPS,
} = setup;
const {
    runWalkthroughStepOp, SetupPrompt, createAlertChannel, createIsolationRole,
} = require('../utils/antiNukeSetupRunner');

// The exported walkthrough executor delegates the backend steps
// (permissions / alert / isolation) to runStep — call it with the manager shim.
const runStep = (key, { client, guild, options }) =>
    runWalkthroughStepOp(key, { manager: client && client.antiNukeManager, guild, state: { method: 'automatic' }, options: options || {} });

// A guild stub with real role positions + create capabilities.
function guildStub({ botRolePosition = 5, roles = [], channels = [] } = {}) {
    const roleList = roles.slice();
    const channelList = channels.slice();
    return {
        id: 'g1', name: 'Test', ownerId: 'owner1', memberCount: 10,
        channels: {
            cache: {
                size: channelList.length,
                get: (id) => channelList.find(c => String(c.id) === String(id)) || null,
                has: (id) => channelList.some(c => String(c.id) === String(id)),
                values: () => channelList.values(),
                find: (fn) => channelList.find(fn),
            },
            fetch: async (id) => channelList.find(c => String(c.id) === String(id)) || null,
            create: async (opts = {}) => {
                const ch = { id: 'newch', name: opts.name, type: opts.type };
                channelList.push(ch);
                return ch;
            },
        },
        roles: {
            cache: {
                size: roleList.length,
                values: () => roleList.values(),
                get: (id) => roleList.find(r => String(r.id) === String(id)) || null,
                has: (id) => roleList.some(r => String(r.id) === String(id)),
            },
            create: async (opts = {}) => {
                const r = { id: 'newrole', name: opts.name, position: opts.position, setPosition: async () => {} };
                roleList.push(r);
                return r;
            },
        },
        members: { me: { permissions: { has: () => true }, roles: { highest: { position: botRolePosition } } } },
    };
}

function managerStub(initial = {}) {
    const stored = { g1: Object.assign({ enabled: true, dryRun: false, watched: {}, trustedUserIds: [], trustedRoleIds: [] }, initial) };
    return {
        getSettings: (id) => stored[id] || {},
        async updateSettingsAsync(id, patch) { stored[id] = Object.assign({}, stored[id] || {}, patch); return stored[id]; },
        async _refreshFromDatabase() { return true; },
        _stored: stored,
    };
}

test('the walkthrough no longer contains a `restore` step', () => {
    assert.ok(!AUTO_WALKTHROUGH_STEPS.some(s => s.key === 'restore'), 'restore must be removed');
});

test('the automatic catalog has the requested order and names', () => {
    const keys = stepsForMethod('automatic').map(s => s.key);
    assert.equal(keys[1], 'permissions', 'step 2 is permissions');
    assert.equal(keys[2], 'alert', 'step 3 is alert (log channel)');
    assert.equal(keys[6], 'isolation', 'step 7 is isolation role');
    assert.ok(keys.includes('isolation'));
    assert.ok(!keys.includes('restore'));
});

// ── botRolePositionCheck ────────────────────────────────────────────────────

test('botRolePositionCheck passes when the bot is in the top 3', () => {
    const roles = [
        { id: 'r1', position: 5 }, { id: 'r2', position: 4 }, { id: 'r3', position: 3 },
        { id: 'r4', position: 2 }, { id: 'r5', position: 1 },
    ];
    const r = botRolePositionCheck(guildStub({ botRolePosition: 4, roles }));
    assert.equal(r.ok, true);
    assert.equal(r.rank, 2);
});

test('botRolePositionCheck fails when the bot is outside the top 3', () => {
    const roles = [
        { id: 'r1', position: 9 }, { id: 'r2', position: 8 }, { id: 'r3', position: 7 },
        { id: 'r4', position: 6 }, { id: 'r5', position: 5 },
    ];
    const r = botRolePositionCheck(guildStub({ botRolePosition: 5, roles }));
    assert.equal(r.ok, false);
    assert.equal(r.rank, 5);
    assert.match(r.message, /top 3 role position/i);
});

test('botRolePositionCheck never blocks on missing data', () => {
    const r = botRolePositionCheck({ members: { me: {} }, roles: { cache: { values: () => [].values() } } });
    assert.equal(r.ok, true);
    assert.equal(r.indeterminate, true);
});

// ── step 2: permissions gate ────────────────────────────────────────────────

test('the permissions step fails (stops setup) when the bot is not in the top 3', async () => {
    const roles = [
        { id: 'r1', position: 9 }, { id: 'r2', position: 8 }, { id: 'r3', position: 7 }, { id: 'r4', position: 6 },
    ];
    await assert.rejects(
        () => runStep('permissions', { client: { antiNukeManager: managerStub() }, guild: guildStub({ botRolePosition: 6, roles }), options: {} }),
        /top 3 role position/i,
    );
});

test('the permissions step passes when the bot is in the top 3', async () => {
    const roles = [{ id: 'r1', position: 9 }, { id: 'r2', position: 8 }, { id: 'r3', position: 7 }];
    const res = await runStep('permissions', { client: { antiNukeManager: managerStub() }, guild: guildStub({ botRolePosition: 8, roles }), options: {} });
    assert.equal(res.roleRank, 2);
});

// ── step 3: alert channel ───────────────────────────────────────────────────

test('createAlertChannel creates #primebot-antinuke-log', async () => {
    const guild = guildStub();
    const res = await createAlertChannel(guild, ALERT_CHANNEL_NAME);
    assert.equal(res.name, 'primebot-antinuke-log');
    assert.equal(res.source, 'created');
});

test('the alert step prompts the dashboard admin when no channel exists', async () => {
    await assert.rejects(
        () => runStep('alert', { client: { antiNukeManager: managerStub() }, guild: guildStub(), options: { interactive: true } }),
        (err) => err instanceof SetupPrompt && err.kind === 'alert_channel',
    );
});

test('the alert step auto-creates the channel on "Make automatically"', async () => {
    const res = await runStep('alert', {
        client: { antiNukeManager: managerStub() },
        guild: guildStub(),
        options: { interactive: true, automaticChannel: true },
    });
    assert.equal(res.name, 'primebot-antinuke-log');
    assert.equal(res.source, 'created');
});

test('the alert step uses an existing channel without prompting', async () => {
    const guild = guildStub({ channels: [{ id: 'c1', name: 'security-logs', type: 0 }] });
    const res = await runStep('alert', { client: { antiNukeManager: managerStub() }, guild, options: { interactive: true } });
    assert.equal(res.channelId, 'c1');
    assert.notEqual(res.source, 'created');
});

test('the alert step honors an explicitly picked channel', async () => {
    const guild = guildStub({ channels: [{ id: 'c9', name: 'logs', type: 0 }] });
    const res = await runStep('alert', { client: { antiNukeManager: managerStub() }, guild, options: { interactive: true, alertChannelId: 'c9' } });
    assert.equal(res.channelId, 'c9');
});

// ── step 7: isolation role ──────────────────────────────────────────────────

test('createIsolationRole creates `isolated` just below the bot role', async () => {
    const guild = guildStub({ botRolePosition: 7 });
    const res = await createIsolationRole(guild, ISOLATION_ROLE_NAME);
    assert.equal(res.name, 'isolated');
    assert.equal(res.position, 6);
    assert.equal(res.source, 'created');
});

test('the isolation step prompts the dashboard admin when none is configured', async () => {
    await assert.rejects(
        () => runStep('isolation', { client: { antiNukeManager: managerStub() }, guild: guildStub(), options: { interactive: true } }),
        (err) => err instanceof SetupPrompt && err.kind === 'isolation_role',
    );
});

test('the isolation step auto-creates and persists the role on "Make automatically"', async () => {
    const manager = managerStub();
    const res = await runStep('isolation', {
        client: { antiNukeManager: manager },
        guild: guildStub({ botRolePosition: 4 }),
        options: { interactive: true, automaticRole: true },
    });
    assert.equal(res.name, 'isolated');
    assert.equal(manager._stored.g1.quarantineRoleId, 'newrole');
});

test('the isolation step reuses an already-configured role', async () => {
    const manager = managerStub({ quarantineRoleId: '111111111111111111' });
    const res = await runStep('isolation', { client: { antiNukeManager: manager }, guild: guildStub(), options: { interactive: true } });
    assert.equal(res.roleId, '111111111111111111');
    assert.equal(res.source, 'existing');
});
