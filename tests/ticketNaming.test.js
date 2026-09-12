// Regression tests for ticket channel NAME templates + {count}:
//  - Role-tab (TROLE pool) open/close name templates are honored (the
//    resolver `_troleNameState` was previously dead code — the open/close/
//    reopen/claim flows always used the legacy panel template and never fed
//    {count} a real value).
//  - The {count} placeholder renders the user's open-ticket count.
//  - Per-input (button/option) config overrides apply to the open channel name.
const { test } = require('node:test');
const assert = require('node:assert/strict');

// Stub DB pools before requiring the manager so `_init` never hits Postgres.
const { ticketPool } = require('../server/ticketDb');
const { tclaimPool } = require('../server/tclaimDb');
const { trolePool } = require('../server/troleDb');
ticketPool.query = async () => ({ rows: [] });
tclaimPool.query = async () => ({ rows: [] });
trolePool.query = async () => ({ rows: [] });
trolePool.connect = async () => ({ query: async () => ({}), release: () => {} });

const { TicketPanelManager } = require('../utils/ticketManager');

async function makeManager(roleRows = []) {
    trolePool.query = async () => ({ rows: roleRows });
    const mgr = new TicketPanelManager({});
    // The constructor's _init is async; wait for the role settings to land in
    // the in-memory map so _troleNameState sees them.
    await mgr._loadRoleSettings();
    return mgr;
}

const ROLE_ROW = (panelId, state, over = {}) => ({
    panel_id: panelId,
    ...(state === 'open' ? {
        open_enabled: true, open_name: '(open) {name} #{count}', open_show_user: false, open_show_count: true,
        open_add_role: null, open_remove_role: null, close_enabled: false, close_name: null,
        close_show_user: false, close_show_count: false, close_add_role: null, close_remove_role: null,
    } : {
        close_enabled: true, close_name: '(closed) {name} #{count}', close_show_user: false, close_show_count: true,
        close_add_role: null, close_remove_role: null, open_enabled: false, open_name: null,
        open_show_user: false, open_show_count: false, open_add_role: null, open_remove_role: null,
    }),
    ...over,
});

test('_troleNameState prefers role settings when enabled and carries count', async () => {
    const mgr = await makeManager([ROLE_ROW('7', 'open')]);
    const panel = mgr._normalizePanel({ id: 7, name: 'Support', openNameTemplate: '(open) {name}' });
    const state = mgr._troleNameState(panel, 'open', panel.openNameTemplate, 3);
    assert.equal(state.template, '(open) {name} #{count}');
    assert.equal(state.showCount, true);
    assert.equal(state.showUserName, false);
    assert.equal(state.count, 3);
});

test('_troleNameState falls back to legacy template with username fallback', async () => {
    const mgr = await makeManager([]);
    const panel = mgr._normalizePanel({ id: 7, name: 'Support', openNameTemplate: '(open) {name}' });
    const state = mgr._troleNameState(panel, 'open', panel.openNameTemplate, 99);
    assert.equal(state.template, '(open) {name}');
    assert.equal(state.showCount, false);
    assert.equal(state.showUserName, true); // legacy → {name} may fall back to username
    // Legacy templates are not renumbered.
    assert.equal(mgr._renderTicketName(panel.openNameTemplate, panel, { username: 'alice' }), 'open-alice');
});

test('_renderTicketName renders {count} when passed', async () => {
    const mgr = await makeManager([]);
    const panel = mgr._normalizePanel({ id: 7, name: 'Support', ticketName: 'support' });
    assert.equal(
        mgr._renderTicketName('{name}-{count}', panel, { username: 'alice' }, { showUserName: true, showCount: true, count: 2 }),
        'support-2'
    );
});

test('_openTicket names the new channel via role settings + includes created ticket in {count}', async () => {
    const mgr = await makeManager([ROLE_ROW('7', 'open')]);
    // Pre-existing open ticket for the same user → the new one is #2.
    mgr._byChannel.set('c-old', { guildId: 'g', userId: 'u', status: 'open' });

    const createdChannels = [];
    const guild = {
        id: 'g',
        channels: {
            create: async ({ name }) => {
                const ch = { id: `c-${createdChannels.length}`, name, send: async () => ({ id: 'm1' }), isThread: () => false };
                createdChannels.push(ch);
                return ch;
            },
        },
        members: { me: { id: 'bot' } },
    };
    const interaction = {
        guild,
        member: { id: 'u', roles: { cache: new Set() }, permissions: { has: () => false } },
        user: { id: 'u', username: 'alice', tag: 'alice#0000' },
        reply: async () => {},
    };
    // Stub _saveInstance + _ensureClaimRow to keep the flow DB-free.
    mgr._saveInstance = async () => {};
    mgr._ensureClaimRow = async () => {};
    mgr._applyRoleSettings = async () => {};

    const panel = mgr._normalizePanel({ id: 7, guildId: 'g', name: 'Support', ticketName: 'support' });
    await mgr._openTicket(interaction, panel, guild, interaction.member, 'u', null, null);

    assert.equal(createdChannels.length, 1);
    // show user OFF → {name} = panel.ticketName; {count} = 2 (existing + new).
    assert.equal(createdChannels[0].name, 'open-support-2');
});

test('_openTicket applies per-component open name template override', async () => {
    const mgr = await makeManager([]);
    const createdChannels = [];
    const guild = {
        id: 'g',
        channels: {
            create: async ({ name }) => {
                const ch = { id: `c-${createdChannels.length}`, name, send: async () => ({ id: 'm1' }), isThread: () => false };
                createdChannels.push(ch);
                return ch;
            },
        },
        members: { me: { id: 'bot' } },
    };
    const interaction = {
        guild,
        member: { id: 'u', roles: { cache: new Set() }, permissions: { has: () => false } },
        user: { id: 'u', username: 'bob', tag: 'bob#0000' },
        reply: async () => {},
    };
    mgr._saveInstance = async () => {};
    mgr._ensureClaimRow = async () => {};
    mgr._applyRoleSettings = async () => {};

    const basePanel = mgr._normalizePanel({ id: 9, guildId: 'g', name: 'Support', ticketName: null });
    const cfg = mgr._ticketConfigFor(basePanel, { openNameTemplate: 'urgent-{name}', ticketName: 'urgent' });
    await mgr._openTicket(interaction, basePanel, guild, interaction.member, 'u', null, cfg);

    assert.equal(createdChannels.length, 1);
    assert.equal(createdChannels[0].name, 'urgent-urgent');
});

test('_troleNameState handles close-state role setting with count', async () => {
    const mgr = await makeManager([ROLE_ROW('7', 'close')]);
    const panel = mgr._normalizePanel({ id: 7, name: 'Support', ticketName: 'support' });
    const state = mgr._troleNameState(panel, 'close', panel.closedNameTemplate, 1);
    assert.equal(state.template, '(closed) {name} #{count}');
    assert.equal(state.count, 1);
    assert.equal(mgr._renderTicketName(state.template, panel, null, {
        showUserName: state.showUserName,
        showCount: state.showCount,
        count: state.count,
    }), 'closed-support-1');
});