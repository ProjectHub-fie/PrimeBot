const test = require('node:test');
const assert = require('node:assert/strict');

/**
 * Tests for the ticket "ask for reason" modal flow (utils/ticketManager.js).
 *
 * When a panel has askReason enabled, pressing the panel's Open button must
 * show a modal instead of opening the ticket immediately. The ticket is created
 * on modal submit with the entered reason. Button interactions carry no
 * `interaction.options`, so this modal is the only path that ever collects a reason.

 * The manager is constructed with a stubbed ticket pool (no Postgres needed),
 * mirroring the other ticket tests.
 */
const { ticketPool } = require('../server/ticketDb');
ticketPool.query = async () => ({ rows: [] });

const { TicketPanelManager } = require('../utils/ticketManager');

function makeMember(memberId) {
    return {
        id: memberId,
        roles: { cache: new Map(), has: () => false, add: async () => {}, remove: async () => {} },
        permissions: { has: () => false },
    };
}

function makeGuild(guildId, member) {
    return {
        id: guildId,
        members: { me: { id: 'bot-id' }, fetch: async () => member },
    };
}

function makeUser(overrides = {}) {
    return { id: 'user-1', username: 'tester', tag: 'tester#0000', ...overrides };
}

function makeInteraction(overrides = {}) {
    const member = makeMember('user-1');
    const base = {
        guild: makeGuild('guild-1', member),
        user: makeUser(),
        member,
        reply: async () => {},
        showModal: async () => {},
        customId: '',
        fields: null,
        channel: null,
        ...overrides,
    };
    return base;
}

function makeChannel() {
    return { id: 'channel-created', parentId: null, isThread: () => false, send: async () => ({ id: 'msg-1' }) };
}

function makePanel(overrides = {}) {
    return {
        id: 42,
        name: 'Support',
        enabled: true,
        askReason: false,
        reasonPlaceholder: 'Briefly describe your issue',
        maxOpenPerUser: 1,
        ticketName: null,
        openNameTemplate: null,
        supportRoleIds: [],
        pingRoleIds: [],
        ticketCategoryId: null,
        category: 'general',
        closeFlow: { closeEmbed: { enabled: false } },
        ...overrides,
    };
}

function freshManager(panel) {
    const mgr = new TicketPanelManager({});
    mgr._byPanel.set(String(panel.id), panel);
    return mgr;
}

test('askReason enabled → Open button shows a modal (no ticket created)', async () => {
    const panel = makePanel({ askReason: true });
    const mgr = freshManager(panel);
    const interaction = makeInteraction();
    let shownModal = null;
    interaction.showModal = async (m) => { shownModal = m; return m; };
    const replies = [];
    interaction.reply = async (p) => { replies.push(p); return p; };

    await mgr.handleOpen(interaction, panel);

    assert.ok(shownModal, 'expected a modal');
    assert.equal(replies.length, 0, 'no reply expected');
    assert.equal(mgr._byChannel.size, 0);

    const json = shownModal.toJSON();
    assert.equal(json.custom_id, 'ticketpanel:reason:42');
    const input = json.components[0].components[0];
    assert.equal(input.custom_id, 'ticket-reason');
    assert.equal(input.label, 'Reason for opening this ticket');
    assert.equal(input.required, true);
    assert.equal(input.placeholder, 'Briefly describe your issue');
});

test('askReason enabled + disabled panel → error and NO modal', async () => {
    const panel = makePanel({ askReason: true, enabled: false });
    const mgr = freshManager(panel);
    const interaction = makeInteraction();
    let shownModal = null;
    interaction.showModal = async (m) => { shownModal = m; return m; };
    let reply = null;
    interaction.reply = async (p) => { reply = p; return p; };

    await mgr.handleOpen(interaction, panel);

    assert.equal(shownModal, null);
    assert.ok(reply.content.includes('disabled'));
    assert.equal(mgr._byChannel.size, 0);
});

test('askReason enabled + open-limit reached → error and NO modal', async () => {
    const panel = makePanel({ askReason: true, maxOpenPerUser: 1 });
    const mgr = new TicketPanelManager({});
    mgr._byPanel.set('42', panel);
    mgr._byChannel.set('ch-old', { guildId: 'guild-1', userId: 'user-1', status: 'open' });
    const interaction = makeInteraction();
    let shownModal = null;
    interaction.showModal = async (m) => { shownModal = m; return m; };
    let reply = null;
    interaction.reply = async (p) => { reply = p; return p; };

    await mgr.handleOpen(interaction, panel);

    assert.equal(shownModal, null);
    assert.ok(reply.content.includes('already have'));
    assert.equal(mgr._byChannel.size, 1);
});

test('askReason disabled → ticket opens immediately with reason null', async () => {
    const panel = makePanel({ askReason: false, supportRoleIds: ['role-1'] });
    const mgr = freshManager(panel);
    const interaction = makeInteraction();
    interaction.guild.channels = { create: async () => makeChannel() };
    let reply = null;
    interaction.reply = async (p) => { reply = p; return p; };

    await mgr.handleOpen(interaction, panel);

    const inst = mgr._byChannel.get('channel-created');
    assert.ok(inst, 'instance created');
    assert.equal(inst.reason, null);
    assert.equal(inst.panelId, 42);
    assert.ok(reply.content.includes('has been opened'));
});

test('modal submit opensthe ticket with the entered reason', async () => {
    const panel = makePanel({ askReason: true });
    const mgr = freshManager(panel);
    const interaction = makeInteraction({
        customId: 'ticketpanel:reason:42',
        fields: { getTextInputValue: () => 'I forgot my password',
            get: () => ({ value: 'I forgot my password' }) },
    });
    interaction.guild.channels = { create: async () => makeChannel() };
    let reply = null;
    interaction.reply = async (p) => { reply = p; return p; };

    await mgr.handleOpenReasonSubmit(interaction);

    const inst = mgr._byChannel.get('channel-created');
    assert.ok(inst, 'instance created');
    assert.equal(inst.reason, 'I forgot my password');
    assert.equal(inst.panelId, 42);
    assert.equal(inst.userId, 'user-1');
    assert.ok(reply.content.includes('has been opened'));
});

test('modal submit without reason → error, no ticket', async () => {
    const panel = makePanel({ askReason: true });
    const mgr = freshManager(panel);
    const interaction = makeInteraction({
        customId: 'ticketpanel:reason:42',
        fields: { getTextInputValue: () => '', get: () => null },
    });
    let reply = null;
    interaction.reply = async (p) => { reply = p; return p; };

    await mgr.handleOpenReasonSubmit(interaction);

    assert.ok(reply.content.includes('A reason is required'));
    assert.equal(mgr._byChannel.size, 0);
});

test('modal submit for unknown panel → error, no ticket', async () => {
    const mgr = new TicketPanelManager({});
    const interaction = makeInteraction({
        customId: 'ticketpanel:reason:999',
        fields: { getTextInputValue: () => 'some reason', get: () => ({ value: 'some reason' }) },
    });
    let reply = null;
    interaction.reply = async (p) => { reply = p; return p; };

    await mgr.handleOpenReasonSubmit(interaction);

    assert.ok(reply.content.includes('could not be found'));
    assert.equal(mgr._byChannel.size, 0);
});