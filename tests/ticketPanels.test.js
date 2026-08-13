const test = require('node:test');
const assert = require('node:assert/strict');

/**
 * Tests for the premium ticket-panel feature's pure logic. The DB-backed manager
 * is constructed lazily and only touches the pool on _init, so we can exercise
 * the deterministic helpers (panel normalization, button-style/message-type
 * validation, embed building) without a live Postgres by stubbing the pool.
 */

// Stub the ticket pool BEFORE requiring the manager so its constructor's
// async _init never hits a real database.
const { ticketPool } = require('../server/ticketDb');
ticketPool.query = async () => ({ rows: [] });

const { TicketPanelManager } = require('../utils/ticketManager');

test('_normalizePanel fills defaults and validates enum fields', () => {
    const mgr = new TicketPanelManager({}); // _init is async + stubbed
    const p = mgr._normalizePanel({ name: '  Support  ', buttonStyle: 'bogus', messageType: 'weird', color: 'nope' });
    assert.equal(p.name, 'Support');
    assert.equal(p.buttonStyle, 'Primary');
    assert.equal(p.messageType, 'embed');
    assert.equal(p.color, '#5865F2');
    assert.equal(p.enabled, true);
    assert.deepEqual(p.supportRoleIds, []);
    assert.equal(p.cooldownSeconds, 0);
    assert.equal(p.maxOpenPerUser, 1);
});

test('_normalizePanel coerces role ids to strings and clamps numbers', () => {
    const mgr = new TicketPanelManager({});
    const p = mgr._normalizePanel({
        name: 'Billing',
        supportRoleIds: [111, 222],
        pingRoleIds: ['333'],
        cooldownSeconds: -5,
        maxOpenPerUser: '3',
    });
    assert.deepEqual(p.supportRoleIds, ['111', '222']);
    assert.deepEqual(p.pingRoleIds, ['333']);
    assert.equal(p.cooldownSeconds, 0);
    assert.equal(p.maxOpenPerUser, 3);
});

test('_normalizePanel trims emoji fields to null when empty', () => {
    const mgr = new TicketPanelManager({});
    const p = mgr._normalizePanel({
        buttonEmoji: '   ',
        closeButtonEmoji: '',
        claimButtonLabel: '  ',
    });
    assert.equal(p.buttonEmoji, null);
    assert.equal(p.closeButtonEmoji, null);
    assert.equal(p.claimButtonLabel, null);
});

test('_normalizePanel keeps a valid color, style, and message type', () => {
    const mgr = new TicketPanelManager({});
    const p = mgr._normalizePanel({
        color: '#57F287', buttonStyle: 'Danger', messageType: 'plain',
    });
    assert.equal(p.color, '#57F287');
    assert.equal(p.buttonStyle, 'Danger');
    assert.equal(p.messageType, 'plain');
});

test('buildPanelMessage builds an embed with the open button for embed type', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        id: 42, name: 'Support', title: 'Need help?', description: 'Click below',
        color: '#57F287', buttonLabel: 'Open Ticket', buttonStyle: 'Success', buttonEmoji: '🎫',
    });
    const payload = mgr.buildPanelMessage(panel);
    assert.ok(payload.embeds && payload.embeds.length === 1);
    const e = payload.embeds[0].toJSON ? payload.embeds[0].toJSON() : payload.embeds[0];
    assert.equal(e.title, 'Need help?');
    assert.equal(e.color, 0x57F287);
    assert.ok(payload.components.length >= 1);
    const btn = payload.components[0].components[0];
    assert.equal(btn.custom_id, 'ticketpanel:open:42');
    assert.equal(btn.label, 'Open Ticket');
});

test('buildPanelMessage builds a plain message with the open button for plain type', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        id: 7, messageType: 'plain', content: 'Press to open a ticket',
        buttonLabel: 'Open', buttonStyle: 'Primary',
    });
    const payload = mgr.buildPanelMessage(panel);
    assert.equal(payload.content, 'Press to open a ticket');
    assert.ok(!payload.embeds);
    const btn = payload.components[0].components[0];
    assert.equal(btn.custom_id, 'ticketpanel:open:7');
    assert.equal(btn.label, 'Open');
});

test('buildControlMessage includes a close button and a claim button when configured', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        name: 'Support', claimButtonLabel: 'Claim', claimButtonEmoji: '✋',
    });
    const payload = mgr.buildControlMessage(panel, '<@123>');
    assert.equal(payload.components.length, 2);
    const closeBtn = payload.components[0].components[0];
    assert.equal(closeBtn.custom_id, 'ticketpanel:close');
    const claimBtn = payload.components[1].components[0];
    assert.equal(claimBtn.custom_id, 'ticketpanel:claim');
    assert.equal(claimBtn.label, 'Claim');
});

test('buildControlMessage omits the claim button when not configured', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({ name: 'Support' });
    const payload = mgr.buildControlMessage(panel, '<@123>');
    assert.equal(payload.components.length, 1);
    assert.equal(payload.components[0].components[0].custom_id, 'ticketpanel:close');
});

test('countOpenTickets counts only open tickets for the guild+user', () => {
    const mgr = new TicketPanelManager({});
    mgr._byChannel.set('c1', { guildId: 'g', userId: 'u', status: 'open' });
    mgr._byChannel.set('c2', { guildId: 'g', userId: 'u', status: 'closed' });
    mgr._byChannel.set('c3', { guildId: 'g', userId: 'other', status: 'open' });
    mgr._byChannel.set('c4', { guildId: 'other', userId: 'u', status: 'open' });
    assert.equal(mgr.countOpenTickets('g', 'u'), 1);
});
