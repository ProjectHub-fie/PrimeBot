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

// The builders return discord.js ButtonBuilder/ActionRowBuilder objects; tests
// need the serialized form (custom_id, label, ...) to assert against.
function btnOf(payload, rowIdx = 0, colIdx = 0) {
    const comp = payload.components[rowIdx].components[colIdx];
    return comp && comp.toJSON ? comp.toJSON() : comp;
}

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
    const btn = btnOf(payload);
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
    const btn = btnOf(payload);
    assert.equal(btn.custom_id, 'ticketpanel:open:7');
    assert.equal(btn.label, 'Open');
});

test('buildControlMessage includes a close button, a claim button, and a rename button when configured', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        name: 'Support', claimButtonLabel: 'Claim', claimButtonEmoji: '✋',
    });
    const payload = mgr.buildControlMessage(panel, '<@123>');
    assert.equal(payload.components.length, 2);
    const closeBtn = btnOf(payload, 0, 0);
    assert.equal(closeBtn.custom_id, 'ticketpanel:close');
    const claimBtn = btnOf(payload, 1, 0);
    assert.equal(claimBtn.custom_id, 'ticketpanel:claim');
    assert.equal(claimBtn.label, 'Claim');
    // Rename button is in the second extra row alongside claim.
    const renameBtn = btnOf(payload, 1, 1);
    assert.equal(renameBtn.custom_id, 'ticketpanel:rename');
});

test('buildControlMessage includes a rename button (with close) when no claim button is configured', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({ name: 'Support' });
    const payload = mgr.buildControlMessage(panel, '<@123>');
    assert.equal(payload.components.length, 2);
    assert.equal(btnOf(payload, 0, 0).custom_id, 'ticketpanel:close');
    assert.equal(btnOf(payload, 1, 0).custom_id, 'ticketpanel:rename');
});

test('_normalizePanel applies default status name templates and trims to null when empty', () => {
    const mgr = new TicketPanelManager({});
    const p = mgr._normalizePanel({ name: 'Support' });
    assert.equal(p.openNameTemplate, '(open) {name}');
    assert.equal(p.claimedNameTemplate, '(solved) {name}');
    assert.equal(p.closedNameTemplate, '(closed) {name}');
    const blank = mgr._normalizePanel({
        openNameTemplate: '   ', claimedNameTemplate: '', closedNameTemplate: '   ',
    });
    assert.equal(blank.openNameTemplate, null);
    assert.equal(blank.claimedNameTemplate, null);
    assert.equal(blank.closedNameTemplate, null);
});

test('_renderTicketName substitutes placeholders and sanitizes to Discord channel rules', () => {
    const mgr = new TicketPanelManager({});
    const panel = { name: 'Support Panel', ticketName: 'billing' };
    const opener = { id: '42', username: 'Alice' };
    assert.equal(mgr._renderTicketName('(open) {name}', panel, opener), 'open-billing');
    assert.equal(mgr._renderTicketName('(solved) {username}', panel, opener), 'solved-alice');
    assert.equal(mgr._renderTicketName('{panel} - {id}', panel, opener), 'support-panel---42');
    // Empty/null template → no rename.
    assert.equal(mgr._renderTicketName('', panel, opener), null);
    assert.equal(mgr._renderTicketName(null, panel, opener), null);
    // Falls back to username when ticketName is unset.
    const noName = mgr._renderTicketName('(open) {name}', { name: 'P', ticketName: null }, opener);
    assert.equal(noName, 'open-alice');
});

test('_renderTicketName trims to 100 chars', () => {
    const mgr = new TicketPanelManager({});
    const long = 'x'.repeat(150);
    const out = mgr._renderTicketName(`(open) ${long}`, { ticketName: 'n' }, { username: 'u' });
    assert.ok(out.length <= 100);
});

test('countOpenTickets counts only open tickets for the guild+user', () => {
    const mgr = new TicketPanelManager({});
    mgr._byChannel.set('c1', { guildId: 'g', userId: 'u', status: 'open' });
    mgr._byChannel.set('c2', { guildId: 'g', userId: 'u', status: 'closed' });
    mgr._byChannel.set('c3', { guildId: 'g', userId: 'other', status: 'open' });
    mgr._byChannel.set('c4', { guildId: 'other', userId: 'u', status: 'open' });
    assert.equal(mgr.countOpenTickets('g', 'u'), 1);
});

// ── Per-guild panel-name uniqueness (dashboard/db.js) ───────────────────────

test('isTicketNameConflict detects a 23505 violation on the guild+name index', () => {
    const dashboardDb = require('../dashboard/db');
    assert.equal(dashboardDb.isTicketNameConflict({ code: '23505', constraint: 'ticket_panels_guild_name_idx' }), true);
    assert.equal(dashboardDb.isTicketNameConflict({ code: '23505', constraint: 'some_other_idx' }), false);
    assert.equal(dashboardDb.isTicketNameConflict({ code: '42P01', constraint: 'ticket_panels_guild_name_idx' }), false);
    assert.equal(dashboardDb.isTicketNameConflict(null), false);
});

test('uniqueCloneName picks the first free "(copy)"/"(copy n)" name', () => {
    const dashboardDb = require('../dashboard/db');
    assert.equal(dashboardDb.uniqueCloneName('Support', []), 'Support (copy)');
    assert.equal(
        dashboardDb.uniqueCloneName('Support', [{ name: 'Support (copy)' }]),
        'Support (copy 2)',
    );
    assert.equal(
        dashboardDb.uniqueCloneName('Support', [{ name: 'Support (copy)' }, { name: 'Support (copy 2)' }]),
        'Support (copy 3)',
    );
});

test('createTicketPanel maps a duplicate-name 23505 to a friendly 409 error', async () => {
    const savedQuery = ticketPool.query;
    ticketPool.query = async (sql) => {
        if (/INSERT INTO ticket_panels/i.test(String(sql))) {
            const err = new Error('duplicate key value violates unique constraint "ticket_panels_guild_name_idx"');
            err.code = '23505';
            err.constraint = 'ticket_panels_guild_name_idx';
            throw err;
        }
        return { rows: [] };
    };
    try {
        const dashboardDb = require('../dashboard/db');
        await assert.rejects(
            () => dashboardDb.createTicketPanel('g1', { name: 'Support' }),
            (err) => {
                assert.equal(err.status, 409);
                assert.match(err.message, /already exists/);
                assert.doesNotMatch(err.message, /duplicate key/);
                return true;
            },
        );
    } finally {
        ticketPool.query = savedQuery;
    }
});

test('cloneTicketPanel auto-suffixes the default copy name when it is taken', async () => {
    const savedQuery = ticketPool.query;
    const panels = [
        { id: 7, guild_id: 'g1', name: 'Support', support_role_ids: [], ping_role_ids: [], enabled: true },
        { id: 8, guild_id: 'g1', name: 'Support (copy)', support_role_ids: [], ping_role_ids: [], enabled: true },
    ];
    let insertedName = null;
    ticketPool.query = async (sql, params) => {
        const text = String(sql);
        if (/INSERT INTO ticket_panels/i.test(text)) {
            insertedName = params[1];
            return { rows: [{ id: 9 }] };
        }
        if (/FROM ticket_panels WHERE id = \$1/i.test(text) && params[0] === 7) {
            return { rows: [panels[0]] };
        }
        if (/FROM ticket_panels WHERE id = \$1/i.test(text)) {
            return { rows: [] }; // refetch of the new panel
        }
        if (/FROM ticket_panels WHERE guild_id = \$1/i.test(text)) {
            return { rows: panels };
        }
        return { rows: [] }; // ensureTicketTables CREATEs
    };
    try {
        const dashboardDb = require('../dashboard/db');
        await dashboardDb.cloneTicketPanel(7, null);
        assert.equal(insertedName, 'Support (copy 2)');
    } finally {
        ticketPool.query = savedQuery;
    }
});
