// Ticket panel editor modal: the page must NOT show the editor form inline —
// it only renders the panel list + a "Create a panel" button, and the editor
// markup lives inside a hidden modal (#tk-modal) that the client opens for
// Create (POST) or Edit (PATCH). Also covers the PATCH endpoint's DB helper.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const guildPages = require('../dashboard/render/guild-pages');
const dashboardDb = require('../dashboard/db');

// Stub the ticket pool BEFORE any updateTicketPanel call so it never hits a
// real database (same justified-mock pattern as ticketPanels.test.js).
const { ticketPool } = require('../server/ticketDb');

function fakeGuild() {
    return {
        id: '123456789012345678',
        name: 'Test Guild',
        icon: null,
        _bypassUpcoming: true, // developer bypass → real markup, no overlay
        _channels: [],
        _roles: [],
        _beta: false,
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, ticketPanels: [] },
    };
}

test('ticketsPage: no inline editor card — Create button + hidden modal', () => {
    const html = guildPages.ticketsPage({ guild: fakeGuild(), user: null });
    assert.ok(html.includes('id="tk-create-open"'), 'Create a panel button exists');
    assert.ok(html.includes('id="tk-modal"'), 'editor lives in a modal');
    assert.ok(html.includes('modal-overlay hidden'), 'modal starts hidden');
    // The editor form is inside the modal body, not as a page-level card.
    assert.ok(/id=["']tk-modal["'][\s\S]*id=["']tk-save["']/.test(html), 'editor form is within #tk-modal');
    assert.ok(!html.includes('Create a panel</span>'), 'no inline "Create a panel" card');
});

test('ticketsPage: Edit/POST/PATCH endpoints are wired (client buttons)', () => {
    const fs = require('fs');
    const path = require('path');
    const client = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'tickets.js'), 'utf8');
    assert.ok(client.includes('.tk-edit'), 'Edit button handler');
    assert.ok(client.includes("method: 'PATCH'"), 'edit saves via PATCH');
    assert.ok(client.includes('editingPanel'), 'tracks editing vs create mode');

    const server = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'server.js'), 'utf8');
    assert.ok(/app\.patch\('\/api\/guilds\/:guildId\/tickets\/:id'/.test(server), 'PATCH endpoint exists');
});

test('updateTicketPanel persists field edits (PATCH backing)', async () => {
    const statements = [];
    ticketPool.query = async (sql, params) => {
        statements.push({ sql, params });
        if (/SELECT \* FROM ticket_panels WHERE id = \$1/.test(sql)) {
            // One row shaped like ticketsRowToPanel expects.
            return {
                rows: [{
                    id: 42, guild_id: '123', name: 'Support', channel_id: null, message_id: null,
                    message_type: 'embed', title: 'old', description: null, color: '#5865F2',
                    thumbnail_url: null, image_url: null, footer_text: null, content: null,
                    button_label: 'Open Ticket', button_style: 'Primary', button_emoji: null,
                    category: 'general', ticket_name: null,
                    support_role_ids: [], ping_role_ids: [], ticket_category_id: null,
                    cooldown_seconds: 0, max_open_per_user: 1, ask_reason: false,
                    reason_placeholder: 'x', welcome_message: null,
                    close_button_label: 'Close', close_button_emoji: null, close_button_style: 'Danger',
                    claim_button_label: null, claim_button_emoji: null,
                    open_name_template: null, claimed_name_template: null, closed_name_template: null,
                    close_flow: {}, enabled: true, created_by: 'u', created_at: null, updated_at: null,
                }],
            };
        }
        return { rows: [], rowCount: 1 };
    };

    await dashboardDb.updateTicketPanel(42, { name: 'Billing', title: 'new', enabled: false });

    const update = statements.find(s => s.sql.includes('UPDATE ticket_panels SET'));
    assert.ok(update, 'UPDATE executed');
    const params = update.params;
    assert.equal(params[1], 'Billing', 'name updated');
    assert.equal(params[5], 'new', 'title updated');
    assert.equal(params[34], false, 'enabled updated');
});

test('updateTicketPanel on a missing panel throws a friendly not-found', async () => {
    ticketPool.query = async () => ({ rows: [], rowCount: 0 });
    await assert.rejects(() => dashboardDb.updateTicketPanel(99, { name: 'n' }), /not found/i);
});
