// Ticket editor embed-builder (Ticket Tool "Panel Embed Settings" pattern).
// The Message tab renders the panel embed with each embed region (content, author,
// title, description, thumbnail, image, footer, color, open button) holding its
// OWN editing field(s) attached to that region + a tiny live render beneath the input,
// instead of a detached page-level "Live embed preview" pane. Also covers the new
// author (name + icon URL) fields flowing through the bot's embed builder and the
// dashboard's DB round-trip.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('fs');
const path = require('path');

const guildPages = require('../dashboard/render/guild-pages');
const dashboardDb = require('../dashboard/db');
const { ticketPool } = require('../server/ticketDb');
const { TicketPanelManager } = require('../utils/ticketManager');

ticketPool.query = async () => ({ rows: [] });

function fakeGuild(panel) {
    return {
        id: '123',
        name: 'Test Guild',
        icon: null,
        _bypassUpcoming: true,
        _channels: [],
        _roles: [],
        _ticketPanel: panel || {
            id: 42, name: 'Support', messageType: 'embed', title: 'Need help?',
            description: 'Click below', color: '#57F287', content: '@support hello',
            authorName: 'Support Team', authorIconUrl: 'https://x/a.png',
            thumbnailUrl: 'https://x/t.png', imageUrl: 'https://x/i.png',
            footerText: 'PrimeBot · Tickets', buttonLabel: 'Open', buttonStyle: 'Success',
            buttonEmoji: '🎫',
        },
    };
}

test('ticketEditPage: Message tab renders an embed builder — fields ON the embed', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild(), user: null });
    assert.ok(html.includes('tk-embed-builder'), 'embed-builder container');
    assert.ok(html.includes('edb-author'), 'author region');
    assert.ok(html.includes('id="tk-author-name"'), 'author name field');
    assert.ok(html.includes('id="tk-author-icon"'), 'author icon URL field');
    assert.ok(html.includes('id="tk-title"'), 'title field on the embed');
    assert.ok(html.includes('id="tk-description"'), 'description field on the embed');
    assert.ok(html.includes('id="tk-thumbnail"'), 'thumbnail field on the embed');
    assert.ok(html.includes('id="tk-image"'), 'image field on the embed');
    assert.ok(html.includes('id="tk-footer"'), 'footer field on the embed');
    assert.ok(html.includes('id="tk-color"'), 'color field on the embed');
    assert.ok(html.includes('id="tk-button-style"'), 'open-button style field on the embed');
    assert.ok(html.includes('id="edb-author"'), 'live author row');
    assert.ok(html.includes('id="edb-title"'), 'live title row');
    assert.ok(html.includes('id="edb-desc"'), 'live description row');
    assert.ok(html.includes('id="edb-bar"'), 'live color bar');
    assert.ok(html.includes('id="edb-button"'), 'live open-button preview');
    assert.ok(!html.includes('tk-live-preview'), 'no detached live preview pane');
    assert.ok(!html.includes('tk-editor-grid'), 'no page-level two-column preview grid');
});

test('ticketEditPage: every embed-builder input id is unique', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild(), user: null });
    const ids = ['tk-title', 'tk-description', 'tk-content', 'tk-footer', 'tk-thumbnail', 'tk-image',
        'tk-color', 'tk-color-text', 'tk-author-name', 'tk-author-icon',
        'tk-button-label', 'tk-button-emoji', 'tk-button-style'];
    for (const id of ids) {
        const n = (html.match(new RegExp(`id="${id}"`, 'g')) || []).length;
        assert.equal(n, 1, `id #${id} appears exactly once`);
    }
});

test('manager buildPanelMessage renders the author name + icon via setAuthor', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        id: 42, name: 'Support', title: 'Need help?', description: 'Click below',
        authorName: 'Support Team', authorIconUrl: 'https://x/a.png',
    });
    const payload = mgr.buildPanelMessage(panel);
    const e = payload.embeds[0].toJSON ? payload.embeds[0].toJSON() : payload.embeds[0];
    assert.equal(e.author.name, 'Support Team');
    assert.equal(e.author.icon_url,'https://x/a.png');
    const plain = mgr.buildPanelMessage(mgr._normalizePanel({ id: 1, authorName: '  ' }));
    const e2 = plain.embeds[0].toJSON ? plain.embeds[0].toJSON() : plain.embeds[0];
    assert.equal(e2.author, undefined);
});

test('updateTicketPanel persists author fields (DB round-trip)', async () => {
    const statements = [];
    ticketPool.query = async (sql, params) => {
        statements.push({ sql, params });
        if (/SELECT \* FROM ticket_panels WHERE id = \$1/.test(sql)) {
            return {
                rows: [{
                    id: 42, guild_id: '123', name: 'Support', channel_id: null, message_id: null,
                    message_type: 'embed', title: 'old', description: null, color: '#5865F2',
                    thumbnail_url: null, image_url: null, author_name: null, author_icon_url: null,
                    footer_text: null, content: null,
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

    await dashboardDb.updateTicketPanel(42, {
        authorName: 'Support Team', authorIconUrl: 'https://x/a.png', title: 'new',
    });

    const update = statements.find(s => s.sql.includes('UPDATE ticket_panels SET'));
    assert.ok(update, 'UPDATE executed');
    const params = update.params;
    assert.equal(params[10], 'Support Team', 'author_name persisted');
    assert.equal(params[11], 'https://x/a.png', 'author_icon_url persisted');
    assert.equal(params[36], true, 'enabled still persisted at shifted index');
});

test('client renderTicketPreview updates live output nodes without rebuilding inputs', () => {
    const TICKET_EDITOR = fs.readFileSync(
        path.join(__dirname, '..', 'dashboard', 'public', 'js', 'ticket-editor.js'), 'utf8');

    const els = {};
    function makeEl(id) {
        if (els[id]) return els[id];
        const cls = new Set();
        const el = {
            id, value: '', _text: '',
            style: {},
            classList: {
                add: c => cls.add(c),
                remove: c => cls.delete(c),
                toggle: (c, on) => { if (on === undefined ? !cls.has(c) : on) cls.add(c); else cls.delete(c); },
                contains: c => cls.has(c),
            },
            get textContent() { return this._text; },
            set textContent(v) { this._text = v; },
            removeAttribute: k => { delete el[k]; },
            addEventListener: () => {},
            remove: () => {},
            insertBefore: () => {},
            querySelector: () => null,
            querySelectorAll: () => [],
            closest: () => null,
            dataset: {},
        };
        els[id] = el;
        return el;
    }
    const make = id => makeEl(id);
    const setId = (id, v) => { make(id).value = v; };
    const sandbox = {
        window: {
            guildData: { guildId: '1' },
            location: { pathname: '/guild/1/tickets/42/edit' },
            populateRoleSelects: () => {},
            populateChannelSelects: () => {},
            refreshPanelActions: () => {},
            saveBar: { register: () => {}, track: () => {}, markDirty: () => {} },
            saveTicketPanel: async () => {},
        },
        document: {
            querySelector: sel => {
                if (sel === '.tk-editor-tabs' || sel === '.tk-editor-panels') return null;
                if (sel.startsWith('#')) return make(sel.slice(1));
                return null;
            },
            getElementById: id => make(id),
            querySelectorAll: () => [],
            createElement: tag => {
                const el = makeEl('tmp-' + Math.random());
                return el;
            },
        },
        esc: s => String(s),
        toast: () => {},
        bindColorSync: () => {},
        populateRoleSelects: () => {},
        populateChannelSelects: () => {},
        bindReactionRemovals: () => {},
        confirm: () => true,
        prompt: () => null,
        localStorage: {},
        console,
    };
    vm.createContext(sandbox);
    vm.runInContext(TICKET_EDITOR, sandbox);

    setId('tk-author-name', 'Support Team');
    setId('tk-author-icon', 'https://x/a.png');
    setId('tk-title', 'Need help?');
    setId('tk-description', 'Click below');
    setId('tk-content', '@support hello');
    setId('tk-footer', 'PrimeBot');
    setId('tk-thumbnail', 'https://x/t.png');
    setId('tk-image', 'https://x/i.png');
    setId('tk-color', '#57F287');
    setId('tk-button-label', 'Open');
    setId('tk-button-emoji', '🎫');
    setId('tk-button-style', 'Success');

    vm.runInContext('renderTicketPreview();', sandbox);

    assert.equal(make('edb-title').textContent,'Need help?');
    assert.equal(make('edb-desc').textContent,'Click below');
    assert.equal(make('edb-content').textContent,'@support hello');
    assert.equal(make('edb-footer').textContent,'PrimeBot');
    assert.equal(make('edb-author-name').textContent,'Support Team');
    assert.equal(make('edb-author-icon').src,'https://x/a.png');
    assert.equal(make('edb-thumb').src,'https://x/t.png');
    assert.equal(make('edb-image').src,'https://x/i.png');
    assert.equal(make('edb-bar').style.background,'#57F287');
    assert.equal(make('edb-button-label').textContent,'Open');
    assert.ok(make('edb-button').classList.contains('tk-preview-button-success'), 'button style class updated');
    assert.equal(make('tk-title').value,'Need help?');
});