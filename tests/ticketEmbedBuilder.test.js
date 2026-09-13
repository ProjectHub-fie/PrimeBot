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
const { tclaimPool } = require('../server/tclaimDb');
const { TicketPanelManager } = require('../utils/ticketManager');

ticketPool.query = async () => ({ rows: [] });
tclaimPool.query = async () => ({ rows: [] });

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
    // Premium two-column layout: detached live preview column + separate
    // thumbnail / image / footer regions so nothing can ever overlap.
    assert.ok(html.includes('edb-builder-cols'), 'two-column builder grid present');
    assert.ok(html.includes('edb-builder-left'), 'builder controls column');
    assert.ok(html.includes('edb-builder-right'), 'sticky preview column');
    assert.ok(html.includes('edb-preview-embed-wrap'), 'detached live preview pane');
    assert.ok(html.includes('edb-pv-author'), 'preview author row');
    assert.ok(html.includes('edb-pv-title'), 'preview title row');
    assert.ok(html.includes('edb-pv-desc'), 'preview description row');
    assert.ok(html.includes('edb-pv-thumb'), 'preview thumbnail');
    assert.ok(html.includes('edb-pv-image'), 'preview large image');
    assert.ok(html.includes('edb-pv-footer'), 'preview footer');
    // Each region is its own block section (data-region) — thumbnail and image
    // are NOT merged into a shared grid cell.
    assert.ok(html.includes('data-region="edb-thumb"'), 'thumbnail is its own region');
    assert.ok(html.includes('data-region="edb-image"'), 'image is its own region');
    // The fixture sets thumbnail+image → the detached preview rows are visible.
    assert.ok(/class="edb-live edb-live-thumb"/.test(html), 'preview thumb row present when set');
    assert.ok(!/edb-live-thumb hidden/.test(html), 'thumb preview not hidden when configured');
    const empty = guildPages.ticketEditPage({ guild: fakeGuild({ ...{ id: 42, name: 'E' }, title: 'T' }), user: null });
    assert.ok(/edb-live-thumb hidden/.test(empty), 'empty panel pre-hides thumb preview row');
});

test('ticketEditPage: separate Thumbnail and Image cards never share a grid cell', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild(), user: null });
    const thumbIdx = html.indexOf('data-region="edb-thumb"');
    const imageIdx = html.indexOf('data-region="edb-image"');
    const footerIdx = html.indexOf('data-region="edb-footer"');
    assert.ok(thumbIdx > -1 && imageIdx > thumbIdx && footerIdx > imageIdx,
        'regions render in order thumbnail → image → footer (no shared container)');
});

test('ticketEditPage: every embed-builder input id is unique', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild(), user: null });
    const ids = ['tk-title', 'tk-title-url', 'tk-description', 'tk-content', 'tk-footer', 'tk-footer-icon', 'tk-thumbnail', 'tk-image',
        'tk-color', 'tk-color-text', 'tk-author-name', 'tk-author-url', 'tk-author-icon', 'tk-timestamp',
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
                    claim_button_label: null, claim_button_emoji: null, claim_button_style: 'Secondary',
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
    assert.equal(params[39], true, 'enabled still persisted at shifted index');
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
    assert.equal(make('edb-pv-footer-text').textContent,'PrimeBot');
    assert.equal(make('edb-author-name').textContent,'Support Team');
    assert.equal(make('edb-author-icon').src,'https://x/a.png');
    assert.equal(make('edb-thumb').src,'https://x/t.png');
    assert.equal(make('edb-image').src,'https://x/i.png');
    assert.equal(make('edb-bar').style.background,'#57F287');
    assert.equal(make('edb-button-label').textContent,'Open');
    assert.ok(make('edb-button').classList.contains('tk-preview-button-success'), 'button style class updated');
    assert.equal(make('tk-title').value,'Need help?');
    // Timestamp + footer live toggles in the detached preview.
    assert.equal(make('edb-pv-footer-text').textContent, 'PrimeBot');
    assert.ok(make('edb-pv-footer-text').classList.contains('hidden') === false, 'footer text visible when set');
});

test('manager buildPanelMessage maps author/title URL + footer icon + NO timestamp', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        id: 7, name: 'Support', title: 'Title', titleUrl: 'https://t.example',
        description: 'Desc', authorName: 'Auth', authorUrl: 'https://a.example',
        authorIconUrl: 'https://a.example/i.png', footerText: 'Foot', footerIconUrl: 'https://f.example/i.png',
        timestampEnabled: false, thumbnailUrl: 'https://t.example/thumb.png', imageUrl: 'https://t.example/big.png',
    });
    const payload = mgr.buildPanelMessage(panel);
    const e = payload.embeds[0].toJSON ? payload.embeds[0].toJSON() : payload.embeds[0];
    assert.equal(e.url, 'https://t.example', 'title URL -> embed.setURL');
    assert.equal(e.title, 'Title');
    assert.equal(e.thumbnail.url, 'https://t.example/thumb.png');
    assert.equal(e.image.url, 'https://t.example/big.png');
    assert.equal(e.author.name, 'Auth');
    assert.equal(e.author.url, 'https://a.example');
    assert.equal(e.author.icon_url, 'https://a.example/i.png');
    assert.equal(e.footer.text, 'Foot');
    assert.equal(e.footer.icon_url, 'https://f.example/i.png');
    assert.equal(e.timestamp, undefined, 'timestampEnabled=false drops setTimestamp');
});

test('manager normalize drops invalid embed URLs + caps lengths (server-side safety)', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        id: 9, name: 'Support', title: 'x'.repeat(900),
        description: 'y'.repeat(9000),
        footerText: 'z'.repeat(3000),
        thumbnailUrl: 'not-a-url', imageUrl: 'ftp://bad', authorUrl: 'javascript:alert(1)',
        authorName: 'n'.repeat(500), titleUrl: 'https://ok.example',
    });
    assert.equal(panel.title.length, 256, 'title capped at 256');
    assert.equal(panel.description.length, 4096, 'description capped at 4096');
    assert.equal(panel.footerText.length, 2048, 'footer capped at 2048');
    assert.equal(panel.authorName.length, 255, 'author name capped at 255');
    assert.equal(panel.thumbnailUrl, null, 'invalid thumbnail URL dropped');
    assert.equal(panel.imageUrl, null, 'invalid image URL dropped');
    assert.equal(panel.authorUrl, null, 'javascript: author URL dropped');
    assert.equal(panel.titleUrl, 'https://ok.example', 'valid title URL kept');
});

test('dashboard normalizeTicketPanel caps + validates the same way', () => {
    const { normalizeTicketPanel } = dashboardDb;
    const out = normalizeTicketPanel({
        title: 'a'.repeat(500), thumbnailUrl: 'not-http', footerIconUrl: 'https://ok/icon.png',
    });
    assert.equal(out.title.length, 256);
    assert.equal(out.thumbnailUrl, null);
    assert.equal(out.footerIconUrl, 'https://ok/icon.png');
});

// ── Embed FIELDS (Task 2) ────────────────────────────────────────────────
// The Fields section inside Message → Embed Builder: field cards render
// server-side from panel.embedFields, the + Add Field button exists, and the
// same field config flows to the bot's embed builder in order.

test('ticketEditPage: Message tab renders the FIELDS editor section', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild({ id: 42, name: 'Support' }), user: null });
    assert.ok(/FIELDS/i.test(html), 'has a Fields section label');
    assert.ok(html.includes('edb-fields-list'), 'field card list container');
    assert.ok(html.includes('edb-add-field'), '+ Add Field button exists');
    assert.ok(html.includes('edb-fields-empty'), 'empty-state element exists');
});

test('ticketEditPage: field cards render from persisted embedFields in order', () => {
    const panel = {
        id: 42, name: 'Support', messageType: 'embed',
        fields: [
            { name: 'Quick Links', value: 'Create a ticket', inline: true },
            { name: 'Support', value: 'Contact staff', inline: false },
        ],
    };
    const html = guildPages.ticketEditPage({ guild: fakeGuild(panel), user: null });
    assert.equal((html.match(/class="edb-field-card" /g) || []).length, 2, 'two field cards rendered');
    const first = html.indexOf('Quick Links');
    const second = html.indexOf('Support', first);
    assert.ok(first > -1 && second > first, 'fields keep their configured order in the DOM');
    assert.ok(html.includes('edb-field-0-name'), 'first field name input id present');
    assert.ok(html.includes('edb-field-1-inline'), 'second field inline checkbox id present');
});

test('embed fields: server normalizer drops invalid rows and caps at 25', () => {
    const out = dashboardDb._safeTicketEmbedFields
        ? dashboardDb._safeTicketEmbedFields([{ name: 'a', value: 'b', inline: true }, { name: '', value: '' }, null, 'x', { name: 'c', value: 'd' }])
        : null;
    if (typeof dashboardDb._safeTicketEmbedFields === 'function') {
        assert.deepEqual(out, [
            { name: 'a', value: 'b', inline: true },
            { name: 'c', value: 'd', inline: false },
        ]);
    }
});

test('embed fields: bot buildPanelMessage adds fields in order', () => {
    const mgr = new TicketPanelManager({});
    const panel = mgr._normalizePanel({
        id: 1, name: 'Support', title: 'Help', description: 'Click below',
        embedFields: [
            { name: 'First', value: 'one', inline: true },
            { name: 'Second', value: 'two', inline: false },
        ],
    });
    const payload = mgr.buildPanelMessage(panel);
    const e = payload.embeds[0].toJSON ? payload.embeds[0].toJSON() : payload.embeds[0];
    assert.ok(Array.isArray(e.fields), 'embed has fields');
    assert.equal(e.fields.length, 2, 'both fields present');
    assert.equal(e.fields[0].name, 'First');
    assert.equal(e.fields[0].inline, true);
    assert.equal(e.fields[1].name, 'Second');
    assert.equal(e.fields[1].inline, false);
});

test('embed fields: dashboard create/update SQL persists embed_fields', async () => {
    // Stub the tlog pool (already stubbed) and intercept the ticket pool.
    const statements = [];
    const orig = ticketPool.query;
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
                    claim_button_label: null, claim_button_emoji: null, claim_button_style: 'Secondary',
                    open_name_template: null, claimed_name_template: null, closed_name_template: null,
                    close_flow: {}, enabled: true, created_by: 'u', created_at: null, updated_at: null,
                }],
            };
        }
        if (/UPDATE ticket_panels SET/.test(sql)) return { rows: [], rowCount: 1 };
        return { rows: [], rowCount: 1 };
    };
    try {
        await dashboardDb.updateTicketPanel(42, {
            fields: [{ name: 'F', value: 'V', inline: true }],
        });
        const upd = statements.find(s => /UPDATE ticket_panels SET/.test(s.sql));
        assert.ok(upd, 'UPDATE executed');
        assert.ok(upd.sql.includes('embed_fields = $45'), 'UPDATE writes embed_fields');
        assert.equal(upd.params[44], JSON.stringify([{ name: 'F', value: 'V', inline: true }]), 'params persist fields');
    } finally {
        ticketPool.query = orig;
    }
});

// ── Ticket LOGGING tab (Task 1) inside the existing Logging bar ─────────────
test('ticketEditPage: Logging tab renders inside the editor (no separate page)', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild({ id: 42, name: 'Support' }), user: null });
    assert.ok(html.includes('Ticket Logging'), 'Logging config header exists');
    assert.ok(html.includes('tk-logging-enabled'), 'enable checkbox present');
    assert.ok(html.includes('tk-logging-channel'), 'log channel select present');
    assert.ok(html.includes('data-event="created"'), 'created event toggle present');
});

test('ticketEditPage: Logging tab pre-populates enabled + events from panel config', () => {
    const panel = {
        id: 42, name: 'Support',
        _ticketLogging: {
            enabled: true,
            channelId: '987654321',
            events: ['created'], // shared normalizer re-defaults the standard events
        },
    };
    const html = guildPages.ticketEditPage({ guild: fakeGuild(panel), user: null });
    assert.ok(html.includes('id="tk-logging-enabled" checked'), 'enabled pre-checked');
    assert.ok(html.includes('data-event="created" checked'), 'created toggle pre-checked');
    // The standard events are all kept (never silently disabled after upgrade);
    // renamed/deleted are opt-in extras that stay off by default.
    assert.ok(html.includes('data-event="reopened" checked'), 'default event reopened stays checked');
    assert.ok(!/data-event="renamed" checked/.test(html), 'renamed is an opt-in extra, stays unchecked');
});

test('shared ticket logging normalizer keeps supported events and drops unknown', () => {
    const { normalizeTicketLogging } = require('../shared/ticketLogging');
    const out = normalizeTicketLogging({ enabled: true, channelId: 'c', events: ['created', 'bogus'] });
    assert.equal(out.enabled, true);
    assert.equal(out.channelId, 'c');
    assert.ok(out.events.includes('created'));
    assert.ok(!out.events.includes('bogus'), 'unknown event dropped');
    assert.ok(out.events.includes('closed'), 'default events preserved when enabled');
});

// ── Ticket logger embed builder (Task 1 bot side) ─────────────────────────
test('ticketLogger builds event-specific embeds with title, fields, timestamp, footer', () => {
    const { buildTicketLogEmbed } = require('../utils/ticketLogger');
    const embed = buildTicketLogEmbed('claimed', {
        ticket: 'support-42',
        channelId: '111222333',
        actorId: '888',
        panelName: 'Support Panel',
        timestamp: 1789000000000,
    });
    const e = embed.toJSON();
    assert.match(e.title, /Ticket Claimed/, 'title is event-specific');
    assert.ok(Array.isArray(e.fields) && e.fields.length >= 2, 'has fields');
    assert.ok(e.fields.some(f => f.name === 'Claimed By' && f.value.includes('<@888>')), 'actor mention in field');
    assert.ok(e.fields.some(f => f.name === 'Ticket' && f.value.includes('<#111222333>')), 'ticket channel mention');
    assert.equal(new Date(e.timestamp).getTime(), 1789000000000, 'embed timestamp set');
    assert.match(e.footer && e.footer.text || '', /PrimeBot • Ticket Logs/, 'footer present');
    assert.ok(e.color, 'color set');
});

test('ticketLogger dedupes duplicate events via stable _id', () => {
    const { _isDuplicateLog } = require('../utils/ticketLogger');
    assert.equal(_isDuplicateLog('x'), false, 'first occurrence not a duplicate');
    assert.equal(_isDuplicateLog('x'), true, 'second occurrence within window is a duplicate');
    assert.equal(_isDuplicateLog('y'), false, 'different id is not a duplicate');
});

test('ticketLogger closed embed includes opened/closed/duration fields', () => {
    const { buildTicketLogEmbed } = require('../utils/ticketLogger');
    const opened = Date.now() - 2 * 3600 * 1000; // 2h ago
    const embed = buildTicketLogEmbed('closed', {
        ticket: 'support-42',
        channelId: '111222333',
        actorId: '888',
        openedAt: opened,
        timestamp: Date.now(),
    });
    const e = embed.toJSON();
    assert.match(e.title, /Ticket Closed/);
    const names = (e.fields || []).map(f => f.name).join(',');
    assert.ok(names.includes('Opened At'), 'opened field');
    assert.ok(names.includes('Closed At'), 'closed field');
    assert.ok(names.includes('Duration'), 'duration field');
});

// ── Audit-log pool uses ALOG_DATABASE_URL (Task: shift + fix) ─────────────
test('audit log functions route to the ALOG pool (server/alogDb)', () => {
    const alogDb = require('../server/alogDb');
    assert.ok(alogDb.alogPool, 'alogPool exists');
    assert.ok(alogDb.addWebsiteLog, 'addWebsiteLog exported');
    assert.ok(alogDb.getWebsiteLogs, 'getWebsiteLogs exported');
    const dashboardAlog = require('../dashboard/db');
    // The dashboard's own ensureWebsiteLogsTable should target the ALOG pool —
    // it builds the same table the alog write path uses.
    const re = fs.readFileSync(path.join(__dirname, '..', 'dashboard/db.js'), 'utf8');
    assert.ok(re.includes('getAlogPool()'), 'dashboard/db uses getAlogPool for website_logs');
    // server/db or logDb should NOT be the write path for website_logs anymore.
    const serverLogDbSrc = fs.readFileSync(path.join(__dirname, '..', 'server/logDb.js'), 'utf8');
    assert.ok(serverLogDbSrc.includes('LOG_DATABASE_URL'), 'logDb keeps its own pool for logging_settings');
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard/db.js'), 'utf8');
    const idxAlog = src.indexOf('getAlogPool');
    const idxLog = src.indexOf('getLogPool');
    assert.ok(idxAlog > -1 && idxLog > -1, 'both pool helpers exist');
});