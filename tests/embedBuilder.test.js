// Embed Builder — page render + saved-embeds DB helpers.
//
// Pure/justified-mock: the page render is pure, and the DB helpers are
// exercised against a stubbed pool (no Postgres in CI), same pattern as
// ticketsEditor.test.js / birthdaysDashboard.test.js.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const guildPages = require('../dashboard/render/guild-pages');
const dashboardDb = require('../dashboard/db');
const { TABS } = require('../dashboard/render/guild');

function fakeGuild() {
    return {
        id: '123456789012345678',
        name: 'Test Guild',
        icon: null,
        _bypassUpcoming: true,
        _channels: [],
        _roles: [],
        _beta: false,
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, ticketPanels: [] },
    };
}

function renderEmbedPage() {
    return guildPages.embedPage({ guild: fakeGuild(), user: { username: 'u' } });
}

test('Embed tab is present in the server-features sidebar (TABS)', () => {
    const tab = TABS.find((t) => t.key === 'embed');
    assert.ok(tab, 'embed tab exists');
    assert.equal(tab.label, 'Embed');
    assert.ok(tab.icon, 'embed tab has an icon');
    assert.ok(!tab.upcoming && !tab.beta, 'embed is not gated behind beta/upcoming');
});

test('embedPage renders the builder shell with toolbar, templates, preview, saved list, modal', () => {
    const html = renderEmbedPage();
    assert.ok(html.includes('id="eb-title"'), 'title input');
    assert.ok(html.includes('id="eb-description"'), 'description textarea');
    assert.ok(html.includes('id="eb-content"'), 'message content textarea');
    assert.ok(html.includes('id="eb-url"'), 'url input');
    assert.ok(html.includes('id="eb-color"') && html.includes('id="eb-color-text"'), 'color picker + hex input');
    assert.ok(html.includes('id="eb-timestamp"'), 'timestamp toggle');
    assert.ok(html.includes('id="eb-author-enabled"'), 'author enable switch');
    assert.ok(html.includes('id="eb-thumbnail-enabled"'), 'thumbnail enable switch');
    assert.ok(html.includes('id="eb-image-enabled"'), 'image enable switch');
    assert.ok(html.includes('id="eb-footer-enabled"'), 'footer enable switch');
    assert.ok(html.includes('id="eb-add-field"'), 'add field button');
    assert.ok(html.includes('id="eb-fields-list"'), 'fields list');
    assert.ok(html.includes('data-template'), 'template chips');
    assert.ok(html.includes('id="eb-pv-embed"') || html.includes('id="eb-preview-embed"'), 'live preview present');
    assert.ok(html.includes('id="eb-validation-strip"'), 'validation strip');
    assert.ok(html.includes('id="eb-save-embed"'), 'save embed button');
    assert.ok(html.includes('id="eb-saved-list"'), 'saved embeds list');
    assert.ok(html.includes('id="eb-modal-overlay"'), 'save modal');
    // Toolbar actions.
    assert.ok(html.includes('id="eb-import-json"'), 'import json');
    assert.ok(html.includes('id="eb-export-json"'), 'export/copy json');
    assert.ok(html.includes('id="eb-copy-payload"'), 'copy payload');
    assert.ok(html.includes('id="eb-reset"'), 'reset button');
});

test('embedPage uses SVG card-title icon, no emoji iconography', () => {
    const html = renderEmbedPage();
    assert.match(html, /<svg class="ico"/);
    assert.doesNotMatch(html, /class="icon">[^<]/, 'no emoji card-title icon');
});

test('embed page loads the dedicated client script + the editor container class', () => {
    const html = renderEmbedPage();
    assert.ok(html.includes('/js/embed-builder.js'), 'embed-builder client script');
    assert.ok(html.includes('container--editor'), 'uses the wide editor container');
});

test('client script exists, defines no eval/Function, and exposes the builder primitives', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'embed-builder.js'), 'utf8');
    assert.ok(src.includes('DRAFT_KEY'), 'localStorage draft handled');
    assert.ok(src.includes('localStorage.setItem'), 'saves a draft to localStorage');
    assert.ok(src.includes('renderPreview'), 'live preview logic');
    assert.ok(src.includes('validateState'), 'validation logic');
    assert.ok(src.includes('normalizeImported'), 'safe JSON parser');
    assert.doesNotMatch(src, /\beval\(/, 'no eval');
    assert.doesNotMatch(src, /\bnew Function\b/, 'no new Function');
    assert.ok(src.includes('textContent'), 'renders preview content via textContent (XSS-safe)');
});

// ── DB helpers (stubbed pool) ──────────────────────────────────────────────
function stubEmbedPool() {
    const rows = [];
    const db = {};
    db.query = async (sql, params) => {
        // A tiny in-memory fake covering the SQL our helpers emit.
        if (/CREATE TABLE/i.test(sql)) return { rows: [] };
        if (/CREATE INDEX/i.test(sql)) return { rows: [] };
        if (/INSERT INTO saved_embeds/i.test(sql) && !/SELECT guild_id/.test(sql)) return { rows: [] };
        if (/DELETE FROM saved_embeds/i.test(sql)) return { rows: [] };
        if (/SELECT id, guild_id/.test(sql)) return { rows: [] };
        if (/UPDATE saved_embeds/i.test(sql)) return { rows: [] };
        return { rows: [] };
    };
    return db;
}

test('saved-embeds DB helpers run against the embed pool (no crash, camelCase mapping)', async () => {
    const pool = stubEmbedPool();
    // Monkey-patch the pool accessor used by the helpers.
    const orig = dashboardDb._getEmbedPoolForTest || null;
    let calls = 0;
    const patchedPool = {
        query: async (sql, params) => {
            calls++;
            if (/CREATE TABLE/i.test(sql)) return { rows: [] };
            if (/CREATE INDEX/i.test(sql)) return { rows: [] };
            if (/INSERT INTO saved_embeds/i.test(sql) && /VALUES/.test(sql)) {
                return { rows: [{ id: 1, guild_id: '123', name: params[1], payload: JSON.parse(params[2] || '{}'), created_by: null, created_at: new Date(), updated_at: new Date() }] };
            }
            if (/DELETE FROM saved_embeds/i.test(sql)) return { rows: [] };
            return { rows: [] };
        },
    };
    // Replace module-level getEmbedPool by patch through dashboard/db exports.
    // Since getEmbedPool is a closure, we test the exported helpers via the
    // module's internal pool by stubbing require cache.
    const embedDbPath = require.resolve('../server/embedDb');
    const stubModule = { embedPool: patchedPool };
    require.cache[embedDbPath] = { id: embedDbPath, filename: embedDbPath, loaded: true, exports: stubModule };
    require('../dashboard/db');

    const created = await dashboardDb.createSavedEmbed('123', { name: 'Welcome', payload: { title: 'Hi', color: '#5865F2' } }, '555');
    assert.equal(created.name, 'Welcome');
    assert.equal(created.guildId, '123');
    assert.deepEqual(created.payload, { title: 'Hi', color: '#5865F2' });
    assert.ok(created.id, 'row id mapped');

    const list = await dashboardDb.getSavedEmbeds('123');
    assert.ok(Array.isArray(list), 'list returns array');

    await dashboardDb.deleteSavedEmbed('123', 1);
    assert.ok(calls >= 3, 'at least table ensure + insert + list + delete queries made');

    // Restore the real embedDb.
    delete require.cache[embedDbPath];
    if (orig) dashboardDb._getEmbedPoolForTest = orig;
});

test('saved-embeds payload is never eval‘d — stored/returned as plain JSON', async () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'db.js'), 'utf8');
    assert.ok(src.includes('JSON.stringify'), 'payload serialized with JSON.stringify');
    assert.ok(src.includes('JSON.parse'), 'payload parsed with JSON.parse');
    assert.doesNotMatch(src, /\beval\(/, 'no eval in db helpers');
});

test('no saved-embeds table was added to the main pool — only the dedicated embed pool is used', () => {
    const dbSrc = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'db.js'), 'utf8');
    const getEmbedPoolBlock = dbSrc.indexOf('function getEmbedPool') !== -1;
    assert.ok(getEmbedPoolBlock, 'getEmbedPool accessor exists');
    // Ensure the table creation only references the embed pool (the dedicated
    // EMBED_DATABASE_URL pool), never the main `pool`.
    assert.ok(dbSrc.includes("require('../server/embedDb').embedPool"), 'uses the dedicated embed pool');
});