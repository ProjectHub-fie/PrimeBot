// Regression tests for the ticket-editor fixes:
//  1. The dashboard's Discord payload builder (used by Send / Update) must
//     include the embed AUTHOR (name/url/icon), FOOTER icon, title URL, and
//     respect the timestamp toggle — previously author + footer icon were
//     silently dropped, so the Discord embed never showed them.
//  2. "Panel name" must not be conflated with the embed title in the editor UI.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SERVER = path.join(__dirname, '..', 'dashboard', 'server.js');
const GUILD_PAGES = path.join(__dirname, '..', 'dashboard', 'render', 'guild-pages.js');

function loadPayloadFn() {
    const src = fs.readFileSync(SERVER, 'utf8');
    const match = src.match(/function ticketPanelMessagePayload[\s\S]*?\n\}/);
    assert.ok(match, 'ticketPanelMessagePayload exists in dashboard/server.js');
    const sandbox = {};
    vm.createContext(sandbox);
    vm.runInContext(match[0], sandbox);
    assert.equal(typeof sandbox.ticketPanelMessagePayload, 'function', 'function evaluable');
    return sandbox.ticketPanelMessagePayload;
}

const basePanel = (extra = {}) => ({
    id: 7,
    title: 'My Title',
    titleUrl: 'https://ex.com/title',
    color: '#5865F2',
    description: 'Support desk',
    authorName: 'PrimeBot',
    authorUrl: 'https://ex.com/author',
    authorIconUrl: 'https://ex.com/icon.png',
    footerText: 'PrimeBot Tickets',
    footerIconUrl: 'https://ex.com/footer.png',
    thumbnailUrl: null,
    imageUrl: null,
    timestamp: true,
    messageType: 'embed',
    buttonLabel: 'Open Ticket',
    buttonStyle: 'Primary',
    components: [],
    ...extra,
});

test('ticketPanelMessagePayload embeds author name/url/icon', () => {
    const embed = loadPayloadFn()(basePanel()).embeds[0];
    assert.ok(embed.author, 'author present');
    assert.equal(embed.author.name, 'PrimeBot');
    assert.equal(embed.author.url, 'https://ex.com/author');
    assert.equal(embed.author.icon_url, 'https://ex.com/icon.png');
});

test('ticketPanelMessagePayload embeds footer icon + title url', () => {
    const embed = loadPayloadFn()(basePanel()).embeds[0];
    assert.ok(embed.footer, 'footer present');
    assert.equal(embed.footer.text, 'PrimeBot Tickets');
    assert.equal(embed.footer.icon_url, 'https://ex.com/footer.png');
    assert.equal(embed.url, 'https://ex.com/title', 'title url becomes embed url');
});

test('ticketPanelMessagePayload respects timestamp toggle', () => {
    const on = loadPayloadFn()(basePanel({ timestamp: true })).embeds[0];
    assert.equal(typeof on.timestamp, 'string', 'timestamp present when enabled');
    const off = loadPayloadFn()(basePanel({ timestamp: false })).embeds[0];
    assert.equal(off.timestamp, undefined, 'timestamp omitted when disabled');
});

test('ticketPanelMessagePayload omits author when not configured', () => {
    const embed = loadPayloadFn()(basePanel({ authorName: null, authorUrl: null, authorIconUrl: null })).embeds[0];
    assert.equal(embed.author, undefined, 'no author block');
});

test('General tab: panel name hint no longer claims it is the ticket title', () => {
    const guildPagesSrc = fs.readFileSync(GUILD_PAGES, 'utf8');
    assert.ok(
        guildPagesSrc.includes('Identifies this panel in the dashboard list'),
        'panel-name hint explains it identifies the panel list'
    );
    assert.ok(
        guildPagesSrc.includes('panel name and embed title are independent'),
        'hint explicitly separates panel name from embed title'
    );
    assert.ok(
        !guildPagesSrc.includes('Shown as the ticket title'),
        'hint no longer says panel name is shown as the ticket title'
    );
});