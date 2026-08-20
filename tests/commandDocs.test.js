// Command documentation: extractCommandGroups parses the real prefix-command
// switch out of events/messageCreate.js; buildCommandDocs + docsPage render a
// searchable command-documentation layout. Pure — no DB, no network.
const { test } = require('node:test');
const assert = require('node:assert');

const commandDocs = require('../dashboard/commandDocs');
const pages = require('../dashboard/render/pages');

test('extractCommandGroups finds the prefix commands from messageCreate.js', () => {
    const primaries = commandDocs.extractCommandGroups().map((g) => g.primary);
    for (const expected of ['help', 'purge', 'autoresponder', 'poll', 'lgiveway', 'beta', 'np', 'level-enable']) {
        assert.ok(primaries.includes(expected), `expected ${expected} in extracted commands`);
    }
});

test('developer/diagnostic commands are excluded', () => {
    const all = commandDocs.extractCommandGroups().flatMap((g) => g.aliases);
    for (const excluded of ['tokentest', 'ses', 'sync', 'betaserver']) {
        assert.ok(!all.includes(excluded), `${excluded} should be excluded`);
    }
});

test('aliases fall through to their primary and are not doubled up', () => {
    const all = commandDocs.extractCommandGroups().flatMap((g) => g.aliases);
    const counts = all.reduce((acc, n) => ((acc[n] = (acc[n] || 0) + 1), acc), {});
    for (const [name, count] of Object.entries(counts)) {
        assert.strictEqual(count, 1, `${name} appears ${count} times`);
    }
    // "move" appears in two switch groups (tictactoe + moderation); only the first must win.
    assert.strictEqual(counts.move, 1);
});

test('buildCommandDocs attaches metadata and categories', () => {
    const { categories, commands } = commandDocs.buildCommandDocs();
    assert.ok(categories.length >= 5);
    assert.ok(commands.length >= 50);
    const purge = commands.find((c) => c.name === 'purge');
    assert.strictEqual(purge.category, 'Moderation');
    assert.ok(purge.description.length > 10);
    // every command's icon exists in the icon catalog
    const { ICONS } = require('../dashboard/public/js/icons');
    for (const cmd of commands) assert.ok(ICONS[cmd.icon], `missing icon ${cmd.icon} for ${cmd.name}`);
});

test('docs page renders the command-documentation layout with a search box', () => {
    const html = pages.docsPage({});
    assert.match(html, /id="docs-search"/);
    assert.match(html, /class="doc-cmd"/);
    assert.match(html, /<svg class="ico"/);
    assert.match(html, /\/js\/docs\.js/);
    const { commands } = commandDocs.buildCommandDocs();
    const cardCount = (html.match(/<article class="doc-cmd"/g) || []).length;
    assert.strictEqual(cardCount, commands.length);
    // excluded developer commands must not appear
    for (const excluded of ['tokentest', 'ses', 'betaserver']) {
        assert.ok(!html.includes(`id="cmd-${excluded}"`), `docs page leaked ${excluded}`);
    }
});
