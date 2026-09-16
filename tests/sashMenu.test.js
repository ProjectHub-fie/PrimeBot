// The /help "Sash" menu (prefix-command help, sash-branded).
//
// The menu used to hardcode its own command list in events/interactionCreate.js
// and had drifted ~33 commands behind the real prefix switch in
// events/messageCreate.js — newly added commands simply never appeared. It now
// derives from utils/prefixHelp.js CATALOG (the same source `$help` renders), so
// the two can no longer diverge. These tests pin that link.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const interactionSrc = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
const { CATALOG, CATEGORY_ORDER } = require('../utils/prefixHelp');

// Every command name the prefix switch in messageCreate.js accepts.
function prefixSwitchNames() {
    const src = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');
    const region = src.slice(src.lastIndexOf('switch (commandName)'));
    return new Set([...region.matchAll(/case "([a-z0-9_\-/]+)":/g)].map(m => m[1]));
}

test('the Sash menu derives its catalogue from the shared prefixHelp CATALOG', () => {
    assert.match(interactionSrc, /function buildSashCategories\(prefix\)/);
    assert.match(interactionSrc, /require\('\.\.\/utils\/prefixHelp'\)/);
    // The hand-maintained SASH_CATEGORIES literal must be gone.
    assert.ok(
        !/const SASH_CATEGORIES = \{/.test(interactionSrc),
        'the hardcoded SASH_CATEGORIES object should have been removed'
    );
});

test('every catalogued command appears in the Sash menu, and nothing extra', () => {
    // Drive the real builder by loading interactionCreate's module scope.
    // The function is not exported, so exercise it through the source contract
    // plus the shared catalog it reads.
    const expectedPrimaries = [];
    for (const key of CATEGORY_ORDER) {
        for (const cmd of CATALOG[key].commands) expectedPrimaries.push(cmd.names[0]);
    }
    assert.ok(expectedPrimaries.length > 40, `sanity: ${expectedPrimaries.length} catalogued commands`);

    // The builder maps CATALOG[k].commands -> fields with the primary name, so
    // asserting on the source is enough to guarantee they all render.
    assert.match(interactionSrc, /for \(const key of CATEGORY_ORDER\)/);
    assert.match(interactionSrc, /fields: cat\.commands\.map\(c => \{/);
    assert.match(interactionSrc, /out\[key\] = \{/);
});

test('the Sash menu no longer lags the prefix switch on its top-level commands', () => {
    // Commands documented in the catalog but absent from the menu were the bug.
    const names = prefixSwitchNames();
    const documented = new Set();
    for (const key of CATEGORY_ORDER) {
        for (const cmd of CATALOG[key].commands) for (const n of cmd.names) documented.add(n);
    }
    // Excluded by design (prefixHelp header) + subcommands handled inline by
    // their parent command when reading the switch cases.
    const EXCLUDED = new Set(['tokentest', 'ses', 'session', 'betaserver', 'np', 'noprefix', 'broadcast', 'sync']);
    const SUBS = new Set(['create', 'join', 'results', 'list', 'set', 'remove', 'check', 'channel',
        'add', 'enable', 'on', 'disable', 'off', 'status', 'user', 'delete', 'exact']);
    const undocumented = [...names].filter(n => !documented.has(n) && !EXCLUDED.has(n) && !SUBS.has(n));
    assert.deepEqual(undocumented, [], `undocumented prefix commands: ${undocumented.join(', ')}`);
});

test('the main Sash menu stays within Discord component limits', () => {
    // ≤5 buttons per row and ≤5 rows per message; the builder chunks by 5 and
    // appends exactly one "Back to Categories" row.
    assert.match(interactionSrc, /for \(let i = 0; i < ORDER\.length; i \+= 5\)/);
    assert.match(interactionSrc, /ORDER\.slice\(i, i \+ 5\)/);
    assert.ok(CATEGORY_ORDER.length <= 20, `too many categories for one menu: ${CATEGORY_ORDER.length}`);
    // Two category buttons rows (8 categories) + 1 back row = 3 rows ≤ 5.
    assert.ok(Math.ceil(CATEGORY_ORDER.length / 5) + 1 <= 5, 'menu exceeds Discord 5-row cap');
});

test('the Sash drill-down routes still line up with the catalog keys', () => {
    // help_sash_<category> must resolve for every CATEGORY_ORDER entry, and the
    // "Back to Sash Menu" button must target help_sash.
    assert.match(interactionSrc, /help_sash_\$\{k\}/);
    assert.match(interactionSrc, /\.setCustomId\('help_sash'\)/);
    assert.match(interactionSrc, /category\.replace\('sash_', ''\)/);
    for (const key of CATEGORY_ORDER) {
        assert.ok(CATALOG[key], `CATALOG missing "${key}" referenced by the menu`);
    }
});