// The help menu shows one summary line above the categories (and on every
// category page): prefix, command totals (with aliases) and the server count.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const help = require('../utils/prefixHelp');

const ROOT = path.join(__dirname, '..');

test('commandStats counts canonical commands and every alias', () => {
    let commands = 0;
    let withAliases = 0;
    for (const key of help.CATEGORY_ORDER) {
        for (const cmd of help.CATALOG[key].commands) {
            commands += 1;
            withAliases += cmd.names.length;
        }
    }
    const stats = help.commandStats();
    assert.equal(stats.commands, commands);
    assert.equal(stats.withAliases, withAliases);
    assert.ok(stats.withAliases >= stats.commands, 'aliases can only add names');
    assert.equal(stats.categories, help.CATEGORY_ORDER.length);
});

test('the stats line shows prefix, total commands and servers on separate lines', () => {
    const stats = help.commandStats();
    const lines = help.helpStatsLine({ prefix: '!', servers: 51 }).split('\n');
    assert.deepEqual(lines, [
        '**Prefix**: `!`',
        `**Commands**: ${stats.withAliases}`,
        '**Servers**: 51',
    ]);
    assert.ok(!lines.join('\n').includes('with aliases'), 'no alias wording in the menu');
});

test('the server count comes from the client guild cache', () => {
    const client = { guilds: { cache: new Map([['1', {}], ['2', {}], ['3', {}]]) } };
    const line = help.helpStatsLine({ prefix: '$', client });
    assert.ok(line.includes('**Servers**: 3'));
});

test('servers is omitted when no client or count is available', () => {
    const line = help.helpStatsLine({ prefix: '$' });
    assert.ok(!line.includes('**Servers**'), 'no fake server count');
    assert.ok(line.includes('**Commands**:'));
});

test('the main menu and every category page start with the stats line', () => {
    const options = { prefix: '$', servers: 7 };
    const expected = help.helpStatsLine(options).split('\n');
    const menu = help.mainMenuText(options).split('\n');
    assert.deepEqual(menu.slice(0, expected.length), expected);
    assert.equal(menu[expected.length], '', 'blank line before the categories');

    for (const key of help.CATEGORY_ORDER) {
        const lines = help.categoryText(key, options).split('\n');
        assert.deepEqual(lines.slice(0, expected.length), expected, `${key} is missing the stats block`);
        assert.equal(lines[expected.length], '', `${key} needs a blank line before the command list`);
    }
});

test('every help surface passes the prefix and client into the builders', () => {
    const slashHelp = fs.readFileSync(path.join(ROOT, 'commands', 'help.js'), 'utf8');
    assert.match(slashHelp, /mainMenuText\(\{ prefix: '\/', client: interaction\.client \}\)/);
    assert.match(slashHelp, /categoryText\(category, \{ prefix: '\/', client: interaction\.client \}\)/);

    const categories = fs.readFileSync(path.join(ROOT, 'commands', 'categories.js'), 'utf8');
    assert.match(categories, /mainMenuText\(\{ prefix: '\/', client: interaction\.client \}\)/);

    const prefixHelp = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');
    assert.match(prefixHelp, /mainMenuText\(\{ prefix, client: message\.client \}\)/);

    const interactions = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    assert.match(interactions, /mainMenuText\(\{ prefix: config\.prefix, client: interaction\.client \}\)/);
    assert.match(interactions, /categoryText\(category, \{ prefix, client: interaction\.client \}\)/);
    assert.match(interactions, /helpCategoryLines\(interaction\.client\)/);
});

test('the stats line survives the V2 payload builder', () => {
    const payload = help.buildHelpPayload({
        text: help.mainMenuText({ prefix: '$', servers: 12 }),
        rows: [help.categorySelectRow(null, 'help_select')],
    });
    assert.deepEqual(Object.keys(payload).sort(), ['components', 'flags']);
    const text = payload.components[0].components[0].content;
    assert.ok(text.startsWith('**Prefix**: `$`'));
    assert.ok(text.includes('**Commands**: '));
    assert.ok(text.includes('**Servers**: 12'));
});
