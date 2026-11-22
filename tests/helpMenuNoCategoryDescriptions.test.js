const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const {
    CATALOG,
    CATEGORY_ORDER,
    mainMenuEmbed,
    categoryEmbed,
    categorySelectRow,
    homeButtonRow,
} = require('../utils/prefixHelp');

const user = {
    id: '123456789012345678',
    displayAvatarURL: () => 'https://cdn.example/user.png',
};
const client = {
    commands: new Map([['help', {}]]),
    guilds: { cache: new Map([['1', {}]]) },
    user: { displayAvatarURL: () => 'https://cdn.example/bot.png' },
};

test('prefix and sash category catalogs carry no category descriptions', () => {
    for (const key of CATEGORY_ORDER) {
        const cat = CATALOG[key];
        assert.ok(cat, `missing category ${key}`);
        assert.equal(cat.description, undefined, `${key} must not carry a category description`);
        assert.equal(cat.selectDesc, undefined, `${key} must not carry a select-menu description`);
    }
});

test('the help main menu follows the Linix layout and has no category blurbs', () => {
    const menu = mainMenuEmbed('$', client, { user, kind: 'prefix' });
    assert.match(menu.data.description, /Prefix For This Server/);
    assert.match(menu.data.description, /Total Commands/);
    assert.equal(menu.data.fields.length, 1);
    assert.match(menu.data.fields[0].name, /My Commands/);
    for (const key of CATEGORY_ORDER) {
        assert.ok(menu.data.fields[0].value.includes(CATALOG[key].label), `missing ${key} in My Commands`);
    }
    assert.ok(!menu.data.fields[0].value.includes('Basic bot'), 'category description leaked into the menu');
    assert.equal(menu.data.thumbnail.url, 'https://cdn.example/user.png');
    assert.match(menu.data.footer.text, /^Loved by 1 Servers$/);
});

test('the help main menu has no coloured side stripe', () => {
    const menu = mainMenuEmbed('$', client, { user, kind: 'prefix' });
    assert.equal(menu.data.color, undefined);
});

test('the category detail lists command names, not a category description', () => {
    const general = categoryEmbed('general', '$', { iconURL: 'https://cdn.example/bot.png' });
    assert.match(general.data.title, /General Commands$/);
    assert.equal(general.data.fields, undefined);
    assert.ok(general.data.description.includes('`help`'));
    assert.ok(!general.data.description.includes('Basic bot'));
    assert.equal(general.data.footer.text, 'Total 8 commands.');
    assert.equal(general.data.color, undefined);
});

test('the admin category still lists antinuke for the slash help surface', () => {
    const admin = categoryEmbed('admin', '/');
    assert.ok(admin.data.description.includes('`antinuke`'));
});

test('the category select has labels and emoji but no descriptions', () => {
    const options = categorySelectRow().toJSON().components[0].options;
    assert.equal(options.length, CATEGORY_ORDER.length);
    for (const option of options) {
        assert.ok(option.label);
        assert.ok(option.emoji);
        assert.equal(option.description, undefined);
    }
});

test('the home button is emoji-only and lives in the same component row set', () => {
    const row = homeButtonRow('help_back').toJSON();
    assert.equal(row.components.length, 1);
    assert.equal(row.components[0].custom_id, 'help_back');
    assert.ok(row.components[0].emoji);
    assert.equal(row.components[0].label, undefined);
});

test('the Sash menu builder and drill-down do not render category descriptions', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    const builder = src.slice(src.indexOf('function buildSashCategories'), src.indexOf('async function showSashHelp'));
    assert.ok(!/desc:\s*\(cat\.description/.test(builder), 'Sash builder still copies a category description');
    assert.ok(!/\.setDescription\(cat\.desc\)/.test(src), 'Sash drill-down still sets a category description');
});

test('slash help uses the shared Linix builders and routes the select menu', () => {
    const helpSrc = fs.readFileSync(path.join(ROOT, 'commands', 'help.js'), 'utf8');
    assert.match(helpSrc, /mainMenuEmbed\('\/'/);
    assert.match(helpSrc, /categorySelectRow\(null, 'help_select'\)/);
    assert.match(helpSrc, /homeButtonRow\('help_back'\)/);

    const interactionSrc = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    assert.match(interactionSrc, /interaction\.customId === 'help_select'/);
});
