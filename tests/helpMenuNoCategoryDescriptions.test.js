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
} = require('../utils/prefixHelp');

test('prefix and sash category catalogs carry no category descriptions', () => {
    for (const key of CATEGORY_ORDER) {
        const cat = CATALOG[key];
        assert.ok(cat, `missing category ${key}`);
        assert.equal(cat.description, undefined, `${key} must not carry a category description`);
        assert.equal(cat.selectDesc, undefined, `${key} must not carry a select-menu description`);
    }
});

test('the prefix help main menu shows usage + command count, never a description', () => {
    const menu = mainMenuEmbed('$', null);
    assert.equal(menu.data.fields.length, CATEGORY_ORDER.length);
    for (const field of menu.data.fields) {
        assert.match(field.value, /^`\$help [a-z]+`\n\d+ commands$/, `unexpected category value: ${field.value}`);
        assert.ok(!field.value.includes('Basic bot'), 'category description leaked into the prefix menu');
    }
});

test('the prefix category detail has no category description line', () => {
    const general = categoryEmbed('general', '$');
    assert.equal(general.data.description, undefined);
    assert.ok(general.data.title);
    assert.ok(general.data.fields.some(f => f.name.startsWith('$help')));
});

test('the prefix category select has labels and emoji but no descriptions', () => {
    const options = categorySelectRow().toJSON().components[0].options;
    assert.equal(options.length, CATEGORY_ORDER.length);
    for (const option of options) {
        assert.ok(option.label);
        assert.ok(option.emoji);
        assert.equal(option.description, undefined);
    }
});

test('the Sash menu builder and drill-down do not render category descriptions', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    const builder = src.slice(src.indexOf('function buildSashCategories'), src.indexOf('async function showSashHelp'));
    assert.ok(!/desc:\s*\(cat\.description/.test(builder), 'Sash builder still copies a category description');
    assert.ok(!/\.setDescription\(cat\.desc\)/.test(src), 'Sash drill-down still sets a category description');
});
