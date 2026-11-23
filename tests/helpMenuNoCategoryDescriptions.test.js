const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const {
    CATALOG,
    hasBetaCommands,
    CATEGORY_ORDER,
    mainMenuEmbed,
    categoryEmbed,
    categorySelectRow,
    homeButtonRow,
    categoryIcon,
    CATEGORY_SEPARATOR,
    mainMenuText,
    categoryTitle,
    categoryText,
    buildHelpPayload,
    helpActionRow,
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

test('the help main menu is the stats line plus the category lines', () => {
    const menu = mainMenuEmbed('$', client, { user, kind: 'prefix' });
    const lines = menu.data.description.split('\n');
    assert.match(lines[0], /^\*\*Prefix\*\*: `\$`/, 'the stats block must come first');
    assert.match(lines[1], /^\*\*Commands\*\*: \d+$/);
    assert.match(lines[2], /^\*\*Servers\*\*: \d+$/);
    assert.equal(lines[3], '', 'a blank line separates the stats block from the categories');
    const betaLegendLines = hasBetaCommands() ? 2 : 0;
    assert.equal(lines.length, CATEGORY_ORDER.length + 4 + betaLegendLines);
    for (let i = 0; i < CATEGORY_ORDER.length; i++) {
        const key = CATEGORY_ORDER[i];
        assert.equal(lines[i + 4], `${categoryIcon(key)} ${CATEGORY_SEPARATOR} ${CATALOG[key].label}`);
    }
    assert.equal(menu.data.fields, undefined);
    assert.equal(menu.data.thumbnail, undefined);
    assert.equal(menu.data.footer, undefined);
    assert.equal(menu.data.image, undefined);
    assert.ok(!menu.data.description.includes('Basic bot'), 'category description leaked into the menu');
});

test('the help main menu has no coloured side stripe', () => {
    const menu = mainMenuEmbed('$', client, { user, kind: 'prefix' });
    assert.equal(menu.data.color, undefined);
});

test('the category detail lists command names, not a category description', () => {
    const general = categoryEmbed('general', '$', { iconURL: 'https://cdn.example/bot.png' });
    assert.equal(general.data.title, `${categoryIcon('general')} ${CATEGORY_SEPARATOR} General`);
    assert.equal(general.data.fields, undefined);
    assert.equal(general.data.footer, undefined);
    assert.ok(general.data.description.includes('`help`'));
    assert.ok(!general.data.description.includes('Basic bot'));
    assert.equal(general.data.color, undefined);
});

test('the Anti-Nuke category lists antinuke for the slash help surface', () => {
    const antinuke = categoryEmbed('antinuke', '/');
    assert.ok(antinuke.data.description.includes('`antinuke`'));
});

test('the category select has labels and emoji but no descriptions', () => {
    const options = categorySelectRow().toJSON().components[0].options;
    assert.equal(options.length, CATEGORY_ORDER.length);
    for (const option of options) {
        assert.match(option.label, /^–> /);
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

test('category help text is derived from the shared catalog (prefix + Sash)', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    assert.match(src, /helpCategoryLines\(/, 'the category help reply must use the shared catalog');
    assert.ok(!src.includes('• General - Basic'), 'the old hardcoded category list must be gone');
    assert.ok(!src.includes('• Administration - Advanced'), 'the old hardcoded category list must be gone');
    for (const key of ['information', 'birthdays', 'automation', 'antinuke']) {
        assert.ok(CATEGORY_ORDER.includes(key), `${key} must be a help category`);
    }
});

test('slash help uses the shared V2 builders and routes the select menu', () => {
    const helpSrc = fs.readFileSync(path.join(ROOT, 'commands', 'help.js'), 'utf8');
    assert.match(helpSrc, /buildHelpPayload\(/);
    assert.match(helpSrc, /mainMenuText\(\{/);
    assert.match(helpSrc, /categorySelectRow\(null, 'help_select'\)/);
    assert.match(helpSrc, /helpActionRow\(\)/);
    assert.ok(!/embeds:/.test(helpSrc), 'slash help still sends a legacy embed field');

    const interactionSrc = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    assert.match(interactionSrc, /interaction\.customId === 'help_select'/);
    assert.match(interactionSrc, /buildHelpPayload\(/);
});

test('the help payload is Components V2 with no legacy embeds or content', () => {
    const payload = buildHelpPayload({
        text: mainMenuText(),
        rows: [categorySelectRow(null, 'help_select'), helpActionRow()],
    });
    assert.deepEqual(Object.keys(payload).sort(), ['components', 'flags']);
    assert.equal(payload.embeds, undefined);
    assert.equal(payload.content, undefined);
    assert.ok(payload.flags & require('discord.js').MessageFlags.IsComponentsV2);
    assert.equal(payload.components[0].type, 17);

    const json = JSON.stringify(payload);
    assert.ok(!json.includes('"embeds"'), 'payload must not contain an embeds key');
});

test('slash help emits V2 payloads for the main menu and every category', async () => {
    const helpCommand = require('../commands/help');
    const captured = [];
    const interaction = {
        editReply: async payload => { captured.push(payload); },
        fetchReply: async () => null,
    };

    await helpCommand.showMainHelp(interaction);
    await helpCommand.showCategoryHelp(interaction, 'general');

    assert.equal(captured.length, 2);
    for (const payload of captured) {
        assert.deepEqual(Object.keys(payload).sort(), ['components', 'flags']);
        assert.equal(payload.embeds, undefined);
        assert.equal(payload.content, undefined);
        assert.ok(payload.flags & require('discord.js').MessageFlags.IsComponentsV2);
        assert.ok(!JSON.stringify(payload).includes('"embeds"'));
    }
    assert.equal(captured[1].components[0].components[0].content, `${categoryIcon('general')} –> General`);
});

test('every help update path uses V2 payloads, never legacy embeds', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    const start = src.indexOf('async function showMainHelpUpdate');
    const end = src.indexOf('function parseAppealCustomId');
    const helpRegion = src.slice(start, end);
    assert.ok(start >= 0 && end > start);
    assert.match(helpRegion, /buildHelpPayload\(/);
    assert.ok(!/embeds\s*:/.test(helpRegion), 'an interaction help path still sends legacy embeds');

    const messageSrc = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');
    const blockStart = messageSrc.indexOf('case "help":');
    const blockEnd = messageSrc.indexOf('case "giveaway":');
    const helpBlock = messageSrc.slice(blockStart, blockEnd);
    assert.ok(blockStart >= 0 && blockEnd > blockStart);
    assert.match(helpBlock, /buildHelpPayload\(/);
    assert.ok(!/embeds\s*:/.test(helpBlock), 'the prefix help path still sends legacy embeds');
});

test('every help category builds a valid V2 payload with the exact format', () => {
    for (const key of CATEGORY_ORDER) {
        const payload = buildHelpPayload({
            title: categoryTitle(key),
            text: categoryText(key),
            rows: [categorySelectRow(key, 'help_select'), helpActionRow()],
        });
        assert.deepEqual(Object.keys(payload).sort(), ['components', 'flags'], `${key} has legacy fields`);
        assert.ok(payload.flags & require('discord.js').MessageFlags.IsComponentsV2);
        assert.equal(payload.components[0].type, 17);
        const title = payload.components[0].components[0].content;
        assert.ok(title.includes('–>'), `${key} title is missing the separator`);
        assert.ok(title.endsWith(CATALOG[key].label), `${key} title is missing the category name`);
        const select = payload.components[0].components.find(c => c.type === 1);
        assert.ok(select, `${key} is missing its select row`);
    }
});

test('category titles and lines use the exact –> separator', () => {
    assert.equal(CATEGORY_SEPARATOR, '–>');
    assert.equal(categoryTitle('general'), `${categoryIcon('general')} –> General`);
    const menuLines = mainMenuText().split('\n');
    const firstCategory = menuLines.indexOf('') + 1;
    assert.equal(menuLines[firstCategory], `${categoryIcon('general')} –> General`);
    assert.match(categoryText('general'), /`help`/);
});
