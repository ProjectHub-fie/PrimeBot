// $stats reports the same command total the help menu advertises (catalog
// entries + aliases) instead of only PrimeBot's slash-command collection, which
// made the two surfaces disagree.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const help = require('../utils/prefixHelp');

function runStats() {
    global.botActive = true;
    const mcPath = require.resolve('../events/messageCreate');
    delete require.cache[mcPath];
    const mc = require(mcPath);

    const replies = [];
    const cache = new Map([
        ['1', { id: '1', memberCount: 10 }],
        ['2', { id: '2', memberCount: 20 }],
    ]);
    cache.reduce = (fn, initial) => {
        let acc = initial;
        for (const value of cache.values()) acc = fn(acc, value);
        return acc;
    };

    const message = {
        content: '$stats',
        guild: { id: 'g1' },
        channel: { id: 'c1' },
        member: { permissions: { has: () => true } },
        author: { id: 'u1', tag: 'u#0001', bot: false },
        mentions: { has: () => false, channels: { first: () => null } },
        reply: async (payload) => { replies.push(payload); return { delete: async () => {} }; },
    };

    const client = {
        user: { id: 'bot', username: 'PrimeBot', displayAvatarURL: () => 'https://cdn.discordapp.com/embed/avatars/0.png' },
        guilds: { cache },
        channels: { cache: new Map() },
        commands: new Map([
            ['help', {}], ['embed', {}], ['stats', {}], // deliberately tiny
        ]),
        ws: { ping: 42 },
        serverSettingsManager: { getGuildPrefix: () => '$' },
    };

    return mc.execute(message, client).then(() => replies);
}

test('$stats uses the help-menu command total, not just the slash collection', async () => {
    const replies = await runStats();
    assert.equal(replies.length, 1, 'one stats embed');

    const embed = replies[0].embeds[0].toJSON();
    const botField = embed.fields.find((f) => f.name.includes('Bot'));
    assert.ok(botField, 'bot field present');

    const expected = help.commandStats().withAliases;
    assert.match(botField.value, new RegExp(`\\*\\*Commands:\\*\\* ${expected}\\b`));
    assert.doesNotMatch(botField.value, /\*\*Commands:\*\* 4\b/, 'not the slash-command count');
    assert.ok(expected > 4, 'catalog total is larger than the stubbed slash collection');
});

test('the stats embed no longer hardcodes client.commands.size', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');
    assert.match(src, /commandStats\(\)\.withAliases/);
    assert.doesNotMatch(src, /\*\*Commands:\*\* \$\{client\.commands\.size\}/);
});

test('the help menu and $stats share a single command-count source', () => {
    assert.equal(typeof help.commandStats, 'function');
    assert.equal(help.helpStatsLine({ prefix: '$', servers: 3 }).split('\n')[1],
        `**Commands**: ${help.commandStats().withAliases}`);
});
