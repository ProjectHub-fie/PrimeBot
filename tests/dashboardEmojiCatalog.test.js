'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const discord = require('../dashboard/discord');
const catalog = require('../dashboard/emojiCatalog');

test('dashboard emoji catalog validates live guild emojis with deterministic priority', async () => {
    const previous = process.env.EMOJI_GUILD_IDS;
    process.env.EMOJI_GUILD_IDS = '111111111111111111,222222222222222222';
    const original = discord.getGuildEmojis;
    discord.getGuildEmojis = async (guildId) => {
        if (guildId === '111111111111111111') {
            return [
                { id: '111111111111111110', name: 'yes', animated: false },
                { id: '111111111111111111', name: 'dup', animated: false },
            ];
        }
        return [
            { id: '222222222222222221', name: 'dup', animated: true },
            { id: '222222222222222222', name: 'wave', animated: true },
        ];
    };
    try {
        const data = await catalog.getEmojiCatalog({ force: true });
        const names = data.entries.map(e => e.name).sort();
        assert.deepEqual(names, ['dup', 'wave', 'yes']);
        const dup = data.byName.get('dup');
        assert.equal(dup.id, '111111111111111111');
        assert.equal(dup.sourceGuildId, '111111111111111111');
        assert.equal(data.byName.get('wave').animated, true);
        assert.equal(data.conflicts.length, 1);
        assert.equal(data.conflicts[0].name, 'dup');
        assert.equal(data.conflicts[0].kept.id, '111111111111111111');
        assert.equal(data.conflicts[0].rejected.id, '222222222222222221');

        const resolved = catalog.normalizeConfiguredEmoji('<:wave:222222222222222222>', data);
        assert.equal(resolved.raw, '<a:wave:222222222222222222>');
        assert.equal(catalog.normalizeConfiguredEmoji({ id: '222222222222222222', name: 'wave', animated: true }, data).id, '222222222222222222');
        assert.equal(catalog.normalizeConfiguredEmoji('<:gone:999999999999999999>', data), null);
        assert.equal(catalog.normalizeConfiguredEmoji('🟢', data), null);

        const report = catalog.report(data);
        assert.equal(report.ready, true);
        assert.equal(report.emojiCount, 3);
        assert.equal(report.animated, 1);
        assert.equal(report.static, 2);
        assert.ok(report.unavailable.length > 0);
    } finally {
        discord.getGuildEmojis = original;
        if (previous === undefined) delete process.env.EMOJI_GUILD_IDS;
        else process.env.EMOJI_GUILD_IDS = previous;
    }
});

test('dashboard emoji catalog survives an unreachable guild', async () => {
    const previous = process.env.EMOJI_GUILD_IDS;
    process.env.EMOJI_GUILD_IDS = '333333333333333333,444444444444444444';
    const original = discord.getGuildEmojis;
    discord.getGuildEmojis = async (guildId) => {
        if (guildId === '333333333333333333') throw new Error('Missing Access');
        return [{ id: '444444444444444444', name: 'ok', animated: false }];
    };
    try {
        const data = await catalog.getEmojiCatalog({ force: true });
        assert.equal(data.entries.length, 1);
        assert.equal(data.guilds.find(g => g.id === '333333333333333333').ok, false);
        assert.match(data.guilds.find(g => g.id === '333333333333333333').error, /Missing Access/);
        assert.equal(catalog.report(data).ready, true);
    } finally {
        discord.getGuildEmojis = original;
        if (previous === undefined) delete process.env.EMOJI_GUILD_IDS;
        else process.env.EMOJI_GUILD_IDS = previous;
    }
});
