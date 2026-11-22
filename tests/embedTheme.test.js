const test = require('node:test');
const assert = require('node:assert/strict');
const discord = require('discord.js');
const { installEmbedTheme } = require('../utils/embedTheme');

installEmbedTheme(discord);

test('embeds never carry a colour', () => {
    const embed = new discord.EmbedBuilder().setTitle('Example').toJSON();
    assert.equal(embed.color, undefined);
});

test('legacy semantic colors are removed', () => {
    const colors = [0x5865F2, 0x4752C4, 0x57F287, 0xED4245, 0xFEE75C];
    for (const color of colors) {
        const embed = new discord.EmbedBuilder().setColor(color).toJSON();
        assert.equal(embed.color, undefined);
    }
});

test('custom embed colors are removed but content is preserved', () => {
    const embed = new discord.EmbedBuilder()
        .setColor('#FFC0CB')
        .setTitle('Existing title')
        .setDescription('Existing description')
        .addFields({ name: 'Existing section', value: 'Existing value' })
        .toJSON();

    assert.equal(embed.color, undefined);
    assert.equal(embed.title, 'Existing title');
    assert.equal(embed.description, 'Existing description');
    assert.deepEqual(embed.fields, [{ name: 'Existing section', value: 'Existing value' }]);
});

test('installing the theme more than once is safe', () => {
    const themedBuilder = discord.EmbedBuilder;
    installEmbedTheme(discord);
    assert.equal(discord.EmbedBuilder, themedBuilder);
});
