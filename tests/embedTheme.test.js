const test = require('node:test');
const assert = require('node:assert/strict');
const discord = require('discord.js');
const config = require('../config');
const { installEmbedTheme } = require('../utils/embedTheme');

installEmbedTheme(discord);

function colorNumber(hex) {
    return Number.parseInt(hex.replace(/^#/, ''), 16);
}

test('embeds without an explicit color use the shared violet accent', () => {
    const embed = new discord.EmbedBuilder().setTitle('Example').toJSON();
    assert.equal(embed.color, colorNumber(config.colors.primary));
});

test('legacy semantic colors map to the coordinated palette', () => {
    const colors = [
        [0x5865F2, config.colors.primary],
        [0x4752C4, config.colors.secondary],
        [0x57F287, config.colors.success],
        [0xED4245, config.colors.error],
        [0xFEE75C, config.colors.warning],
    ];

    for (const [legacyColor, themedColor] of colors) {
        const embed = new discord.EmbedBuilder().setColor(legacyColor).toJSON();
        assert.equal(embed.color, colorNumber(themedColor));
    }
});

test('custom embed colors and existing content are preserved', () => {
    const embed = new discord.EmbedBuilder()
        .setColor('#FFC0CB')
        .setTitle('Existing title')
        .setDescription('Existing description')
        .addFields({ name: 'Existing section', value: 'Existing value' })
        .toJSON();

    assert.equal(embed.color, 0xFFC0CB);
    assert.equal(embed.title, 'Existing title');
    assert.equal(embed.description, 'Existing description');
    assert.deepEqual(embed.fields, [{ name: 'Existing section', value: 'Existing value' }]);
});

test('installing the theme more than once is safe', () => {
    const themedBuilder = discord.EmbedBuilder;
    installEmbedTheme(discord);
    assert.equal(discord.EmbedBuilder, themedBuilder);
});
