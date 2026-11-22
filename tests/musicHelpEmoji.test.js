const { test } = require('node:test');
const assert = require('node:assert');
const { musicHelpEmbed } = require('../music/help');

test('the music overview card renders custom emoji and no side stripe', () => {
    const client = {
        emoji: {
            play: '<:play:1188349488184701018>',
            filter: '<:filter:1188187546321158184>',
            autoplay: '<:autoplay:1188188713428209777>',
            music: '<:music:1127607386799083592>',
        },
        musicCommands: new Map([
            ['play', { name: 'play', category: 'Music' }],
            ['skip', { name: 'skip', category: 'Music' }],
        ]),
        user: { displayAvatarURL: () => 'https://cdn.example/bot.png' },
    };

    const embed = musicHelpEmbed(client, '$').toJSON();
    assert.ok(embed.description.includes('<:play:1188349488184701018>'));
    assert.ok(embed.description.includes('<:filter:1188187546321158184>'));
    assert.ok(embed.description.includes('<:autoplay:1188188713428209777>'));
    assert.ok(embed.fields[0].name.includes('<:music:1127607386799083592>'));
    assert.ok(embed.fields[0].value.includes('`$play`'));
    assert.equal(embed.color, undefined);
});
