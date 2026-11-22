'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
    ActionRowBuilder,
    ButtonBuilder,
    ButtonStyle,
    EmbedBuilder,
    MessageFlags,
    StringSelectMenuBuilder,
    StringSelectMenuOptionBuilder,
} = require('discord.js');

const { EmojiManager } = require('../utils/emojiManager');
const { buildEmbedWithButtons, sendEmbedWithButtons, editEmbedWithButtons } = require('../utils/embedComponentsV2');

function installEmojiManager() {
    const manager = new EmojiManager({ global: false, guildIds: ['1190256755096158208'] });
    manager.byId.set('1188185761955188737', {
        id: '1188185761955188737', name: 'pause', animated: false, sourceGuildId: '1190256755096158208',
    });
    manager.byId.set('1193991974718537840', {
        id: '1193991974718537840', name: 'loading', animated: true, sourceGuildId: '1190256755096158208',
    });
    manager.byId.set('1127619660519575612', {
        id: '1127619660519575612', name: 'yes', animated: false, sourceGuildId: '1190256755096158208',
    });
    manager.bySemantic.set('tick', manager.byId.get('1127619660519575612'));
    globalThis.__primebotEmojiManager = manager;
    return manager;
}

function rowWithButtons(...buttons) {
    return new ActionRowBuilder().addComponents(...buttons);
}

test('buildEmbedWithButtons renders one V2 container with embed text and integrated buttons', () => {
    installEmojiManager();
    const embed = new EmbedBuilder()
        .setAuthor({ name: 'PrimeBot' })
        .setTitle('Ticket panel')
        .setDescription('Open a ticket below.')
        .addFields({ name: 'Support', value: '24/7', inline: true })
        .setFooter({ text: 'Footer' })
        .setTimestamp(new Date('2026-01-01T00:00:00Z'));
    const row = rowWithButtons(
        new ButtonBuilder().setCustomId('ticket:open').setLabel('Open').setStyle(ButtonStyle.Primary)
            .setEmoji({ id: '1188185761955188737', name: 'pause', animated: false }),
        new ButtonBuilder().setURL('https://example.com').setLabel('Docs').setStyle(ButtonStyle.Link),
    );

    const payload = buildEmbedWithButtons({ embeds: [embed], components: [row], allowedMentions: { parse: [] } });
    assert.equal(payload.flags, MessageFlags.IsComponentsV2);
    assert.equal(payload.content, undefined);
    assert.equal(payload.embeds, undefined);
    assert.equal(payload.allowedMentions.parse.length, 0);
    assert.equal(payload.components.length, 1);
    const container = payload.components[0];
    assert.equal(container.type, 17);
    const text = container.components.filter(c => c.type === 10).map(c => c.content).join('\n');
    assert.match(text, /PrimeBot/);
    assert.match(text, /## Ticket panel/);
    assert.match(text, /Open a ticket below/);
    assert.match(text, /\*\*Support\*\*/);
    assert.match(text, /Footer/);
    const actionRow = container.components.find(c => c.type === 1);
    assert.ok(actionRow, 'action row is inside the container');
    assert.equal(actionRow.components[0].custom_id, 'ticket:open');
    assert.deepEqual(actionRow.components[0].emoji, { id: '1188185761955188737', name: 'pause', animated: false });
    assert.equal(actionRow.components[1].url, 'https://example.com');
});

test('buildEmbedWithButtons chunks buttons into five-per-row and keeps select rows', () => {
    installEmojiManager();
    const buttons = Array.from({ length: 7 }, (_, i) =>
        new ButtonBuilder().setCustomId(`b${i}`).setLabel(`B${i}`).setStyle(ButtonStyle.Secondary));
    const select = new StringSelectMenuBuilder()
        .setCustomId('pick')
        .setPlaceholder('Pick')
        .addOptions(new StringSelectMenuOptionBuilder().setLabel('One').setValue('1'));

    const payload = buildEmbedWithButtons({
        content: 'Pick one',
        buttons,
        components: [new ActionRowBuilder().addComponents(select)],
    });
    const container = payload.components[0];
    const rows = container.components.filter(c => c.type === 1);
    assert.equal(rows.length, 3);
    assert.equal(rows[0].components[0].type, 3);
    assert.equal(rows[0].components[0].custom_id, 'pick');
    assert.equal(rows[1].components.length, 5);
    assert.equal(rows[2].components.length, 2);
});

test('unavailable custom emojis degrade to a fallback instead of a broken token', () => {
    installEmojiManager();
    const button = new ButtonBuilder()
        .setCustomId('gone')
        .setLabel('Gone')
        .setStyle(ButtonStyle.Secondary)
        .setEmoji({ id: '999999999999999999', name: 'deleted', animated: false });
    const payload = buildEmbedWithButtons({ embeds: [new EmbedBuilder().setDescription('x')], buttons: [button] });
    const action = payload.components[0].components.find(c => c.type === 1);
    assert.equal(action.components[0].custom_id, 'gone');
    assert.equal(action.components[0].emoji, undefined);
});

test('a Unicode button emoji is upgraded to the catalog emoji when one exists', () => {
    installEmojiManager();
    const button = new ButtonBuilder()
        .setCustomId('yes')
        .setLabel('Yes')
        .setStyle(ButtonStyle.Success)
        .setEmoji('✅');
    const payload = buildEmbedWithButtons({ embeds: [new EmbedBuilder().setDescription('x')], buttons: [button] });
    const action = payload.components[0].components.find(c => c.type === 1);
    assert.deepEqual(action.components[0].emoji, { id: '1127619660519575612', name: 'yes', animated: false });
});

test('animated emojis keep their animated flag', () => {
    installEmojiManager();
    const button = new ButtonBuilder()
        .setCustomId('load')
        .setLabel('Loading')
        .setStyle(ButtonStyle.Secondary)
        .setEmoji({ id: '1193991974718537840', name: 'loading', animated: true });
    const payload = buildEmbedWithButtons({ embeds: [new EmbedBuilder().setDescription('x')], buttons: [button] });
    const action = payload.components[0].components.find(c => c.type === 1);
    assert.deepEqual(action.components[0].emoji, { id: '1193991974718537840', name: 'loading', animated: true });
});

test('send and edit helpers send the same V2 payload and preserve customIds', async () => {
    installEmojiManager();
    const calls = [];
    const target = {
        send: async (payload) => { calls.push(['send', payload]); return { id: 'm1' }; },
        edit: async (payload) => { calls.push(['edit', payload]); return { id: 'm1' }; },
    };
    const options = {
        embeds: [new EmbedBuilder().setTitle('Hi')],
        buttons: [new ButtonBuilder().setCustomId('keep:me').setLabel('Keep').setStyle(ButtonStyle.Secondary)],
    };
    await sendEmbedWithButtons(target, options);
    await editEmbedWithButtons(target, options);
    assert.equal(calls[0][0], 'send');
    assert.equal(calls[1][0], 'edit');
    for (const [, payload] of calls) {
        assert.equal(payload.flags, MessageFlags.IsComponentsV2);
        const row = payload.components[0].components.find(c => c.type === 1);
        assert.equal(row.components[0].custom_id, 'keep:me');
    }
});

test('interaction.update receives a V2 container whose customIds route unchanged', async () => {
    installEmojiManager();
    const interaction = {
        updated: null,
        async update(payload) { this.updated = payload; },
    };
    const payload = buildEmbedWithButtons({
        embeds: [new EmbedBuilder().setDescription('Menu')],
        buttons: [new ButtonBuilder().setCustomId('help_select').setLabel('Select').setStyle(ButtonStyle.Secondary)],
    });
    await interaction.update(payload);
    const row = interaction.updated.components[0].components.find(c => c.type === 1);
    assert.equal(row.components[0].custom_id, 'help_select');
    assert.equal(interaction.updated.flags, MessageFlags.IsComponentsV2);
});

test('a message with no content, embed or buttons returns null', () => {
    installEmojiManager();
    assert.equal(buildEmbedWithButtons({}), null);
    assert.equal(buildEmbedWithButtons({ embeds: [] }), null);
});
