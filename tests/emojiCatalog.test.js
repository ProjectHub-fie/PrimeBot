const test = require('node:test');
const assert = require('node:assert/strict');
const { Collection, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, StringSelectMenuBuilder } = require('discord.js');

const {
    DEFAULT_EMOJI_GUILDS,
    LINIX_EMOJI_CATALOG,
    UNICODE_TO_SEMANTIC,
} = require('../shared/emojiCatalog');
const EmojiManager = require('../utils/emojiManager');
const { installEmojiTransformer } = require('../utils/emojiTransformer');

const GUILD_A = DEFAULT_EMOJI_GUILDS[0];
const GUILD_B = DEFAULT_EMOJI_GUILDS[1];
const GUILD_C = DEFAULT_EMOJI_GUILDS[2];

function makeEmoji(id, name, animated = false, available = true) {
    return { id, name, animated, available };
}

function makeMessages(contents) {
    const collection = new Collection();
    contents.forEach((content, index) => {
        collection.set(String(index), {
            id: String(index),
            content,
            embeds: [],
        });
    });
    return collection;
}

function makeGuild({ id, emojis, messages = [], channelName = 'emoji list', channelFails = false }) {
    const emojiCollection = new Collection();
    for (const emoji of emojis) emojiCollection.set(emoji.id, emoji);

    const channel = {
        id: `${id}-channel`,
        name: channelName,
        messages: {
            async fetch() {
                if (channelFails) throw Object.assign(new Error('Missing Access'), { status: 403 });
                return makeMessages(messages);
            },
        },
    };

    const channels = new Collection();
    channels.set(channel.id, channel);

    return {
        id,
        available: true,
        emojis: {
            cache: emojiCollection,
            async fetch() { return emojiCollection; },
        },
        channels: {
            cache: channels,
            async fetch() { return channels; },
        },
    };
}

function makeClient(guilds) {
    const cache = new Collection();
    for (const guild of guilds) cache.set(guild.id, guild);
    return {
        guilds: {
            cache,
            async fetch(id) {
                const guild = cache.get(id);
                if (!guild) throw Object.assign(new Error('Unknown Guild'), { status: 404 });
                return guild;
            },
        },
        on() {},
    };
}

function buildManager(client, options = {}) {
    const manager = new EmojiManager({ global: false, guildIds: [GUILD_A, GUILD_B, GUILD_C], ...options });
    manager.client = client;
    return manager;
}

test('catalog: exact guild ids and Linix mapping', () => {
    assert.deepEqual(DEFAULT_EMOJI_GUILDS, [
        '1190256755096158208',
        '1127600524586401792',
        '1222896507838009394',
    ]);
    assert.equal(Object.keys(LINIX_EMOJI_CATALOG).length, 98);
    assert.equal(new Set(Object.values(LINIX_EMOJI_CATALOG).map(e => e.id)).size, 92);
    assert.equal(LINIX_EMOJI_CATALOG.tick.id, '1127619660519575612');
    assert.equal(LINIX_EMOJI_CATALOG.tick.name, 'yes');
    assert.equal(LINIX_EMOJI_CATALOG.playing.animated, true);
    assert.equal(LINIX_EMOJI_CATALOG.loading.animated, true);
    assert.equal(LINIX_EMOJI_CATALOG.music.id, '1127607386799083592');
    assert.equal(LINIX_EMOJI_CATALOG.antinuke.id, '1389892187805974558');
});

test('resolves semantic aliases and animated emojis from live guilds', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [
            makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes'),
            makeEmoji(LINIX_EMOJI_CATALOG.cross.id, 'no'),
            makeEmoji(LINIX_EMOJI_CATALOG.playing.id, 'Playing', true),
            makeEmoji(LINIX_EMOJI_CATALOG.music.id, 'music'),
        ],
        messages: [
            'Success : <:yes:1127619660519575612>\nFailure : <:no:1127619635316015184>',
        ],
    });
    const manager = buildManager(makeClient([guildA]));
    const report = await manager.refresh({ force: true });

    assert.equal(manager.emoji('success'), '<:yes:1127619660519575612>');
    assert.equal(manager.emoji('error'), '<:no:1127619635316015184>');
    assert.equal(manager.emoji('music'), '<:music:1127607386799083592>');
    assert.equal(manager.emoji('playing'), '<a:Playing:1188088755819663400>');
    assert.equal(manager.componentEmoji('success').id, '1127619660519575612');
    assert.equal(report.ready, true);
});

test('falls back to Unicode when the catalog id is not in the live collection', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes')],
    });
    const manager = buildManager(makeClient([guildA]));
    await manager.refresh({ force: true });

    assert.equal(manager.emoji('success'), '<:yes:1127619660519575612>');
    assert.equal(manager.emoji('error'), '❌');
    assert.equal(manager.emoji('error', 'ERR'), 'ERR');
    assert.equal(manager.custom('error'), null);
    assert.ok(manager.report().unavailable.some(e => e.name === 'no'));
});

test('deterministic priority resolves duplicate names and reports conflicts', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji('111111111111111111', 'dupe')],
    });
    const guildB = makeGuild({
        id: GUILD_B,
        emojis: [makeEmoji('222222222222222222', 'dupe')],
    });
    const manager = buildManager(makeClient([guildA, guildB]));
    await manager.refresh({ force: true });

    assert.equal(manager.emoji('dupe'), '<:dupe:111111111111111111>');
    const report = manager.report();
    const conflict = report.conflicts.find(c => c.name === 'dupe');
    assert.ok(conflict);
    assert.equal(conflict.kept.sourceGuildId, GUILD_A);
    assert.equal(conflict.rejected.sourceGuildId, GUILD_B);
    assert.equal(report.entries.find(e => e.name === 'dupe').sourceGuildId, GUILD_A);
    assert.equal(EmojiManager.fallbackFor('✅'), '✅');
});

test('reads the emoji list channel and records categories', async () => {
    const guildC = makeGuild({
        id: GUILD_C,
        emojis: [makeEmoji('333333333333333333', 'sparkle')],
        messages: ['Music:\nsparkle : <:sparkle:333333333333333333>'],
    });
    const manager = buildManager(makeClient([guildC]));
    const report = await manager.refresh({ force: true });

    const row = report.guilds.find(g => g.id === GUILD_C);
    assert.equal(row.channelFound, true);
    assert.ok(row.discoveredCount >= 1);
    assert.equal(manager.emoji('sparkle'), '<:sparkle:333333333333333333>');
    assert.equal(manager.bySemantic.get('sparkle').category, 'Music');
});

test('a renamed emoji resolves by id and keeps the old catalog name as an alias', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes_renamed')],
    });
    const manager = buildManager(makeClient([guildA]));
    await manager.refresh({ force: true });

    assert.equal(manager.emoji('success'), `<:yes_renamed:${LINIX_EMOJI_CATALOG.tick.id}>`);
    assert.equal(manager.emoji('yes'), `<:yes_renamed:${LINIX_EMOJI_CATALOG.tick.id}>`);
    assert.equal(manager.byName.get('yes').id, LINIX_EMOJI_CATALOG.tick.id);
});

test('one unavailable guild does not stop the others', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes')],
    });
    const client = makeClient([guildA]);
    const manager = buildManager(client);
    await manager.refresh({ force: true });

    assert.equal(manager.emoji('success'), '<:yes:1127619660519575612>');
    const missing = manager.report().guilds.find(g => g.id === GUILD_B);
    assert.equal(missing.ok, false);
    assert.equal(missing.error, 'guild_unavailable');
});

test('channel permission errors are reported, emoji collection still works', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes')],
        channelFails: true,
    });
    const manager = buildManager(makeClient([guildA]));
    const report = await manager.refresh({ force: true });
    const row = report.guilds.find(g => g.id === GUILD_A);
    assert.equal(row.ok, true);
    assert.equal(row.channelFound, true);
    assert.match(row.error, /channel_read_failed/);
    assert.equal(manager.emoji('success'), '<:yes:1127619660519575612>');
});

test('renderText replaces only safe Unicode and skips code, URLs and existing custom emoji', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [
            makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes'),
            makeEmoji(LINIX_EMOJI_CATALOG.cross.id, 'no'),
            makeEmoji(LINIX_EMOJI_CATALOG.warn.id, 'warn'),
        ],
    });
    const manager = buildManager(makeClient([guildA]));
    await manager.refresh({ force: true });

    assert.equal(manager.renderText('✅ done'), '<:yes:1127619660519575612> done');
    assert.equal(manager.renderText('❌ failed'), '<:no:1127619635316015184> failed');
    assert.equal(manager.renderText('⚠️ careful'), '<:warn:1127619432865337344> careful');
    assert.equal(manager.renderText('`✅ code`'), '`✅ code`');
    assert.equal(manager.renderText('```\n✅ fence\n```'), '```\n✅ fence\n```');
    assert.equal(manager.renderText('see https://x.test/✅'), 'see https://x.test/✅');
    assert.equal(manager.renderText('<:yes:1127619660519575612>'), '<:yes:1127619660519575612>');
    assert.equal(manager.renderText('🎉 no equivalent'), '🎉 no equivalent');
});

test('transformPayload rewrites content, embeds and component emoji', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [
            makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes'),
            makeEmoji(LINIX_EMOJI_CATALOG.music.id, 'music'),
            makeEmoji(LINIX_EMOJI_CATALOG.left.id, 'left'),
        ],
    });
    const manager = buildManager(makeClient([guildA]));
    await manager.refresh({ force: true });

    const embed = new EmbedBuilder()
        .setTitle('✅ Title')
        .setDescription('🎵 body')
        .addFields({ name: '✅ field', value: '✅ value' })
        .setFooter({ text: '✅ footer' });
    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('x').setLabel('Go').setStyle(ButtonStyle.Primary).setEmoji('◀️')
    );
    const select = new ActionRowBuilder().addComponents(
        new StringSelectMenuBuilder().setCustomId('s').addOptions({ label: 'One', value: '1', emoji: '◀️' })
    );

    const transformed = manager.transformPayload({
        content: '✅ hello',
        embeds: [embed],
        components: [row, select],
    });

    assert.equal(transformed.content, '<:yes:1127619660519575612> hello');
    assert.equal(transformed.embeds[0].title, '<:yes:1127619660519575612> Title');
    assert.equal(transformed.embeds[0].description, '<:music:1127607386799083592> body');
    assert.equal(transformed.embeds[0].fields[0].name, '<:yes:1127619660519575612> field');
    assert.equal(transformed.embeds[0].footer.text, '<:yes:1127619660519575612> footer');
    const button = transformed.components[0].components[0];
    assert.equal(button.emoji.id, LINIX_EMOJI_CATALOG.left.id);
    assert.equal(transformed.components[1].components[0].options[0].emoji.id, LINIX_EMOJI_CATALOG.left.id);
});

test('transformPayload handles interaction callback data', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes')],
    });
    const manager = buildManager(makeClient([guildA]));
    await manager.refresh({ force: true });

    const transformed = manager.transformPayload({
        type: 4,
        data: { content: '✅ ok', embeds: [new EmbedBuilder().setDescription('✅ embed')] },
    });
    assert.equal(transformed.data.content, '<:yes:1127619660519575612> ok');
    assert.equal(transformed.data.embeds[0].description, '<:yes:1127619660519575612> embed');
});

test('cache avoids repeat fetches unless forced', async () => {
    let fetchCount = 0;
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes')],
    });
    const originalFetch = guildA.emojis.fetch;
    guildA.emojis.fetch = async () => { fetchCount += 1; return originalFetch(); };
    const manager = buildManager(makeClient([guildA]));

    await manager.refresh({ force: true });
    await manager.refresh();
    assert.equal(fetchCount, 1);
    await manager.refresh({ force: true });
    assert.equal(fetchCount, 2);
});

test('canUseIn requires UseExternalEmojis', () => {
    const manager = new EmojiManager({ global: false });
    assert.equal(manager.canUseIn({ members: { me: { permissions: { has: () => true } } } }), true);
    assert.equal(manager.canUseIn({ members: { me: { permissions: { has: () => false } } } }), false);
    assert.equal(manager.canUseIn(null), false);
});

test('diagnostics never expose token-shaped strings', () => {
    const manager = new EmojiManager({ global: false });
    // Assembled at runtime so no credential-shaped literal ever lands in git.
    const fakeToken = ['MTIzNDU2Nzg5MDEyMzQ1Njc4', 'ABCDEF', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('.');
    const sanitized = EmojiManager.sanitizeError(new Error(`401 Unauthorized Bot ${fakeToken}`));
    assert.ok(!sanitized.includes(fakeToken));
    assert.match(sanitized, /redacted/i);
});

test('help menu renders category emojis in headings, fields and select options', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [
            makeEmoji(LINIX_EMOJI_CATALOG.home.id, 'home'),
            makeEmoji(LINIX_EMOJI_CATALOG.profile.id, 'profile'),
            makeEmoji(LINIX_EMOJI_CATALOG.fun.id, 'fun'),
            makeEmoji(LINIX_EMOJI_CATALOG.extra.id, 'extra'),
            makeEmoji(LINIX_EMOJI_CATALOG.music.id, 'music'),
            makeEmoji(LINIX_EMOJI_CATALOG.utility.id, 'utility'),
            makeEmoji(LINIX_EMOJI_CATALOG.playing.id, 'Playing', true),
            makeEmoji(LINIX_EMOJI_CATALOG.welc.id, 'welc'),
            makeEmoji(LINIX_EMOJI_CATALOG.moderation.id, 'mod'),
            makeEmoji(LINIX_EMOJI_CATALOG.config.id, 'config'),
            makeEmoji(LINIX_EMOJI_CATALOG.information.id, 'information'),
            makeEmoji(LINIX_EMOJI_CATALOG.autoresponder.id, 'autoresponder'),
            makeEmoji(LINIX_EMOJI_CATALOG.antinuke.id, 'antinuke'),
        ],
    });
    const manager = buildManager(makeClient([guildA]));
    await manager.refresh({ force: true });
    globalThis.__primebotEmojiManager = manager;

    const { mainMenuEmbed, categorySelectRow, categoryEmbed, CATEGORY_ORDER } = require('../utils/prefixHelp');
    const menu = mainMenuEmbed('$', null);
    assert.equal(menu.data.fields, undefined);
    assert.ok(menu.data.description.includes(`<:home:${LINIX_EMOJI_CATALOG.home.id}> General`));

    const select = categorySelectRow().toJSON().components[0].options;
    assert.equal(select.length, CATEGORY_ORDER.length);
    assert.ok(select.every(o => o.emoji && o.emoji.id));

    const general = categoryEmbed('general', '$');
    assert.match(general.data.title, /^<:home:/);
    assert.ok(general.data.description.includes('`help`'));

    delete globalThis.__primebotEmojiManager;
});

test('REST transformer only rewrites message routes', async () => {
    const guildA = makeGuild({
        id: GUILD_A,
        emojis: [makeEmoji(LINIX_EMOJI_CATALOG.tick.id, 'yes')],
    });
    const manager = buildManager(makeClient([guildA]));
    await manager.refresh({ force: true });

    const calls = [];
    const client = {
        rest: {
            post(route, options) { calls.push({ method: 'post', route, options }); return 'ok'; },
            patch(route, options) { calls.push({ method: 'patch', route, options }); return 'ok'; },
            put(route, options) { calls.push({ method: 'put', route, options }); return 'ok'; },
        },
    };
    assert.equal(installEmojiTransformer(client, manager), true);
    assert.equal(installEmojiTransformer(client, manager), true); // idempotent

    await client.rest.post('/channels/123/messages', { body: { content: '✅ hi' } });
    await client.rest.patch('/channels/123/messages/456', { body: { content: '✅ edit' } });
    await client.rest.post('/webhooks/1/token', { body: { content: '✅ hook' } });
    await client.rest.post('/interactions/1/token/callback', { body: { type: 4, data: { content: '✅ cb' } } });
    await client.rest.post('/applications/1/commands', { body: { description: '✅ command' } });
    await client.rest.put('/channels/123/messages/456/reactions/%E2%9C%85/@me');

    assert.equal(calls[0].options.body.content, '<:yes:1127619660519575612> hi');
    assert.equal(calls[1].options.body.content, '<:yes:1127619660519575612> edit');
    assert.equal(calls[2].options.body.content, '<:yes:1127619660519575612> hook');
    assert.equal(calls[3].options.body.data.content, '<:yes:1127619660519575612> cb');
    assert.equal(calls[4].options.body.description, '✅ command');
    assert.equal(calls[5].options, undefined);
});
