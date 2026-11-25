// The broadcast announcement card delivered to servers: Components V2 payload
// with the two management buttons inside the card, plus the ephemeral panels
// behind them ("Broadcast setting" → toggle, "Broadcast channel" → picker).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Collection, MessageFlags } = require('discord.js');

const ROOT = path.join(__dirname, '..');
const {
    MANAGE_TEXT,
    SETTING_BUTTON_ID,
    TOGGLE_BUTTON_ID,
    CHANNEL_BUTTON_ID,
    CHANNEL_SELECT_ID,
    BROADCAST_CHANNEL_TYPES,
    isBroadcastChannel,
    resolveBroadcastChannel,
    buildBroadcastPayload,
    buildBroadcastPayloadFromEmbed,
    buildBroadcastEmbed,
    buildSettingPanel,
    buildChannelPanel,
} = require('../utils/broadcastPayload');
const handlers = require('../utils/broadcastInteractions');

function containerOf(payload) {
    assert.ok(payload.flags & MessageFlags.IsComponentsV2, 'must be Components V2');
    assert.equal(payload.embeds, undefined, 'no legacy embeds');
    assert.equal(payload.content, undefined, 'no legacy content');
    assert.equal(payload.components.length, 1);
    return payload.components[0].toJSON();
}

function textOf(container) {
    return container.components.filter((c) => c.type === 10).map((c) => c.content).join('\n');
}

function buttonsOf(container) {
    return container.components
        .filter((c) => c.type === 1)
        .flatMap((row) => row.components)
        .filter((c) => c.type === 2);
}

function fakeInteraction({ customId, perms = true, manager = null, values = null, channels = new Map() }) {
    const calls = { replies: [], updates: [], followUps: [] };
    const interaction = {
        customId,
        values,
        guild: {
            id: 'g1',
            channels: { cache: channels },
            members: { me: { id: 'bot' } },
        },
        memberPermissions: { has: () => perms },
        client: { serverSettingsManager: manager },
        replied: false,
        deferred: false,
        async reply(payload) { this.replied = true; calls.replies.push(payload); },
        async update(payload) { calls.updates.push(payload); },
        async followUp(payload) { calls.followUps.push(payload); },
        async deferUpdate() {},
    };
    return { interaction, calls };
}

function fakeManager({ enabled = true, channelId = null } = {}) {
    const state = { enabled, channelId, toggles: 0, saved: [] };
    return {
        state,
        receivesBroadcasts: () => state.enabled,
        toggleBroadcastReception: () => {
            state.enabled = !state.enabled;
            state.toggles += 1;
            return state.enabled;
        },
        getBroadcastChannel: () => state.channelId,
        setBroadcastChannel: (_guildId, id) => {
            state.channelId = id;
            state.saved.push(id);
            return true;
        },
    };
}

test('delivered card is Components V2 with both management buttons inside it', () => {
    const payload = buildBroadcastPayload({
        title: 'Maintenance',
        message: 'The server restarts tonight.',
        color: '#5865F2',
        imageUrl: 'https://example.com/banner.png',
        footer: 'Version 1.2',
    });
    const container = containerOf(payload);

    assert.equal(container.type, 17, 'container');

    const text = textOf(container);
    assert.ok(text.includes('## Maintenance'), 'title rendered as a heading');
    assert.ok(text.includes('The server restarts tonight.'));
    assert.ok(text.includes(MANAGE_TEXT), 'the new hint text is in the card');
    assert.ok(text.includes('-# Version 1.2'), 'footer as small text');
    assert.ok(!text.includes('Use `$broadcast enable`'), 'old hint removed');

    const buttons = buttonsOf(container);
    assert.deepEqual(buttons.map((b) => b.label), ['Broadcast setting', 'Broadcast channel']);
    assert.deepEqual(buttons.map((b) => b.custom_id), [SETTING_BUTTON_ID, CHANNEL_BUTTON_ID]);

    assert.ok(container.components.some((c) => c.type === 12), 'image media gallery');
});

test('card without an image omits the media gallery and tolerates missing fields', () => {
    const container = containerOf(buildBroadcastPayload({ title: 'Hi', message: 'There' }));
    assert.ok(!container.components.some((c) => c.type === 12));
    assert.ok(textOf(container).includes(MANAGE_TEXT));
});

test('the legacy preview embed carries the new hint and never the old one', () => {
    const embed = buildBroadcastEmbed({
        title: 'T',
        message: 'M',
        color: '#000000',
        footer: 'Version 3',
    }).toJSON();
    const field = embed.fields.find((f) => f.name.includes('Manage This Server'));
    assert.ok(field, 'manage field present');
    assert.equal(field.value, MANAGE_TEXT);
    assert.ok(!JSON.stringify(embed).includes('$broadcast enable'));
    assert.ok(!JSON.stringify(embed).includes('$broadcast disable'));
});

test('a delivered card can be rebuilt from the preview embed', () => {
    const embed = buildBroadcastEmbed({ title: 'T', message: 'M', color: '#123456' });
    embed.addFields({ name: '📊 Servers', value: 'Sent to 12 servers.', inline: false });
    const container = containerOf(buildBroadcastPayloadFromEmbed(embed.toJSON()));
    const text = textOf(container);
    assert.ok(text.includes('## T'));
    assert.ok(text.includes('**📊 Servers**\nSent to 12 servers.'), 'reach line survives');
    assert.equal(text.split(MANAGE_TEXT).length - 1, 1, 'manage hint rendered exactly once');
    assert.equal(buttonsOf(container).length, 2);
});

test('broadcast setting panel reports the setting and shows a toggle button', () => {
    for (const [enabled, word] of [[true, 'on'], [false, 'off']]) {
        const container = containerOf(buildSettingPanel({ enabled }));
        assert.ok(textOf(container).includes(`Your current setting is \`${word}\``));
        const buttons = buttonsOf(container);
        assert.equal(buttons.length, 1);
        assert.equal(buttons[0].label, 'Toggle setting');
        assert.equal(buttons[0].custom_id, TOGGLE_BUTTON_ID);
    }
});

test('broadcast channel panel is a dropdown of the channels a broadcast can go to', () => {
    const container = containerOf(buildChannelPanel({ channelId: '123' }));
    assert.ok(textOf(container).includes('<#123>'));
    const select = container.components
        .filter((c) => c.type === 1)
        .flatMap((row) => row.components)
        .find((c) => c.type === 8);
    assert.ok(select, 'channel select present');
    assert.equal(select.custom_id, CHANNEL_SELECT_ID);
    assert.deepEqual(select.channel_types, [0, 5], 'text + announcement channels');
    assert.deepEqual(select.default_values, [{ id: '123', type: 'channel' }], 'current channel preselected');

    const fresh = containerOf(buildChannelPanel({}));
    const select2 = fresh.components
        .filter((c) => c.type === 1)
        .flatMap((row) => row.components)
        .find((c) => c.type === 8);
    assert.equal(select2.default_values, undefined, 'nothing preselected when unset');
});

test('only text and announcement channels are broadcast channels', () => {
    assert.deepEqual(BROADCAST_CHANNEL_TYPES, [0, 5]);
    assert.equal(isBroadcastChannel({ type: 0 }), true);
    assert.equal(isBroadcastChannel({ type: 5 }), true);
    for (const type of [2, 4, 13, 15]) assert.equal(isBroadcastChannel({ type }), false);
    assert.equal(isBroadcastChannel(null), false);
});

test('resolveBroadcastChannel prefers the configured channel, then the first text channel', () => {
    const guild = (channels, id = 'g1') => ({
        id,
        channels: { cache: new Collection(channels.map((c) => [c.id, c])) },
    });
    const text = { id: 't1', type: 0, position: 3 };
    const text2 = { id: 't2', type: 0, position: 1 };
    const announcement = { id: 'a1', type: 5, position: 2 };
    const voice = { id: 'v1', type: 2, position: 0 };

    const configured = { getBroadcastChannel: () => 'a1' };
    assert.equal(resolveBroadcastChannel(guild([text, announcement]), configured).id, 'a1',
        'a configured announcement channel is honoured');
    assert.equal(resolveBroadcastChannel(guild([text, voice]), { getBroadcastChannel: () => null }).id, 't1',
        'falls back to the first text channel');
    assert.equal(resolveBroadcastChannel(guild([text, text2]), { getBroadcastChannel: () => 'gone' }).id, 't2',
        'a stale channel id falls back to the lowest-position text channel');
    assert.equal(resolveBroadcastChannel(guild([voice]), { getBroadcastChannel: () => 'gone' }), null,
        'no postable channel → null');
    assert.equal(resolveBroadcastChannel(null, configured), null);
});

test('"Broadcast setting" answers ephemerally with the current state', async () => {
    const manager = fakeManager({ enabled: true });
    const { interaction, calls } = fakeInteraction({ customId: SETTING_BUTTON_ID, manager });

    assert.equal(await handlers.handleBroadcastButton(interaction), true);
    assert.equal(calls.replies.length, 1);
    const payload = calls.replies[0];
    assert.ok(payload.flags & MessageFlags.Ephemeral, 'ephemeral');
    assert.ok(textOf(containerOf(payload)).includes('`on`'));
    assert.equal(manager.state.toggles, 0, 'showing the panel does not change the setting');
});

test('"Toggle setting" flips the setting and updates the panel', async () => {
    const manager = fakeManager({ enabled: true });
    const { interaction, calls } = fakeInteraction({ customId: TOGGLE_BUTTON_ID, manager });

    assert.equal(await handlers.handleBroadcastButton(interaction), true);
    assert.equal(manager.state.enabled, false, 'on -> off');
    assert.equal(calls.updates.length, 1);
    assert.ok(textOf(containerOf(calls.updates[0])).includes('`off`'));

    const second = fakeInteraction({ customId: TOGGLE_BUTTON_ID, manager });
    await handlers.handleBroadcastButton(second.interaction);
    assert.equal(manager.state.enabled, true, 'off -> on');
    assert.ok(textOf(containerOf(second.calls.updates[0])).includes('`on`'));
});

test('"Broadcast channel" answers with the picker and saving a channel persists it', async () => {
    const manager = fakeManager({ channelId: null });
    const { interaction, calls } = fakeInteraction({ customId: CHANNEL_BUTTON_ID, manager });

    assert.equal(await handlers.handleBroadcastButton(interaction), true);
    assert.ok(textOf(containerOf(calls.replies[0])).includes('first available text channel'));

    const channels = new Map([['c9', { id: 'c9', name: 'announcements', type: 0, permissionsFor: () => ({ has: () => true }) }]]);
    const select = fakeInteraction({
        customId: CHANNEL_SELECT_ID,
        manager,
        values: ['c9'],
        channels,
    });
    assert.equal(await handlers.handleBroadcastChannelSelect(select.interaction), true);
    assert.deepEqual(manager.state.saved, ['c9']);
    assert.ok(textOf(containerOf(select.calls.updates[0])).includes('<#c9>'));
});

test('the channel picker refuses channels a broadcast cannot use', async () => {
    const manager = fakeManager({ channelId: null });

    const voice = fakeInteraction({
        customId: CHANNEL_SELECT_ID,
        manager,
        values: ['v1'],
        channels: new Map([['v1', { id: 'v1', type: 2, permissionsFor: () => ({ has: () => true }) }]]),
    });
    assert.equal(await handlers.handleBroadcastChannelSelect(voice.interaction), true);
    assert.match(voice.calls.replies[0].content, /text or announcement channel/);
    assert.deepEqual(manager.state.saved, []);

    const noPerms = fakeInteraction({
        customId: CHANNEL_SELECT_ID,
        manager,
        values: ['c1'],
        channels: new Map([['c1', { id: 'c1', type: 0, permissionsFor: () => ({ has: () => false }) }]]),
    });
    assert.equal(await handlers.handleBroadcastChannelSelect(noPerms.interaction), true);
    assert.match(noPerms.calls.replies[0].content, /cannot post in <#c1>/);
    assert.deepEqual(manager.state.saved, []);

    const announcement = fakeInteraction({
        customId: CHANNEL_SELECT_ID,
        manager,
        values: ['a1'],
        channels: new Map([['a1', { id: 'a1', type: 5, permissionsFor: () => ({ has: () => true }) }]]),
    });
    await handlers.handleBroadcastChannelSelect(announcement.interaction);
    assert.deepEqual(manager.state.saved, ['a1'], 'announcement channels are accepted');
});

test('members without Manage Server cannot change broadcast settings', async () => {
    const manager = fakeManager({ enabled: true });
    for (const customId of [SETTING_BUTTON_ID, TOGGLE_BUTTON_ID, CHANNEL_BUTTON_ID]) {
        const { interaction, calls } = fakeInteraction({ customId, perms: false, manager });
        assert.equal(await handlers.handleBroadcastButton(interaction), true);
        assert.match(calls.replies[0].content, /Manage Server/);
        assert.ok(calls.replies[0].flags & MessageFlags.Ephemeral);
    }
    assert.equal(manager.state.toggles, 0, 'no state change');

    const select = fakeInteraction({
        customId: CHANNEL_SELECT_ID,
        perms: false,
        manager,
        values: ['c9'],
        channels: new Map([['c9', { id: 'c9', type: 0, permissionsFor: () => ({ has: () => true }) }]]),
    });
    assert.equal(await handlers.handleBroadcastChannelSelect(select.interaction), true);
    assert.match(select.calls.replies[0].content, /Manage Server/);
    assert.deepEqual(manager.state.saved, []);
});

test('the handlers ignore unrelated component ids', async () => {
    const { interaction } = fakeInteraction({ customId: 'something_else', manager: fakeManager() });
    assert.equal(await handlers.handleBroadcastButton(interaction), false);
    assert.equal(await handlers.handleBroadcastChannelSelect(interaction), false);
});

test('every broadcast delivery path sends the V2 card, and the routers dispatch the buttons', () => {
    const slash = fs.readFileSync(path.join(ROOT, 'commands', 'broadcast.js'), 'utf8');
    assert.match(slash, /channel\.send\(deliveredPayload\)/);
    assert.match(slash, /buildBroadcastPayloadFromEmbed\(broadcastEmbed\)/);

    assert.match(slash, /resolveBroadcastChannel\(guild, interaction\.client\.serverSettingsManager\)/);

    const prefix = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');
    assert.match(prefix, /channel\.send\(deliveredPayload\)/);
    assert.match(prefix, /resolveBroadcastChannel\(guild, client\.serverSettingsManager\)/);

    const interactions = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    assert.match(interactions, /buildBroadcastPayloadFromEmbed\(broadcastEmbed\)/);
    assert.match(interactions, /isBroadcastButton\(customId\)/);
    assert.match(interactions, /isBroadcastChannelSelect\(interaction\.customId\)/);
    assert.match(interactions, /resolveBroadcastChannel\(guild, client\.serverSettingsManager\)/);
    assert.match(interactions, /isChannelSelectMenu/);
});
