/**
 * Broadcast announcement card.
 *
 * The announcement is delivered to every server that receives broadcasts. The
 * management controls live INSIDE the card as a Components V2 container, so the
 * buttons read as part of the announcement instead of a detached action row.
 * A legacy embed version is kept for the developer-facing preview/result
 * messages (Components V2 cannot be mixed with `embeds` in one message).
 */

const {
    ActionRowBuilder,
    ButtonBuilder,
    ButtonStyle,
    ChannelSelectMenuBuilder,
    ChannelType,
    ContainerBuilder,
    EmbedBuilder,
    MediaGalleryBuilder,
    MessageFlags,
    SeparatorBuilder,
    TextDisplayBuilder,
} = require('discord.js');
const config = require('../config');

const MANAGE_FIELD = "⚙️ Manage This Server's Broadcasts";
const MANAGE_TEXT = "Tap 'Broadcast setting' to toggle broadcast setting and tap 'Broadcast channel' to set broadcast channel.";

const SETTING_BUTTON_ID = 'broadcast_setting';
const TOGGLE_BUTTON_ID = 'broadcast_toggle';
const CHANNEL_BUTTON_ID = 'broadcast_channel';
const CHANNEL_SELECT_ID = 'broadcast_channel_select';

const CARD_TEXT_LIMIT = 4000;

// Broadcasts go to text channels and announcement channels (the two places a
// bot can post a message into). Categories, voice, forum and threads are not
// offered in the picker.
const BROADCAST_CHANNEL_TYPES = [ChannelType.GuildText, ChannelType.GuildAnnouncement];
const BROADCAST_CHANNEL_TYPE_SET = new Set(BROADCAST_CHANNEL_TYPES);

/** A channel a broadcast may be posted into (text or announcement). */
function isBroadcastChannel(channel) {
    return Boolean(channel) && BROADCAST_CHANNEL_TYPE_SET.has(channel.type);
}

/**
 * The channel a broadcast is delivered to in a guild: the guild's configured
 * channel when it still exists and is postable, otherwise the first text
 * channel. Returns null when the guild has nowhere to post.
 */
function resolveBroadcastChannel(guild, settingsManager) {
    if (!guild || !guild.channels?.cache) return null;
    let configuredId = null;
    try {
        configuredId = settingsManager?.getBroadcastChannel?.(guild.id) || null;
    } catch (_) {
        configuredId = null;
    }
    const configured = configuredId ? guild.channels.cache.get(configuredId) : null;
    if (isBroadcastChannel(configured)) return configured;

    return guild.channels.cache
        .filter((ch) => ch.type === ChannelType.GuildText)
        .sort((a, b) => a.position - b.position)
        .first() || null;
}

function clampText(text, limit = CARD_TEXT_LIMIT) {
    const value = typeof text === 'string' ? text : text == null ? '' : String(text);
    return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}

function isHttpUrl(url) {
    if (typeof url !== 'string') return false;
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

function manageRow() {
    return new ActionRowBuilder().addComponents(
        new ButtonBuilder()
            .setCustomId(SETTING_BUTTON_ID)
            .setLabel('Broadcast setting')
            .setStyle(ButtonStyle.Secondary)
            .setEmoji('⚙️'),
        new ButtonBuilder()
            .setCustomId(CHANNEL_BUTTON_ID)
            .setLabel('Broadcast channel')
            .setStyle(ButtonStyle.Secondary)
            .setEmoji('📢')
    );
}

/**
 * Components V2 payload for the announcement delivered to servers.
 * @returns {{components: any[], flags: number}}
 */
function buildBroadcastPayload({ title, message, imageUrl, footer, fields } = {}) {
    const container = new ContainerBuilder();

    container.addTextDisplayComponents(
        new TextDisplayBuilder().setContent(`## ${clampText(title || '📣 Announcement', 256)}`)
    );
    container.addTextDisplayComponents(
        new TextDisplayBuilder().setContent(clampText(message || '', CARD_TEXT_LIMIT))
    );

    if (isHttpUrl(imageUrl)) {
        container.addMediaGalleryComponents(
            new MediaGalleryBuilder().addItems((item) => item.setURL(imageUrl))
        );
    }

    for (const field of Array.isArray(fields) ? fields : []) {
        if (!field || !field.name) continue;
        const value = field.value == null ? '' : String(field.value);
        if (!value.trim()) continue;
        container.addTextDisplayComponents(
            new TextDisplayBuilder().setContent(
                `**${clampText(field.name, 256)}**\n${clampText(value, 1024)}`
            )
        );
    }

    if (footer) {
        container.addTextDisplayComponents(
            new TextDisplayBuilder().setContent(`-# ${clampText(footer, 256)}`)
        );
    }

    container.addSeparatorComponents(new SeparatorBuilder().setDivider(true));
    container.addTextDisplayComponents(
        new TextDisplayBuilder().setContent(MANAGE_TEXT)
    );
    container.addActionRowComponents(manageRow());

    return { components: [container], flags: MessageFlags.IsComponentsV2 };
}

/** Rebuild the card from a legacy embed (preview → real send). */
function buildBroadcastPayloadFromEmbed(embed) {
    const data = embed?.data || embed || {};
    return buildBroadcastPayload({
        title: data.title || '📣 Announcement',
        message: data.description || '',
        imageUrl: data.image?.url || null,
        footer: data.footer?.text || null,
        // The management hint is rendered from MANAGE_TEXT, never copied.
        fields: (data.fields || []).filter((field) => field?.name !== MANAGE_FIELD),
    });
}

/** Legacy embed used by the developer preview/result messages. */
function buildBroadcastEmbed({ title, message, color, imageUrl, footer, footerIcon } = {}) {
    const embed = new EmbedBuilder()
        .setColor(color || config.colors.primary)
        .setTitle(title || '📣 Announcement')
        .setDescription(clampText(message || '', 4096))
        .addFields({ name: MANAGE_FIELD, value: MANAGE_TEXT, inline: false })
        .setTimestamp();

    if (isHttpUrl(imageUrl)) embed.setImage(imageUrl);
    if (footer) embed.setFooter({ text: footer, iconURL: footerIcon });
    return embed;
}

/** Ephemeral panel shown when a member taps "Broadcast setting". */
function buildSettingPanel({ enabled } = {}) {
    const on = enabled !== false;
    const container = new ContainerBuilder();
    container.addTextDisplayComponents(
        new TextDisplayBuilder().setContent(
            `## Broadcast setting\nYour current setting is \`${on ? 'on' : 'off'}\`.`
        )
    );
    container.addSeparatorComponents(new SeparatorBuilder().setDivider(true));
    container.addActionRowComponents(
        new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId(TOGGLE_BUTTON_ID)
                .setLabel('Toggle setting')
                .setStyle(on ? ButtonStyle.Danger : ButtonStyle.Success)
                .setEmoji(on ? '🔕' : '🔔')
        )
    );
    return { components: [container], flags: MessageFlags.IsComponentsV2 };
}

/** Ephemeral panel shown when a member taps "Broadcast channel". */
function buildChannelPanel({ channelId } = {}) {
    const container = new ContainerBuilder();
    container.addTextDisplayComponents(
        new TextDisplayBuilder().setContent(
            `## Broadcast channel\n${
                channelId
                    ? `Broadcasts are currently sent to <#${channelId}>.`
                    : 'Broadcasts are currently sent to the first available text channel.'
            }\nPick the channel where broadcasts should be sent from the list below.`
        )
    );
    container.addSeparatorComponents(new SeparatorBuilder().setDivider(true));

    const select = new ChannelSelectMenuBuilder()
        .setCustomId(CHANNEL_SELECT_ID)
        .setPlaceholder('Select a broadcast channel')
        .setChannelTypes(...BROADCAST_CHANNEL_TYPES)
        .setMinValues(1)
        .setMaxValues(1);
    if (channelId) select.setDefaultChannels([channelId]);

    container.addActionRowComponents(new ActionRowBuilder().addComponents(select));
    return { components: [container], flags: MessageFlags.IsComponentsV2 };
}

module.exports = {
    MANAGE_FIELD,
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
};
