/**
 * Handlers for the management controls on the broadcast announcement card.
 *
 * The card is delivered to every server, so these interactions arrive from
 * members of those servers. Changing broadcast settings requires Manage Server;
 * every response is ephemeral so the announcement channel is never polluted.
 */

const { MessageFlags, PermissionFlagsBits } = require('discord.js');
const {
    SETTING_BUTTON_ID,
    TOGGLE_BUTTON_ID,
    CHANNEL_BUTTON_ID,
    CHANNEL_SELECT_ID,
    isBroadcastChannel,
    buildSettingPanel,
    buildChannelPanel,
} = require('./broadcastPayload');

const BUTTON_IDS = [SETTING_BUTTON_ID, TOGGLE_BUTTON_ID, CHANNEL_BUTTON_ID];
const PANEL_FLAGS = MessageFlags.IsComponentsV2 | MessageFlags.Ephemeral;

function isBroadcastButton(customId) {
    return BUTTON_IDS.includes(customId);
}

function isBroadcastChannelSelect(customId) {
    return customId === CHANNEL_SELECT_ID;
}

function broadcastEnabled(manager, guildId) {
    try {
        return manager.receivesBroadcasts(guildId) !== false;
    } catch (_) {
        return true;
    }
}

function toggleBroadcast(manager, guildId) {
    try {
        const next = manager.toggleBroadcastReception(guildId);
        return typeof next === 'boolean' ? next : broadcastEnabled(manager, guildId);
    } catch (_) {
        return broadcastEnabled(manager, guildId);
    }
}

function currentChannelId(manager, guildId) {
    try {
        return manager.getBroadcastChannel(guildId) || null;
    } catch (_) {
        return null;
    }
}

/** The bot must be able to see the channel and post in it. */
function canPostIn(channel, me) {
    if (!channel || !me) return true;
    try {
        return channel
            .permissionsFor(me)
            .has([PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages]);
    } catch (_) {
        return true;
    }
}

function canManage(interaction) {
    try {
        return Boolean(interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild));
    } catch (_) {
        return false;
    }
}

async function respond(interaction, payload) {
    if (interaction.replied || interaction.deferred) {
        return interaction.followUp(payload).catch(() => {});
    }
    return interaction.reply(payload).catch(() => {});
}

async function denyMissingGuild(interaction) {
    await respond(interaction, {
        content: 'Broadcast settings can only be changed inside a server.',
        flags: MessageFlags.Ephemeral,
    });
}

async function denyMissingPermission(interaction) {
    await respond(interaction, {
        content: 'You need the **Manage Server** permission to change broadcast settings.',
        flags: MessageFlags.Ephemeral,
    });
}

async function handleBroadcastButton(interaction) {
    const customId = interaction.customId;
    if (!isBroadcastButton(customId)) return false;

    if (!interaction.guild) {
        await denyMissingGuild(interaction);
        return true;
    }
    if (!canManage(interaction)) {
        await denyMissingPermission(interaction);
        return true;
    }

    const manager = interaction.client.serverSettingsManager;

    if (customId === SETTING_BUTTON_ID) {
        const enabled = broadcastEnabled(manager, interaction.guild.id);
        await respond(interaction, { ...buildSettingPanel({ enabled }), flags: PANEL_FLAGS });
        return true;
    }

    if (customId === TOGGLE_BUTTON_ID) {
        const enabled = toggleBroadcast(manager, interaction.guild.id);
        await interaction
            .update({ ...buildSettingPanel({ enabled }), flags: PANEL_FLAGS })
            .catch(() => {});
        return true;
    }

    const channelId = currentChannelId(manager, interaction.guild.id);
    await respond(interaction, { ...buildChannelPanel({ channelId }), flags: PANEL_FLAGS });
    return true;
}

async function handleBroadcastChannelSelect(interaction) {
    if (!isBroadcastChannelSelect(interaction.customId)) return false;

    if (!interaction.guild) {
        await denyMissingGuild(interaction);
        return true;
    }
    if (!canManage(interaction)) {
        await denyMissingPermission(interaction);
        return true;
    }

    const channelId = (interaction.values && interaction.values[0]) || null;
    const channel = channelId ? interaction.guild.channels?.cache?.get(channelId) : null;
    if (!channel || !isBroadcastChannel(channel)) {
        await respond(interaction, {
            content: 'That channel cannot receive broadcasts. Pick a text or announcement channel.',
            flags: MessageFlags.Ephemeral,
        });
        return true;
    }
    if (!canPostIn(channel, interaction.guild.members?.me)) {
        await respond(interaction, {
            content: `I cannot post in <#${channel.id}> yet. Give me **View Channel** and **Send Messages** there and try again.`,
            flags: MessageFlags.Ephemeral,
        });
        return true;
    }

    const manager = interaction.client.serverSettingsManager;
    try {
        manager?.setBroadcastChannel(interaction.guild.id, channel.id);
    } catch (_) { /* the picker still confirms the selection */ }

    await interaction
        .update({ ...buildChannelPanel({ channelId: channel.id }), flags: PANEL_FLAGS })
        .catch(() => {});
    return true;
}

module.exports = {
    isBroadcastButton,
    isBroadcastChannelSelect,
    handleBroadcastButton,
    handleBroadcastChannelSelect,
};
