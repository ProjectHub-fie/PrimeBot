/**
 * /247 — administrator-controlled persistent voice connection.
 *
 * Subcommands: enable, disable, status, channel. Enabling shows an ephemeral
 * voice-channel selection interface (a channel select menu) so the admin picks
 * the channel; the persistent connection stays up with an empty queue and
 * nobody listening and never auto-disconnects.
 */

const { SlashCommandBuilder, MessageFlags, ActionRowBuilder, ChannelSelectMenuBuilder, ChannelType } = require('discord.js');
const ui = require('../utils/music/musicEmbed');
const perms = require('../utils/music/musicPermissions');

async function settingsFor(interaction) {
    try {
        const { getSettings } = require('../utils/music/musicStore');
        return await getSettings(interaction.guildId) || {};
    } catch (_) { return {}; }
}

function channelSelectRow() {
    return new ActionRowBuilder().addComponents(
        new ChannelSelectMenuBuilder()
            .setCustomId('music_247_channel')
            .setPlaceholder('Select the voice channel for 24/7 music')
            .addChannelTypes(ChannelType.GuildVoice, ChannelType.GuildStageVoice),
    );
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('247')
        .setDescription('Persistent 24/7 voice connection (Administrator)')
        .setDMPermission(false)
        .setDefaultMemberPermissions('0')
        .addSubcommand(sub => sub.setName('enable').setDescription('Enable the persistent connection and pick a voice channel'))
        .addSubcommand(sub => sub.setName('disable').setDescription('Disable the persistent connection and disconnect'))
        .addSubcommand(sub => sub.setName('status').setDescription('Show the 24/7 status'))
        .addSubcommand(sub => sub.setName('channel').setDescription('Change the 24/7 voice channel')),

    async execute(interaction) {
        const m = interaction.client.musicManager;
        if (!m) return interaction.reply({ embeds: [ui.errorEmbed('The music service is not available right now.')], flags: MessageFlags.Ephemeral });
        if (!perms.canConfigure(interaction.member)) {
            return interaction.reply({ embeds: [ui.errorEmbed('You need **Manage Server** to configure 24/7 mode.')], flags: MessageFlags.Ephemeral });
        }
        const sub = interaction.options.getSubcommand();
        const guildId = interaction.guildId;

        try {
            switch (sub) {
                case 'enable': {
                    // Ephemeral voice-channel selection interface.
                    return interaction.reply({
                        embeds: [ui.successEmbed('🕐 Enable 24/7', 'Choose the voice channel PrimeBot should stay connected to. It will remain connected with an empty queue and nobody listening.')],
                        components: [channelSelectRow()],
                        flags: MessageFlags.Ephemeral,
                    });
                }
                case 'disable': {
                    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
                    await m.disable247(guildId);
                    return interaction.editReply({ embeds: [ui.successEmbed('🕐 24/7 disabled', 'PrimeBot has disconnected and will not reconnect until you enable 24/7 again.')] });
                }
                case 'status': {
                    const snap = m.describe(guildId);
                    const settings = await settingsFor(interaction);
                    const view = snap || {
                        twentyFourSeven: settings.twentyFourSevenEnabled, channelId: settings.twentyFourSevenChannelId,
                        connected: false, state: 'idle', queueLength: 0, ownerNode: settings.ownerNode,
                    };
                    return interaction.reply({ embeds: [ui.status247Embed(view)] });
                }
                case 'channel':
                default:
                    return interaction.reply({
                        embeds: [ui.successEmbed('🕐 Change 24/7 channel', 'Choose the new voice channel. PrimeBot will move its connection there safely.')],
                        components: [channelSelectRow()],
                        flags: MessageFlags.Ephemeral,
                    });
            }
        } catch (err) {
            const payload = { embeds: [ui.errorEmbed(err.message || 'Something went wrong.')] };
            if (interaction.deferred || interaction.replied) return interaction.editReply(payload).catch(() => {});
            return interaction.reply(payload).catch(() => {});
        }
    },

    channelSelectRow,
};
