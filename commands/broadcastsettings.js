const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder, ChannelType } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('broadcastsettings')
        .setDescription('Configure server preferences for developer broadcasts')
        // Require MANAGE_GUILD permission to use this command
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
        .addSubcommand(subcommand =>
            subcommand
                .setName('toggle')
                .setDescription('Toggle whether this server receives developer broadcasts')
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('enable')
                .setDescription('Enable developer broadcasts for this server')
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('disable')
                .setDescription('Disable developer broadcasts for this server')
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('channel')
                .setDescription('Set the channel where developer broadcasts should be sent')
                .addChannelOption(option =>
                    option
                        .setName('channel')
                        .setDescription('The text channel to receive broadcasts (leave empty to auto-select)')
                        .addChannelTypes(ChannelType.GuildText)
                        .setRequired(false)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('status')
                .setDescription('Check the current broadcast settings for this server')
        ),

    async execute(interaction) {
        // Get the subcommand
        const subcommand = interaction.options.getSubcommand();

        try {
            const settingsManager = interaction.client.serverSettingsManager;

            if (subcommand === 'toggle') {
                // Toggle broadcast reception for this server
                const newState = settingsManager.toggleBroadcastReception(interaction.guild.id);

                const statusEmbed = new EmbedBuilder()
                    .setColor(newState ? config.colors.success : config.colors.error)
                    .setTitle('Broadcast Settings Updated')
                    .setDescription(
                        newState
                        ? '✅ This server will now receive developer broadcasts.'
                        : '🔕 This server has opted out of developer broadcasts.'
                    )
                    .addFields(
                        {
                            name: 'What This Means',
                            value: newState
                                ? 'The bot developers can send important announcements to this server.'
                                : 'The bot developers cannot send broadcast announcements to this server.'
                        }
                    )
                    .setFooter({ text: `Server ID: ${interaction.guild.id} • Version 2.5.0` })
                    .setTimestamp();

                await interaction.reply({ embeds: [statusEmbed] });

            } else if (subcommand === 'enable' || subcommand === 'disable') {
                const enable = subcommand === 'enable';
                const currentSettings = settingsManager.getGuildSettings(interaction.guild.id);

                if (currentSettings.receiveBroadcasts === enable) {
                    return interaction.reply({
                        content: `Developer broadcasts are already ${enable ? 'enabled' : 'disabled'} for this server.`,
                        ephemeral: true
                    });
                }

                settingsManager.toggleBroadcastReception(interaction.guild.id);

                const statusEmbed = new EmbedBuilder()
                    .setColor(enable ? config.colors.success : config.colors.error)
                    .setTitle('Broadcast Settings Updated')
                    .setDescription(
                        enable
                        ? '✅ This server will now receive developer broadcasts.'
                        : '🔕 This server has opted out of developer broadcasts.'
                    )
                    .setFooter({ text: `Server ID: ${interaction.guild.id} • Version 2.5.0` })
                    .setTimestamp();

                await interaction.reply({ embeds: [statusEmbed] });

            } else if (subcommand === 'channel') {
                const channel = interaction.options.getChannel('channel');

                settingsManager.setBroadcastChannel(interaction.guild.id, channel ? channel.id : null);

                const channelEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Broadcast Channel Updated')
                    .setDescription(
                        channel
                            ? `Developer broadcasts will now be sent to ${channel}.`
                            : 'Developer broadcasts will now be sent to the first available text channel.'
                    )
                    .setFooter({ text: `Server ID: ${interaction.guild.id} • Version 2.5.0` })
                    .setTimestamp();

                await interaction.reply({ embeds: [channelEmbed] });

            } else if (subcommand === 'status') {
                // Show current server settings
                const settings = settingsManager.getGuildSettings(interaction.guild.id);
                const broadcastChannelId = settingsManager.getBroadcastChannel(interaction.guild.id);

                const statusEmbed = new EmbedBuilder()
                    .setColor(config.colors.primary)
                    .setTitle('Server Broadcast Settings')
                    .addFields(
                        {
                            name: 'Developer Broadcasts',
                            value: settings.receiveBroadcasts
                                ? '✅ This server is receiving developer broadcasts'
                                : '🔕 This server has opted out of developer broadcasts'
                        },
                        {
                            name: 'Broadcast Channel',
                            value: broadcastChannelId ? `<#${broadcastChannelId}>` : 'Auto (first available channel)'
                        },
                        {
                            name: 'How to Change',
                            value: 'Use `/broadcastsettings enable` / `/broadcastsettings disable` to control broadcasts, or `/broadcastsettings channel` to set the channel.\nPrefix equivalents: `$broadcast enable`, `$broadcast disable`, `$broadcast channel`.'
                        }
                    )
                    .setFooter({ text: `Server ID: ${interaction.guild.id} • Version 2.5.0` })
                    .setTimestamp();

                await interaction.reply({ embeds: [statusEmbed] });
            }

        } catch (error) {
            console.error('Error executing broadcastsettings command:', error);
            if (interaction.replied || interaction.deferred) {
                await interaction.followUp({
                    content: 'There was an error while executing this command!',
                    ephemeral: true
                });
            } else {
                await interaction.reply({
                    content: 'There was an error while executing this command!',
                    ephemeral: true
                });
            }
        }
    },
};
