const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');
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
                .setName('status')
                .setDescription('Check the current broadcast settings for this server')
        ),

    async execute(interaction) {
        // Get the subcommand
        const subcommand = interaction.options.getSubcommand();
        
        try {
            // Server settings
            if (subcommand === 'toggle') {
                // Toggle broadcast reception for this server
                const newState = interaction.client.serverSettingsManager.toggleBroadcastReception(interaction.guild.id);
                
                const statusEmbed = new EmbedBuilder()
                    .setColor(newState ? config.colors.success : config.colors.danger)
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
                    .setFooter({ text: 'Server ID: ${interaction.guild.id} • Version 2.5.0' })
                    .setTimestamp();
                
                await interaction.reply({ embeds: [statusEmbed] });
                
            } else if (subcommand === 'status') {
                // Show current server settings
                const settings = interaction.client.serverSettingsManager.getGuildSettings(interaction.guild.id);
                
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
                            name: 'How to Change',
                            value: 'Use `/broadcastsettings toggle` to change this setting'
                        }
                    )
                    .setFooter({ text: 'Server ID: ${interaction.guild.id} • Version 2.5.0' })
                    .setTimestamp();
                
                await interaction.reply({ embeds: [statusEmbed] });
            }
            
        } catch (error) {
            console.error('Error executing broadcastsettings command:', error);
            await interaction.reply({
                content: 'There was an error while executing this command!',
                ephemeral: true
            });
        }
    },
};
