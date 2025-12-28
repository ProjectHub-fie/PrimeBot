const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');
const config = require('../config');
const fs = require('fs');
const path = require('path');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('welcomeconfig')
        .setDescription('Configure welcome settings for this server')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild) // Only users with Manage Server permission
        .addSubcommand(subcommand =>
            subcommand
                .setName('enable')
                .setDescription('Enable or disable welcome messages for this server')
                .addBooleanOption(option =>
                    option
                        .setName('enabled')
                        .setDescription('Enable or disable welcome messages')
                        .setRequired(true)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('channel')
                .setDescription('Set the welcome message channel')
                .addChannelOption(option =>
                    option
                        .setName('channel')
                        .setDescription('Select the channel for welcome messages')
                        .setRequired(true)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('message')
                .setDescription('Set the welcome message template')
                .addStringOption(option =>
                    option
                        .setName('message')
                        .setDescription('The welcome message (use {member} as placeholder for the member mention)')
                        .setRequired(true)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('banner')
                .setDescription('Set the welcome banner image URL')
                .addStringOption(option =>
                    option
                        .setName('url')
                        .setDescription('The URL of the welcome banner image')
                        .setRequired(true)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('toggledm')
                .setDescription('Toggle sending welcome DMs to new members')
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('dmmessage')
                .setDescription('Set the welcome DM message template')
                .addStringOption(option =>
                    option
                        .setName('message')
                        .setDescription('Use {username} for username and {server} for server name')
                        .setRequired(true)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('color')
                .setDescription('Set the welcome embed color')
                .addStringOption(option =>
                    option
                        .setName('color')
                        .setDescription('Color in hex format (e.g. #5865F2)')
                        .setRequired(true)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('toggle')
                .setDescription('Toggle welcome features on/off')
                .addStringOption(option =>
                    option
                        .setName('feature')
                        .setDescription('Which feature to toggle')
                        .setRequired(true)
                        .addChoices(
                            { name: 'Show Member Count', value: 'membercount' },
                            { name: 'Show Join Date', value: 'joindate' },
                            { name: 'Show Account Age', value: 'accountage' }
                        )
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('title')
                .setDescription('Set custom title for welcome embeds')
                .addStringOption(option =>
                    option
                        .setName('title')
                        .setDescription('Custom title (leave empty to reset to default)')
                        .setRequired(false)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('footer')
                .setDescription('Set custom footer for welcome embeds')
                .addStringOption(option =>
                    option
                        .setName('footer')
                        .setDescription('Custom footer text (leave empty to reset to default)')
                        .setRequired(false)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('show')
                .setDescription('Show current welcome configuration')
        ),

    async execute(interaction) {
        // Check if the user has permission to manage the server
        if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
            return interaction.reply({
                content: 'You need the Manage Server permission to configure welcome settings!',
                ephemeral: true
            });
        }

        const subcommand = interaction.options.getSubcommand();
        const client = interaction.client;
        
        // Check if server settings manager is available
        if (!client.serverSettingsManager) {
            return interaction.reply({
                content: 'Server settings manager is not available. Please contact the bot owner.',
                ephemeral: true
            });
        }
        
        const guildId = interaction.guild.id;
        const serverSettings = client.serverSettingsManager.getGuildSettings(guildId);
        const welcomeSettings = client.serverSettingsManager.getWelcomeSettings(guildId);

        // Handle different subcommands
        switch (subcommand) {
            case 'enable':
                // Enable or disable welcome messages
                const enabled = interaction.options.getBoolean('enabled');
                
                // Update the setting
                client.serverSettingsManager.updateGuildSetting(guildId, 'welcomeEnabled', enabled);
                
                // Send success message
                const toggleEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome System Updated')
                    .setDescription(`Welcome messages have been ${enabled ? 'enabled' : 'disabled'} for this server.`).setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [toggleEmbed] });
                break;
                
            case 'channel':
                // Get the selected channel
                const channel = interaction.options.getChannel('channel');
                
                // Validate channel type
                if (channel.type !== 0) { // 0 is text channel
                    return interaction.reply({
                        content: 'Please select a text channel for welcome messages.',
                        ephemeral: true
                    });
                }
                
                // Update the setting
                client.serverSettingsManager.setWelcomeChannel(guildId, channel.id);
                
                // Send success message
                const channelEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome Channel Updated')
                    .setDescription(`Welcome messages will now be sent to <#${channel.id}>.`).setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [channelEmbed] });
                break;
                
            case 'message':
                // Get the new message
                const message = interaction.options.getString('message');
                
                // Update the setting
                client.serverSettingsManager.setWelcomeMessage(guildId, message);
                
                // Send success message
                const messageEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome Message Updated')
                    .setDescription('The welcome message has been updated.').setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [messageEmbed] });
                break;
                
            case 'banner':
                // Get the banner URL
                const url = interaction.options.getString('url');
                
                // Validate URL format
                if (!url.match(/^https?:\/\/.+\.(png|jpg|jpeg|gif)$/i)) {
                    return interaction.reply({
                        content: 'Please provide a valid image URL (ending with .png, .jpg, .jpeg, or .gif)',
                        ephemeral: true
                    });
                }
                
                // Update the setting
                client.serverSettingsManager.setWelcomeBanner(guildId, url);
                
                // Send success message with preview
                const bannerEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome Banner Updated')
                    .setDescription('The welcome banner has been updated.')
                    .setImage(url).setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [bannerEmbed] });
                break;
                
            case 'toggledm':
                // Toggle DM setting
                const newDmValue = client.serverSettingsManager.toggleWelcomeDm(guildId);
                
                // Send success message
                const dmEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome DMs Updated')
                    .setDescription(`Welcome DMs have been ${newDmValue ? 'enabled' : 'disabled'} for this server.`).setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [dmEmbed] });
                break;
                
            case 'dmmessage':
                // Get the new DM message
                const dmMessage = interaction.options.getString('message');
                
                // Update the setting
                client.serverSettingsManager.setWelcomeDmMessage(guildId, dmMessage);
                
                // Send success message
                const dmMessageEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome DM Message Updated')
                    .setDescription('The welcome DM message has been updated.').setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [dmMessageEmbed] });
                break;
                
            case 'color':
                // Get the color
                const color = interaction.options.getString('color');
                
                // Validate hex color format
                if (!color.match(/^#[0-9A-F]{6}$/i)) {
                    return interaction.reply({
                        content: 'Please provide a valid hex color code (e.g. #5865F2).',
                        ephemeral: true
                    });
                }
                
                // Update the setting
                client.serverSettingsManager.setWelcomeColor(guildId, color);
                
                // Send success message
                const colorEmbed = new EmbedBuilder()
                    .setColor(color)
                    .setTitle('✅ Welcome Color Updated')
                    .setDescription(`The welcome embed color has been set to ${color}.`).setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [colorEmbed] });
                break;
                
            case 'toggle':
                // Get feature to toggle
                const feature = interaction.options.getString('feature');
                let featureKey = '';
                let featureName = '';
                
                // Map feature value to setting key
                switch (feature) {
                    case 'membercount':
                        featureKey = 'welcomeShowMemberCount';
                        featureName = 'Member Count';
                        break;
                    case 'joindate':
                        featureKey = 'welcomeShowJoinDate';
                        featureName = 'Join Date';
                        break;
                    case 'accountage':
                        featureKey = 'welcomeShowAccountAge';
                        featureName = 'Account Age';
                        break;
                }
                
                // Toggle the feature
                const featureResult = client.serverSettingsManager.toggleWelcomeFeature(guildId, featureKey);
                
                // Get the new state
                const featureState = client.serverSettingsManager.getGuildSettings(guildId)[featureKey];
                
                // Send success message
                const featureEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome Feature Updated')
                    .setDescription(`The "${featureName}" feature is now ${featureState ? 'enabled' : 'disabled'}.`).setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [featureEmbed] });
                break;
                
            case 'title':
                // Get custom title
                const title = interaction.options.getString('title') || null;
                
                // Update the setting
                client.serverSettingsManager.updateGuildSetting(guildId, 'welcomeCustomTitle', title);
                
                // Send success message
                const titleEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome Title Updated')
                    .setDescription(title ? `Custom title set to: "${title}"` : 'Custom title has been reset to default.').setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [titleEmbed] });
                break;
                
            case 'footer':
                // Get custom footer
                const footer = interaction.options.getString('footer') || null;
                
                // Update the setting
                client.serverSettingsManager.updateGuildSetting(guildId, 'welcomeCustomFooter', footer);
                
                // Send success message
                const footerEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('✅ Welcome Footer Updated')
                    .setDescription(footer ? `Custom footer set to: "${footer}"` : 'Custom footer has been reset to default.').setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({ embeds: [footerEmbed] });
                break;
                
            case 'show':
                // Show current configuration                    
                const configEmbed = new EmbedBuilder()
                    .setColor(welcomeSettings.color || config.colors.primary)
                    .setTitle('🔧 Welcome Configuration')
                    .addFields(
                        { name: 'Status', value: welcomeSettings.enabled ? '✅ Enabled' : '❌ Disabled', inline: true },
                        { name: 'Welcome Channel', value: welcomeSettings.channelId 
                            ? `<#${welcomeSettings.channelId}>` 
                            : 'Auto (first available)', inline: true },
                        { name: 'Send DMs', value: welcomeSettings.dmEnabled ? '✅ Enabled' : '❌ Disabled', inline: true },
                        { name: 'Welcome Message', value: welcomeSettings.message || 'Default' },
                        { name: 'DM Message', value: welcomeSettings.dmMessage ? truncateString(welcomeSettings.dmMessage, 100) : 'Default' }
                    )
                    .addFields(
                        { name: 'Features', value: 
                            `- Member Count: ${welcomeSettings.showMemberCount ? '✅' : '❌'}\n` +
                            `- Join Date: ${welcomeSettings.showJoinDate ? '✅' : '❌'}\n` +
                            `- Account Age: ${welcomeSettings.showAccountAge ? '✅' : '❌'}`
                        },
                        { name: 'Custom Settings', value: 
                            `- Title: ${welcomeSettings.customTitle || 'Default'}\n` +
                            `- Footer: ${welcomeSettings.customFooter || 'Default'}\n` +
                            `- Color: ${welcomeSettings.color || 'Default'}`
                        }
                    ).setFooter({ text: 'Version 2.5.0' });
                    
                if (welcomeSettings.bannerUrl) {
                    configEmbed.setImage(welcomeSettings.bannerUrl);
                }
                
                await interaction.reply({ embeds: [configEmbed] });
                break;
        }
    },
};

// Helper function to truncate strings
function truncateString(str, maxLength) {
    if (str.length <= maxLength) return str;
    return str.slice(0, maxLength - 3) + '...';
}