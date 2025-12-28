const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');
const ms = require('ms');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('giveaway')
        .setDescription('Create a new giveaway')
                .setDefaultMemberPermissions('0')
        .addStringOption(option => 
            option.setName('duration')
                .setDescription('Duration of the giveaway (1m, 1h, 1d, etc.)')
                .setRequired(true))
        .addIntegerOption(option => 
            option.setName('winners')
                .setDescription('Number of winners')
                .setRequired(true)
                .setMinValue(1)
                .setMaxValue(10))
        .addStringOption(option => 
            option.setName('prize')
                .setDescription('The prize for the giveaway')
                .setRequired(true))
        .addChannelOption(option => 
            option.setName('channel')
                .setDescription('The channel to start the giveaway in')
                .setRequired(false))
        .addStringOption(option =>
            option.setName('thumbnail')
                .setDescription('Optional URL for giveaway thumbnail image')
                .setRequired(false))
        .addStringOption(option =>
            option.setName('description')
                .setDescription('Optional description/details for the giveaway')
                .setRequired(false))
        .addRoleOption(option =>
            option.setName('requiredrole')
                .setDescription('Optional role required to enter the giveaway')
                .setRequired(false)),
    
    async execute(interaction) {
        try {
            // Defer the reply immediately to prevent timeout
            await interaction.deferReply({ ephemeral: false });

            // Check if user has permission
            if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                return interaction.editReply({ 
                    content: 'You need the Manage Server permission to create giveaways!'
                });
            }

            // Parse command options
            const duration = interaction.options.getString('duration');
            const winnerCount = interaction.options.getInteger('winners');
            const prize = interaction.options.getString('prize');
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            const thumbnail = interaction.options.getString('thumbnail');
            const description = interaction.options.getString('description');
            const requiredRole = interaction.options.getRole('requiredrole');

            // Convert duration to milliseconds
            const ms_duration = ms(duration);
            
            if (!ms_duration) {
                return interaction.editReply({ 
                    content: 'Please provide a valid duration format (e.g., 1m, 1h, 1d)!'
                });
            }

            // Validate thumbnail URL if provided
            if (thumbnail) {
                try {
                    new URL(thumbnail);
                } catch (e) {
                    return interaction.editReply({ 
                        content: 'Please provide a valid URL for the thumbnail image!'
                    });
                }
            }

            // Create detailed response embed
            const detailsEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('🎉 Giveaway Created')
                .setDescription(`Your giveaway for **${prize}** has been started!`)
                .addFields(
                    { name: '🏆 Prize', value: prize, inline: true },
                    { name: '👥 Winners', value: winnerCount.toString(), inline: true },
                    { name: '⏱️ Duration', value: duration, inline: true },
                    { name: '📣 Channel', value: `<#${channel.id}>`, inline: true },
                )
                .setFooter({ text: 'Version 2.5.0', iconURL: this.client?.user?.displayAvatarURL() || client?.user?.displayAvatarURL() }).setTimestamp();

            // Add required role to embed if specified
            if (requiredRole) {
                detailsEmbed.addFields(
                    { name: '🎭 Required Role', value: `${requiredRole}`, inline: true }
                );
            }

            // Create giveaway with additional options if provided
            const giveawayOptions = {
                channelId: channel.id,
                duration: ms_duration,
                prize,
                winnerCount,
                thumbnail: thumbnail || null,
                description: description || null,
                requiredRoleId: requiredRole?.id || null
            };

            const giveaway = await interaction.client.giveawayManager.startGiveaway(giveawayOptions);

            await interaction.editReply({ 
                embeds: [detailsEmbed]
            });
            
        } catch (error) {
            console.error('Error creating giveaway:', error);
            if (interaction.deferred) {
                await interaction.editReply({ 
                    content: 'There was an error creating the giveaway! Please try again later.'
                });
            } else {
                await interaction.reply({ 
                    content: 'There was an error creating the giveaway! Please try again later.', 
                    ephemeral: false 
                });
            }
        }
    },
};
