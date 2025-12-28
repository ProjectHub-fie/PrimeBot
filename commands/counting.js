const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('counting')
        .setDescription('Manage counting games')
		.setDefaultMemberPermissions('0')
        
        .addSubcommand(subcommand =>
            subcommand
                .setName('start')
                .setDescription('Start a new counting game in the current channel')
                .addIntegerOption(option => 
                    option.setName('start_number')
                        .setDescription('Starting number (default: 1)')
                        .setRequired(false))
                .addIntegerOption(option => 
                    option.setName('goal')
                        .setDescription('Goal number to reach (default: 100)')
                        .setRequired(false)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('status')
                .setDescription('Check the status of the current counting game'))
        .addSubcommand(subcommand =>
            subcommand
                .setName('end')
                .setDescription('End the current counting game'))
        .addSubcommand(subcommand =>
            subcommand
                .setName('help')
                .setDescription('Show help information for the counting game')),
    
    async execute(interaction) {
        try {
            const subcommand = interaction.options.getSubcommand();
            const countingManager = interaction.client.countingManager;
            
            switch (subcommand) {
                case 'start': {
                    // Check permissions
                    if (!interaction.member.permissions.has(PermissionFlagsBits.ManageChannels)) {
                        return interaction.reply({
                            content: 'You need the Manage Channels permission to start counting games!',
                            ephemeral: false
                        });
                    }
                    
                    // Check if there's already a game in this channel
                    const existingGame = countingManager.getCountingStatus(interaction.channel.id);
                    if (existingGame) {
                        return interaction.reply({
                            content: 'There is already a counting game in this channel. End it first with `/counting end`.',
                            ephemeral: false
                        });
                    }
                    
                    // Get options
                    const startNumber = interaction.options.getInteger('start_number') || 1;
                    const goalNumber = interaction.options.getInteger('goal') || 100;
                    
                    // Validate numbers
                    if (startNumber < 0) {
                        return interaction.reply({
                            content: 'The starting number must be 0 or greater.',
                            ephemeral: false
                        });
                    }
                    
                    if (goalNumber <= startNumber) {
                        return interaction.reply({
                            content: 'The goal number must be greater than the starting number.',
                            ephemeral: false
                        });
                    }
                    
                    if (goalNumber > 1000000) {
                        return interaction.reply({
                            content: 'The goal number cannot be greater than 1,000,000.',
                            ephemeral: false
                        });
                    }
                    
                    // Start the game
                    const game = await countingManager.startCountingGame({
                        channelId: interaction.channel.id,
                        startNumber,
                        goalNumber
                    });
                    
                    if (game) {
                        // Create embed for the game
                        const embed = countingManager.createCountingEmbed(game);
                        await interaction.reply({ embeds: [embed] });
                    } else {
                        await interaction.reply({
                            content: 'Failed to start the counting game. Please try again later.',
                            ephemeral: false
                        });
                    }
                    
                    break;
                }
                
                case 'status': {
                    // Check if there's a game in this channel
                    const game = countingManager.getCountingStatus(interaction.channel.id);
                    
                    if (!game) {
                        return interaction.reply({
                            content: 'There is no active counting game in this channel.',
                            ephemeral: false
                        });
                    }
                    
                    // Create embed for the game
                    const embed = countingManager.createCountingEmbed(game);
                    await interaction.reply({ embeds: [embed] });
                    
                    break;
                }
                
                case 'end': {
                    // Check permissions
                    if (!interaction.member.permissions.has(PermissionFlagsBits.ManageChannels)) {
                        return interaction.reply({
                            content: 'You need the Manage Channels permission to end counting games!',
                            ephemeral: false
                        });
                    }
                    
                    // Check if there's a game in this channel
                    const game = countingManager.getCountingStatus(interaction.channel.id);
                    
                    if (!game) {
                        return interaction.reply({
                            content: 'There is no active counting game in this channel.',
                            ephemeral: false
                        });
                    }
                    
                    // End the game
                    const success = countingManager.endCountingGame(interaction.channel.id);
                    
                    if (success) {
                        await interaction.reply('The counting game has been ended.');
                    } else {
                        await interaction.reply({
                            content: 'Failed to end the counting game. Please try again later.',
                            ephemeral: false
                        });
                    }
                    
                    break;
                }
                
                case 'help': {
                    // Show help information
                    const embed = countingManager.createHelpEmbed();
                    await interaction.reply({ embeds: [embed] });
                    
                    break;
                }
            }
            
        } catch (error) {
            console.error('Error handling counting command:', error);
            await interaction.reply({
                content: 'There was an error executing the command! Please try again later.',
                ephemeral: false
            });
        }
    },
};