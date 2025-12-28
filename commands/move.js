const { SlashCommandBuilder , PermissionFlagsBits} = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('move')
        .setDescription('Make a move in the tic-tac-toe game')
		.setDefaultMemberPermissions('0')
        
        .addIntegerOption(option => 
            option.setName('position')
                .setDescription('Position to place your marker (1-9)')
                .setRequired(true)
                .setMinValue(1)
                .setMaxValue(9)),
    
    async execute(interaction) {
        // Command version: 2.5.0
        try {
            const position = interaction.options.getInteger('position');
            
            // Make the move
            const result = await interaction.client.ticTacToeManager.makeMove({
                channelId: interaction.channel.id,
                playerId: interaction.user.id,
                position
            });
            
            // Check result
            if (!result) {
                return interaction.reply({
                    content: 'There was an error making your move. Make sure there is an active game and it\'s your turn.',
                    ephemeral: false
                });
            }
            
            // Success response
            await interaction.reply(`${interaction.user} placed their marker at position ${position}!`);
            
        } catch (error) {
            console.error('Error making TicTacToe move:', error);
            await interaction.reply({
                content: 'There was an error making your move! Please try again later.',
                ephemeral: false
            });
        }
    },
};