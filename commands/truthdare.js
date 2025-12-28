const { SlashCommandBuilder , PermissionFlagsBits} = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('truthdare')
        .setDescription('Start a Truth or Dare game in the current channel')
		.setDefaultMemberPermissions('0')
        ,
    
    async execute(interaction) {
        // Command version: 2.5.0
        try {
            // Start the game
            await interaction.client.truthDareManager.startGame(interaction.channel);
            
            // Reply to the user
            await interaction.reply(`${interaction.user} has started a Truth or Dare game! Click the buttons to play.`);
            
        } catch (error) {
            console.error('Error starting Truth or Dare game:', error);
            await interaction.reply({
                content: 'There was an error starting the game! Please try again later.',
                ephemeral: false
            });
        }
    },
};