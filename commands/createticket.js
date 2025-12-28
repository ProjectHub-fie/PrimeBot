const { SlashCommandBuilder , PermissionFlagsBits} = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('createticket')
        .setDescription('Create a ticket with a custom name')
		.setDefaultMemberPermissions('0')
        
        .addStringOption(option => 
            option.setName('name')
                .setDescription('Custom name for the ticket')
                .setRequired(true)),
    
    async execute(interaction) {
        // Command version: 2.5.0
        try {
            const ticketName = interaction.options.getString('name');
            
            // Create the ticket
            await interaction.client.ticketManager.handleTicketCreation(interaction, ticketName);
            
        } catch (error) {
            console.error('Error creating ticket:', error);
            await interaction.reply({ 
                content: 'There was an error creating your ticket! Please try again later.', 
                ephemeral: false 
            });
        }
    },
};