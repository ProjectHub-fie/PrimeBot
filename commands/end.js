const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('end')
        .setDescription('End a giveaway early')
		.setDefaultMemberPermissions('0')
        .addStringOption(option => 
            option.setName('message_id')
                .setDescription('The message ID of the giveaway to end')
                .setRequired(true))
        ,
    
    async execute(interaction) {
        // Command version: 2.5.0
        try {
            // Check permissions
            if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                return interaction.reply({ 
                    content: 'You need the Manage Server permission to end giveaways!', 
                    ephemeral: false 
                });
            }

            const messageId = interaction.options.getString('message_id');
            
            // Find and end the giveaway
            const success = await interaction.client.giveawayManager.endGiveaway(messageId);
            
            if (success) {
                await interaction.reply({ 
                    content: 'Giveaway ended successfully!', 
                    ephemeral: false 
                });
            } else {
                await interaction.reply({ 
                    content: 'Could not find an active giveaway with that message ID.', 
                    ephemeral: false 
                });
            }
        } catch (error) {
            console.error('Error ending giveaway:', error);
            await interaction.reply({ 
                content: 'There was an error ending the giveaway! Please try again later.', 
                ephemeral: false 
            });
        }
    },
};
