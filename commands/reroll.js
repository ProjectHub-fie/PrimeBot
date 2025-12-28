const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('reroll')
        .setDescription('Reroll a giveaway to select new winners')
		.setDefaultMemberPermissions('0')
        .addStringOption(option => 
            option.setName('message_id')
                .setDescription('The message ID of the giveaway to reroll')
                .setRequired(true))
        ,
    
    async execute(interaction) {
        // Command version: 2.5.0
        try {
            // Check permissions
            if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                return interaction.reply({ 
                    content: 'You need the Manage Server permission to reroll giveaways!', 
                    ephemeral: false 
                });
            }

            const messageId = interaction.options.getString('message_id');
            
            // Reroll the giveaway
            const success = await interaction.client.giveawayManager.rerollGiveaway(messageId);
            
            if (success) {
                await interaction.reply({ 
                    content: 'Giveaway rerolled successfully!', 
                    ephemeral: false 
                });
            } else {
                await interaction.reply({ 
                    content: 'Could not find a completed giveaway with that message ID.', 
                    ephemeral: false 
                });
            }
        } catch (error) {
            console.error('Error rerolling giveaway:', error);
            await interaction.reply({ 
                content: 'There was an error rerolling the giveaway! Please try again later.', 
                ephemeral: false 
            });
        }
    },
};
