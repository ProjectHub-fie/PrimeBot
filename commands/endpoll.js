const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('endpoll')
        .setDescription('End a poll early')
                .setDefaultMemberPermissions('0')
        .addStringOption(option => 
            option.setName('message_id')
                .setDescription('The message ID of the poll to end')
                .setRequired(true))
        ,
    
    async execute(interaction) {
        try {
            // Check permissions
            if (!interaction.member.permissions.has(PermissionFlagsBits.ManageMessages)) {
                return interaction.reply({ 
                    content: 'You need the Manage Messages permission to end polls early!', 
                    ephemeral: false 
                });
            }
            
            const messageId = interaction.options.getString('message_id');
            
            // End the poll
            const success = await interaction.client.pollManager.forceEndPoll(messageId);
            
            if (success) {
                const successEmbed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('📊 Poll Ended')
                    .setDescription('The poll has been ended successfully!')
                    .addFields(
                        { name: '📝 Poll ID', value: `\`${messageId}\`` },
                        { name: '📣 Note', value: 'The poll results have been posted in the channel where the poll was created.' }
                    )
                    .setFooter({ 
                        text: 'Poll ended by ' + interaction.user.tag, 
                        iconURL: interaction.user.displayAvatarURL({ dynamic: true }) 
                    })
                    .setTimestamp();
                
                await interaction.reply({ 
                    embeds: [successEmbed],
                    ephemeral: false 
                });
            } else {
                const errorEmbed = new EmbedBuilder()
                    .setColor(config.colors.error)
                    .setTitle('❌ Error Ending Poll')
                    .setDescription('Could not end the poll with the provided ID.')
                    .addFields(
                        { name: '📝 Poll ID', value: `\`${messageId}\`` },
                        { name: '🔍 Possible Reasons', value: '• The poll ID is incorrect\n• The poll has already ended\n• The poll was deleted\n• The poll belongs to a different server' }
                    )
                    .setFooter({ text: 'Use /poll to create a new poll • Version 2.5.0', iconURL: interaction.client.user.displayAvatarURL()
                     });
                
                await interaction.reply({ 
                    embeds: [errorEmbed], 
                    ephemeral: false 
                });
            }
        } catch (error) {
            console.error('Error ending poll:', error);
            await interaction.reply({ 
                content: 'There was an error ending the poll! Please try again later.', 
                ephemeral: false 
            });
        }
    },
};