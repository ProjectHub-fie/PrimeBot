const { SlashCommandBuilder, EmbedBuilder , PermissionFlagsBits} = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('addquestion')
        .setDescription('Add a new Truth or Dare question')
		.setDefaultMemberPermissions('0')
        
        .addStringOption(option => 
            option.setName('type')
                .setDescription('Type of question')
                .setRequired(true)
                .addChoices(
                    { name: 'Truth', value: 'truth' },
                    { name: 'Dare', value: 'dare' }
                ))
        .addStringOption(option => 
            option.setName('question')
                .setDescription('The question to add')
                .setRequired(true)
                .setMaxLength(500)),
    
    async execute(interaction) {
        try {
            const type = interaction.options.getString('type');
            const question = interaction.options.getString('question');
            
            // Add the question
            const success = interaction.client.truthDareManager.addQuestion(type, question);
            
            if (success) {
                const embed = new EmbedBuilder()
                    .setColor(config.colors.success)
                    .setTitle('Question Added')
                    .setDescription(`Your ${type === 'truth' ? 'Truth' : 'Dare'} question has been added!`)
                    .addFields({ name: 'Question', value: question }).setFooter({ text: 'Version 2.5.0' });
                
                await interaction.reply({
                    embeds: [embed],
                    ephemeral: false
                });
            } else {
                await interaction.reply({
                    content: 'Failed to add the question. It may already exist.',
                    ephemeral: false
                });
            }
            
        } catch (error) {
            console.error('Error adding Truth or Dare question:', error);
            await interaction.reply({
                content: 'There was an error adding the question! Please try again later.',
                ephemeral: false
            });
        }
    },
};