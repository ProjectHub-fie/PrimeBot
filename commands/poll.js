const { SlashCommandBuilder, EmbedBuilder , PermissionFlagsBits} = require('discord.js');
const ms = require('ms');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('poll')
        .setDescription('Create a timed poll with options')
                .setDefaultMemberPermissions('0')
        
        .addStringOption(option => 
            option.setName('duration')
                .setDescription('Duration of the poll (e.g., 1h, 1d)')
                .setRequired(true))
        .addStringOption(option => 
            option.setName('question')
                .setDescription('The question for the poll')
                .setRequired(true))
        .addStringOption(option => 
            option.setName('option1')
                .setDescription('First poll option')
                .setRequired(true))
        .addStringOption(option => 
            option.setName('option2')
                .setDescription('Second poll option')
                .setRequired(true))
        .addStringOption(option => 
            option.setName('option3')
                .setDescription('Third poll option (optional)')
                .setRequired(false))
        .addStringOption(option => 
            option.setName('option4')
                .setDescription('Fourth poll option (optional)')
                .setRequired(false))
        .addStringOption(option => 
            option.setName('option5')
                .setDescription('Fifth poll option (optional)')
                .setRequired(false)),
    
    async execute(interaction) {
        try {
            // Parse command options
            const durationStr = interaction.options.getString('duration');
            const question = interaction.options.getString('question');
            
            // Collect options from separate fields
            const options = [];
            for (let i = 1; i <= 5; i++) {
                const option = interaction.options.getString(`option${i}`);
                if (option) {
                    options.push(option.trim());
                }
            }
            
            // Validate options
            if (options.length < 2) {
                return interaction.reply({
                    content: 'You need to provide at least 2 options for the poll.',
                    ephemeral: false
                });
            }
            
            // Parse duration
            const duration = ms(durationStr);
            
            if (!duration || isNaN(duration)) {
                return interaction.reply({
                    content: 'Please provide a valid duration (e.g., 1h, 1d).',
                    ephemeral: false
                });
            }
            
            // Minimum duration of 10 seconds
            if (duration < 10000) {
                return interaction.reply({
                    content: 'Poll duration must be at least 10 seconds.',
                    ephemeral: false
                });
            }
            
            // Create the poll
            const pollMessage = await interaction.client.pollManager.createPoll({
                channelId: interaction.channel.id,
                question,
                options,
                duration,
                userId: interaction.user.id
            });
            
            // Confirm to the user
            const confirmEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Poll Created')
                .setDescription(`Your poll has been created in ${interaction.channel}!`)
                .addFields(
                    { name: '❓ Question', value: question },
                    { name: '⏱️ Duration', value: `Poll will end in **${durationStr}** (<t:${Math.floor((Date.now() + duration) / 1000)}:R>)` },
                    { name: '🔢 Options', value: options.map((opt, i) => `${interaction.client.pollManager.getOptionEmoji(i)} **${opt}**`).join('\n') },
                    { name: '📝 Poll ID', value: `\`${pollMessage.id}\` *(Save this ID if you need to end the poll early with \`/endpoll\`)*` }
                )
                .setFooter({ text: 'Created by ${interaction.user.tag} • Version 2.5.0', iconURL: interaction.user.displayAvatarURL({ dynamic: true  }) 
                })
                .setTimestamp();
            
            await interaction.reply({
                embeds: [confirmEmbed],
                ephemeral: false
            });
            
        } catch (error) {
            console.error('Error creating poll:', error);
            await interaction.reply({
                content: 'There was an error creating the poll! Please try again later.',
                ephemeral: false
            });
        }
    },
};