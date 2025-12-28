const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');
const { logCommandExecution, logError } = require('../utils/logUtils');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('echo')
        .setDescription('Make the bot repeat a message')
        .addStringOption(option => 
            option.setName('message')
                .setDescription('The message to repeat')
                .setRequired(true))
        .addChannelOption(option => 
            option.setName('channel')
                .setDescription('The channel to echo in (defaults to current channel)')
                .setRequired(false))
        .addBooleanOption(option => 
            option.setName('embed')
                .setDescription('Whether to send the message as an embed (defaults to false)')
                .setRequired(false))
        // No default permission requirement - accessible to all users
        .setDMPermission(false), // Disable in DMs for security
    
    async execute(interaction) {
        try {
            console.log('DEBUG: Echo command execution started');
            
            // Get command options
            const message = interaction.options.getString('message');
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            const useEmbed = interaction.options.getBoolean('embed') || false;
            
            console.log(`DEBUG: Echo command options - Message: ${message.substring(0, 20)}..., Channel: ${channel.name}, Embed: ${useEmbed}`);
            
            // Check if the bot can send messages in the target channel
            const botPermissions = channel.permissionsFor(interaction.client.user);
            
            console.log(`DEBUG: Bot permissions in channel ${channel.name}: ${botPermissions ? 'Permissions found' : 'No permissions'}`);
            
            if (!botPermissions || !botPermissions.has('SendMessages')) {
                console.log(`DEBUG: Bot doesn't have permission to send messages in ${channel.name}`);
                return interaction.reply({ 
                    content: `I don't have permission to send messages in ${channel}.`, 
                    ephemeral: false 
                });
            }
            
            // Send the echo message
            console.log(`DEBUG: Attempting to send echo message to ${channel.name}`);
            
            if (useEmbed) {
                // Create embed
                const echoEmbed = new EmbedBuilder()
                    .setColor(config.colors.primary)
                    .setDescription(message)
                    .setFooter({ text: 'Echoed by ${interaction.user.tag} • Version 2.5.0', iconURL: interaction.user.displayAvatarURL({ dynamic: true  }) 
                    })
                    .setTimestamp();
                
                await channel.send({ embeds: [echoEmbed] });
                console.log(`DEBUG: Sent embed message to ${channel.name}`);
            } else {
                await channel.send(message);
                console.log(`DEBUG: Sent text message to ${channel.name}`);
            }
            
            // Confirm to the user
            await interaction.reply({ 
                content: `Message has been echoed in ${channel}.`, 
                ephemeral: false 
            });
            
            console.log('DEBUG: Echo command completed successfully');
            
        } catch (error) {
            logError('Echo command', error);
            console.error('DEBUG: Error executing echo command:', error);
            
            try {
                if (!interaction.replied && !interaction.deferred) {
                    await interaction.reply({ 
                        content: 'There was an error executing the command! Please try again later.', 
                        ephemeral: false 
                    });
                } else {
                    await interaction.followUp({
                        content: 'There was an error executing the command! Please try again later.',
                        ephemeral: false
                    });
                }
            } catch (replyError) {
                console.error('DEBUG: Error sending error response:', replyError);
            }
        }
    },
};