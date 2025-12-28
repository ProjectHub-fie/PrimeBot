const { SlashCommandBuilder, EmbedBuilder , PermissionFlagsBits} = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('updates')
        .setDescription('Show recent updates and upcoming features')
		.setDefaultMemberPermissions('0')
        ,
    
    async execute(interaction) {
        try {
            // Create update log embed
            const updateEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle("Update Log | Updated on 14/04/2025")
                .setDescription(
                    "Keep track of the latest updates and upcoming features!",
                )
                .addFields(
                    {
                        name: "✅ Recent Updates",
                        value:
                            "• Added custom ticket names with the /createticket command\n" +
                            "• Added developer broadcast system\n" +
                            "• Added Birthday celebration system with /birthday commands\n" +
                            "• Added Poll system with /poll and /endpoll commands\n" +
                            "• Added Multiplayer TicTacToe game with /tictactoe, /move, and /endgame commands\n" +
                            "• Added ticket system for support requests\n" +
                            "• Added slash commands support for all features",
                    },
                    { 
                        name: '🔜 Coming Soon', 
                        value: 
                            '• Leveling system\n' +
                            '• Custom reaction roles\n' +
                            '• Server statistics tracking\n' +
                            '• Auto-responses for common questions'
                    },
                )
                .setFooter({ text: 'Version 2.5.0', iconURL: this.client?.user?.displayAvatarURL() || client?.user?.displayAvatarURL() }).setTimestamp()
                .setFooter({
                    text: `Current Version: 1.1.0`,
                    iconURL: interaction.client.user.displayAvatarURL()
                });
                
            await interaction.reply({ embeds: [updateEmbed] });
            
        } catch (error) {
            console.error('Error displaying updates:', error);
            await interaction.reply({
                content: 'There was an error displaying the update information! Please try again later.',
                ephemeral: false
            });
        }
    },
};