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
                .setTitle(`Update Log • Version ${config.version}`)
                .setDescription(
                    "PrimeBot has been extended with developer-only no-prefix management and a moderation cleanup command.",
                )
                .addFields(
                    {
                        name: "✅ Recent Updates",
                        value:
                            "• Added the developer-only `/np` command for selected users to use commands without a prefix\n" +
                            "• Added `np add`, `np remove`, and `np status` developer flow through the no-prefix server settings table\n" +
                            "• Added the `/purge` moderation command with `messages`, `user`, and `between` subcommands\n" +
                            "• Added prefix-command support for `$purge` to mirror the slash command privacy and permissions model\n" +
                            "• Refreshed the category browser and moderation help view so purge is discoverable",
                    },
                    { 
                        name: '🔜 Planned Work', 
                        value: 
                            '• More role-based automation\n' +
                            '• Additional moderation audit polish\n' +
                            '• Performance and reliability improvements'
                    },
                )
                .setFooter({ text: `Current Version: ${config.version}`, iconURL: interaction.client.user.displayAvatarURL() })
                .setTimestamp();
                
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