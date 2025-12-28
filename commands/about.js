const { SlashCommandBuilder, EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder , PermissionFlagsBits} = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('about')
        .setDescription('Display information about the bot')
                .setDefaultMemberPermissions('0')
        ,
    
    async execute(interaction) {
        try {
            // Calculate uptime
            const uptime = process.uptime();
            function formatUptime(uptime) {
                const seconds = Math.floor(uptime % 60);
                const minutes = Math.floor((uptime / 60) % 60);
                const hours = Math.floor((uptime / 3600) % 24);
                const days = Math.floor(uptime / 86400);
        
                const parts = [];
                if (days > 0) parts.push(`${days}d`);
                if (hours > 0) parts.push(`${hours}h`);
                if (minutes > 0) parts.push(`${minutes}m`);
                if (seconds > 0) parts.push(`${seconds}s`);
        
                return parts.join(" ") || "0s";
            }
            const uptimeString = formatUptime(uptime);
            
            // Get guild count
            const guildCount = interaction.client.guilds.cache.size;
            
            // Create buttons
            const inviteButton = new ButtonBuilder()
                .setLabel("Invite Me")
                .setStyle(ButtonStyle.Link)
                .setURL(
                    `https://discord.com/api/oauth2/authorize?client_id=${interaction.client.user.id}&permissions=274878024704&scope=bot%20applications.commands`
                );
                
            const supportServerButton = new ButtonBuilder()
                .setLabel("Support Server")
                .setStyle(ButtonStyle.Link)
                .setURL(config.supportServer);
            
            const row = new ActionRowBuilder().addComponents(inviteButton, supportServerButton);
            
            // Create embed
            const embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle(`About ${interaction.client.user.username}`)
                .setDescription(
                    "A feature-rich Discord bot designed to enhance server management and user engagement through interactive commands, giveaway management, and much more!"
                )
                .addFields(
                    {
                        name: "🛠️ Features",
                        value: 
                            "• Giveaway Management\n" +
                            "• Support Ticket System\n" +
                            "• Birthday Celebrations\n" +
                            "• Interactive Games\n" +
                            "• Polls and Voting\n" +
                            "• Custom Emojis\n" +
                            "• And more...",
                        inline: true
                    },
                    {
                        name: "📊 Statistics",
                        value: 
                            `• Servers: ${guildCount}\n` +
                            `• Uptime: ${uptimeString}\n` +
                            `• Version: ${config.version}`,
                        inline: true
                    },
                    {
                        name: "🔗 Links",
                        value: 
                            "• [Invite Bot](https://discord.com/api/oauth2/authorize?client_id=" + 
                            interaction.client.user.id + 
                            "&permissions=274878024704&scope=bot%20applications.commands)\n" +
                            "• [Support Server](" + config.supportServer + ")",
                        inline: false
                    }
                )
                .setThumbnail(interaction.client.user.displayAvatarURL({ dynamic: true }))
                .setFooter({ text: `Requested by ${interaction.user.tag} • Version ${config.version}`, iconURL: interaction.user.displayAvatarURL({ dynamic: true })
                })
                .setTimestamp();
            
            await interaction.reply({
                embeds: [embed],
                components: [row]
            });
            
        } catch (error) {
            console.error('Error displaying about information:', error);
            await interaction.reply({
                content: 'There was an error displaying the information! Please try again later.',
                ephemeral: false
            });
        }
    },
};