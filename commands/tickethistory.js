const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('tickethistory')
        .setDescription('View ticket history')
		.setDefaultMemberPermissions('0')
        .addIntegerOption(option => 
            option.setName('page')
                .setDescription('Page number to view')
                .setRequired(false)
                .setMinValue(1))
        ,
    
    async execute(interaction) {
        try {
            // Check permissions
            if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                return interaction.reply({ 
                    content: 'You need the Manage Server permission to view ticket history!', 
                    ephemeral: false 
                });
            }
            
            const page = interaction.options.getInteger('page') || 1;
            const pageSize = 10;
            
            // Get ticket history
            const ticketHistory = interaction.client.ticketManager.getTicketHistory(interaction.guild.id);
            
            if (!ticketHistory || ticketHistory.length === 0) {
                return interaction.reply('There are no closed tickets in the history.');
            }
            
            // Calculate pagination
            const maxPage = Math.ceil(ticketHistory.length / pageSize);
            const startIndex = (page - 1) * pageSize;
            const endIndex = Math.min(startIndex + pageSize, ticketHistory.length);
            
            if (page > maxPage) {
                return interaction.reply({ 
                    content: `Invalid page number. There are only ${maxPage} pages.`, 
                    ephemeral: false 
                });
            }
            
            // Get tickets for current page
            const tickets = ticketHistory.slice(startIndex, endIndex);
            
            // Create the embed
            const embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('Ticket History')
                .setDescription(tickets.map((ticket, index) => {
                    const createdDate = new Date(ticket.createdAt).toLocaleString();
                    const closedDate = new Date(ticket.closedAt).toLocaleString();
                    return `**${startIndex + index + 1}. Ticket #${ticket.number} - ${ticket.username}**
                    • ID: \`${ticket.id}\`
                    • Created: ${createdDate}
                    • Closed: ${closedDate}
                    • Closed by: ${ticket.closedBy}`;
                }).join('\n\n'))
                .setFooter({ text: `Page ${page}/${maxPage} • Total tickets: ${ticketHistory.length} • Version 2.5.0` });
            
            await interaction.reply({ embeds: [embed] });
            
        } catch (error) {
            console.error('Error viewing ticket history:', error);
            await interaction.reply({ 
                content: 'There was an error viewing the ticket history! Please try again later.', 
                ephemeral: false 
            });
        }
    },
};