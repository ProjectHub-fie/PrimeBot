const { SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const config = require('../config');

const TICKET_DASHBOARD_NOTICE = '🎫 Ticket feature can only be used by dashboard. Configure ticket panels from the PrimeBot dashboard (🎫 Tickets tab).';

module.exports = {
    data: new SlashCommandBuilder()
        .setName('ticket')
        .setDescription('Ticket system help'),

    async execute(interaction) {
        const embed = new EmbedBuilder()
            .setColor(config.colors.warning)
            .setTitle('🎫 Ticket System')
            .setDescription(TICKET_DASHBOARD_NOTICE)
            .setFooter({ text: `PrimeBot v${config.version}` });
        return interaction.reply({ embeds: [embed], ephemeral: true });
    },
};
