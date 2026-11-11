const { SlashCommandBuilder, EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

/**
 * /youtube — YouTube Notifications (Creator Hub).
 *
 * The feature is configured ENTIRELY from the PrimeBot dashboard (the 🎬 YouTube
 * tab under Server features): subscribing to creators, choosing the destination
 * channel, customizing the announcement embed and viewing history/health. This
 * command exists so admins who type `/youtube` in Discord are pointed at the
 * right place instead of getting an "unknown command" error — the same pattern
 * the Tickets feature uses. It does not modify any configuration.
 */

const DASHBOARD_NOTICE = '🎬 YouTube Notifications are configured from the PrimeBot dashboard (Server settings → 🎬 YouTube). There you can subscribe to creators, choose the announcement channel, customize the embed and view announcement history.';

function dashboardUrl() {
    const base = (config.website || process.env.DASHBOARD_BASE_URL || 'https://primebot-online.vercel.app').replace(/\/$/, '');
    return base;
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('youtube')
        .setDescription('YouTube upload notifications (configured from the dashboard)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
        .setDMPermission(false),

    async execute(interaction) {
        try {
            const url = dashboardUrl();
            const embed = new EmbedBuilder()
                .setColor(0xFF0000)
                .setTitle('🎬 YouTube Notifications')
                .setDescription(DASHBOARD_NOTICE)
                .addFields(
                    { name: '📺 What it does', value: 'Announces new uploads from any public YouTube channel — no API key required. Existing videos are never announced; only new uploads after you subscribe.', inline: false },
                    { name: '🎛️ Configure it', value: `[Open the PrimeBot dashboard](${url})`, inline: false },
                )
                .setFooter({ text: `PrimeBot v${config.version}` })
                .setTimestamp();

            const button = new ButtonBuilder()
                .setLabel('Open dashboard')
                .setStyle(ButtonStyle.Link)
                .setURL(url);

            return interaction.reply({
                embeds: [embed],
                components: [new ActionRowBuilder().addComponents(button)],
                ephemeral: true,
            });
        } catch (error) {
            console.error('[YOUTUBE] Command failed:', error);
            if (!interaction.replied && !interaction.deferred) {
                return interaction.reply({ content: 'YouTube notifications are configured from the PrimeBot dashboard.', ephemeral: true }).catch(() => {});
            }
        }
    },
};
