const { SlashCommandBuilder, EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder } = require('discord.js');
const config = require('../config');

/**
 * /invite — shows an embed with the bot's invite link so server admins can add
 * PrimeBot (with administrator permissions and slash commands) to their server.
 *
 * Slash-only (per request). The invite URL is also surfaced as a link button on
 * the embed and on the dashboard login screen.
 */

// The bot's public invite link. Kept in one place (dashboard/constants.js also
// mirrors it) so it never drifts between the command and the dashboard.
const BOT_INVITE_URL = 'https://discord.com/oauth2/authorize?client_id=1356575287151951943&permissions=8&integration_type=0&scope=bot%20applications.commands';

module.exports = {
    data: new SlashCommandBuilder()
        .setName('invite')
        .setDescription('Get the PrimeBot invite link to add it to your server'),

    async execute(interaction) {
        try {
            const embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('➕ Invite PrimeBot')
                .setDescription(
                    'Add **PrimeBot** to your server to unlock premium features for free — leveling, welcome messages, reaction roles, automod, tickets, giveaways and more.'
                )
                .addFields(
                    { name: '🔗 Invite Link', value: `[Click here to invite PrimeBot](${BOT_INVITE_URL})`, inline: false },
                    { name: '🛡️ Permissions', value: 'Administrator (recommended for full feature access)', inline: true },
                    { name: '⚡ Scope', value: 'bot + application.commands (slash commands)', inline: true },
                    { name: '🏠 Dashboard', value: `[PrimeBot Dashboard](${config.website || 'https://primebot-online.vercel.app/'})`, inline: false },
                    { name: '🆘 Support', value: `[Join our support server](${config.supportServer || 'https://discord.gg/primebot'})`, inline: false }
                )
                .setFooter({ text: `Version ${config.version}` })
                .setTimestamp();

            const inviteButton = new ButtonBuilder()
                .setLabel('Invite PrimeBot')
                .setStyle(ButtonStyle.Link)
                .setURL(BOT_INVITE_URL)
                .setEmoji('➕');

            const row = new ActionRowBuilder().addComponents(inviteButton);

            return interaction.reply({ embeds: [embed], components: [row] });
        } catch (error) {
            console.error('[INVITE] Command failed:', error);
            if (!interaction.replied && !interaction.deferred) {
                return interaction.reply({
                    content: 'There was an error generating the invite link.',
                    ephemeral: true,
                }).catch(() => {});
            }
        }
    },
};
