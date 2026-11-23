const { SlashCommandBuilder, MessageFlags } = require('discord.js');
const { buildServerInfoEmbed } = require('../utils/serverInfoEmbed');

/**
 * /si — server information (owner, members, channels, roles, boosts, creation).
 * The prefix equivalent is `$si` (alias `$serverinfo`).
 */
module.exports = {
    data: new SlashCommandBuilder()
        .setName('si')
        .setDescription('Show information about this server')
        .setDMPermission(false),

    async execute(interaction) {
        if (!interaction.guild) {
            return interaction.reply({
                content: 'This command only works inside a server.',
                flags: MessageFlags.Ephemeral,
            }).catch(() => {});
        }
        try {
            await interaction.reply({ embeds: [buildServerInfoEmbed(interaction.guild)] });
        } catch (error) {
            console.error('[SI] Command failed:', error);
            if (!interaction.replied && !interaction.deferred) {
                await interaction.reply({
                    content: 'There was an error showing the server information.',
                    flags: MessageFlags.Ephemeral,
                }).catch(() => {});
            }
        }
    },
};
