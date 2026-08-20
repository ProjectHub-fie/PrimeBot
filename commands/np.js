const { SlashCommandBuilder } = require('discord.js');
const config = require('../config');
const npEmbed = require('../utils/npEmbed');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('np')
        .setDescription('Developer-only no-prefix command using the main database')
        .setDefaultMemberPermissions('0')
        .addStringOption(option =>
            option.setName('action')
                .setDescription('What to do with no-prefix mode')
                .setRequired(true)
                .addChoices(
                    { name: 'Add', value: 'add' },
                    { name: 'Remove', value: 'remove' },
                    { name: 'Enable', value: 'enable' },
                    { name: 'Disable', value: 'disable' },
                    { name: 'Status', value: 'status' }
                ))
        .addUserOption(option =>
            option.setName('user')
                .setDescription('Developer target to add/remove (defaults to yourself)')
                .setRequired(false))
        .addIntegerOption(option =>
            option.setName('minutes')
                .setDescription('Duration in minutes (leave empty for a lifetime grant that never expires)')
                .setRequired(false)
                .setMinValue(1)
                .setMaxValue(43200))
        .setDMPermission(false),

    async execute(interaction) {
        try {
            if (!config.developerIds.includes(interaction.user.id)) {
                return interaction.reply({
                    content: 'You do not have permission to use this developer-only command.',
                    ephemeral: true
                });
            }

            const guildId = interaction.guildId;
            if (!guildId) {
                return interaction.reply({
                    content: 'This command must be used inside a server.',
                    ephemeral: true
                });
            }

            const action = interaction.options.getString('action');
            const targetUser = interaction.options.getUser('user') || interaction.user;
            // Optional: when omitted, enableNoPrefixMode treats it as a lifetime grant.
            const minutes = interaction.options.getInteger('minutes');

            const serverSettingsManager = interaction.client.serverSettingsManager;
            if (!serverSettingsManager) {
                return interaction.reply({
                    content: 'The server settings manager is not available.',
                    ephemeral: true
                });
            }

            const LIFETIME = serverSettingsManager.constructor.NO_PREFIX_LIFETIME;

            if (action === 'add' || action === 'enable') {
                const result = serverSettingsManager.enableNoPrefixMode(guildId, targetUser.id, minutes);

                if (!result.success) {
                    return interaction.reply({
                        embeds: [npEmbed.errorEmbed(result.message)],
                        ephemeral: true
                    });
                }

                return interaction.reply({
                    embeds: [npEmbed.grantEmbed({
                        targetUser,
                        minutes,
                        lifetime: !!result.lifetime,
                        expiresAt: result.expiresAt,
                    })],
                    ephemeral: true
                });
            }

            if (action === 'remove' || action === 'disable') {
                const disabled = serverSettingsManager.disableNoPrefixMode(guildId, targetUser.id);

                return interaction.reply({
                    embeds: [npEmbed.revokeEmbed({ targetUser, removed: !!disabled })],
                    ephemeral: true
                });
            }

            if (action === 'status') {
                const raw = serverSettingsManager.getNoPrefixExpiration(guildId, targetUser.id);
                const expiresAt = raw === LIFETIME ? 'lifetime' : raw;

                return interaction.reply({
                    embeds: [npEmbed.statusEmbed({ targetUser, expiresAt })],
                    ephemeral: true
                });
            }

            return interaction.reply({
                content: 'Unknown no-prefix action.',
                ephemeral: true
            });
        } catch (error) {
            console.error('[NP COMMAND] Execution failed:', error);
            return interaction.reply({
                content: 'An unexpected error occurred while running the no-prefix command.',
                ephemeral: true
            }).catch(() => {});
        }
    }
};
