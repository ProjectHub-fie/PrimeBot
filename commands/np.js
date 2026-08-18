const { SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const config = require('../config');

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

            const embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTimestamp();

            if (action === 'add' || action === 'enable') {
                const result = serverSettingsManager.enableNoPrefixMode(guildId, targetUser.id, minutes);

                if (!result.success) {
                    return interaction.reply({
                        embeds: [
                            new EmbedBuilder()
                                .setColor(config.colors.error)
                                .setTitle('❌ No-Prefix Error')
                                .setDescription(result.message || 'Could not enable no-prefix mode.')
                                .setTimestamp()
                        ],
                        ephemeral: true
                    });
                }

                embed
                    .setColor(config.colors.success)
                    .setTitle('🪄 No-Prefix Mode Enabled')
                    .setDescription(`No-prefix mode is now enabled for ${targetUser}.`)
                    .addFields(
                        result.lifetime
                            ? { name: 'Duration', value: 'Lifetime (never expires)', inline: true }
                            : { name: 'Duration', value: `${minutes} minute${minutes !== 1 ? 's' : ''}`, inline: true },
                        result.lifetime
                            ? { name: 'Expires', value: 'Never', inline: true }
                            : { name: 'Expires', value: `<t:${Math.floor(result.expiresAt / 1000)}:R>`, inline: true }
                    )
                    .setFooter({ text: `Developer command • ${config.version}` });

                return interaction.reply({ embeds: [embed], ephemeral: true });
            }

            if (action === 'remove' || action === 'disable') {
                const disabled = serverSettingsManager.disableNoPrefixMode(guildId, targetUser.id);

                embed
                    .setColor(disabled ? config.colors.success : config.colors.warning)
                    .setTitle(disabled ? '🪄 No-Prefix Mode Disabled' : 'ℹ️ No-Prefix Mode Was Not Active')
                    .setDescription(
                        disabled
                            ? `No-prefix mode has been disabled for ${targetUser}.`
                            : `${targetUser} does not currently have no-prefix mode enabled.`
                    )
                    .setFooter({ text: `Developer command • ${config.version}` });

                return interaction.reply({ embeds: [embed], ephemeral: true });
            }

            if (action === 'status') {
                const expiresAt = serverSettingsManager.getNoPrefixExpiration(guildId, targetUser.id);

                if (expiresAt) {
                    const isLifetime = expiresAt === serverSettingsManager.constructor.NO_PREFIX_LIFETIME;
                    embed
                        .setColor(config.colors.success)
                        .setTitle('🪄 No-Prefix Mode Status')
                        .setDescription(`${targetUser} currently has no-prefix mode enabled.`)
                        .addFields(
                            isLifetime
                                ? { name: 'Duration', value: 'Lifetime (never expires)', inline: true }
                                : { name: 'Expires', value: `<t:${Math.floor(expiresAt / 1000)}:R>`, inline: false }
                        )
                        .setFooter({ text: `Developer command • ${config.version}` });
                } else {
                    embed
                        .setColor(config.colors.warning)
                        .setTitle('ℹ️ No-Prefix Mode Status')
                        .setDescription(`${targetUser} does not currently have no-prefix mode enabled.`)
                        .setFooter({ text: `Developer command • ${config.version}` });
                }

                return interaction.reply({ embeds: [embed], ephemeral: true });
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
