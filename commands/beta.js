const { SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const config = require('../config');
const betaManager = require('../utils/betaManager');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('beta')
        .setDescription('Manage beta program access for this server (server owner only)')
        .setDMPermission(false)
        .addSubcommand(sub =>
            sub.setName('enable')
                .setDescription('Opt this server into beta features'))
        .addSubcommand(sub =>
            sub.setName('disable')
                .setDescription('Opt this server out of beta features'))
        .addSubcommand(sub =>
            sub.setName('status')
                .setDescription('Check the current beta status for this server')),

    async execute(interaction) {
        // Must be used in a server
        if (!interaction.guild) {
            return interaction.reply({
                content: 'This command can only be used inside a server.',
                ephemeral: true,
            });
        }

        // Server owner only
        if (interaction.user.id !== interaction.guild.ownerId) {
            return interaction.reply({
                embeds: [
                    new EmbedBuilder()
                        .setColor(config.colors.error)
                        .setTitle('🔒 Server Owner Only')
                        .setDescription(
                            'The `/beta` command can only be used by the **server owner**.\n\n' +
                            'Ask your server owner to run this command.'
                        )
                        .setTimestamp()
                ],
                ephemeral: true,
            });
        }

        await interaction.deferReply({ ephemeral: false });

        const guildId = interaction.guild.id;
        const sub = interaction.options.getSubcommand();

        // ── /beta status ────────────────────────────────────────────────
        if (sub === 'status') {
            const allowed = await betaManager.isAllowed(guildId);
            const enabled = await betaManager.isEnabled(guildId);

            const statusEmbed = new EmbedBuilder()
                .setColor(enabled ? config.colors.success : config.colors.primary)
                .setTitle('🔬 PrimeBot Beta Program')
                .setDescription(
                    'The beta program gives selected servers early access to new features still in testing.\n\n' +
                    `**Access:** ${allowed ? '✅ This server is on the allowed list' : '❌ This server is not on the allowed list'}\n` +
                    `**Status:** ${enabled ? '🟢 Beta features are enabled' : '🔴 Beta features are disabled'}`
                )
                .addFields(
                    { name: '/beta enable',  value: 'Opt this server into beta features',  inline: true },
                    { name: '/beta disable', value: 'Opt this server out of beta features', inline: true },
                    {
                        name: '📋 Beta Features',
                        value: config.betaFeatures.length > 0
                            ? config.betaFeatures.map(f => `\`/${f}\``).join(', ')
                            : '*No beta features configured yet.*',
                        inline: false,
                    }
                )
                .setFooter({ text: `PrimeBot Beta Program • Server Owner Only • Version: ${config.version}` })
                .setTimestamp();

            return interaction.editReply({ embeds: [statusEmbed] });
        }

        // ── /beta enable ────────────────────────────────────────────────
        if (sub === 'enable') {
            const allowed = await betaManager.isAllowed(guildId);
            if (!allowed) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle('🔬 Beta Access Required')
                            .setDescription(
                                'This server has not been approved for the beta program.\n\n' +
                                'To request access, join the [support server](' + config.supportServer + ') and ask a bot developer.'
                            )
                            .setFooter({ text: `Version: ${config.version}` })
                            .setTimestamp()
                    ]
                });
            }

            if (await betaManager.isEnabled(guildId)) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.warning)
                            .setTitle('🔬 Already Enabled')
                            .setDescription('Beta features are already enabled for this server.')
                            .setTimestamp()
                    ]
                });
            }

            const ok = await betaManager.enable(guildId);
            if (!ok) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle('❌ Database Error')
                            .setDescription('Failed to save beta settings. Please try again in a moment.')
                            .setTimestamp()
                    ]
                });
            }

            // Append (beta) to bot's nickname in this guild
            try {
                const me = interaction.guild.members.me;
                if (me) {
                    const baseName = (me.nickname || interaction.client.user.username).replace(/ \(beta\)$/i, '');
                    await me.setNickname(`${baseName} (beta)`);
                }
            } catch (_) { /* nickname update is best-effort */ }

            return interaction.editReply({
                embeds: [
                    new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('🔬 Beta Enabled!')
                        .setDescription('Beta features have been enabled for this server. You now have early access to features still in testing.')
                        .addFields(
                            {
                                name: '📋 Beta Features',
                                value: config.betaFeatures.length > 0
                                    ? config.betaFeatures.map(f => `\`/${f}\``).join(', ')
                                    : '*No beta features configured yet.*',
                                inline: false,
                            },
                            { name: '❌ To Disable', value: 'Run `/beta disable`', inline: false }
                        )
                        .setFooter({ text: `Version: ${config.version}` })
                        .setTimestamp()
                ]
            });
        }

        // ── /beta disable ───────────────────────────────────────────────
        if (sub === 'disable') {
            if (!(await betaManager.isEnabled(guildId))) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.warning)
                            .setTitle('🔬 Already Disabled')
                            .setDescription('Beta features are not currently enabled for this server.')
                            .setTimestamp()
                    ]
                });
            }

            const ok = await betaManager.disable(guildId);
            if (!ok) {
                return interaction.editReply({
                    embeds: [
                        new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle('❌ Database Error')
                            .setDescription('Failed to save beta settings. Please try again in a moment.')
                            .setTimestamp()
                    ]
                });
            }

            // Remove (beta) from bot's nickname
            try {
                const me = interaction.guild.members.me;
                if (me) {
                    const cleanName = (me.nickname || interaction.client.user.username).replace(/ \(beta\)$/i, '');
                    await me.setNickname(cleanName || null);
                }
            } catch (_) { /* best-effort */ }

            return interaction.editReply({
                embeds: [
                    new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('🔬 Beta Disabled')
                        .setDescription(
                            'Beta features have been disabled for this server. You\'re back on the stable release.\n\n' +
                            'Run `/beta enable` at any time to re-enable beta.'
                        )
                        .setFooter({ text: `Version: ${config.version}` })
                        .setTimestamp()
                ]
            });
        }
    },
};
