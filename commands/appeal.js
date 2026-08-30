const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder, ChannelType } = require('discord.js');
const { ACTIONS, normalizeAction, metaFor } = require('../utils/automodRules');

/**
 * /appeal — let members appeal an automod punishment, and let moderators
 * review/decide appeals.
 *
 * Subcommands:
 *   file    (action, reason) — any member files a new appeal for a punishment.
 *   list    [status]         — list this server's appeals (ManageGuild only).
 *   approve (id, note)       — approve an appeal; reverses the action (ManageGuild).
 *   deny    (id, note)       — deny an appeal (ManageGuild).
 *
 * Appeals are stored in automod_appeals (shared with the dashboard). When an
 * appeal is approved, the bot's AutomodManager reverses the underlying action
 * (unban / remove timeout / remove mute role) best-effort. If an appeal channel
 * is configured (/automod set appeal_channel), new appeals are posted there.
 */

function actionChoices() {
    return ACTIONS.map(a => ({ name: `${a.icon} ${a.label}`, value: a.key }));
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('appeal')
        .setDescription('Appeal an automod punishment or review appeals')
        .addSubcommand(sub =>
            sub.setName('file')
                .setDescription('File an appeal for an automod punishment')
                .addStringOption(o => o.setName('action').setDescription('The punishment you received').setRequired(true)
                    .addChoices(actionChoices()))
                .addStringOption(o => o.setName('reason').setDescription('Why the punishment should be lifted').setRequired(true)))
        .addSubcommand(sub =>
            sub.setName('list')
                .setDescription('List appeals in this server')
                .addStringOption(o => o.setName('status').setDescription('Filter by status').setRequired(false)
                    .addChoices([
                        { name: '⏳ Pending', value: 'pending' },
                        { name: '✅ Approved', value: 'approved' },
                        { name: '⛔ Denied', value: 'denied' },
                    ])))
        .addSubcommand(sub =>
            sub.setName('approve')
                .setDescription('Approve an appeal (reverses the punishment)')
                .addIntegerOption(o => o.setName('id').setDescription('Appeal ID').setRequired(true).setMinValue(1))
                .addStringOption(o => o.setName('note').setDescription('Optional decision note').setRequired(false)))
        .addSubcommand(sub =>
            sub.setName('deny')
                .setDescription('Deny an appeal')
                .addIntegerOption(o => o.setName('id').setDescription('Appeal ID').setRequired(true).setMinValue(1))
                .addStringOption(o => o.setName('note').setDescription('Optional decision note').setRequired(false))),

    async execute(interaction) {
        const sub = interaction.options.getSubcommand();
        const manager = interaction.client.automodManager;
        if (!manager) return interaction.reply({ content: 'Appeals are unavailable (automod not loaded).', ephemeral: true });
        const guildId = interaction.guild.id;

        if (sub === 'file') {
            const action = normalizeAction(interaction.options.getString('action'), 'timeout');
            const reason = (interaction.options.getString('reason') || '').trim().slice(0, 1000);
            try {
                const appeal = await manager.submitAppeal({
                    guildId, userId: interaction.user.id, action, reason,
                });
                // Post to the configured appeal channel — or the automod log
                // channel as fallback — for moderators.
                const settings = manager.getSettings(guildId);
                const channelId = settings.appealChannelId || settings.logChannelId || null;
                if (channelId) {
                    const ch = await interaction.client.channels.fetch(channelId).catch(() => null);
                    if (ch && ch.isTextBased?.() && ch.type !== ChannelType.DM) {
                        const embed = new EmbedBuilder()
                            .setColor(0xFEE75C)
                            .setTitle(`📨 New appeal #${appeal.id}`)
                            .addFields(
                                { name: 'Member', value: `<@${interaction.user.id}>`, inline: true },
                                { name: 'Action', value: `${ACTIONS.find(a => a.key === action)?.icon || ''} ${action}`, inline: true },
                                { name: 'Reason', value: reason || '—', inline: false },
                            )
                            .setTimestamp();
                        ch.send({ embeds: [embed], content: `Use \`/appeal approve id:${appeal.id}\` or \`/appeal deny id:${appeal.id}\`.` }).catch(() => {});
                    }
                }
                return interaction.reply({
                    content: channelId
                        ? `📨 Your appeal (**#${appeal.id}**) for **${action}** has been submitted and posted to <#${channelId}>. Moderators will review it.`
                        : `📨 Your appeal (**#${appeal.id}**) for **${action}** has been recorded. No appeal channel is configured for this server yet.`,
                    ephemeral: true,
                });
            } catch (err) {
                console.error('[APPEAL] file failed:', err.message);
                return interaction.reply({ content: 'Failed to submit your appeal. Please try again later.', ephemeral: true });
            }
        }

        // Remaining subcommands require Manage Guild.
        if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild)) {
            return interaction.reply({ content: 'You need the **Manage Server** permission to review appeals.', ephemeral: true });
        }

        if (sub === 'list') {
            const status = interaction.options.getString('status') || null;
            try {
                const appeals = await manager.getAppeals(guildId, { status });
                if (!appeals.length) return interaction.reply({ content: 'No appeals found.', ephemeral: true });
                const lines = appeals.slice(0, 25).map(a => {
                    const when = a.createdAt ? new Date(a.createdAt).toLocaleString() : '';
                    return `**#${a.id}** · \`${a.action}\` · ${a.status} · <@${a.userId}> — ${a.reason || '—'} _(${when})_`;
                });
                const embed = new EmbedBuilder()
                    .setColor(0x5865F2)
                    .setTitle('📨 Appeals')
                    .setDescription(lines.join('\n\n'))
                    .setFooter({ text: 'PrimeBot Automod · appeals' });
                return interaction.reply({ embeds: [embed], ephemeral: true });
            } catch (err) {
                console.error('[APPEAL] list failed:', err.message);
                return interaction.reply({ content: 'Failed to load appeals.', ephemeral: true });
            }
        }

        if (sub === 'approve' || sub === 'deny') {
            const id = interaction.options.getInteger('id');
            const note = (interaction.options.getString('note') || '').trim().slice(0, 1000) || '';
            const approved = sub === 'approve';
            try {
                const appeal = await manager.decideAppeal(id, {
                    approved, decidedBy: interaction.user.id, note,
                });
                if (!appeal) return interaction.reply({ content: `Appeal #${id} not found or already decided.`, ephemeral: true });
                return interaction.reply({
                    content: `${approved ? '✅ Approved' : '⛔ Denied'} appeal **#${id}**${approved ? ' — the punishment has been reversed.' : ''}${note ? `\nNote: ${note}` : ''}`,
                    ephemeral: true,
                });
            } catch (err) {
                console.error('[APPEAL] decide failed:', err.message);
                return interaction.reply({ content: 'Failed to decide the appeal.', ephemeral: true });
            }
        }
    },
};
