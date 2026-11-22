const {
    SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder,
} = require('discord.js');
const config = require('../config');
const repo = require('../server/inviteRepo');
const {
    PAGE_SIZE, statsEmbed, leaderboardEmbed, infoEmbed, configEmbed, helpEmbed,
} = require('../utils/inviteEmbeds');

const EXCLUDED_LIMIT = 50;

function parseIds(input) {
    if (!input) return [];
    const ids = String(input).split(/[\s,]+/).map(s => s.trim()).filter(s => /^\d{15,22}$/.test(s));
    return Array.from(new Set(ids)).slice(0, EXCLUDED_LIMIT);
}

async function targetProfile(user) {
    return {
        id: user.id,
        username: user.username || user.tag || user.id,
        avatarUrl: typeof user.displayAvatarURL === 'function' ? user.displayAvatarURL({ size: 64 }) : null,
    };
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('invites')
        .setDescription('Invite tracking — stats, leaderboard and configuration')
        .addSubcommand(sub => sub
            .setName('stats')
            .setDescription('Show invite statistics (yours or another member\'s)')
            .addUserOption(o => o.setName('user').setDescription('Member (default: you)')))
        .addSubcommand(sub => sub
            .setName('leaderboard')
            .setDescription('Top inviters in this server')
            .addIntegerOption(o => o.setName('page').setDescription('Page number').setMinValue(1)))
        .addSubcommand(sub => sub
            .setName('info')
            .setDescription('Detailed invite history for a member')
            .addUserOption(o => o.setName('user').setDescription('Member').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('config')
            .setDescription('View or change invite tracking configuration (Manage Server)')
            .addBooleanOption(o => o.setName('enabled').setDescription('Enable or disable tracking'))
            .addChannelOption(o => o.setName('log_channel').setDescription('Channel for join/leave logs'))
            .addBooleanOption(o => o.setName('join_notifications').setDescription('Post join notifications'))
            .addBooleanOption(o => o.setName('leave_notifications').setDescription('Post leave notifications'))
            .addBooleanOption(o => o.setName('vanity').setDescription('Mark joins as possible vanity joins when no invite changed'))
            .addBooleanOption(o => o.setName('exclude_bots').setDescription('Exclude bot joins from statistics'))
            .addStringOption(o => o.setName('excluded').setDescription('Comma-separated member ids to exclude from statistics')))
        .addSubcommand(sub => sub
            .setName('reset')
            .setDescription('Reset this server\'s invite statistics (Manage Server)')
            .addBooleanOption(o => o.setName('confirm').setDescription('Set to true to confirm the reset').setRequired(true))),

    async execute(interaction, client) {
        const guild = interaction.guild;
        if (!guild) {
            return interaction.reply({ content: 'Invite tracking can only be used inside a server.', ephemeral: true }).catch(() => {});
        }
        const sub = interaction.options.getSubcommand();
        const settings = await repo.getInviteSettings(guild.id);
        const isAdmin = interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild) === true
            || interaction.member?.id === guild.ownerId;

        await interaction.deferReply({ ephemeral: true }).catch(() => {});
        try {
            if (sub === 'stats' || sub === 'info') {
                const user = interaction.options.getUser('user') || interaction.user;
                const profile = await targetProfile(user);
                let stat;
                if (client.inviteTracker && typeof client.inviteTracker.getStats === 'function') {
                    stat = await client.inviteTracker.getStats(guild.id, user.id);
                } else {
                    stat = await repo.getInviteStat(guild.id, user.id);
                    const active = await repo.getActiveInviteCounts(guild.id);
                    const mine = active.find(a => String(a.inviterId) === String(user.id));
                    stat = { ...stat, activeInvites: mine ? mine.active : 0, activeCodes: mine ? mine.codes : 0 };
                }
                if (sub === 'stats') {
                    const { rank, total } = await repo.getInviteRank(guild.id, user.id);
                    return interaction.editReply({
                        embeds: [statsEmbed({ target: profile, stat, rank, totalTracked: total })],
                    }).catch(() => {});
                }
                const [recent, invited] = await Promise.all([
                    repo.getJoinsForUser(guild.id, user.id, { limit: 5 }),
                    repo.getInvitesForMember(guild.id, user.id, { limit: 10 }),
                ]);
                return interaction.editReply({
                    embeds: [infoEmbed({ target: profile, stat, recent, invited })],
                }).catch(() => {});
            }

            if (sub === 'leaderboard') {
                const page = Math.max(1, interaction.options.getInteger('page') || 1);
                const [rows, total] = await Promise.all([
                    repo.getLeaderboard(guild.id, { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
                    repo.countLeaderboard(guild.id),
                ]);
                const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
                if (page > totalPages) {
                    return interaction.editReply({ content: `There are only ${totalPages} page(s).` }).catch(() => {});
                }
                return interaction.editReply({
                    embeds: [leaderboardEmbed({ rows, page, total, totalPages })],
                }).catch(() => {});
            }

            if (sub === 'config') {
                if (!isAdmin) {
                    return interaction.editReply({ content: '❌ You need **Manage Server** to change invite tracking configuration.' }).catch(() => {});
                }
                const patch = {};
                const enabled = interaction.options.getBoolean('enabled');
                if (enabled !== null) patch.enabled = enabled;
                const channel = interaction.options.getChannel('log_channel');
                if (channel) patch.logChannelId = channel.id;
                const joinN = interaction.options.getBoolean('join_notifications');
                if (joinN !== null) patch.joinNotifications = joinN;
                const leaveN = interaction.options.getBoolean('leave_notifications');
                if (leaveN !== null) patch.leaveNotifications = leaveN;
                const vanity = interaction.options.getBoolean('vanity');
                if (vanity !== null) patch.vanityTracking = vanity;
                const excludeBots = interaction.options.getBoolean('exclude_bots');
                if (excludeBots !== null) patch.excludeBots = excludeBots;
                const excluded = interaction.options.getString('excluded');
                if (excluded !== null) patch.excludedUserIds = parseIds(excluded);

                const next = Object.keys(patch).length
                    ? (client.inviteTracker?.updateSettings
                        ? await client.inviteTracker.updateSettings(guild.id, patch)
                        : await repo.upsertInviteSettings(guild.id, patch))
                    : settings;
                if (Object.keys(patch).length) {
                    await repo.addInviteActivity(guild.id, {
                        type: 'config', userId: interaction.user.id, username: interaction.user.username,
                        detail: `Updated: ${Object.keys(patch).join(', ')}`,
                    }).catch(() => {});
                }
                return interaction.editReply({ embeds: [configEmbed(next)] }).catch(() => {});
            }

            if (sub === 'reset') {
                if (!isAdmin) {
                    return interaction.editReply({ content: '❌ You need **Manage Server** to reset invite statistics.' }).catch(() => {});
                }
                if (interaction.options.getBoolean('confirm') !== true) {
                    return interaction.editReply({
                        content: '⚠️ Reset cancelled. Re-run with `confirm: true` to permanently clear this server\'s invite statistics.',
                    }).catch(() => {});
                }
                const result = await repo.resetGuildInviteStats(guild.id);
                return interaction.editReply({
                    embeds: [new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('🧹 Invite statistics reset')
                        .setDescription(`Cleared **${result.joins}** join records and **${result.stats}** inviter counters.\nLive invite snapshots were preserved, so attribution keeps working immediately.`)
                        .setFooter({ text: `PrimeBot Invites • v${config.version}` })],
                }).catch(() => {});
            }

            return interaction.editReply({ embeds: [helpEmbed('/')] }).catch(() => {});
        } catch (err) {
            console.error('[INVITES CMD] error:', err.message);
            await interaction.editReply({ content: `❌ ${err.message || 'Something went wrong.'}` }).catch(() => {});
        }
    },
};
