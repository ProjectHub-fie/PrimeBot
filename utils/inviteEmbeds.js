/**
 * Invite Tracking embeds — shared by `/invites` and `$invite` so both entry
 * points render identical output.
 *
 * Counting policy (stated on every stats surface):
 *   joins   = tracked joins attributed to this inviter
 *   leaves  = invited members who have since left
 *   net     = joins - leaves
 *   active  = current sum of `uses` across the inviter's live invite codes
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../config');

const PAGE_SIZE = 10;

function bar(value, max, width = 10) {
    if (!max) return '';
    const filled = Math.max(0, Math.min(width, Math.round((value / max) * width)));
    return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function policyFooter(extra) {
    const base = 'Counting: joins − leaves = net • Unknown = Discord did not expose the invite used';
    return { text: extra ? `${extra} • ${base}` : base };
}

function statsEmbed({ target, stat, rank, totalTracked }) {
    const lines = [
        `**Joins:** ${stat.joins}`,
        `**Leaves:** ${stat.leaves}`,
        `**Net invites:** ${stat.net}`,
        `**Active invites:** ${stat.activeInvites || 0}${stat.activeCodes ? ` (${stat.activeCodes} code${stat.activeCodes === 1 ? '' : 's'})` : ''}`,
    ];
    if (rank) lines.push(`**Rank:** #${rank} of ${totalTracked}`);
    return new EmbedBuilder()
        .setColor(config.colors.primary)
        .setAuthor({ name: `${target.username || target.id}`, iconURL: target.avatarUrl || undefined })
        .setTitle('📨 Invite Statistics')
        .setDescription(lines.join('\n'))
        .setFooter(policyFooter())
        .setTimestamp();
}

function leaderboardEmbed({ rows, page, total, totalPages }) {
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🏆 Invite Leaderboard')
        .setFooter(policyFooter(totalPages ? `Page ${page}/${totalPages}` : undefined));
    if (!rows.length) {
        embed.setDescription('No invites tracked yet. Invite someone and their join will appear here.');
        return embed;
    }
    const maxNet = Math.max(...rows.map(r => Math.max(r.net, 0)), 1);
    const lines = rows.map((r, i) => {
        const place = (page - 1) * PAGE_SIZE + i + 1;
        const medal = place === 1 ? '🥇' : place === 2 ? '🥈' : place === 3 ? '🥉' : `**#${place}**`;
        return `${medal} <@${r.userId}> — **${r.net}** net\n\`${bar(Math.max(r.net, 0), maxNet)}\` ${r.joins} joins · ${r.leaves} left · ${r.activeInvites || 0} active`;
    });
    embed.setDescription(lines.join('\n\n'));
    if (typeof total === 'number') {
        embed.addFields({ name: 'Tracked inviters', value: String(total), inline: true });
    }
    return embed;
}

function infoEmbed({ target, stat, recent = [], invited = [] }) {
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle(`🔎 Invite Info — ${target.username || target.id}`)
        .addFields(
            { name: 'Joins', value: String(stat.joins), inline: true },
            { name: 'Leaves', value: String(stat.leaves), inline: true },
            { name: 'Net', value: String(stat.net), inline: true },
            { name: 'Active invites', value: String(stat.activeInvites || 0), inline: true },
        )
        .setFooter(policyFooter())
        .setTimestamp();
    if (invited.length) {
        embed.addFields({
            name: 'Recently invited',
            value: invited.slice(0, 10).map(j =>
                `<@${j.userId}>${j.leftAt ? ' (left)' : ''} — <t:${Math.floor(new Date(j.joinedAt).getTime() / 1000)}:R>`).join('\n'),
        });
    }
    if (recent.length) {
        embed.addFields({
            name: 'Their join history',
            value: recent.slice(0, 5).map(j => {
                const via = j.inviterId ? `<@${j.inviterId}>` : 'Unknown';
                return `<t:${Math.floor(new Date(j.joinedAt).getTime() / 1000)}:d> — invited by ${via}`;
            }).join('\n'),
        });
    }
    return embed;
}

function configEmbed(settings) {
    return new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('⚙️ Invite Tracking Configuration')
        .setDescription([
            `**Tracking:** ${settings.enabled ? 'enabled' : 'disabled'}`,
            `**Log channel:** ${settings.logChannelId ? `<#${settings.logChannelId}>` : 'not set'}`,
            `**Join notifications:** ${settings.joinNotifications ? 'on' : 'off'}`,
            `**Leave notifications:** ${settings.leaveNotifications ? 'on' : 'off'}`,
            `**Vanity URL detection:** ${settings.vanityTracking ? 'on' : 'off'}`,
            `**Exclude bots:** ${settings.excludeBots ? 'yes' : 'no'}`,
            `**Excluded members:** ${settings.excludedUserIds.length ? settings.excludedUserIds.map(id => `\`${id}\``).join(', ') : 'none'}`,
        ].join('\n'))
        .setFooter({ text: 'Manage everything visually in the dashboard → Invite Tracking' });
}

function helpEmbed(prefix = '/') {
    const p = prefix === '/' ? '/invites ' : `${prefix}invite `;
    return new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('📨 Invite Tracking')
        .setDescription('See who is bringing members to the server. Free for every server — no setup required.')
        .addFields(
            { name: 'Members', value: `\`${p}stats [@user]\` • \`${p}leaderboard [page]\` • \`${p}info @user\`` },
            { name: 'Administrators', value: `\`${p}config\` • \`${p}reset confirm:true\`` },
            { name: 'How it counts', value: 'joins − leaves = net. When Discord does not expose which invite was used, the inviter is recorded as **Unknown** instead of guessing.' },
        )
        .setFooter({ text: `PrimeBot Invites • v${config.version}` });
}

module.exports = {
    PAGE_SIZE,
    statsEmbed,
    leaderboardEmbed,
    infoEmbed,
    configEmbed,
    helpEmbed,
};
