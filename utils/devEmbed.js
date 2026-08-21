const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const { ROLE_INFO, ROLE_ORDER } = require('./botRoles');

// Shared embed builders for the /dev + $dev bot-role service. Both the prefix
// and slash paths render identical output from here (mirrors utils/npEmbed).

const FOOTER = `PrimeBot role service • Version ${config.version}`;

// The role hobby card: a coloured stripe per role with its description.
function roleEmbed({ targetUser, role, assigned }) {
    const info = ROLE_INFO[role] || ROLE_INFO.user;
    const displayName = targetUser?.tag || targetUser?.username || null;
    const mention = targetUser?.id ? `<@${targetUser.id}>` : 'this user';
    return new EmbedBuilder()
        .setColor(info.color)
        .setAuthor({
            name: `${displayName || 'PrimeBot user'}`,
            iconURL: targetUser?.displayAvatarURL?.({ dynamic: true }) || undefined,
        })
        .setTitle(`${info.emoji} ${info.label}`)
        .setDescription(`${mention} holds the role **${info.label}**`)
        .addFields(
            { name: 'Role', value: `${info.emoji} **${info.label}**`, inline: true },
            { name: 'Source', value: assigned === 'config' ? 'config (owner id)' : (assigned === 'database' ? 'database' : 'default'), inline: true },
            { name: 'Description', value: info.description },
        )
        .setThumbnail(targetUser?.displayAvatarURL?.({ dynamic: true }) || null)
        .setFooter({ text: FOOTER })
        .setTimestamp();
}

// Hierarchy overview used by $dev with no subcommand confusion / help.
function helpEmbed(prefix) {
    const roles = ROLE_ORDER.map(r => `${ROLE_INFO[r].emoji} **${ROLE_INFO[r].label}** — ${ROLE_INFO[r].description}`).join('\n');
    return new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🎖️ PrimeBot Role Service')
        .setDescription(roles)
        .addFields(
            { name: 'Usage', value: `\`${prefix}dev\` — your role\n\`${prefix}dev @user\` — a user's role\n\`${prefix}dev add @user <role>\` — assign (owner only)\n\`${prefix}dev remove @user\` — reset to user (owner only)\n\`${prefix}dev list\` — all assigned roles (owner only)` },
        )
        .setFooter({ text: FOOTER })
        .setTimestamp();
}

function listEmbed(rows) {
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🎖️ Assigned PrimeBot roles')
        .setFooter({ text: FOOTER })
        .setTimestamp();
    if (!rows.length) {
        embed.setDescription('No roles assigned yet. The owner lives in `config.developerIds`.');
        return embed;
    }
    const lines = rows.map(r => {
        const info = ROLE_INFO[r.role] || ROLE_INFO.user;
        return `${info.emoji} **${info.label}** — <@${r.user_id}>`;
    });
    embed.setDescription(lines.slice(0, 25).join('\n'));
    if (lines.length > 25) {
        embed.setFooter({ text: `Showing first 25 of ${lines.length} assigned roles • ${FOOTER}` });
    }
    return embed;
}

function errorEmbed(message) {
    return new EmbedBuilder()
        .setColor(config.colors.error)
        .setTitle('❌ PrimeBot Role Service')
        .setDescription(message || 'Something went wrong.')
        .setFooter({ text: FOOTER })
        .setTimestamp();
}

function successEmbed(title, description) {
    return new EmbedBuilder()
        .setColor(config.colors.success)
        .setTitle(title)
        .setDescription(description)
        .setFooter({ text: FOOTER })
        .setTimestamp();
}

module.exports = { roleEmbed, helpEmbed, listEmbed, errorEmbed, successEmbed };
