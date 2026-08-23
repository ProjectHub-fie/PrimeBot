const { EmbedBuilder } = require('discord.js');
const config = require('../config');

// Shared embed builders for the developer-only no-prefix command (/np, $np).
// Used by both the slash command (commands/np.js) and the prefix handler in
// events/messageCreate.js so the two paths always render the same outputs.

function formatDuration(minutes, lifetime) {
    if (lifetime) return 'Lifetime (never expires)';
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}

function formatExpiry(expiresAt) {
    if (!expiresAt || expiresAt === 'lifetime') return 'Never';
    return `<t:${Math.floor(Number(expiresAt) / 1000)}:R>`;
}

function targetLabel(user) {
    const tag = user?.tag || user?.username || 'unknown';
    return `${user} (${tag})`;
}

function baseEmbed(color, title, description) {
    return new EmbedBuilder()
        .setColor(color)
        .setTitle(title)
        .setDescription(description)
        .setFooter({ text: `Developer command • Version ${config.version}` })
        .setTimestamp();
}

function helpEmbed(prefix) {
    return baseEmbed(
        config.colors.primary,
        '🪄 No-Prefix Mode',
        'Developer-only no-prefix management. Granted users can run commands without typing the prefix — set once, it works in **every** server.'
    ).addFields(
        { name: `${prefix}np add @user [minutes]`, value: 'Grant a user no-prefix access. Omit minutes for a lifetime grant.', inline: false },
        { name: `${prefix}np remove @user`, value: "Revoke a user's no-prefix access.", inline: false },
        { name: `${prefix}np status [@user]`, value: "Check a user's current no-prefix status (defaults to yourself).", inline: false },
        { name: `${prefix}np enable [minutes]`, value: 'Grant yourself no-prefix access (omit minutes for lifetime).', inline: false },
        { name: `${prefix}np disable`, value: 'Revoke your own no-prefix access.', inline: false }
    );
}

function grantEmbed({ targetUser, minutes, lifetime, expiresAt }) {
    return baseEmbed(
        config.colors.success,
        '🪄 No-Prefix Mode Enabled',
        `${targetUser} can now run commands **without the prefix** in every server.`
    ).addFields(
        { name: 'Target User', value: targetLabel(targetUser), inline: false },
        { name: 'Duration', value: formatDuration(minutes, lifetime), inline: true },
        { name: 'Expires', value: lifetime ? 'Never' : formatExpiry(expiresAt), inline: true },
        { name: 'How to use', value: 'The granted user simply types a command name (e.g. `help`) with no prefix, in any server.', inline: false }
    );
}

function revokeEmbed({ targetUser, removed }) {
    if (!removed) {
        return baseEmbed(
            config.colors.warning,
            'ℹ️ No-Prefix Mode Not Active',
            `${targetUser} does not currently have no-prefix mode enabled.`
        ).addFields(
            { name: 'Target User', value: targetLabel(targetUser), inline: false }
        );
    }
    return baseEmbed(
        config.colors.error,
        '🪄 No-Prefix Mode Disabled',
        `${targetUser} must use the command prefix again.`
    ).addFields(
        { name: 'Target User', value: targetLabel(targetUser), inline: false },
        { name: 'Status', value: 'No-prefix access revoked', inline: true }
    );
}

function statusEmbed({ targetUser, expiresAt }) {
    const lifetime = expiresAt === 'lifetime';
    if (!expiresAt) {
        return baseEmbed(
            config.colors.warning,
            '🪄 No-Prefix Mode Status',
            `${targetUser} does not currently have no-prefix mode enabled.`
        ).addFields(
            { name: 'Target User', value: targetLabel(targetUser), inline: false },
            { name: 'Status', value: 'Not enabled', inline: true }
        );
    }
    return baseEmbed(
        config.colors.success,
        '🪄 No-Prefix Mode Status',
        `${targetUser} currently has no-prefix mode enabled.`
    ).addFields(
        { name: 'Target User', value: targetLabel(targetUser), inline: false },
        { name: 'Status', value: 'Enabled', inline: true },
        lifetime
            ? { name: 'Duration', value: 'Lifetime (never expires)', inline: true }
            : { name: 'Expires', value: formatExpiry(expiresAt), inline: true }
    );
}

function errorEmbed(message) {
    return baseEmbed(
        config.colors.error,
        '❌ No-Prefix Error',
        message || 'Could not apply the requested no-prefix change.'
    );
}

module.exports = { helpEmbed, grantEmbed, revokeEmbed, statusEmbed, errorEmbed };
