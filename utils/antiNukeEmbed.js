/**
 * Anti-Nuke Discord embeds.
 *
 * Shared by the `/antinuke` slash command and the setup button flow so the two
 * render identically (mirrors utils/npEmbed.js / utils/devEmbed.js). Icons are
 * emoji here — these are Discord embeds the bot posts, not dashboard chrome.
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const { NUKE_MODULES, NUKE_RESPONSES, NUKE_RESPONSE_BY_KEY, DANGEROUS_PERMISSION_BY_KEY } = require('./antiNukeRules');

const BRAND = config.colors.primary;

function statusEmbed(settings, { lockdown = null, permissionReport = null } = {}) {
    const enabled = settings.enabled === true;
    const dryRun = settings.dryRun !== false;
    const modules = NUKE_MODULES.map(m => {
        const on = Object.keys(settings.watched || {})
            .filter(k => settings.watched[k] && settings.watched[k].enabled !== false)
            .filter(k => (require('./antiNukeRules').NUKE_ACTION_BY_KEY[k] || {}).module === m.key)
            .length;
        return `${on > 0 ? '🟢' : '⚪'} **${m.label}** — ${on} action${on === 1 ? '' : 's'}`;
    }).join('\n');

    const embed = new EmbedBuilder()
        .setColor(enabled ? config.colors.success : config.colors.error)
        .setTitle('🛡️ PrimeBot Anti-Nuke')
        .setDescription(enabled
            ? (dryRun ? '**Enabled** · 🧪 DRY RUN (no containment)' : '**Enabled** · live containment')
            : '**Disabled** — Anti-Nuke is not monitoring this server.')
        .addFields(
            { name: 'Protection modules', value: modules || 'None', inline: false },
            { name: 'Alert channel', value: settings.alertChannelId ? `<#${settings.alertChannelId}>` : '—', inline: true },
            { name: 'Responses', value: (settings.responses || []).map(r => (NUKE_RESPONSE_BY_KEY[r] || {}).label || r).join(', ') || '—', inline: true },
            { name: 'Trusted users', value: String((settings.trustedUserIds || []).length), inline: true },
            { name: 'Trusted roles', value: String((settings.trustedRoleIds || []).length), inline: true },
        );

    if (lockdown && lockdown.active) {
        embed.addFields({ name: '🔒 Lockdown', value: `Active${lockdown.startedAt ? ` since <t:${Math.floor(new Date(lockdown.startedAt).getTime() / 1000)}:R>` : ''}`, inline: false });
    }
    if (permissionReport && !permissionReport.ok) {
        embed.addFields({
            name: '⚠️ Missing permissions',
            value: permissionReport.checks.filter(c => !c.available).map(c => `• ${c.label} — ${c.neededFor}`).join('\n') || '—',
            inline: false,
        });
    }
    return embed.setFooter({ text: `PrimeBot Security · v${config.version}` }).setTimestamp();
}

function thresholdsEmbed(settings) {
    const { NUKE_ACTIONS } = require('./antiNukeRules');
    const lines = NUKE_ACTIONS.map(a => {
        const w = (settings.watched || {})[a.key] || {};
        const on = w.enabled !== false;
        return `${on ? '🟢' : '⚪'} **${a.label}** — ${w.threshold != null ? w.threshold : a.threshold} in ${w.seconds != null ? w.seconds : a.seconds}s`;
    });
    return new EmbedBuilder()
        .setColor(BRAND)
        .setTitle('🛡️ Anti-Nuke thresholds')
        .setDescription(lines.join('\n').slice(0, 4000))
        .setFooter({ text: 'Edit these from the dashboard → Anti-Nuke' })
        .setTimestamp();
}

function whitelistEmbed(settings) {
    const users = (settings.trustedUserIds || []).map(id => `<@${id}>`).join(', ') || '—';
    const roles = (settings.trustedRoleIds || []).map(id => `<@&${id}>`).join(', ') || '—';
    return new EmbedBuilder()
        .setColor(BRAND)
        .setTitle('🛡️ Anti-Nuke whitelist')
        .setDescription('The server owner and PrimeBot are always exempt. Administrators are **not** trusted automatically.')
        .addFields(
            { name: 'Trusted users', value: users.slice(0, 1024), inline: false },
            { name: 'Trusted roles', value: roles.slice(0, 1024), inline: false },
        )
        .setFooter({ text: `PrimeBot Security · v${config.version}` })
        .setTimestamp();
}

function successEmbed(title, description = '') {
    return new EmbedBuilder()
        .setColor(config.colors.success)
        .setTitle(title)
        .setDescription(description || null)
        .setTimestamp();
}

function errorEmbed(description) {
    return new EmbedBuilder()
        .setColor(config.colors.error)
        .setTitle('⚠️ Anti-Nuke')
        .setDescription(description)
        .setTimestamp();
}

function setupEmbed(progress = null) {
    const embed = new EmbedBuilder()
        .setColor(BRAND)
        .setTitle('🛡️ PrimeBot Anti-Nuke Setup')
        .setDescription('Choose a setup method. Nothing is activated until you confirm — Anti-Nuke starts in dry-run mode, so it detects and alerts without containing anyone.');

    if (progress && progress.steps && progress.steps.length) {
        const lines = progress.steps.map(s => {
            const icon = s.status === 'completed' ? '✓' : s.status === 'running' ? '●' : s.status === 'failed' ? '✗' : s.status === 'skipped' ? '–' : '○';
            return `${icon} ${s.label}${s.required ? '' : ' _(optional)_'}`;
        });
        embed.addFields({
            name: `Progress — ${progress.percent}% (${progress.completed}/${progress.total})`,
            value: lines.join('\n').slice(0, 4000),
            inline: false,
        });
    } else {
        embed.addFields(
            { name: '⚡ Automatic Setup', value: 'Recommended security configuration, applied for you.', inline: true },
            { name: '⚙ Manual Setup', value: 'Configure each protection module yourself.', inline: true },
        );
    }
    return embed.setFooter({ text: `PrimeBot Security · v${config.version}` }).setTimestamp();
}

module.exports = {
    statusEmbed,
    thresholdsEmbed,
    whitelistEmbed,
    successEmbed,
    errorEmbed,
    setupEmbed,
    DANGEROUS_PERMISSION_BY_KEY,
};
