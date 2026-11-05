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
        .setDescription('Choose a setup method. Nothing is activated until you press **Confirm** — the recommended configuration keeps your existing custom settings.');

    if (progress && progress.steps && progress.steps.length) {
        const pct = Math.max(0, Math.min(100, Number(progress.percent) || 0));
        const width = 16;
        const filled = Math.round((pct / 100) * width);
        // Unicode bar chart — Discord normalizes emoji blocks, so we use the
        // plain "█" block + "░" (U+2593) as the empty cell. A literal 10-wide
        // render keeps the number always visible.
        const bar = '█'.repeat(filled) + '░'.repeat(width - filled);

        const lines = progress.steps.map(s => {
            const icon = s.status === 'completed' ? '✅' : s.status === 'running' ? '🔄' : s.status === 'failed' ? '❌' : s.status === 'skipped' ? '⏭️' : '⬜';
            return `${icon} ${s.label}${s.required ? '' : ' _(optional)_'}`;
        });
        embed.addFields(
            {
                name: `Setup progress — ${bar} ${pct}%`,
                value: `${progress.completed}/${progress.total} required steps · ${progress.failed || 0} failed · ${progress.skipped || 0} skipped · ${progress.remaining || 0} remaining`,
                inline: false,
            },
            {
                name: progress.currentStep ? `Current step: ${String(progress.currentStep).replace(/[A-Z]/g, c => ' ' + c.toLowerCase())}` : 'Current step: —',
                value: lines.join('\n').slice(0, 3900),
                inline: false,
            },
        );
    } else {
        embed.addFields(
            { name: '⚡ Automatic Setup', value: 'Recommended security configuration, applied for you.', inline: true },
            { name: '⚙ Manual Setup', value: 'Configure each protection module yourself.', inline: true },
        );
    }
    return embed.setFooter({ text: `PrimeBot Security · v${config.version}` }).setTimestamp();
}

/**
 * Render the owner-controlled access hierarchy for an embed.
 *
 * `ctx` is the result of `authorizeAntiNuke` (or `computeAccess`) — includes
 * `role`, `level`, `isOwner`, `permissions`, `ownerId`. Title/description are
 * overridable so the same builder serves both the overview and the
 * "your access" views.
 */
function accessOverviewEmbed(ctx, { title = '🛡️ Anti-Nuke — Access Control', description = null } = {}) {
    const labelFor = {
        owner: '👑 Server Owner',
        coOwner: '🤝 Co-Owner',
        trustedAdmin: '🛡️ Trusted Admin',
        none: '⛔ No Access',
    };
    const perms = ctx.isOwner ? ['Owns the server — full Anti-Nuke control'] : (ctx.permissions || []);
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle(title)
        .setDescription(description || 'The Anti-Nuke access hierarchy is **owner-controlled**: only the actual server owner can appoint Co-Owners, and every other user receives only the bot-defined permissions delegated to them.')
        .addFields(
            { name: 'Your access level', value: labelFor[ctx.role] || labelFor.none, inline: true },
            { name: 'Delegated', value: ctx.isOwner ? 'Full authority' : (perms.length ? `${perms.length} permission${perms.length === 1 ? '' : 's'}` : 'None'), inline: true },
            { name: 'Can manage access', value: ctx.canManageAccess ? 'Yes' : 'No', inline: true },
            { name: 'Can appoint Co-Owners', value: ctx.canAppointCoOwners ? 'Yes' : 'Only the server owner', inline: true },
            { name: 'Effective permissions', value: perms.length ? perms.slice(0, 10).map(p => {
                const meta = require('../shared/antiNukePermissions').ANTI_NUKE_PERMISSION_BY_ID[p];
                return `• \`${p}\` — ${meta ? meta.label : p}`;
            }).join('\n') : '_(none — ask the server owner for access)_' },
            { name: 'Server owner', value: ctx.ownerId ? `<@${ctx.ownerId}>` : 'Unknown', inline: true },
        )
        .setFooter({ text: 'Management access is separate from detection trust — being trusted to manage Anti-Nuke never exempts you from it.' });
    return embed;
}

module.exports = {
    statusEmbed,
    thresholdsEmbed,
    whitelistEmbed,
    successEmbed,
    errorEmbed,
    setupEmbed,
    accessOverviewEmbed,
    DANGEROUS_PERMISSION_BY_KEY,
};
