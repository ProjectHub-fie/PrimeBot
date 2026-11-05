const {
    SlashCommandBuilder, PermissionFlagsBits, ActionRowBuilder,
    ButtonBuilder, ButtonStyle, MessageFlags,
} = require('discord.js');
const config = require('../config');
const {
    NUKE_ACTION_BY_KEY, NUKE_RESPONSE_BY_KEY, isTrusted,
} = require('../utils/antiNukeRules');
const {
    statusEmbed, thresholdsEmbed, whitelistEmbed, successEmbed, errorEmbed, setupEmbed,
} = require('../utils/antiNukeEmbed');
const { computeProgress } = require('../utils/antiNukeSetup');
const { runAll } = require('../utils/antiNukeSetupRunner');

/**
 * /antinuke — manage Anti-Nuke protection from Discord.
 *
 * Subcommands mirror the dashboard's Anti-Nuke tab:
 *   status / setup / enable / disable / dryrun / thresholds
 *   whitelist user|role / unwhitelist user|role
 *   lockdown / restore
 *
 * Authorization follows the owner-controlled access hierarchy, exactly like the
 * dashboard: the ACTUAL guild owner always passes; every other user needs the
 * bot-defined permission for the specific subcommand. A plain Discord
 * Administrator/Manage Server permission is NOT sufficient on its own — see
 * `AUTH_REQUIREMENTS` below, enforced through `authorizeAntiNuke`. The
 * `ManageGuild` default member permission is kept so Discord still hides the
 * command from non-staff; the hierarchy is what actually gates each action.
 */

// Per-subcommand bot-defined permission (from shared/antiNukePermissions).
// View-only/setup reads are gated by the access hierarchy too — a status read
// is only shown to someone with at least `antinuke.view`.
const AUTH_REQUIREMENTS = {
    status: 'antinuke.view',
    setup: 'antinuke.setup',
    enable: 'antinuke.config',
    disable: 'antinuke.config',
    dryrun: 'antinuke.responses',
    thresholds: 'antinuke.rules',
    whitelist: 'antinuke.trusted.manage',
    unwhitelist: 'antinuke.trusted.manage',
    lockdown: 'antinuke.lockdown',
    restore: 'antinuke.recovery',
};
async function denyEmbed(interaction, required) {
    const embeds = [errorEmbed(`You do not have Anti-Nuke permission to run this. (Required: \`${required}\` — the server owner can grant it in the Anti-Nuke → Access Control page.)`)];
    if (interaction.deferred || interaction.replied) return interaction.editReply({ embeds, components: [] });
    return interaction.reply({ embeds, flags: MessageFlags.Ephemeral, components: [] });
}

const SETUP_BUTTONS = () => new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('antinuke:setup:automatic').setLabel('Automatic Setup').setStyle(ButtonStyle.Primary).setEmoji('⚡'),
    new ButtonBuilder().setCustomId('antinuke:setup:manual').setLabel('Manual Setup').setStyle(ButtonStyle.Secondary).setEmoji('⚙️'),
    new ButtonBuilder().setCustomId('antinuke:setup:progress').setLabel('View Progress').setStyle(ButtonStyle.Secondary).setEmoji('📊'),
);

module.exports = {
    data: new SlashCommandBuilder()
        .setName('antinuke')
        .setDescription('Configure PrimeBot Anti-Nuke protection')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
        .setDMPermission(false)
        .addSubcommand(sub => sub.setName('status').setDescription('Show the Anti-Nuke configuration and protection status'))
        .addSubcommand(sub => sub.setName('setup').setDescription('Start the guided Anti-Nuke setup wizard'))
        .addSubcommand(sub => sub.setName('enable').setDescription('Enable Anti-Nuke for this server'))
        .addSubcommand(sub => sub.setName('disable').setDescription('Disable Anti-Nuke for this server'))
        .addSubcommand(sub => sub.setName('dryrun')
            .setDescription('Toggle dry-run mode (detect + alert, never contain)')
            .addBooleanOption(o => o.setName('enabled').setDescription('Enable dry-run?').setRequired(true)))
        .addSubcommand(sub => sub.setName('thresholds').setDescription('List the detection thresholds'))
        .addSubcommand(sub => sub.setName('whitelist')
            .setDescription('Add a trusted user or role')
            .addStringOption(o => o.setName('type').setDescription('What to trust').setRequired(true)
                .addChoices({ name: 'User', value: 'user' }, { name: 'Role', value: 'role' }))
            .addUserOption(o => o.setName('user').setDescription('The user to trust (type: user)').setRequired(false))
            .addRoleOption(o => o.setName('role').setDescription('The role to trust (type: role)').setRequired(false)))
        .addSubcommand(sub => sub.setName('unwhitelist')
            .setDescription('Remove a trusted user or role')
            .addStringOption(o => o.setName('type').setDescription('What to remove').setRequired(true)
                .addChoices({ name: 'User', value: 'user' }, { name: 'Role', value: 'role' }))
            .addUserOption(o => o.setName('user').setDescription('The user to untrust (type: user)').setRequired(false))
            .addRoleOption(o => o.setName('role').setDescription('The role to untrust (type: role)').setRequired(false)))
        .addSubcommand(sub => sub.setName('lockdown').setDescription('Engage emergency lockdown'))
        .addSubcommand(sub => sub.setName('restore').setDescription('Lift an active lockdown')),

    async execute(interaction) {
        const manager = interaction.client.antiNukeManager;
        if (!manager || typeof manager.updateSettings !== 'function') {
            return interaction.reply({ embeds: [errorEmbed('Anti-Nuke is not available right now.')], flags: MessageFlags.Ephemeral });
        }
        const guild = interaction.guild;
        const guildId = guild.id;
        const sub = interaction.options.getSubcommand();
        const settings = manager.getSettings(guildId);

        // Owner-controlled access hierarchy — every subcommand is gated by a
        // bot-defined permission. The ACTUAL guild owner always passes; a
        // Discord Administrator without an assignment does not.
        const antiNukeAccess = require('../utils/antiNukeAccess');
        const member = {
            present: true,
            roles: Array.from((guild.members && guild.members.me && interaction.member && interaction.member.roles)
                ? interaction.member.roles.cache.keys() : []),
        };
        const auth = await antiNukeAccess.authorizeAntiNuke(
            { id: guild.id, owner_id: guild.ownerId }, interaction.user.id,
            AUTH_REQUIREMENTS[sub] || null, { requireMember: true, member },
        );
        if (!auth.ok) return denyEmbed(interaction, AUTH_REQUIREMENTS[sub] || 'any');

        // ── status ───────────────────────────────────────────────────────────
        if (sub === 'status') {
            let lockdown = null;
            if (typeof manager.getLockdown === 'function') {
                lockdown = await manager.getLockdown(guildId).catch(() => null);
            }
            const permissionReport = typeof manager.getPermissionReport === 'function' ? manager.getPermissionReport(guild) : null;
            return interaction.reply({ embeds: [statusEmbed(settings, { lockdown, permissionReport })], flags: MessageFlags.Ephemeral });
        }

        // ── setup ────────────────────────────────────────────────────────────
        if (sub === 'setup') {
            const setup = typeof manager.getSetup === 'function' ? await manager.getSetup(guildId).catch(() => null) : null;
            const progress = setup && setup.state ? computeProgress(setup.method || 'automatic', setup.state) : null;
            return interaction.reply({ embeds: [setupEmbed(progress)], components: [SETUP_BUTTONS()], flags: MessageFlags.Ephemeral });
        }

        // ── enable / disable ─────────────────────────────────────────────────
        if (sub === 'enable') {
            manager.updateSettings(guildId, { enabled: true });
            return interaction.reply({ embeds: [successEmbed('🛡️ Anti-Nuke enabled', settings.dryRun !== false ? 'Dry-run is on — incidents are detected and alerted but nobody is contained.' : 'Live containment is active.')], flags: MessageFlags.Ephemeral });
        }
        if (sub === 'disable') {
            manager.updateSettings(guildId, { enabled: false });
            return interaction.reply({ embeds: [successEmbed('🛡️ Anti-Nuke disabled', 'This server is no longer monitored.')], flags: MessageFlags.Ephemeral });
        }

        // ── dryrun ───────────────────────────────────────────────────────────
        if (sub === 'dryrun') {
            const enabled = interaction.options.getBoolean('enabled');
            manager.updateSettings(guildId, { dryRun: enabled });
            return interaction.reply({ embeds: [successEmbed(enabled ? '🧪 Dry-run enabled' : '⚡ Dry-run disabled', enabled ? 'Incidents are detected and alerted but nobody is contained.' : 'Live containment is now active for the configured responses.')], flags: MessageFlags.Ephemeral });
        }

        // ── thresholds ───────────────────────────────────────────────────────
        if (sub === 'thresholds') {
            return interaction.reply({ embeds: [thresholdsEmbed(settings)], flags: MessageFlags.Ephemeral });
        }

        // ── whitelist / unwhitelist ──────────────────────────────────────────
        if (sub === 'whitelist' || sub === 'unwhitelist') {
            const type = interaction.options.getString('type');
            const adding = sub === 'whitelist';
            if (type === 'user') {
                const user = interaction.options.getUser('user');
                if (!user) return interaction.reply({ embeds: [errorEmbed('Provide a `user` to trust.')], flags: MessageFlags.Ephemeral });
                // Never trust the bot itself; the owner is always exempt anyway.
                if (user.id === interaction.client.user.id) {
                    return interaction.reply({ embeds: [errorEmbed('PrimeBot cannot be trusted — it is always exempt.')], flags: MessageFlags.Ephemeral });
                }
                if (guild.ownerId === user.id) {
                    return interaction.reply({ embeds: [errorEmbed('The server owner is always exempt and does not need to be trusted.')], flags: MessageFlags.Ephemeral });
                }
                const list = new Set(settings.trustedUserIds || []);
                if (adding) list.add(user.id); else list.delete(user.id);
                manager.updateSettings(guildId, { trustedUserIds: Array.from(list) });
                return interaction.reply({ embeds: [successEmbed(adding ? `✅ Trusted <@${user.id}>` : `🗑️ Removed <@${user.id}> from the whitelist`)], flags: MessageFlags.Ephemeral });
            }
            const role = interaction.options.getRole('role');
            if (!role) return interaction.reply({ embeds: [errorEmbed('Provide a `role` to trust.')], flags: MessageFlags.Ephemeral });
            if (role.id === guild.id) {
                return interaction.reply({ embeds: [errorEmbed('@everyone cannot be trusted.')], flags: MessageFlags.Ephemeral });
            }
            // A role the bot cannot manage cannot be safely evaluated for trust.
            const me = guild.members.me;
            if (me && role.position >= me.roles.highest.position && !role.managed) {
                return interaction.reply({ embeds: [errorEmbed('That role is above PrimeBot\'s highest role, so it cannot be used for trust.')], flags: MessageFlags.Ephemeral });
            }
            const list = new Set(settings.trustedRoleIds || []);
            if (adding) list.add(role.id); else list.delete(role.id);
            manager.updateSettings(guildId, { trustedRoleIds: Array.from(list) });
            return interaction.reply({ embeds: [successEmbed(adding ? `✅ Trusted <@&${role.id}>` : `🗑️ Removed <@&${role.id}> from the whitelist`)], flags: MessageFlags.Ephemeral });
        }

        // ── lockdown / restore ───────────────────────────────────────────────
        if (sub === 'lockdown') {
            if (typeof manager.engageLockdown !== 'function') {
                return interaction.reply({ embeds: [errorEmbed('Lockdown is not available right now.')], flags: MessageFlags.Ephemeral });
            }
            const record = await manager.engageLockdown(guild, { startedBy: interaction.user.id, reason: `Lockdown by ${interaction.user.tag}` });
            const warn = record.warnings && record.warnings.length ? `\nWarnings: ${record.warnings.join('; ')}` : '';
            return interaction.reply({ embeds: [successEmbed('🔒 Lockdown engaged', `Verification level and invites were restricted. Use \`/antinuke restore\` to reverse it.${warn}`)], flags: MessageFlags.Ephemeral });
        }
        if (sub === 'restore') {
            if (typeof manager.liftLockdown !== 'function') {
                return interaction.reply({ embeds: [errorEmbed('Lockdown restore is not available right now.')], flags: MessageFlags.Ephemeral });
            }
            const { warnings } = await manager.liftLockdown(guild, { reason: `Lockdown lifted by ${interaction.user.tag}` });
            const warn = warnings && warnings.length ? `\nNotes: ${warnings.join('; ')}` : '';
            return interaction.reply({ embeds: [successEmbed('🔓 Lockdown restored', `Pre-lockdown settings were restored where they had not been changed since.${warn}`)], flags: MessageFlags.Ephemeral });
        }
    },

    // Exported for the button flow in events/interactionCreate.js.
    SETUP_BUTTONS,
    runAll,
    isTrusted,
    NUKE_ACTION_BY_KEY,
    NUKE_RESPONSE_BY_KEY,
    config,
};
