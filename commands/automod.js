const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');
const { RULES, RULE_BY_KEY, ACTIONS, normalizeRules, normalizeAction, normalizeActions, normalizeWarnActions, metaFor } = require('../utils/automodRules');

/**
 * /automod — configure Premium Automod from Discord (premium, free).
 *
 * Subcommands mirror the dashboard's Automod tab:
 *   enable / disable / status / list
 *   addrule  (type, actions, words/threshold/seconds)
 *   removerule (type)
 *   set (logchannel / muterole / appealchannel / warnthreshold / warnactions / dm_enabled)
 *
 * A rule can take MULTIPLE actions at once (e.g. delete + warn + ban). Pass a
 * comma-separated list to the `actions` option, e.g. `/automod addrule type:spam actions:"warn,delete"`.
 *
 * The bot and dashboard share the same automod_settings table, so changes made
 * here appear in the dashboard (and vice-versa) within the cache reload window.
 */

function buildRulesEmbed(settings) {
    const embed = new EmbedBuilder()
        .setColor(settings.enabled ? 0x57F287 : 0x5865F2)
        .setTitle('🛡️ Automod configuration')
        .setDescription(settings.enabled ? 'Automod is **enabled**.' : 'Automod is **disabled**.')
        .addFields(
            { name: 'Log channel', value: settings.logChannelId ? `<#${settings.logChannelId}>` : '—', inline: true },
            { name: 'Mute role', value: settings.muteRoleId ? `<@&${settings.muteRoleId}>` : '—', inline: true },
            { name: 'DM members', value: settings.dmEnabled !== false ? '✅ on' : '⛔ off', inline: true },
            { name: 'Warn escalation', value: `${settings.warnThreshold} warnings → **${(settings.warnActions || [settings.warnAction || 'timeout']).join(', ')}**`, inline: true },
        );

    if (settings.rules.length === 0) {
        embed.addFields({ name: 'Rules', value: 'No rules configured. Use `/automod addrule`.', inline: false });
    } else {
        const list = settings.rules.map(r => {
            const meta = metaFor(r.type);
            const acts = (r.actions && r.actions.length ? r.actions : [r.action]).join(',');
            const extra = [];
            if (r.words) extra.push(`words: ${r.words.length}`);
            if (r.threshold != null) extra.push(`threshold: ${r.threshold}`);
            if (r.seconds != null) extra.push(`seconds: ${r.seconds}`);
            return `${r.enabled ? '✅' : '⛔'} ${meta.icon} **${meta.label}** → \`${acts}\`${extra.length ? ` (${extra.join(', ')})` : ''}`;
        }).join('\n');
        embed.addFields({ name: 'Rules', value: list, inline: false });
    }
    embed.setFooter({ text: 'PrimeBot Automod · premium features in free' });
    return embed;
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('automod')
        .setDescription('Configure Premium Automod (premium, free)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
        .addSubcommand(sub => sub.setName('enable').setDescription('Enable automod for this server'))
        .addSubcommand(sub => sub.setName('disable').setDescription('Disable automod for this server'))
        .addSubcommand(sub => sub.setName('status').setDescription('Show the current automod configuration'))
        .addSubcommand(sub =>
            sub.setName('list').setDescription('List configured automod rules'))
        .addSubcommand(sub =>
            sub.setName('addrule')
                .setDescription('Add or replace an automod rule (supports multiple actions)')
                .addStringOption(o => o.setName('type').setDescription('Rule type').setRequired(true)
                    .addChoices(RULES.map(r => ({ name: `${r.icon} ${r.label}`, value: r.key }))))
                .addStringOption(o => o.setName('actions').setDescription('Comma-separated actions, e.g. "delete,warn,ban" (default: delete)').setRequired(false))
                .addStringOption(o => o.setName('words').setDescription('Comma-separated blocked words/domains (blockedWords/badLinks/nsfw)').setRequired(false))
                .addIntegerOption(o => o.setName('threshold').setDescription('Numeric threshold (mentions/spam/caps/emoji/newlines/repeatedChars/newAccount days)').setRequired(false).setMinValue(1))
                .addIntegerOption(o => o.setName('seconds').setDescription('Spam window in seconds (spam only)').setRequired(false).setMinValue(1).setMaxValue(3600)))
        .addSubcommand(sub =>
            sub.setName('removerule')
                .setDescription('Remove an automod rule')
                .addStringOption(o => o.setName('type').setDescription('Rule type to remove').setRequired(true)
                    .addChoices(RULES.map(r => ({ name: `${r.icon} ${r.label}`, value: r.key })))))
        .addSubcommand(sub =>
            sub.setName('set')
                .setDescription('Set a global automod option')
                .addChannelOption(o => o.setName('log_channel').setDescription('Channel for automod logs').setRequired(false))
                .addRoleOption(o => o.setName('mute_role').setDescription('Role used for mutes').setRequired(false))
                .addChannelOption(o => o.setName('appeal_channel').setDescription('Channel where new appeals are posted').setRequired(false))
                .addIntegerOption(o => o.setName('warn_threshold').setDescription('Warnings before escalation').setRequired(false).setMinValue(1).setMaxValue(50))
                .addStringOption(o => o.setName('warn_actions').setDescription('Comma-separated escalation actions, e.g. "timeout,ban"').setRequired(false)
                    .addChoices([
                        { name: '⚠️ warn', value: 'warn' },
                        { name: '🔇 timeout', value: 'timeout' },
                        { name: '👢 kick', value: 'kick' },
                        { name: '🔨 ban', value: 'ban' },
                    ]))
                .addBooleanOption(o => o.setName('dm_enabled').setDescription('Whether to DM punished members').setRequired(false))),

    async execute(interaction) {
        const sub = interaction.options.getSubcommand();
        const manager = interaction.client.automodManager;
        const guildId = interaction.guild.id;
        const settings = manager.getSettings(guildId);

        if (sub === 'enable' || sub === 'disable') {
            manager.updateSettings(guildId, { enabled: sub === 'enable' });
            return interaction.reply({ content: `🛡️ Automod is now **${sub === 'enable' ? 'enabled' : 'disabled'}**.`, ephemeral: true });
        }

        if (sub === 'status' || sub === 'list') {
            return interaction.reply({ embeds: [buildRulesEmbed(settings)], ephemeral: true });
        }

        if (sub === 'addrule') {
            const type = interaction.options.getString('type');
            const meta = RULE_BY_KEY[type];
            if (!meta) return interaction.reply({ content: 'Unknown rule type.', ephemeral: true });
            const rawActions = (interaction.options.getString('actions') || 'delete')
                .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
            const actions = normalizeActions(rawActions, 'delete');
            const rule = { type, enabled: true, actions };
            if (meta.params.includes('words')) {
                const w = (interaction.options.getString('words') || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
                if (w.length === 0) return interaction.reply({ content: 'Provide at least one word/domain with the `words` option.', ephemeral: true });
                rule.words = w;
            }
            if (meta.params.includes('threshold')) rule.threshold = interaction.options.getInteger('threshold') || null;
            if (meta.params.includes('seconds')) rule.seconds = interaction.options.getInteger('seconds') || null;

            const rules = settings.rules.filter(r => r.type !== type);
            rules.push(rule);
            manager.updateSettings(guildId, { rules });
            return interaction.reply({ content: `✅ Added ${meta.icon} **${meta.label}** rule with actions: \`${actions.join(', ')}\`.`, ephemeral: true });
        }

        if (sub === 'removerule') {
            const type = interaction.options.getString('type');
            const rules = settings.rules.filter(r => r.type !== type);
            manager.updateSettings(guildId, { rules });
            return interaction.reply({ content: `🗑️ Removed the **${metaFor(type).label}** rule.`, ephemeral: true });
        }

        if (sub === 'set') {
            const patch = {};
            const logChannel = interaction.options.getChannel('log_channel');
            if (logChannel) patch.logChannelId = logChannel.id;
            const muteRole = interaction.options.getRole('mute_role');
            if (muteRole) patch.muteRoleId = muteRole.id;
            const appealChannel = interaction.options.getChannel('appeal_channel');
            if (appealChannel) patch.appealChannelId = appealChannel.id;
            const wt = interaction.options.getInteger('warn_threshold');
            if (wt) patch.warnThreshold = wt;
            const wa = interaction.options.getString('warn_actions');
            if (wa) {
                patch.warnActions = normalizeWarnActions(wa.split(','), settings.warnAction || 'timeout');
            }
            if (interaction.options.getBoolean('dm_enabled') !== null) {
                patch.dmEnabled = interaction.options.getBoolean('dm_enabled');
            }
            if (Object.keys(patch).length === 0) return interaction.reply({ content: 'Nothing to set. Provide at least one option.', ephemeral: true });
            manager.updateSettings(guildId, patch);
            return interaction.reply({ content: `✅ Updated automod settings: ${Object.keys(patch).join(', ')}.`, ephemeral: true });
        }
    },
};
