const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');
const config = require('../config');

/**
 * /reactionrole — manage reaction-role menus.
 *
 * Two creation flows, matching the dashboard:
 *   create  — bot posts a role embed to a channel and watches its own message
 *   attach  — attach emoji→role mappings to ANY existing message by id
 *
 * Plus list / edit / delete / show subcommands. All premium modes (normal,
 * sticky, verify, unique) and options (persistent, includeBots, required
 * role, exclusive role) are configurable from here too — free, per PrimeBot's
 * "premium features in free" motto.
 *
 * The mappings come in as a single JSON string option for portability; the
 * dashboard provides a richer UI for the same data.
 */

function parseMappings(input) {
    if (!input) return [];
    let arr;
    try {
        arr = JSON.parse(input);
    } catch {
        throw new Error('Mappings must be valid JSON, e.g. `[{"emoji":"🎉","roleId":"123","label":"Party"}]`');
    }
    if (!Array.isArray(arr)) throw new Error('Mappings must be a JSON array.');
    return arr;
}

module.exports = {
    data: new SlashCommandBuilder()
        .setName('reactionrole')
        .setDescription('Create and manage reaction-role menus (premium, free)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles | PermissionFlagsBits.ManageGuild)
        .addSubcommand(sub =>
            sub.setName('create')
                .setDescription('Post a role embed the bot will watch for reactions')
                .addChannelOption(o => o.setName('channel').setDescription('Channel to post the embed in').setRequired(true))
                .addStringOption(o => o.setName('title').setDescription('Embed title').setRequired(false))
                .addStringOption(o => o.setName('description').setDescription('Embed body text').setRequired(false))
                .addStringOption(o => o.setName('mappings').setDescription('JSON array: [{"emoji":"🎉","roleId":"123","label":"..."}]').setRequired(true))
                .addStringOption(o => o.setName('mode').setDescription('Behavior').setRequired(false)
                    .addChoices(
                        { name: 'Normal (toggle on/off)', value: 'normal' },
                        { name: 'Sticky (one-click assign)', value: 'sticky' },
                        { name: 'Verify (grant once, no remove)', value: 'verify' },
                        { name: 'Unique (only one role at a time)', value: 'unique' },
                    ))
                .addStringOption(o => o.setName('color').setDescription('Embed hex color (e.g. #5865F2)').setRequired(false))
                .addRoleOption(o => o.setName('required_role').setDescription('Role required to use the menu').setRequired(false))
                .addRoleOption(o => o.setName('exclusive_role').setDescription('Role removed when a role is taken').setRequired(false))
                .addBooleanOption(o => o.setName('persistent').setDescription('Re-apply roles on bot restart (default true)').setRequired(false))
                .addBooleanOption(o => o.setName('include_bots').setDescription('Allow bots to trigger (default false)').setRequired(false))
        )
        .addSubcommand(sub =>
            sub.setName('attach')
                .setDescription('Attach reaction roles to an existing message by its ID')
                .addStringOption(o => o.setName('message_id').setDescription('The message ID to attach to').setRequired(true))
                .addChannelOption(o => o.setName('channel').setDescription('Channel the message is in').setRequired(true))
                .addStringOption(o => o.setName('mappings').setDescription('JSON array: [{"emoji":"🎉","roleId":"123"}]').setRequired(true))
                .addStringOption(o => o.setName('title').setDescription('Optional label for the dashboard').setRequired(false))
                .addStringOption(o => o.setName('mode').setDescription('Behavior').setRequired(false)
                    .addChoices(
                        { name: 'Normal (toggle on/off)', value: 'normal' },
                        { name: 'Sticky (one-click assign)', value: 'sticky' },
                        { name: 'Verify (grant once, no remove)', value: 'verify' },
                        { name: 'Unique (only one role at a time)', value: 'unique' },
                    ))
                .addRoleOption(o => o.setName('required_role').setDescription('Role required to use the menu').setRequired(false))
                .addRoleOption(o => o.setName('exclusive_role').setDescription('Role removed when a role is taken').setRequired(false))
                .addBooleanOption(o => o.setName('persistent').setDescription('Re-apply roles on bot restart (default true)').setRequired(false))
                .addBooleanOption(o => o.setName('include_bots').setDescription('Allow bots to trigger (default false)').setRequired(false))
        )
        .addSubcommand(sub =>
            sub.setName('list')
                .setDescription('List this server\'s reaction-role menus')
        )
        .addSubcommand(sub =>
            sub.setName('edit')
                .setDescription('Edit an existing menu (by its menu ID from /reactionrole list)')
                .addIntegerOption(o => o.setName('id').setDescription('Menu ID').setRequired(true))
                .addStringOption(o => o.setName('title').setDescription('New embed title').setRequired(false))
                .addStringOption(o => o.setName('description').setDescription('New embed body text').setRequired(false))
                .addStringOption(o => o.setName('mode').setDescription('Behavior').setRequired(false)
                    .addChoices(
                        { name: 'Normal (toggle on/off)', value: 'normal' },
                        { name: 'Sticky (one-click assign)', value: 'sticky' },
                        { name: 'Verify (grant once, no remove)', value: 'verify' },
                        { name: 'Unique (only one role at a time)', value: 'unique' },
                    ))
                .addStringOption(o => o.setName('color').setDescription('Embed hex color').setRequired(false))
                .addRoleOption(o => o.setName('required_role').setDescription('Role required to use the menu').setRequired(false))
                .addRoleOption(o => o.setName('exclusive_role').setDescription('Role removed when a role is taken').setRequired(false))
                .addStringOption(o => o.setName('mappings').setDescription('Replace mappings JSON array').setRequired(false))
                .addBooleanOption(o => o.setName('enabled').setDescription('Enable/disable the menu').setRequired(false))
                .addBooleanOption(o => o.setName('persistent').setDescription('Re-apply roles on bot restart').setRequired(false))
                .addBooleanOption(o => o.setName('include_bots').setDescription('Allow bots to trigger').setRequired(false))
        )
        .addSubcommand(sub =>
            sub.setName('delete')
                .setDescription('Delete a reaction-role menu (does not remove granted roles)')
                .addIntegerOption(o => o.setName('id').setDescription('Menu ID').setRequired(true))
        )
        .addSubcommand(sub =>
            sub.setName('show')
                .setDescription('Show details of a reaction-role menu')
                .addIntegerOption(o => o.setName('id').setDescription('Menu ID').setRequired(true))
        ),

    async execute(interaction) {
        if (!interaction.memberPermissions.has(PermissionFlagsBits.ManageRoles)) {
            return interaction.reply({ content: 'You need the Manage Roles permission to manage reaction roles.', ephemeral: true });
        }
        const client = interaction.client;
        const mgr = client.reactionRoleManager;
        if (!mgr || typeof mgr.createMenu !== 'function') {
            return interaction.reply({ content: 'Reaction-role manager is not available. Set REACTION_DATABASE_URL (or DATABASE_URL).', ephemeral: true });
        }

        const sub = interaction.options.getSubcommand();
        const guildId = interaction.guild.id;

        try {
            switch (sub) {
                case 'create':
                case 'attach': {
                    const mappings = parseMappings(interaction.options.getString('mappings'));
                    if (mappings.length === 0) {
                        return interaction.reply({ content: 'You must provide at least one emoji→role mapping.', ephemeral: true });
                    }
                    const channel = interaction.options.getChannel('channel');
                    const mode = interaction.options.getString('mode') || 'normal';
                    const attach = sub === 'attach';
                    const menu = await mgr.createMenu({
                        guildId,
                        channelId: channel.id,
                        title: interaction.options.getString('title'),
                        description: interaction.options.getString('description'),
                        color: interaction.options.getString('color'),
                        mode,
                        persistent: interaction.options.getBoolean('persistent'),
                        includeBots: interaction.options.getBoolean('include_bots'),
                        requiredRoleId: interaction.options.getRole('required_role')?.id,
                        exclusiveRoleId: interaction.options.getRole('exclusive_role')?.id,
                        createdBy: interaction.user.id,
                        mappings,
                        attach,
                        messageId: attach ? interaction.options.getString('message_id') : null,
                    });
                    const embed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('✅ Reaction-role menu created')
                        .setDescription(attach
                            ? `Attached to message \`${menu.messageId}\` in <#${menu.channelId}> (menu #${menu.id}).`
                            : `Posted in <#${menu.channelId}> (menu #${menu.id}).`)
                        .addFields({ name: 'Mappings', value: menu.mappings.map(m => `${mgr._emojiDisplay(m.emoji)} → <@&${m.roleId}>`).join('\n') || 'None' })
                        .setFooter({ text: `Version ${config.version}` });
                    return interaction.reply({ embeds: [embed] });
                }

                case 'list': {
                    const menus = mgr.getGuildMenus(guildId);
                    if (menus.length === 0) {
                        return interaction.reply({ content: 'No reaction-role menus in this server. Use `/reactionrole create` or `attach`.', ephemeral: true });
                    }
                    const lines = menus.map(m =>
                        `**#${m.id}** — <#${m.channelId}> [\`${m.messageId}\`] · ${m.mappings.length} role(s) · mode: \`${m.mode}\` · ${m.enabled ? '✅' : '⛔'}`
                    ).join('\n');
                    const embed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('🎭 Reaction-role menus')
                        .setDescription(lines)
                        .setFooter({ text: `Version ${config.version}` });
                    return interaction.reply({ embeds: [embed] });
                }

                case 'edit': {
                    const id = interaction.options.getInteger('id');
                    const patch = {};
                    if (interaction.options.getString('title') !== null) patch.title = interaction.options.getString('title');
                    if (interaction.options.getString('description') !== null) patch.description = interaction.options.getString('description');
                    if (interaction.options.getString('mode')) patch.mode = interaction.options.getString('mode');
                    if (interaction.options.getString('color')) patch.color = interaction.options.getString('color');
                    if (interaction.options.getRole('required_role')) patch.requiredRoleId = interaction.options.getRole('required_role').id;
                    if (interaction.options.getRole('exclusive_role')) patch.exclusiveRoleId = interaction.options.getRole('exclusive_role').id;
                    if (interaction.options.getBoolean('enabled') !== null) patch.enabled = interaction.options.getBoolean('enabled');
                    if (interaction.options.getBoolean('persistent') !== null) patch.persistent = interaction.options.getBoolean('persistent');
                    if (interaction.options.getBoolean('include_bots') !== null) patch.includeBots = interaction.options.getBoolean('include_bots');
                    if (interaction.options.getString('mappings')) patch.mappings = parseMappings(interaction.options.getString('mappings'));
                    const menu = await mgr.updateMenu(id, patch);
                    return interaction.reply({ content: `✅ Menu #${menu.id} updated.`, ephemeral: true });
                }

                case 'delete': {
                    const id = interaction.options.getInteger('id');
                    const ok = await mgr.deleteMenu(id);
                    return interaction.reply({ content: ok ? `🗑️ Menu #${id} deleted.` : `No menu with ID ${id}.`, ephemeral: true });
                }

                case 'show': {
                    const id = interaction.options.getInteger('id');
                    const m = mgr.getMenuById(id);
                    if (!m || m.guildId !== guildId) {
                        return interaction.reply({ content: 'No such menu in this server.', ephemeral: true });
                    }
                    const embed = new EmbedBuilder()
                        .setColor(m.color || config.colors.primary)
                        .setTitle(`🎭 Menu #${m.id}`)
                        .addFields(
                            { name: 'Channel', value: `<#${m.channelId}>`, inline: true },
                            { name: 'Message', value: `\`${m.messageId}\``, inline: true },
                            { name: 'Mode', value: `\`${m.mode}\``, inline: true },
                            { name: 'Enabled', value: m.enabled ? '✅' : '⛔', inline: true },
                            { name: 'Persistent', value: m.persistent ? '✅' : '⛔', inline: true },
                            { name: 'Include bots', value: m.includeBots ? '✅' : '⛔', inline: true },
                            { name: 'Required role', value: m.requiredRoleId ? `<@&${m.requiredRoleId}>` : '—', inline: true },
                            { name: 'Exclusive role', value: m.exclusiveRoleId ? `<@&${m.exclusiveRoleId}>` : '—', inline: true },
                            { name: 'Mappings', value: m.mappings.map(mm => `${mgr._emojiDisplay(mm.emoji)} → <@&${mm.roleId}>${mm.label ? ` (${mm.label})` : ''}`).join('\n') || 'None' },
                        )
                        .setFooter({ text: `Version ${config.version}` });
                    return interaction.reply({ embeds: [embed] });
                }
            }
        } catch (err) {
            console.error('[REACTIONROLE CMD] Error:', err);
            return interaction.reply({ content: `Error: ${err.message}`, ephemeral: true });
        }
    },
};
