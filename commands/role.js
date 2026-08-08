const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('role')
        .setDescription('Manage roles for this server')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addSubcommand(subcommand =>
            subcommand
                .setName('add')
                .setDescription('Add a role to a user')
                .addUserOption(option => option.setName('user').setDescription('The member to receive the role').setRequired(true))
                .addRoleOption(option => option.setName('role').setDescription('The role to assign').setRequired(true))
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('remove')
                .setDescription('Remove a role from a user')
                .addUserOption(option => option.setName('user').setDescription('The member to remove the role from').setRequired(true))
                .addRoleOption(option => option.setName('role').setDescription('The role to remove').setRequired(true))
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('create')
                .setDescription('Create a new role')
                .addStringOption(option => option.setName('name').setDescription('Role name').setRequired(true))
                .addStringOption(option => option.setName('color').setDescription('Role color as hex (e.g. #5865F2)').setRequired(false))
                .addBooleanOption(option => option.setName('hoist').setDescription('Show role separately in the member list').setRequired(false))
                .addBooleanOption(option => option.setName('mentionable').setDescription('Allow anyone to mention this role').setRequired(false))
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('list')
                .setDescription('List roles in this server')
        ),

    async execute(interaction) {
        try {
            const subcommand = interaction.options.getSubcommand();
            const guild = interaction.guild;
            const botMember = guild.members.me;

            if (!botMember) {
                return interaction.reply({ content: 'The bot member details are not available right now.', ephemeral: true });
            }

            switch (subcommand) {
                case 'add': {
                    const targetUser = interaction.options.getUser('user');
                    const targetRole = interaction.options.getRole('role');
                    const member = await guild.members.fetch(targetUser.id).catch(() => null);

                    if (!member) {
                        return interaction.reply({ content: 'That user is not a member of this server.', ephemeral: true });
                    }

                    if (targetRole.position >= botMember.roles.highest.position) {
                        return interaction.reply({ content: 'I cannot assign a role that is at or above my highest role.', ephemeral: true });
                    }

                    if (member.roles.cache.has(targetRole.id)) {
                        return interaction.reply({ content: `${targetUser} already has the role ${targetRole}.`, ephemeral: true });
                    }

                    await member.roles.add(targetRole);

                    const embed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('✅ Role Added')
                        .setDescription(`${targetUser} now has ${targetRole}.`)
                        .setFooter({ text: `Version ${config.version}` })
                        .setTimestamp();

                    return interaction.reply({ embeds: [embed] });
                }

                case 'remove': {
                    const targetUser = interaction.options.getUser('user');
                    const targetRole = interaction.options.getRole('role');
                    const member = await guild.members.fetch(targetUser.id).catch(() => null);

                    if (!member) {
                        return interaction.reply({ content: 'That user is not a member of this server.', ephemeral: true });
                    }

                    if (targetRole.position >= botMember.roles.highest.position) {
                        return interaction.reply({ content: 'I cannot remove a role that is at or above my highest role.', ephemeral: true });
                    }

                    if (member.roles.highest.position >= botMember.roles.highest.position) {
                        return interaction.reply({ content: 'I cannot remove roles from a member whose highest role is above my highest role for safety.', ephemeral: true });
                    }

                    if (!member.roles.cache.has(targetRole.id)) {
                        return interaction.reply({ content: `${targetUser} does not have the role ${targetRole}.`, ephemeral: true });
                    }

                    await member.roles.remove(targetRole);

                    const embed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('✅ Role Removed')
                        .setDescription(`${targetRole} has been removed from ${targetUser}.`)
                        .setFooter({ text: `Version ${config.version}` })
                        .setTimestamp();

                    return interaction.reply({ embeds: [embed] });
                }

                case 'create': {
                    const name = interaction.options.getString('name');
                    const colorValue = interaction.options.getString('color') || null;
                    const hoist = interaction.options.getBoolean('hoist') || false;
                    const mentionable = interaction.options.getBoolean('mentionable') || false;

                    const color = colorValue ? colorValue : null;

                    const createdRole = await guild.roles.create({
                        name,
                        color: color && /^#[0-9A-F]{6}$/i.test(color) ? color : undefined,
                        hoist,
                        mentionable,
                        reason: `Created by ${interaction.user.tag}`,
                    });

                    const embed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('✅ Role Created')
                        .setDescription(`The role ${createdRole} has been created.`)
                        .addFields(
                            { name: 'Name', value: createdRole.name, inline: true },
                            { name: 'Color', value: createdRole.hexColor || 'Default', inline: true },
                            { name: 'Hoist', value: createdRole.hoist ? 'Yes' : 'No', inline: true },
                            { name: 'Mentionable', value: createdRole.mentionable ? 'Yes' : 'No', inline: true }
                        )
                        .setFooter({ text: `Version ${config.version}` })
                        .setTimestamp();

                    return interaction.reply({ embeds: [embed] });
                }

                case 'list': {
                    const roles = [...guild.roles.cache.values()]
                        .sort((a, b) => b.position - a.position)
                        .slice(0, 25);

                    const description = roles.map(role => `${role} • ${role.members.size} member${role.members.size === 1 ? '' : 's'}`).join('\n');

                    const embed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('📋 Server Roles')
                        .setDescription(description || 'No roles found.')
                        .setFooter({ text: `Version ${config.version}` })
                        .setTimestamp();

                    return interaction.reply({ embeds: [embed] });
                }

                default:
                    return interaction.reply({ content: 'Unknown role subcommand.', ephemeral: true });
            }
        } catch (error) {
            console.error('[ROLE CMD] Error:', error);
            return interaction.reply({ content: 'There was an error while running the role command.', ephemeral: true });
        }
    },
};
