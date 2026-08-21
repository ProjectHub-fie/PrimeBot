const { SlashCommandBuilder } = require('discord.js');
const botRoles = require('../utils/botRoles');
const devEmbed = require('../utils/devEmbed');

// /dev — PrimeBot bot-management role service. Anyone can inspect roles; only
// the owner (config.developerIds) can assign/remove them. Owner level itself is
// never assignable through the command.
module.exports = {
    data: new SlashCommandBuilder()
        .setName('dev')
        .setDescription('PrimeBot management role service')
        .addSubcommand(sub =>
            sub.setName('user')
                .setDescription('Show a user\'s PrimeBot role (defaults to yourself)')
                .addUserOption(opt =>
                    opt.setName('target')
                        .setDescription('User to inspect')
                        .setRequired(false)))
        .addSubcommand(sub =>
            sub.setName('add')
                .setDescription('Assign a role to a user (owner only)')
                .addUserOption(opt =>
                    opt.setName('target')
                        .setDescription('User to assign')
                        .setRequired(true))
                .addStringOption(opt =>
                    opt.setName('role')
                        .setDescription('Role to assign')
                        .setRequired(true)
                        .addChoices(
                            { name: 'User', value: 'user' },
                            { name: 'Moderator', value: 'moderator' },
                            { name: 'Admin', value: 'admin' },
                            { name: 'Developer', value: 'developer' },
                        )))
        .addSubcommand(sub =>
            sub.setName('remove')
                .setDescription('Reset a user back to the user role (owner only)')
                .addUserOption(opt =>
                    opt.setName('target')
                        .setDescription('User to reset')
                        .setRequired(true)))
        .addSubcommand(sub =>
            sub.setName('list')
                .setDescription('List all assigned roles (owner only)'))
        .setDMPermission(false),

    async execute(interaction) {
        try {
            const sub = interaction.options.getSubcommand();
            const invokerIsOwner = botRoles.isConfigOwner(interaction.user.id);

            if (sub === 'user') {
                const target = interaction.options.getUser('target') || interaction.user;
                const role = await botRoles.getRole(target.id);
                const assigned = botRoles.isConfigOwner(target.id) ? 'config' : 'database';
                return interaction.reply({
                    embeds: [devEmbed.roleEmbed({ targetUser: target, role, assigned: role === 'user' && !botRoles.isConfigOwner(target.id) ? 'default' : assigned })],
                });
            }

            if (sub === 'list') {
                if (!invokerIsOwner) {
                    return interaction.reply({ embeds: [devEmbed.errorEmbed('Only the bot owner can list assigned roles.')], ephemeral: true });
                }
                const rows = await botRoles.listRoleRows();
                return interaction.reply({ embeds: [devEmbed.listEmbed(rows)] });
            }

            if (sub === 'add' || sub === 'remove') {
                if (!invokerIsOwner) {
                    return interaction.reply({ embeds: [devEmbed.errorEmbed('Only the bot owner can manage roles.')], ephemeral: true });
                }
                const target = interaction.options.getUser('target');

                if (sub === 'add') {
                    const roleInput = interaction.options.getString('role');
                    const role = botRoles.normalizeRoleName(roleInput);
                    if (!role || role === 'owner') {
                        return interaction.reply({
                            embeds: [devEmbed.errorEmbed('The **owner** role is reserved for the bot owner id in `config.developerIds` and cannot be assigned. Use user/moderator/admin/developer.')],
                            ephemeral: true,
                        });
                    }
                    const ok = await botRoles.setRole(target.id, role, interaction.user.id);
                    if (!ok) {
                        return interaction.reply({ embeds: [devEmbed.errorEmbed('Failed to save the role — check the database connection.')], ephemeral: true });
                    }
                    return interaction.reply({
                        embeds: [devEmbed.successEmbed('✅ Role assigned', `<@${target.id}> is now **${botRoles.ROLE_INFO[role].emoji} ${botRoles.ROLE_INFO[role].label}**.`)],
                    });
                }

                // remove
                if (botRoles.isConfigOwner(target.id)) {
                    return interaction.reply({
                        embeds: [devEmbed.errorEmbed('The bot **owner** (from `config.developerIds`) cannot be reset.')],
                        ephemeral: true,
                    });
                }
                const ok = await botRoles.removeRole(target.id);
                if (!ok) {
                    return interaction.reply({ embeds: [devEmbed.errorEmbed('Failed to reset the role — check the database connection.')], ephemeral: true });
                }
                return interaction.reply({
                    embeds: [devEmbed.successEmbed('✅ Role reset', `<@${target.id}> is back to **${botRoles.ROLE_INFO.user.emoji} ${botRoles.ROLE_INFO.user.label}**.`)],
                });
            }

            return interaction.reply({ embeds: [devEmbed.helpEmbed('/')] });
        } catch (error) {
            console.error('[DEV COMMAND] Execution failed:', error);
            const payload = { embeds: [devEmbed.errorEmbed('An unexpected error occurred while running the role service.')], ephemeral: true };
            if (interaction.replied || interaction.deferred) return interaction.followUp(payload).catch(() => {});
            return interaction.reply(payload).catch(() => {});
        }
    },
};
