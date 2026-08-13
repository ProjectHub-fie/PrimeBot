const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('unwarn')
        .setDescription('Remove warnings from a member (premium automod, free)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers)
        .addUserOption(option =>
            option.setName('member').setDescription('Member to remove warnings from').setRequired(true)
        )
        .addIntegerOption(option =>
            option.setName('count')
                .setDescription('How many recent warnings to remove (omit for all)')
                .setRequired(false)
                .setMinValue(1)
        ),

    async execute(interaction) {
        const member = interaction.options.getMember('member');
        const count = interaction.options.getInteger('count'); // null => all

        if (!member) {
            return interaction.reply({ content: 'That member is not in this server.', ephemeral: true });
        }

        try {
            const remaining = await interaction.client.automodManager.removeWarnings(
                interaction.guild.id, member.id, count || 'all'
            );
            return interaction.reply({
                content: `✅ Removed warnings from **${member.user.tag}**. ${remaining} warning(s) remaining.`,
                ephemeral: true,
            });
        } catch (error) {
            console.error('[UNWARN] failed:', error);
            return interaction.reply({ content: 'I could not remove warnings for that member.', ephemeral: true });
        }
    },
};
