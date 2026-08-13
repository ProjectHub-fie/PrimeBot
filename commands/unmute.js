const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('unmute')
        .setDescription('Unmute/remove a timeout from a member (premium automod, free)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers)
        .addUserOption(option =>
            option.setName('member').setDescription('Member to unmute').setRequired(true)
        ),

    async execute(interaction) {
        const member = interaction.options.getMember('member');
        if (!member) {
            return interaction.reply({ content: 'That member is not in this server.', ephemeral: true });
        }

        try {
            await interaction.client.automodManager.unmuteMember(interaction, member);
            return interaction.reply({ content: `🔊 Unmuted **${member.user.tag}**.`, ephemeral: true });
        } catch (error) {
            console.error('[UNMUTE] failed:', error);
            return interaction.reply({ content: 'I could not unmute that member.', ephemeral: true });
        }
    },
};
