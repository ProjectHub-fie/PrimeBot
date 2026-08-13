const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('mute')
        .setDescription('Mute/timeout a member (premium automod, free)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers)
        .addUserOption(option =>
            option.setName('member').setDescription('Member to mute').setRequired(true)
        )
        .addIntegerOption(option =>
            option.setName('seconds')
                .setDescription('Mute duration in seconds (omit for an indefinite role mute)')
                .setRequired(false)
                .setMinValue(1)
                .setMaxValue(2419200)
        )
        .addStringOption(option =>
            option.setName('reason').setDescription('Reason for the mute').setRequired(false)
        ),

    async execute(interaction) {
        const member = interaction.options.getMember('member');
        const seconds = interaction.options.getInteger('seconds');
        const reason = interaction.options.getString('reason') || 'Muted by moderator';

        if (!member) {
            return interaction.reply({ content: 'That member is not in this server.', ephemeral: true });
        }
        if (member.id === interaction.guild.ownerId || member.roles.highest.comparePositionTo(interaction.member.roles.highest) >= 0) {
            return interaction.reply({ content: 'You can’t mute a member who is higher than or equal to you.', ephemeral: true });
        }

        try {
            await interaction.client.automodManager.muteMember(interaction, member, seconds, reason);
            return interaction.reply({
                content: `🔇 Muted **${member.user.tag}**${seconds ? ` for ${seconds}s` : ''}. Reason: ${reason}`,
                ephemeral: true,
            });
        } catch (error) {
            console.error('[MUTE] failed:', error);
            return interaction.reply({ content: 'I could not mute that member. Make sure I have the Timeout Members permission or a mute role is set in the dashboard.', ephemeral: true });
        }
    },
};
