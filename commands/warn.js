const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('warn')
        .setDescription('Warn a member (premium automod, free)')
        .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers)
        .addUserOption(option =>
            option.setName('member').setDescription('Member to warn').setRequired(true)
        )
        .addStringOption(option =>
            option.setName('reason').setDescription('Reason for the warning').setRequired(false)
        ),

    async execute(interaction) {
        const member = interaction.options.getMember('member');
        const reason = interaction.options.getString('reason') || 'No reason provided';

        if (!member) {
            return interaction.reply({ content: 'That member is not in this server.', ephemeral: true });
        }
        if (member.id === interaction.guild.ownerId || member.roles.highest.comparePositionTo(interaction.member.roles.highest) >= 0) {
            return interaction.reply({ content: 'You can’t warn a member who is higher than or equal to you.', ephemeral: true });
        }

        try {
            const r = await interaction.client.automodManager.warnMember(interaction, member, reason);
            if (r.escalated) {
                return interaction.reply({
                    content: `⚠️ Warned **${member.user.tag}** (${r.count}/${r.warnThreshold}). They reached the threshold and were escalated to **${r.warnAction}**.`,
                    ephemeral: true,
                });
            }
            return interaction.reply({
                content: `⚠️ Warned **${member.user.tag}** — warning ${r.count}/${r.warnThreshold}. Reason: ${reason}`,
                ephemeral: true,
            });
        } catch (error) {
            console.error('[WARN] failed:', error);
            return interaction.reply({ content: 'I could not warn that member.', ephemeral: true });
        }
    },
};
