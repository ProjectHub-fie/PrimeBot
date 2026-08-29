const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('ban')
        .setDescription('Ban a member from the server')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addUserOption(option =>
            option.setName('member')
                .setDescription('Member to ban')
                .setRequired(true)
        )
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Ban reason')
                .setRequired(false)
        )
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('Delete recent messages from the past N days')
                .setRequired(false)
                .setMinValue(0)
                .setMaxValue(7)
        ),

    async execute(interaction) {
        try {
            const member = interaction.options.getUser('member');
            const reason = interaction.options.getString('reason') || 'No reason provided';
            const deleteDays = interaction.options.getInteger('days') || 0;

            await interaction.guild.members.ban(member, {
                reason,
                deleteMessageSeconds: deleteDays * 24 * 60 * 60,
            });

            // Ban DM (all-fields embed + optional Appeal button, driven by the
            // dashboard Automod tab → "DM user" / "Use appeal").
            interaction.client.appealManager?.sendBanDm?.({
                guild: interaction.guild,
                user: member,
                reason,
                action: 'ban',
                moderator: interaction.user,
                cid: null,
            }).catch(() => {});

            return interaction.reply({ content: `Banned **${member.tag}** for: ${reason}`, ephemeral: true });
        } catch (error) {
            console.error('[BAN] failed:', error);
            return interaction.reply({ content: 'I could not ban that member.', ephemeral: true });
        }
    },
};
