const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('kick')
        .setDescription('Kick a member from the server')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addUserOption(option =>
            option.setName('member')
                .setDescription('Member to kick')
                .setRequired(true)
        )
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Kick reason')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const member = interaction.options.getMember('member');
            const reason = interaction.options.getString('reason') || 'No reason provided';

            if (!member) {
                return interaction.reply({ content: 'That member is not in this server.', ephemeral: true });
            }

            if (member.id === interaction.guild.ownerId || member.roles.highest.comparePositionTo(interaction.member.roles.highest) >= 0) {
                return interaction.reply({ content: 'I can’t kick that member because they are higher than or equal to you.', ephemeral: true });
            }

            await member.kick(reason);
            return interaction.reply({ content: `Kicked **${member.user.tag}** for: ${reason}`, ephemeral: true });
        } catch (error) {
            console.error('[KICK] failed:', error);
            return interaction.reply({ content: 'I could not kick that member.', ephemeral: true });
        }
    },
};
