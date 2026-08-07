const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('lock')
        .setDescription('Lock a channel so @everyone cannot send messages')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to lock (defaults to the current channel)')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            if (!channel || !channel.isTextBased?.()) {
                return interaction.reply({ content: 'That channel cannot be locked.', ephemeral: true });
            }

            const everyone = channel.guild.roles.everyone;
            await channel.permissionOverwrites.edit(everyone, {
                SendMessages: false,
                AddReactions: false,
            });

            return interaction.reply({ content: `Locked **${channel.name}**.`, ephemeral: true });
        } catch (error) {
            console.error('[LOCK] failed:', error);
            return interaction.reply({ content: 'I could not lock that channel.', ephemeral: true });
        }
    },
};
