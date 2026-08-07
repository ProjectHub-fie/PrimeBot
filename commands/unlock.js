const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('unlock')
        .setDescription('Unlock a channel so @everyone can send messages again')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to unlock (defaults to the current channel)')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            if (!channel || !channel.isTextBased?.()) {
                return interaction.reply({ content: 'That channel cannot be unlocked.', ephemeral: true });
            }

            const everyone = channel.guild.roles.everyone;
            await channel.permissionOverwrites.edit(everyone, {
                SendMessages: null,
                AddReactions: null,
            });

            return interaction.reply({ content: `Unlocked **${channel.name}**.`, ephemeral: true });
        } catch (error) {
            console.error('[UNLOCK] failed:', error);
            return interaction.reply({ content: 'I could not unlock that channel.', ephemeral: true });
        }
    },
};
