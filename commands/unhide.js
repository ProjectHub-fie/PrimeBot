const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('unhide')
        .setDescription('Unhide a channel for @everyone')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to unhide (defaults to the current channel)')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            if (!channel) {
                return interaction.reply({ content: 'That channel cannot be unhidden.', ephemeral: true });
            }

            const everyone = channel.guild.roles.everyone;
            await channel.permissionOverwrites.edit(everyone, {
                ViewChannel: null,
            });

            return interaction.reply({ content: `Unhidden **${channel.name}** for everyone in this server.`, ephemeral: true });
        } catch (error) {
            console.error('[UNHIDE] failed:', error);
            return interaction.reply({ content: 'I could not unhide that channel.', ephemeral: true });
        }
    },
};
