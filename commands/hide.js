const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('hide')
        .setDescription('Hide a channel from @everyone')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to hide (defaults to the current channel)')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            if (!channel) {
                return interaction.reply({ content: 'That channel cannot be hidden.', ephemeral: true });
            }

            const everyone = channel.guild.roles.everyone;
            await channel.permissionOverwrites.edit(everyone, {
                ViewChannel: false,
            });

            return interaction.reply({ content: `Hidden **${channel.name}** from @everyone.`, ephemeral: true });
        } catch (error) {
            console.error('[HIDE] failed:', error);
            return interaction.reply({ content: 'I could not hide that channel.', ephemeral: true });
        }
    },
};
