const { SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('rm')
        .setDescription('Rename a channel')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addStringOption(option =>
            option.setName('name')
                .setDescription('New channel name')
                .setRequired(true)
        )
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to rename (defaults to the current channel)')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const targetChannel = interaction.options.getChannel('channel') || interaction.channel;
            const name = interaction.options.getString('name');

            if (!targetChannel || !targetChannel.editable) {
                return interaction.reply({ content: 'I can’t rename that channel from here.', ephemeral: true });
            }

            await targetChannel.setName(name);
            return interaction.reply({ content: `Renamed ${targetChannel} to **${name}**.`, ephemeral: true });
        } catch (error) {
            console.error('[RM] Rename failed:', error);
            return interaction.reply({ content: 'The channel rename failed. Check permissions or the name format.', ephemeral: true });
        }
    },
};
