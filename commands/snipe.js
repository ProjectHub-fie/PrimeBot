const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('snipe')
        .setDescription('Show the last deleted message in this channel')
        .setDefaultMemberPermissions('0')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to inspect (defaults to this one)')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const channel = interaction.options.getChannel('channel') || interaction.channel;
            if (!channel || !channel.guildId) {
                return interaction.reply({ content: 'Snipe is only available in guild channels.', ephemeral: true });
            }

            const record = interaction.client.snipeManager?.get(channel.guildId, channel.id);
            if (!record) {
                return interaction.reply({ content: 'I don’t have a recently deleted message for this channel.', ephemeral: true });
            }

            const embed = new EmbedBuilder()
                .setColor(0xffd700)
                .setTitle('🗑️ Recently Deleted Message')
                .setDescription(record.content || '*No text content*')
                .addFields(
                    { name: 'Author', value: record.authorUsername || 'Unknown', inline: true },
                    { name: 'Channel', value: `<#${channel.id}>`, inline: true },
                    { name: 'Created', value: new Date(record.createdTimestamp).toLocaleString(), inline: true }
                );

            if (record.attachments?.length) {
                embed.addFields({ name: 'Attachments', value: record.attachments.map(a => a.url).join('\n'), inline: false });
            }

            await interaction.reply({ embeds: [embed] });
        } catch (error) {
            console.error('[SNIPE] failed:', error);
            await interaction.reply({ content: 'I could not fetch the deleted message.', ephemeral: true });
        }
    },
};
