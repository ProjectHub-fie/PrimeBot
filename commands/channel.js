const { SlashCommandBuilder, PermissionFlagsBits, ChannelType, MessageFlags } = require('discord.js');
const channelAdmin = require('../utils/channelAdmin');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('channel')
        .setDescription('Create and delete channels and categories')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageChannels)
        .setDMPermission(false)
        .addSubcommand(sub => sub
            .setName('create')
            .setDescription('Create a text channel')
            .addStringOption(o => o.setName('name').setDescription('Channel name').setRequired(true).setMaxLength(100))
            .addChannelOption(o => o.setName('category').setDescription('Category to place it in')
                .addChannelTypes(ChannelType.GuildCategory).setRequired(false)))
        .addSubcommand(sub => sub
            .setName('delete')
            .setDescription('Delete a channel')
            .addChannelOption(o => o.setName('channel').setDescription('Channel to delete').setRequired(true)
                .addChannelTypes(ChannelType.GuildText, ChannelType.GuildVoice, ChannelType.GuildAnnouncement,
                    ChannelType.GuildStageVoice, ChannelType.GuildForum, ChannelType.GuildMedia)))
        .addSubcommand(sub => sub
            .setName('category-create')
            .setDescription('Create a channel category')
            .addStringOption(o => o.setName('name').setDescription('Category name').setRequired(true).setMaxLength(100)))
        .addSubcommand(sub => sub
            .setName('category-delete')
            .setDescription('Delete a channel category (channels inside are kept)')
            .addChannelOption(o => o.setName('category').setDescription('Category to delete').setRequired(true)
                .addChannelTypes(ChannelType.GuildCategory))),

    async execute(interaction) {
        const sub = interaction.options.getSubcommand();
        const guild = interaction.guild;
        const invokerId = interaction.user.id;
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });

        let result;
        if (sub === 'create') {
            const category = interaction.options.getChannel('category');
            result = await channelAdmin.createTextChannel(
                guild,
                interaction.options.getString('name', true),
                category ? category.id : null,
                { invokerId },
            );
        } else if (sub === 'delete') {
            const channel = interaction.options.getChannel('channel', true);
            result = await channelAdmin.deleteChannel(guild, channel.id, {
                invokerId,
                currentChannelId: interaction.channelId,
            });
        } else if (sub === 'category-create') {
            result = await channelAdmin.createCategory(guild, interaction.options.getString('name', true), { invokerId });
        } else {
            const category = interaction.options.getChannel('category', true);
            result = await channelAdmin.deleteCategory(guild, category.id, { invokerId });
        }

        return interaction.editReply({ content: result.text });
    },
};
