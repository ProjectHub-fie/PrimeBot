const { SlashCommandBuilder, PermissionFlagsBits, ChannelType } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('nuke')
        .setDescription('Delete and recreate a channel inside the same category')
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
        .addStringOption(option =>
            option.setName('name')
                .setDescription('Optional replacement name for the recreated channel')
                .setRequired(false)
        )
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to nuke (defaults to the current channel)')
                .setRequired(false)
        ),

    async execute(interaction) {
        try {
            const target = interaction.options.getChannel('channel') || interaction.channel;
            if (!target || !target.parent || !target.guild) {
                return interaction.reply({ content: 'That channel cannot be nuked.', ephemeral: true });
            }

            const guild = target.guild;
            const oldName = target.name;
            const category = target.parent;
            const position = target.position;
            const topic = target.topic || null;
            const nsfw = Boolean(target.nsfw);
            const reason = `Nuke requested by ${interaction.user.tag}`;

            const newChannel = await target.clone({
                name: interaction.options.getString('name') || oldName,
                topic,
                nsfw,
                parent: category,
                position,
            });

            await target.delete(reason);

            await newChannel.setPosition(position);
            await interaction.reply({ content: `Nuked **${oldName}** and recreated it as **${newChannel.name}**.`, ephemeral: true });
        } catch (error) {
            console.error('[NUKE] failed:', error);
            return interaction.reply({ content: 'I could not nuke that channel.', ephemeral: true });
        }
    },
};
