const { SlashCommandBuilder, PermissionFlagsBits, EmbedBuilder } = require('discord.js');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('purge')
        .setDescription('Delete messages from a channel')
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageMessages)
        .addSubcommand(subcommand =>
            subcommand
                .setName('messages')
                .setDescription('Delete a batch of recent messages')
                .addIntegerOption(option =>
                    option.setName('count')
                        .setDescription('How many messages to delete')
                        .setRequired(true)
                        .setMinValue(1)
                        .setMaxValue(100)
                )
                .addChannelOption(option =>
                    option.setName('channel')
                        .setDescription('Channel to purge (defaults to current channel)')
                        .setRequired(false)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('user')
                .setDescription('Delete messages from a specific user')
                .addUserOption(option =>
                    option.setName('member')
                        .setDescription('User whose messages should be removed')
                        .setRequired(true)
                )
                .addIntegerOption(option =>
                    option.setName('count')
                        .setDescription('How many messages to inspect and delete')
                        .setRequired(false)
                        .setMinValue(1)
                        .setMaxValue(100)
                )
                .addChannelOption(option =>
                    option.setName('channel')
                        .setDescription('Channel to purge (defaults to current channel)')
                        .setRequired(false)
                )
        )
        .addSubcommand(subcommand =>
            subcommand
                .setName('between')
                .setDescription('Delete messages between two message ids')
                .addStringOption(option =>
                    option.setName('start')
                        .setDescription('Starting message id')
                        .setRequired(true)
                )
                .addStringOption(option =>
                    option.setName('end')
                        .setDescription('Ending message id')
                        .setRequired(true)
                )
                .addChannelOption(option =>
                    option.setName('channel')
                        .setDescription('Channel to purge (defaults to current channel)')
                        .setRequired(false)
                )
        )
        .setDMPermission(false),

    async execute(interaction) {
        try {
            if (!interaction.member.permissions.has(PermissionFlagsBits.ManageMessages)) {
                return interaction.reply({
                    content: 'You need the Manage Messages permission to use this command.',
                    ephemeral: true
                });
            }

            const subcommand = interaction.options.getSubcommand();
            const channel = interaction.options.getChannel('channel') || interaction.channel;

            if (!channel || !channel.isTextBased || !channel.isTextBased()) {
                return interaction.reply({
                    content: 'Please run this command in a text channel.',
                    ephemeral: true
                });
            }

            if (!channel.permissionsFor(interaction.client.user).has(PermissionFlagsBits.ManageMessages)) {
                return interaction.reply({
                    content: `I need Manage Messages permission in ${channel}.`,
                    ephemeral: true
                });
            }

            if (subcommand === 'messages') {
                const count = interaction.options.getInteger('count');
                const deleted = await channel.bulkDelete(count, true).catch(err => {
                    console.error('[PURGE] bulkDelete failed:', err);
                    return null;
                });

                if (!deleted) {
                    return interaction.reply({
                        content: `I could not delete that many messages in ${channel}.`,
                        ephemeral: true
                    });
                }

                return interaction.reply({
                    content: `Deleted ${deleted.size || count} message${count === 1 ? '' : 's'} from ${channel}.`,
                    ephemeral: true
                });
            }

            if (subcommand === 'user') {
                const member = interaction.options.getUser('member');
                const count = interaction.options.getInteger('count') || 50;

                const fetched = await channel.messages.fetch({ limit: Math.min(count, 100) });
                const ids = [...fetched.values()]
                    .filter(msg => msg.author.id === member.id)
                    .map(msg => msg.id);

                if (ids.length === 0) {
                    return interaction.reply({
                        content: `No recent messages from ${member} were found in ${channel}.`,
                        ephemeral: true
                    });
                }

                const deleted = await channel.bulkDelete(ids, true).catch(err => {
                    console.error('[PURGE] user bulkDelete failed:', err);
                    return null;
                });

                if (!deleted) {
                    return interaction.reply({
                        content: `I could not remove the selected user's messages in ${channel}.`,
                        ephemeral: true
                    });
                }

                return interaction.reply({
                    content: `Removed ${deleted.size || ids.length} message${ids.length === 1 ? '' : 's'} from ${member} in ${channel}.`,
                    ephemeral: true
                });
            }

            if (subcommand === 'between') {
                const start = interaction.options.getString('start');
                const end = interaction.options.getString('end');

                const fetched = await channel.messages.fetch({ limit: 100 });
                const ids = [...fetched.values()]
                    .filter(msg => msg.id >= start && msg.id <= end)
                    .map(msg => msg.id);

                if (ids.length === 0) {
                    return interaction.reply({
                        content: `No messages were found between those ids in ${channel}.`,
                        ephemeral: true
                    });
                }

                const deleted = await channel.bulkDelete(ids, true).catch(err => {
                    console.error('[PURGE] between bulkDelete failed:', err);
                    return null;
                });

                if (!deleted) {
                    return interaction.reply({
                        content: `I could not remove that message batch in ${channel}.`,
                        ephemeral: true
                    });
                }

                return interaction.reply({
                    content: `Removed ${deleted.size || ids.length} message${ids.length === 1 ? '' : 's'} in ${channel}.`,
                    ephemeral: true
                });
            }

            return interaction.reply({
                content: 'Unknown purge subcommand.',
                ephemeral: true
            });
        } catch (error) {
            console.error('[PURGE] Command failed:', error);
            return interaction.reply({
                content: 'There was an error while purging messages.',
                ephemeral: true
            }).catch(() => {});
        }
    }
};
