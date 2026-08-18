const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const ms = require('ms');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('lgiveway')
        .setDescription('Live giveaway system - create giveaways that can be shared across servers')
        .setDefaultMemberPermissions(PermissionFlagsBits.SendMessages)

        .addSubcommand(subcommand =>
            subcommand
                .setName('create')
                .setDescription('Create a new live giveaway')
                .addStringOption(option =>
                    option.setName('prize')
                        .setDescription('The prize for the giveaway')
                        .setRequired(true))
                .addStringOption(option =>
                    option.setName('duration')
                        .setDescription('Giveaway duration (e.g., 1h, 2d) or leave empty for permanent')
                        .setRequired(false))
                .addIntegerOption(option =>
                    option.setName('winners')
                        .setDescription('Number of winners (default 1)')
                        .setRequired(false)
                        .setMinValue(1)
                        .setMaxValue(10))
                .addStringOption(option =>
                    option.setName('description')
                        .setDescription('Optional description/details for the giveaway')
                        .setRequired(false)))

        .addSubcommand(subcommand =>
            subcommand
                .setName('join')
                .setDescription('Join a live giveaway using giveaway ID or pass code')
                .addStringOption(option =>
                    option.setName('identifier')
                        .setDescription('Giveaway ID or pass code')
                        .setRequired(true)))

        .addSubcommand(subcommand =>
            subcommand
                .setName('results')
                .setDescription('View live giveaway results / winners')
                .addStringOption(option =>
                    option.setName('identifier')
                        .setDescription('Giveaway ID or pass code')
                        .setRequired(true)))

        .addSubcommand(subcommand =>
            subcommand
                .setName('end')
                .setDescription('End your giveaway (creator only)')
                .addStringOption(option =>
                    option.setName('giveaway_id')
                        .setDescription('Giveaway ID to end')
                        .setRequired(true)))

        .addSubcommand(subcommand =>
            subcommand
                .setName('list')
                .setDescription('List your created live giveaways')),

    async execute(interaction) {
        const subcommand = interaction.options.getSubcommand();
        try {
            switch (subcommand) {
                case 'create':
                    return await this.handleCreate(interaction);
                case 'join':
                    return await this.handleJoin(interaction);
                case 'results':
                    return await this.handleResults(interaction);
                case 'end':
                    return await this.handleEnd(interaction);
                case 'list':
                    return await this.handleList(interaction);
                default:
                    return interaction.reply({ content: 'Unknown subcommand.', ephemeral: true });
            }
        } catch (error) {
            console.error(`Error in lgiveway ${subcommand}:`, error);
            const content = 'There was an error processing your request. Please try again later.';
            if (interaction.replied || interaction.deferred) {
                await interaction.followUp({ content, ephemeral: true }).catch(() => {});
            } else {
                await interaction.reply({ content, ephemeral: true }).catch(() => {});
            }
        }
    },

    async handleCreate(interaction) {
        const prize = interaction.options.getString('prize');
        const durationStr = interaction.options.getString('duration');
        const winnerCount = interaction.options.getInteger('winners') ?? 1;
        const description = interaction.options.getString('description');

        let duration = null;
        if (durationStr) {
            duration = ms(durationStr);
            if (!duration || isNaN(duration)) {
                return interaction.reply({ content: 'Please provide a valid duration (e.g., 1h, 2d) or leave empty for a permanent giveaway.', ephemeral: true });
            }
            if (duration < 60000) {
                return interaction.reply({ content: 'Giveaway duration must be at least 1 minute.', ephemeral: true });
            }
        }

        const result = await interaction.client.liveGiveawayManager.createGiveaway({
            prize, description, creatorId: interaction.user.id, winnerCount, duration,
        });

        const embed = new EmbedBuilder()
            .setColor(config.colors.success)
            .setTitle('🎉 Live Giveaway Created!')
            .setDescription(`**Prize**: ${prize}`)
            .addFields(
                { name: '🆔 Giveaway ID', value: `\`${result.giveawayId}\``, inline: true },
                { name: '🔑 Pass Code', value: `\`${result.passCode}\``, inline: true },
                { name: '🏆 Winners', value: `${winnerCount}`, inline: true },
                { name: '🔗 Share Info', value: 'Share the **Giveaway ID** or **Pass Code** so others can join!', inline: false },
            )
            .setFooter({ text: `Created by ${interaction.user.tag} • Version ${config.version}`, iconURL: interaction.user.displayAvatarURL({ dynamic: true }) })
            .setTimestamp();

        if (duration) {
            embed.addFields({ name: '⏰ Expires', value: `<t:${Math.floor((Date.now() + duration) / 1000)}:R>`, inline: true });
        } else {
            embed.addFields({ name: '⏰ Duration', value: 'Permanent (until manually ended)', inline: true });
        }

        await interaction.reply({ embeds: [embed], ephemeral: false });

        const giveaway = await interaction.client.liveGiveawayManager.getGiveaway(result.giveawayId);
        if (giveaway) {
            const votingEmbed = interaction.client.liveGiveawayManager.createGiveawayEmbed(giveaway, 0);
            const buttons = interaction.client.liveGiveawayManager.createJoinButton(result.giveawayId);
            const votingMessage = await interaction.followUp({ embeds: [votingEmbed], components: [buttons], ephemeral: false });
            await interaction.client.liveGiveawayManager.updateGiveawayMessage(
                result.giveawayId, votingMessage.id, interaction.channel.id
            );
        }
    },

    async handleJoin(interaction) {
        const identifier = interaction.options.getString('identifier');
        const giveaway = await interaction.client.liveGiveawayManager.getGiveaway(identifier);
        if (!giveaway) {
            return interaction.reply({ content: 'Giveaway not found. Please check the Giveaway ID or Pass Code.', ephemeral: true });
        }
        if (!giveaway.isActive || giveaway.ended) {
            return interaction.reply({ content: 'This giveaway has ended.', ephemeral: true });
        }
        if (giveaway.endsAt && new Date() > new Date(giveaway.endsAt)) {
            return interaction.reply({ content: 'This giveaway has ended.', ephemeral: true });
        }
        const embed = interaction.client.liveGiveawayManager.createGiveawayEmbed(giveaway, giveaway.participants.size);
        const buttons = interaction.client.liveGiveawayManager.createJoinButton(giveaway.giveawayId);
        await interaction.reply({ embeds: [embed], components: [buttons], ephemeral: false });
    },

    async handleResults(interaction) {
        const identifier = interaction.options.getString('identifier');
        const results = await interaction.client.liveGiveawayManager.getGiveawayResults(identifier);
        if (!results) {
            return interaction.reply({ content: 'Giveaway not found. Please check the Giveaway ID or Pass Code.', ephemeral: true });
        }
        const embed = interaction.client.liveGiveawayManager.createGiveawayEmbed(
            results.giveaway, results.participants.length, results.winners, !results.giveaway.isActive
        );
        await interaction.reply({ embeds: [embed], ephemeral: false });
    },

    async handleEnd(interaction) {
        const giveawayId = interaction.options.getString('giveaway_id');
        const result = await interaction.client.liveGiveawayManager.endGiveaway(giveawayId, interaction.user.id);
        if (!result.success) {
            return interaction.reply({ content: result.message, ephemeral: true });
        }
        if (result.winners && result.winners.length > 0) {
            const winnersEmbed = interaction.client.liveGiveawayManager.createGiveawayEmbed(
                result.giveaway, result.participants.length, result.winners, true
            );
            await interaction.reply({ embeds: [winnersEmbed], ephemeral: false });
        } else {
            const embed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('🎉 Giveaway Ended')
                .setDescription(`Giveaway \`${giveawayId}\` has been ended.\n\nNo one entered this giveaway.`)
                .setFooter({ text: `Ended by ${interaction.user.tag} • Version ${config.version}`, iconURL: interaction.user.displayAvatarURL({ dynamic: true }) })
                .setTimestamp();
            await interaction.reply({ embeds: [embed], ephemeral: false });
        }
    },

    async handleList(interaction) {
        const giveaways = await interaction.client.liveGiveawayManager.getUserGiveaways(interaction.user.id);
        if (giveaways.length === 0) {
            return interaction.reply({ content: "You haven't created any live giveaways yet.", ephemeral: true });
        }
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('🎉 Your Live Giveaways')
            .setDescription('Here are your created giveaways:')
            .setFooter({ text: `Requested by ${interaction.user.tag} • Version ${config.version}`, iconURL: interaction.user.displayAvatarURL({ dynamic: true }) })
            .setTimestamp();
        const list = giveaways.map(g => {
            const status = g.isActive ? '🟢 Active' : '🔴 Ended';
            const expires = g.endsAt ? `<t:${Math.floor(new Date(g.endsAt).getTime() / 1000)}:R>` : 'Permanent';
            return `**ID:** \`${g.giveawayId}\` | **Code:** \`${g.passCode}\`\n${status} • Expires: ${expires}\n**Prize:** ${g.prize}`;
        }).join('\n\n');
        embed.addFields({ name: 'Giveaways', value: list, inline: false });
        await interaction.reply({ embeds: [embed], ephemeral: true });
    },
};
