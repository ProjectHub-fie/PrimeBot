const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const ms = require('ms');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('lpoll_slash')
        .setDescription('Live poll system - create polls that can be shared across servers')
        .setDefaultMemberPermissions(PermissionFlagsBits.SendMessages)
        
        // Create subcommand
        .addSubcommand(subcommand =>
            subcommand
                .setName('create')
                .setDescription('Create a new live poll')
                .addStringOption(option =>
                    option.setName('question')
                        .setDescription('The poll question')
                        .setRequired(true))
                .addStringOption(option =>
                    option.setName('options')
                        .setDescription('Poll options separated by | (e.g., Option1|Option2|Option3)')
                        .setRequired(true))
                .addStringOption(option =>
                    option.setName('duration')
                        .setDescription('Poll duration (e.g., 1h, 2d, permanent if not specified)')
                        .setRequired(false))
                .addBooleanOption(option =>
                    option.setName('multiple_votes')
                        .setDescription('Allow users to vote multiple times')
                        .setRequired(false)))
        
        // Join subcommand
        .addSubcommand(subcommand =>
            subcommand
                .setName('join')
                .setDescription('Join a live poll using poll ID or pass code')
                .addStringOption(option =>
                    option.setName('identifier')
                        .setDescription('Poll ID or pass code')
                        .setRequired(true)))
        
        // Results subcommand
        .addSubcommand(subcommand =>
            subcommand
                .setName('results')
                .setDescription('View poll results')
                .addStringOption(option =>
                    option.setName('identifier')
                        .setDescription('Poll ID or pass code')
                        .setRequired(true)))
        
        // End subcommand
        .addSubcommand(subcommand =>
            subcommand
                .setName('end')
                .setDescription('End your poll')
                .addStringOption(option =>
                    option.setName('poll_id')
                        .setDescription('Poll ID to end')
                        .setRequired(true)))
        
        // List subcommand
        .addSubcommand(subcommand =>
            subcommand
                .setName('list')
                .setDescription('List your created polls')),

    async execute(interaction) {
        const subcommand = interaction.options.getSubcommand();

        try {
            switch (subcommand) {
                case 'create':
                    await this.handleCreate(interaction);
                    break;
                case 'join':
                    await this.handleJoin(interaction);
                    break;
                case 'results':
                    await this.handleResults(interaction);
                    break;
                case 'end':
                    await this.handleEnd(interaction);
                    break;
                case 'list':
                    await this.handleList(interaction);
                    break;
                default:
                    await interaction.reply({
                        content: 'Unknown subcommand.',
                        ephemeral: true
                    });
            }
        } catch (error) {
            console.error(`Error in lpoll ${subcommand}:`, error);
            const content = 'There was an error processing your request. Please try again later.';
            
            if (interaction.replied || interaction.deferred) {
                await interaction.followUp({ content, ephemeral: true });
            } else {
                await interaction.reply({ content, ephemeral: true });
            }
        }
    },

    async handleCreate(interaction) {
        const question = interaction.options.getString('question');
        const optionsStr = interaction.options.getString('options');
        const durationStr = interaction.options.getString('duration');
        const allowMultipleVotes = interaction.options.getBoolean('multiple_votes') ?? false;

        // Parse options
        const options = optionsStr.split('|').map(opt => opt.trim()).filter(opt => opt.length > 0);

        if (options.length < 2) {
            return interaction.reply({
                content: 'You need to provide at least 2 options for the poll.',
                ephemeral: true
            });
        }

        if (options.length > 10) {
            return interaction.reply({
                content: 'You can provide a maximum of 10 options for the poll.',
                ephemeral: true
            });
        }

        // Parse duration
        let duration = null;
        if (durationStr) {
            duration = ms(durationStr);
            if (!duration || isNaN(duration)) {
                return interaction.reply({
                    content: 'Please provide a valid duration (e.g., 1h, 2d) or leave empty for permanent poll.',
                    ephemeral: true
                });
            }

            if (duration < 60000) { // Minimum 1 minute
                return interaction.reply({
                    content: 'Poll duration must be at least 1 minute.',
                    ephemeral: true
                });
            }
        }

        // Create the poll
        const result = await interaction.client.livePollManager.createLivePoll({
            question,
            options,
            creatorId: interaction.user.id,
            duration,
            allowMultipleVotes
        });

        const embed = new EmbedBuilder()
            .setColor(config.colors.success)
            .setTitle('📊 Live Poll Created!')
            .setDescription(`**${question}**`)
            .addFields(
                { name: '🆔 Poll ID', value: `\`${result.pollId}\``, inline: true },
                { name: '🔑 Pass Code', value: `\`${result.passCode}\``, inline: true },
                { name: '🔗 Share Info', value: 'Share the **Poll ID** or **Pass Code** with others to let them vote!', inline: false },
                { name: '📝 Options', value: options.map((opt, i) => `**${i + 1}.** ${opt}`).join('\n'), inline: false }
            )
            .setFooter({ 
                text: `Created by ${interaction.user.tag} • Version ${config.version}`, 
                iconURL: interaction.user.displayAvatarURL({ dynamic: true }) 
            })
            .setTimestamp();

        if (duration) {
            embed.addFields({
                name: '⏰ Expires',
                value: `<t:${Math.floor((Date.now() + duration) / 1000)}:R>`,
                inline: true
            });
        } else {
            embed.addFields({
                name: '⏰ Duration',
                value: 'Permanent (until manually ended)',
                inline: true
            });
        }

        if (allowMultipleVotes) {
            embed.addFields({
                name: '🔄 Multiple Votes',
                value: 'Users can vote multiple times',
                inline: true
            });
        }

        // First send the creation confirmation
        await interaction.reply({
            embeds: [embed],
            ephemeral: false
        });

        // Then send the voting interface in the same channel
        const pollData = await interaction.client.livePollManager.getPoll(result.pollId);
        if (pollData) {
            const votingEmbed = interaction.client.livePollManager.createPollEmbed(
                pollData, 
                pollData.options, 
                0, 
                false
            );
            const buttons = interaction.client.livePollManager.createVoteButtons(result.pollId, pollData.options);

            const votingMessage = await interaction.followUp({
                embeds: [votingEmbed],
                components: buttons,
                ephemeral: false
            });

            // Store the message information for expiration updates
            await interaction.client.livePollManager.updatePollMessage(
                result.pollId, 
                votingMessage.id, 
                interaction.channel.id
            );
        }
    },

    async handleJoin(interaction) {
        const identifier = interaction.options.getString('identifier');

        // Get the poll
        const pollData = await interaction.client.livePollManager.getPoll(identifier);

        if (!pollData) {
            return interaction.reply({
                content: 'Poll not found. Please check the Poll ID or Pass Code.',
                ephemeral: true
            });
        }

        if (!pollData.isActive) {
            return interaction.reply({
                content: 'This poll has ended.',
                ephemeral: true
            });
        }

        // Check if poll has expired
        if (pollData.expiresAt && new Date() > new Date(pollData.expiresAt)) {
            return interaction.reply({
                content: 'This poll has expired.',
                ephemeral: true
            });
        }

        // Create poll embed and buttons
        const embed = interaction.client.livePollManager.createPollEmbed(pollData, pollData.options);
        const buttons = interaction.client.livePollManager.createVoteButtons(pollData.pollId, pollData.options);

        await interaction.reply({
            embeds: [embed],
            components: buttons,
            ephemeral: false
        });
    },

    async handleResults(interaction) {
        const identifier = interaction.options.getString('identifier');

        // Get poll results
        const results = await interaction.client.livePollManager.getPollResults(identifier);

        if (!results) {
            return interaction.reply({
                content: 'Poll not found. Please check the Poll ID or Pass Code.',
                ephemeral: true
            });
        }

        const embed = interaction.client.livePollManager.createPollEmbed(
            results.poll, 
            results.options, 
            results.totalVotes, 
            true
        );

        await interaction.reply({
            embeds: [embed],
            ephemeral: false
        });
    },

    async handleEnd(interaction) {
        const pollId = interaction.options.getString('poll_id');

        const result = await interaction.client.livePollManager.endPoll(pollId, interaction.user.id);

        if (!result.success) {
            return interaction.reply({
                content: result.message,
                ephemeral: true
            });
        }

        // Show winning celebration if there are results
        if (result.results && result.results.totalVotes > 0) {
            const winningEmbed = interaction.client.livePollManager.createPollEmbed(
                result.results.poll, 
                result.results.options, 
                result.results.totalVotes, 
                true,
                true // Show as winning announcement
            );
            
            await interaction.reply({
                embeds: [winningEmbed],
                ephemeral: false
            });
        } else {
            // Regular end message if no votes
            const embed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Poll Ended')
                .setDescription(`Poll \`${pollId}\` has been successfully ended.\n\nNo votes were cast for this poll.`)
                .setFooter({ 
                    text: `Ended by ${interaction.user.tag} • Version ${config.version}`, 
                    iconURL: interaction.user.displayAvatarURL({ dynamic: true }) 
                })
                .setTimestamp();

            await interaction.reply({
                embeds: [embed],
                ephemeral: false
            });
        }
    },

    async handleList(interaction) {
        const polls = await interaction.client.livePollManager.getUserPolls(interaction.user.id);

        if (polls.length === 0) {
            return interaction.reply({
                content: 'You haven\'t created any polls yet.',
                ephemeral: true
            });
        }

        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('📊 Your Live Polls')
            .setDescription('Here are your created polls:')
            .setFooter({ 
                text: `Requested by ${interaction.user.tag} • Version ${config.version}`, 
                iconURL: interaction.user.displayAvatarURL({ dynamic: true }) 
            })
            .setTimestamp();

        const pollsList = polls.map(poll => {
            const status = poll.isActive ? '🟢 Active' : '🔴 Ended';
            const expires = poll.expiresAt ? `<t:${Math.floor(new Date(poll.expiresAt).getTime() / 1000)}:R>` : 'Permanent';
            return `**ID:** \`${poll.pollId}\` | **Code:** \`${poll.passCode}\`\n${status} • Expires: ${expires}\n**Q:** ${poll.question.substring(0, 100)}${poll.question.length > 100 ? '...' : ''}`;
        }).join('\n\n');

        embed.addFields({
            name: 'Polls',
            value: pollsList,
            inline: false
        });

        await interaction.reply({
            embeds: [embed],
            ephemeral: true
        });
    }
};