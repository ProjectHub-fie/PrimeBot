const { safeReply, safeExecute } = require('../utils/stabilityUtils');
const interactionDebugger = require('../utils/interactionDebugger');
const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');

/**
 * Helper function to show main help menu for button interactions
 */
async function showMainHelpUpdate(interaction) {
    const mainEmbed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('📚 Command Categories')
        .setDescription('Choose a category to explore available commands:')
        .addFields(
            { name: '⚡ General', value: 'Basic bot commands and information', inline: true },
            { name: '📊 Leveling', value: 'XP, ranks, and progression system', inline: true },
            { name: '🎮 Games', value: 'Fun interactive games and activities', inline: true },
            { name: '🛡️ Moderation', value: 'Server management and moderation tools', inline: true },
            { name: '👥 Community', value: 'Engagement and social features', inline: true },
            { name: '⚙️ Administration', value: 'Advanced server configuration', inline: true }
        )
        .setFooter({ text: `Total Commands: 25 • Version: ${config.version}` })
        .setTimestamp();

    const categoryButtons = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('help_general')
                .setLabel('General')
                .setStyle(ButtonStyle.Primary)
                .setEmoji('⚡'),
            new ButtonBuilder()
                .setCustomId('help_leveling')
                .setLabel('Leveling')
                .setStyle(ButtonStyle.Primary)
                .setEmoji('📊'),
            new ButtonBuilder()
                .setCustomId('help_games')
                .setLabel('Games')
                .setStyle(ButtonStyle.Primary)
                .setEmoji('🎮'),
            new ButtonBuilder()
                .setCustomId('help_moderation')
                .setLabel('Moderation')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('🛡️'),
            new ButtonBuilder()
                .setCustomId('help_community')
                .setLabel('Community')
                .setStyle(ButtonStyle.Success)
                .setEmoji('👥')
        );

    const adminButton = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('help_admin')
                .setLabel('Administration')
                .setStyle(ButtonStyle.Danger)
                .setEmoji('⚙️'),
            new ButtonBuilder()
                .setCustomId('help_prefix')
                .setLabel('Prefix Commands')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('💬'),
            new ButtonBuilder()
                .setCustomId('help_support')
                .setLabel('Support')
                .setStyle(ButtonStyle.Link)
                .setURL(config.supportServer || 'https://discord.gg/primebot')
                .setEmoji('🆘')
        );

    await interaction.update({
        embeds: [mainEmbed],
        components: [categoryButtons, adminButton]
    });
}

/**
 * Helper function to show category help for button interactions
 */
async function showCategoryHelpUpdate(interaction, category) {
    let categoryEmbed;

    switch (category) {
        case 'general':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('⚡ General Commands')
                .setDescription('Basic bot commands and information:')
                .addFields(
                    { name: '/help', value: 'Show this command menu', inline: true },
                    { name: '/about', value: 'Information about the bot', inline: true },
                    { name: '/updates', value: 'Latest bot updates and features', inline: true },
                    { name: '/ses', value: 'Bot session and status information', inline: true },
                    { name: '/echo', value: 'Make the bot repeat a message', inline: true },
                    { name: '/stats', value: 'Display comprehensive bot statistics', inline: true }
                );
            break;

        case 'leveling':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Leveling System')
                .setDescription('XP, ranks, and progression commands:')
                .addFields(
                    { name: '/leveling rank', value: 'View your or another user\'s level and XP', inline: true },
                    { name: '/leveling leaderboard', value: 'Server XP leaderboard with pagination', inline: true },
                    { name: '/leveling badges', value: 'View available and earned badges', inline: true },
                    { name: '/leveling settings', value: 'Configure leveling system (Admin)', inline: true },
                    { name: '/leveling addrole', value: 'Add role rewards for levels (Admin)', inline: true },
                    { name: '/leveling removerole', value: 'Remove role rewards (Admin)', inline: true },
                    { name: '/leveling listroles', value: 'List all role rewards', inline: true },
                    { name: '/leveling award', value: 'Award XP to users (Admin)', inline: true },
                    { name: '/leveling awardbadge', value: 'Award badges to users (Admin)', inline: true }
                );
            break;

        case 'games':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.warning)
                .setTitle('🎮 Games & Activities')
                .setDescription('Fun interactive games and entertainment:')
                .addFields(
                    { name: '/tictactoe', value: 'Start a TicTacToe game in the channel', inline: true },
                    { name: '/endgame', value: 'End current TicTacToe game', inline: true },
                    { name: '/truthdare', value: 'Interactive Truth or Dare game', inline: true },
                    { name: '/addquestion', value: 'Add custom truth/dare questions', inline: true },
                    { name: '/counting', value: 'Start a number counting game', inline: true },
                    { name: '/poll', value: 'Create interactive polls with timer', inline: true },
                    { name: '/endpoll', value: 'End a poll early', inline: true }
                );
            break;

        case 'moderation':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.secondary)
                .setTitle('🛡️ Moderation Tools')
                .setDescription('Server management and moderation:')
                .addFields(
                    { name: '/ticket', value: 'Create ticket support panel', inline: true },
                    { name: '/createticket', value: 'Create ticket with custom name', inline: true },
                    { name: '/tickethistory', value: 'View ticket history and logs', inline: true },
                    { name: '/move', value: 'Move members between voice channels', inline: true },
                    { name: '/end', value: 'End giveaways and other activities', inline: true }
                );
            break;

        case 'community':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('👥 Community Features')
                .setDescription('Engagement and social features:')
                .addFields(
                    { name: '/poll', value: 'Create server polls with voting options', inline: true },
                    { name: '/lpoll', value: 'Create cross-server live polls', inline: true },
                    { name: '/endpoll', value: 'End active polls and show results', inline: true },
                    { name: '/giveaway', value: 'Create exciting giveaways with role requirements', inline: true },
                    { name: '/reroll', value: 'Reroll giveaway winners', inline: true },
                    { name: '/birthday', value: 'Birthday celebration system', inline: true },
                    { name: '/welcomeconfig', value: 'Configure welcome messages for new members', inline: true },
                    { name: '/broadcast', value: 'Send announcements to all servers', inline: true }
                );
            break;

        case 'admin':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('⚙️ Administration')
                .setDescription('Advanced server configuration (Admin only):')
                .addFields(
                    { name: '/broadcastsettings', value: 'Configure broadcast system settings', inline: true },
                    { name: '/sync configure', value: 'Set up automatic role/badge syncing', inline: true },
                    { name: '/leveling settings', value: 'Advanced leveling system configuration', inline: true },
                    { name: '/welcomeconfig', value: 'Complete welcome system setup', inline: true }
                );
            break;

        default:
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('❌ Unknown Category')
                .setDescription('The requested category was not found.');
    }

    const backButton = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('help_back')
                .setLabel('Back to Categories')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('◀️')
        );

    categoryEmbed.setFooter({ text: `Version: ${config.version}` })
                .setTimestamp();

    await interaction.update({
        embeds: [categoryEmbed],
        components: [backButton]
    });
}

module.exports = {
    name: 'interactionCreate',

    async execute(interaction, client) {
        try {
            // Initialize interaction debugger on first run
            if (!interactionDebugger.client) {
                interactionDebugger.init(client);
            }
            // Log interaction for debugging
            interactionDebugger.logInteraction(interaction, 'Incoming Interaction');

            // Handle slash commands
            if (interaction.isChatInputCommand()) {
                // Log the command usage
                console.log(`[COMMAND] Executing slash command /${interaction.commandName} from ${interaction.user.tag}`);
                interactionDebugger.logInteraction(interaction, `Slash Command (/${interaction.commandName})`);

                const command = client.commands.get(interaction.commandName);

                if (!command) {
                    console.error(`No command matching ${interaction.commandName} was found.`);
                    return safeReply(interaction, {
                        content: `Error: No command matching \`${interaction.commandName}\` was found.`,
                        ephemeral: true
                    });
                }

                try {
                    // Execute the command safely
                    await safeExecute(
                        command.execute.bind(command),
                        [interaction],
                        null,
                        `Slash Command (/${interaction.commandName})`
                    );
                } catch (slashCommandError) {
                    console.error(`Error executing command ${interaction.commandName}:`, slashCommandError);
                    interactionDebugger.debugInteractionError(interaction, slashCommandError, `Slash Command (/${interaction.commandName})`);

                    // Reply with an error message if not already replied
                    if (!interaction.replied && !interaction.deferred) {
                        await safeReply(interaction, {
                            content: 'There was an error while executing this command!',
                            ephemeral: true
                        }).catch(console.error);
                    }
                }

                return;
            }

            // Handle buttons
            if (interaction.isButton()) {
                // Get the full customId
                const customId = interaction.customId;

                // Log ALL button interactions for debugging
                console.log(`[DEBUG] ALL BUTTON INTERACTIONS - CustomId: "${customId}", User: ${interaction.user.username}, Channel: ${interaction.channel?.name}, Guild: ${interaction.guild?.name}`);

                // Handle voting buttons IMMEDIATELY before any other processing
                if (customId.startsWith('vote_')) {
                    console.log(`[VOTE DEBUG] Button pressed: ${customId} by ${interaction.user.username}`);
                    console.log(`[VOTE DEBUG] Interaction state - replied: ${interaction.replied}, deferred: ${interaction.deferred}`);

                    try {
                        // IMMEDIATELY acknowledge the interaction to prevent timeout
                        if (!interaction.replied && !interaction.deferred) {
                            console.log(`[VOTE DEBUG] Deferring interaction immediately...`);
                            await interaction.deferUpdate();
                            console.log(`[VOTE DEBUG] Interaction deferred successfully`);
                        } else {
                            console.log(`[VOTE DEBUG] Interaction already handled - replied: ${interaction.replied}, deferred: ${interaction.deferred}`);
                            return;
                        }

                        const parts = customId.split('_');
                        const pollId = parts[1];
                        const optionIndex = parseInt(parts[2]);

                        console.log(`[VOTE DEBUG] Parsed - Poll ID: ${pollId}, Option: ${optionIndex}`);

                        if (!client.livePollManager) {
                            console.error('[VOTE ERROR] LivePollManager not available!');
                            await interaction.followUp({
                                content: 'Poll system is not available. Please try again later.',
                                ephemeral: true
                            });
                            return;
                        }

                        console.log(`[VOTE DEBUG] Processing vote for poll ${pollId}, option ${optionIndex}...`);
                        const result = await client.livePollManager.vote(pollId, interaction.user.id, optionIndex);
                        console.log(`[VOTE DEBUG] Vote result:`, result);

                        if (result && result.success) {
                            console.log(`[VOTE DEBUG] Vote successful, updating display...`);
                            const pollResults = await client.livePollManager.getPollResults(pollId);

                            if (pollResults) {
                                const updatedEmbed = client.livePollManager.createPollEmbed(
                                    pollResults.poll,
                                    pollResults.options,
                                    pollResults.totalVotes,
                                    true
                                );

                                const buttons = client.livePollManager.createVoteButtons(pollId, pollResults.options);

                                console.log(`[VOTE DEBUG] Editing reply with updated results...`);
                                await interaction.editReply({
                                    embeds: [updatedEmbed],
                                    components: buttons
                                });
                                console.log(`[VOTE DEBUG] Vote processed successfully for poll ${pollId}`);
                            } else {
                                console.log(`[VOTE DEBUG] Could not get poll results after voting`);
                            }
                        } else {
                            console.log(`[VOTE DEBUG] Vote failed: ${result ? result.message : 'Unknown error'}`);
                            await interaction.followUp({
                                content: result ? result.message : 'Failed to record vote',
                                ephemeral: true
                            });
                        }
                    } catch (voteError) {
                        console.error('[VOTE ERROR] Critical error in vote processing:', voteError);
                        console.error('[VOTE ERROR] Stack trace:', voteError.stack);

                        try {
                            if (!interaction.replied && !interaction.deferred) {
                                await interaction.reply({
                                    content: 'There was an error processing your vote. Please try again.',
                                    ephemeral: true
                                });
                            } else {
                                await interaction.followUp({
                                    content: 'There was an error processing your vote. Please try again.',
                                    ephemeral: true
                                });
                            }
                        } catch (errorReplyError) {
                            console.error('[VOTE ERROR] Failed to send error reply:', errorReplyError);
                        }
                    }
                    return; // Exit early for vote buttons to prevent further processing
                }

                // Log detailed button information for debugging (for non-vote buttons)
                console.log(`[DEBUG] Button pressed with customId: "${customId}"`);

                // Log button interaction
                interactionDebugger.logInteraction(interaction, `Button (${customId})`);

                try {
                    // For other buttons that use colons as separators, extract the parts
                    const [action, ...params] = customId.split(':');
                    // Route to the appropriate handler based on customId or action
                    if (action === 'create-ticket' || interaction.customId === 'create-ticket' || interaction.customId === 'ticket_create') {
                        await safeExecute(
                            client.ticketManager.createTicket.bind(client.ticketManager),
                            [interaction],
                            null,
                            'Ticket creation button'
                        );
                    } else if (action === 'close-ticket' || interaction.customId === 'close-ticket' || interaction.customId === 'ticket_close' || action === 'reopen-ticket' || interaction.customId === 'reopen-ticket' || interaction.customId === 'ticket_reopen' || interaction.customId === 'ticket_toggle') {
                        await safeExecute(
                            client.ticketManager.toggleTicket.bind(client.ticketManager),
                            [interaction],
                            null,
                            'Ticket toggle button'
                        );
                    } else if (action === 'tictactoe') {
                        const position = params[0];
                        if (position) {
                            await safeExecute(
                                client.ticTacToeManager.makeMove.bind(client.ticTacToeManager),
                                [{ channelId: interaction.channelId, playerId: interaction.user.id, position }],
                                null,
                                'TicTacToe move button'
                            );
                        }
                    } else if (interaction.customId === 'truth_button') {
                        await safeExecute(
                            client.truthDareManager.handleButtonInteraction.bind(client.truthDareManager),
                            [interaction, 'truth'],
                            null,
                            'Truth button'
                        );
                    } else if (interaction.customId === 'dare_button') {
                        await safeExecute(
                            client.truthDareManager.handleButtonInteraction.bind(client.truthDareManager),
                            [interaction, 'dare'],
                            null,
                            'Dare button'
                        );
                    } else if (interaction.customId === 'add_question') {
                        await safeExecute(
                            client.truthDareManager.handleAddQuestion.bind(client.truthDareManager),
                            [interaction],
                            null,
                            'Add question button'
                        );

                    } else if (action === 'emoji_prev_page' || action === 'emoji_next_page') {
                        // These are handled elsewhere, just acknowledge the interaction
                        try {
                            if (!interaction.replied && !interaction.deferred) {
                                await interaction.deferUpdate();
                            }
                        } catch (error) {
                            console.error('Error acknowledging emoji pagination interaction:', error);
                            // Don't throw here to prevent the entire interaction from failing
                        }
                    } else if (action === 'command_prev_page' || action === 'command_next_page') {
                        // These are handled elsewhere, just acknowledge the interaction
                        try {
                            if (!interaction.replied && !interaction.deferred) {
                                await interaction.deferUpdate();
                            }
                        } catch (error) {
                            console.error('Error acknowledging command pagination interaction:', error);
                            // Don't throw here to prevent the entire interaction from failing
                        }
                    } else if (interaction.customId === 'giveaway_enter_disabled') {
                        // Handle disabled button - just inform user
                        await interaction.reply({
                            content: 'This giveaway has already ended.',
                            ephemeral: true
                        });
                    } else if (interaction.customId.startsWith('help_')) {
                        // Handle help category buttons
                        const category = interaction.customId.replace('help_', '');
                        console.log(`[HELP] Category button pressed: ${category}`);

                        if (category === 'back') {
                            // Show main help menu
                            await showMainHelpUpdate(interaction);
                        } else if (['general', 'leveling', 'games', 'moderation', 'community', 'admin'].includes(category)) {
                            // Show category help
                            await showCategoryHelpUpdate(interaction, category);
                        } else if (category === 'prefix') {
                            // Handle prefix commands help
                            await interaction.reply({
                                content: 'Prefix commands are legacy commands that start with a prefix like `!` or `$`. This bot primarily uses slash commands which are accessed by typing `/` followed by the command name.',
                                ephemeral: true
                            });
                        } else if (category === 'support') {
                            await interaction.reply({
                                content: 'For support, please join our support server or contact the bot administrators.',
                                ephemeral: true
                            });
                        }
                    } else if (interaction.customId === 'categories_main') {
                        const { showCategorySelector } = require('../commands/categories');
                        await showCategorySelector(interaction);
                        return;
                    } else if (interaction.customId === 'categories_refresh') {
                        const { showCategorySelector } = require('../commands/categories');
                        await showCategorySelector(interaction);
                        return;
                    } else if (interaction.customId === 'categories_help') {
                        await interaction.reply({
                            content: 'Use the dropdown menu to browse different command categories. Each category contains specialized commands for different server needs.\n\n**Available Categories:**\n• General - Basic bot commands\n• Leveling - XP and ranking system\n• Games - Interactive games and fun\n• Moderation - Server management tools\n• Community - Social features and events\n• Administration - Advanced server config',
                            ephemeral: true
                        });
                        return;
                    } else if (interaction.customId === 'broadcast_confirm') {
                        console.log('[BROADCAST] Broadcast confirmation button clicked');
                        // Handle broadcast confirmation - this now directly processes the broadcast
                        // Get the broadcast embed from the original message
                        const originalMessage = interaction.message;
                        const broadcastEmbed = originalMessage.embeds.length > 1 ? originalMessage.embeds[1] : null;

                        if (!broadcastEmbed) {
                            await interaction.update({
                                content: 'Error: Could not find broadcast embed. Broadcast cancelled.',
                                embeds: [],
                                components: []
                            });
                            return;
                        }

                        // Update the message to show that broadcasting has started
                        await interaction.update({
                            content: '📣 Broadcasting message to all servers...',
                            embeds: [broadcastEmbed],
                            components: []
                        });

                        // Track statistics
                        let successCount = 0;
                        let failCount = 0;
                        let skippedOptOut = 0;
                        let totalGuilds = client.guilds.cache.size;

                        // Get count of receptive servers
                        const receptiveServers = client.serverSettingsManager ?
                            client.serverSettingsManager.getBroadcastReceptionCount() : totalGuilds;

                        // Broadcast to guilds that haven't opted out
                        console.log(`[BROADCAST] Starting broadcast to ${receptiveServers} guilds that haven't opted out (total: ${totalGuilds})`);

                        // Helper function for progress bar
                        function createProgressBar(percentage) {
                            const barLength = 20;
                            const filledLength = Math.round((percentage / 100) * barLength);
                            const emptyLength = barLength - filledLength;

                            const filled = '█'.repeat(filledLength);
                            const empty = '░'.repeat(emptyLength);

                            return `[${filled}${empty}]`;
                        }

                        // Process each guild
                        let processedCount = 0;
                        const startTime = Date.now();

                        for (const guild of client.guilds.cache.values()) {
                            try {
                                console.log(`[BROADCAST] Processing guild: ${guild.name} (${guild.id})`);
                                processedCount++;

                                // Check if the guild has opted out of broadcasts
                                if (client.serverSettingsManager && !client.serverSettingsManager.receivesBroadcasts(guild.id)) {
                                    console.log(`[BROADCAST] Guild ${guild.name} has opted out of broadcasts, skipping`);
                                    skippedOptOut++;
                                    continue;
                                }

                                // Find the first available text channel
                                const channel = guild.channels.cache
                                    .filter(ch => ch.type === 0) // 0 is GuildText channel type
                                    .sort((a, b) => a.position - b.position)
                                    .first();

                                if (!channel) {
                                    console.log(`[BROADCAST] No suitable text channel found in guild: ${guild.name}`);
                                    failCount++;
                                    continue;
                                }

                                console.log(`[BROADCAST] Selected channel: ${channel.name} (${channel.id})`);

                                // Check bot permissions
                                const hasPermission = channel.permissionsFor(guild.members.me).has("SendMessages");
                                console.log(`[BROADCAST] Bot has SendMessages permission: ${hasPermission}`);

                                if (hasPermission) {
                                    await channel.send({ embeds: [broadcastEmbed] });
                                    console.log(`[BROADCAST] Successfully sent broadcast to guild: ${guild.name}`);
                                    successCount++;
                                } else {
                                    console.log(`[BROADCAST] Missing SendMessages permission in channel: ${channel.name}`);
                                    failCount++;
                                }

                                // Update progress every 5 guilds or when done
                                if (processedCount % 5 === 0 || processedCount === totalGuilds) {
                                    try {
                                        // Calculate progress percentage and display
                                        const progressPercent = Math.round((processedCount / totalGuilds) * 100);
                                        const progressBar = createProgressBar(progressPercent);
                                        const elapsedTime = Math.round((Date.now() - startTime) / 1000);

                                        await interaction.editReply({
                                            content: `📣 Broadcasting message to servers...\n${progressBar} ${progressPercent}% Complete\n\nProgress: ${processedCount}/${totalGuilds} servers\n✅ Success: ${successCount} | ❌ Failed: ${failCount} | 🔕 Opted Out: ${skippedOptOut}\n⏱️ Time elapsed: ${elapsedTime}s`,
                                            embeds: [broadcastEmbed],
                                            components: []
                                        });
                                    } catch (e) {
                                        console.error('[BROADCAST] Failed to update progress:', e);
                                    }
                                }

                            } catch (error) {
                                console.error(`[BROADCAST] Error broadcasting to guild ${guild.name}:`, error);
                                failCount++;
                            }
                        }

                        // Calculate completion metrics
                        const completionTime = Math.round((Date.now() - startTime) / 1000);
                        const eligibleServers = totalGuilds - skippedOptOut;
                        const successRate = eligibleServers > 0 ? Math.round((successCount / eligibleServers) * 100) : 0;

                        // Update with final results - modern design
                        const resultEmbed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setTitle("📣 Broadcast Complete")
                            .setDescription(`Your announcement has been broadcast to ${successCount} out of ${eligibleServers} eligible servers.\n${skippedOptOut} servers were skipped due to opt-out preferences.`)
                            .addFields(
                                { name: "✅ Success", value: `${successCount} servers`, inline: true },
                                { name: "❌ Failed", value: `${failCount} servers`, inline: true },
                                { name: "🔕 Opted Out", value: `${skippedOptOut} servers`, inline: true },
                                { name: "📊 Success Rate", value: `${successRate}%`, inline: true },
                                { name: "⏰ Time Taken", value: `${completionTime} seconds`, inline: true },
                                { name: "💬 Potential Reach", value: `Message potentially reached all members across ${successCount} servers`, inline: false },
                                { name: "📝 Opt-Out Note", value: "Servers can configure broadcast preferences with `/broadcastsettings toggle`", inline: false }
                            )
                            .setTimestamp()
                            .setFooter({ text: `Broadcast ID: ${Date.now().toString(36)}` });

                        await interaction.editReply({
                            content: "✅ Broadcast successfully completed!",
                            embeds: [resultEmbed, broadcastEmbed],
                            components: []
                        });
                    } else if (interaction.customId === 'broadcast_cancel') {
                        // Handle cancellation with a more descriptive response
                        console.log('[BROADCAST] Broadcast cancelled by user');

                        const cancelEmbed = new EmbedBuilder()
                            .setColor(config.colors.danger)
                            .setTitle('📣 Broadcast Cancelled')
                            .setDescription('Your broadcast has been cancelled. No messages were sent to any servers.')
                            .setFooter({ text: `Cancelled by ${interaction.user.tag}` })
                            .setTimestamp();

                        await interaction.update({
                            content: '✅ Broadcast has been cancelled.',
                            embeds: [cancelEmbed],
                            components: []
                        });

                    } else {
                        // Unknown button action
                        console.warn(`Unknown button action: ${action}`);
                        interactionDebugger.logInteraction(interaction, `Unknown Button Action (${action})`);

                        if (!interaction.replied) {
                            await interaction.reply({
                                content: 'This button is not currently functional.',
                                ephemeral: true
                            }).catch(console.error);
                        }
                    }
                } catch (buttonError) {
                    console.error(`[ERROR] Button interaction error for customId "${interaction.customId}":`, buttonError);
                    interactionDebugger.debugInteractionError(interaction, buttonError, `Button (${interaction.customId})`);

                    // Try to provide feedback to the user if we haven't already replied
                    if (!interaction.replied && !interaction.deferred) {
                        await interaction.reply({
                            content: 'There was an error processing your button click. Please try again.',
                            ephemeral: true
                        }).catch(e => console.error('Failed to send error reply:', e));
                    }

                    // Don't throw to prevent the entire interaction handler from failing
                    // This will allow the bot to continue handling other interactions
                }

                return;
            }

            // Handle modal submissions
            if (interaction.isModalSubmit()) {
                // Route to appropriate handler based on customId
                if (interaction.customId === 'add_question_modal') {
                    await safeExecute(
                        client.truthDareManager.handleModalSubmission.bind(client.truthDareManager),
                        [interaction],
                        null,
                        'Truth or Dare modal submission'
                    );
                }
                return;
            }

            // Handle select menus
            if (interaction.isStringSelectMenu()) {
                console.log(`[DEBUG] Select menu interaction with customId: "${interaction.customId}"`);
                interactionDebugger.logInteraction(interaction, `Select Menu (${interaction.customId})`);

                try {
                    if (interaction.customId === 'category_select_prefix') {
                        const selectedCategory = interaction.values[0];
                        console.log(`[CATEGORIES] User selected category: ${selectedCategory}`);

                        // Import the functions from the categories module
                        const { showDetailedCategoryMenuHelp } = require('../utils/categoryHelpers');
                        await showDetailedCategoryMenuHelp(interaction, selectedCategory);
                        return;
                    }
                    if (interaction.customId === 'category_select') {
                        const selectedCategory = interaction.values[0];
                        console.log(`[CATEGORIES] User selected category: ${selectedCategory}`);

                        const { showCategoryDetails } = require('../commands/categories');
                        await showCategoryDetails(interaction, selectedCategory);
                        return;
                    }
                } catch (selectError) {
                    console.error('Error handling select menu interaction:', selectError);
                    if (!interaction.replied && !interaction.deferred) {
                        await interaction.reply({
                            content: 'There was an error processing your selection. Please try again.',
                            ephemeral: true
                        }).catch(console.error);
                    }
                }

                return;
            }

            // Handle other interaction types as needed

        } catch (error) {
            console.error('Error in interactionCreate event:', error);

            // Try to respond to the user if possible
            try {
                if (!interaction.replied && !interaction.deferred) {
                    await interaction.reply({
                        content: 'There was an error executing this interaction! Please try again later.',
                        ephemeral: false
                    });
                }
            } catch (replyError) {
                console.error('Failed to send error response:', replyError);
            }
        }
    }
};