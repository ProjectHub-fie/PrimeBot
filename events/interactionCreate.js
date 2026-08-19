const { safeReply, safeExecute } = require('../utils/stabilityUtils');
const interactionDebugger = require('../utils/interactionDebugger');
const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');
const betaManager = require('../utils/betaManager');
const { isBetaFeature } = require('../utils/betaFeatureMatcher');
const { logEvent } = require('../utils/serverLogger');

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
                .setLabel('Sash')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('💬'),
            new ButtonBuilder()
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
 * Show the "sash" command menu. This is the prefix-command help content
 * (categorized legacy/prefix commands) but branded as "sash" — the word
 * "prefix" is replaced with "sash" everywhere it would appear so the menu
 * reads as a "Sash Commands" menu rather than a "Prefix Commands" one.
 *
 * The button leads here from the main /help menu's "Sash" button.
 */
async function showSashHelp(interaction, page) {
    const category = page || 'main';
    const prefix = config.prefix;

    // Sash (prefix) command catalogue, grouped identically to the messageCreate
    // prefix help so the two stay in sync. Only the label "sash" differs.
    const SASH_CATEGORIES = {
        general: {
            title: '⚡ Sash General Commands',
            desc: 'Basic bot commands you run with your sash:',
            fields: [
                { name: `${prefix}help [category]`, value: 'Show this categorized sash menu' },
                { name: `${prefix}about`, value: 'Information about the bot' },
                { name: `${prefix}updates`, value: 'Latest bot updates and features' },
                { name: `${prefix}ses`, value: 'Bot session and status information' },
                { name: `${prefix}ping`, value: 'Check bot latency and response time' },
                { name: `${prefix}np [duration]`, value: 'Enable no-sash mode for easier commands' },
            ],
            color: config.colors.primary,
        },
        leveling: {
            title: '📊 Sash Leveling System',
            desc: 'XP, ranks, and progression via sash commands:',
            fields: [
                { name: `${prefix}rank [@user]`, value: 'View level and XP progress' },
                { name: `${prefix}leaderboard [page]`, value: 'Server XP leaderboard' },
                { name: `${prefix}badges [@user]`, value: 'View achievement badges' },
                { name: `${prefix}level-enable`, value: 'Enable leveling (Admin)' },
                { name: `${prefix}level-disable`, value: 'Disable leveling (Admin)' },
                { name: `${prefix}level-channel #channel`, value: 'Level-up channel (Admin)' },
                { name: `${prefix}award-xp @user [amount]`, value: 'Award XP (Admin)' },
                { name: `${prefix}award-badge @user [badge]`, value: 'Award badges (Admin)' },
            ],
            color: config.colors.success,
        },
        games: {
            title: '🎮 Sash Games & Activities',
            desc: 'Interactive games run with your sash:',
            fields: [
                { name: `${prefix}tictactoe @user`, value: 'Classic Tic-Tac-Toe game' },
                { name: `${prefix}truthdare`, value: 'Truth or Dare with custom questions' },
                { name: `${prefix}counting [start]`, value: 'Number counting game' },
                { name: `${prefix}poll [question] [options]`, value: 'Create interactive polls' },
            ],
            color: config.colors.warning,
        },
        moderation: {
            title: '🛡️ Sash Moderation Tools',
            desc: 'Moderation and server management sash commands:',
            fields: [
                { name: `${prefix}kick @member [reason]`, value: 'Kick a member' },
                { name: `${prefix}ban @member [reason] [days]`, value: 'Ban a member' },
                { name: `${prefix}move @user #channel`, value: 'Move members between voice channels' },
                { name: `${prefix}end [activity]`, value: 'End ongoing activities' },
                { name: `${prefix}snipe [#channel]`, value: 'Recover last deleted message snapshot' },
                { name: `${prefix}lock [#channel]`, value: 'Lock a channel (Admin)' },
                { name: `${prefix}unlock [#channel]`, value: 'Unlock a channel (Admin)' },
                { name: `${prefix}hide [#channel]`, value: 'Hide a channel (Admin)' },
                { name: `${prefix}unhide [#channel]`, value: 'Unhide a channel (Admin)' },
                { name: `${prefix}nuke [name] [#channel]`, value: 'Nuke and recreate a channel (Admin)' },
            ],
            color: config.colors.secondary || config.colors.primary,
        },
        community: {
            title: '👥 Sash Community Features',
            desc: 'Engagement and social sash commands:',
            fields: [
                { name: `${prefix}poll "[question]" opt1 opt2 [time]`, value: 'Create server polls' },
                { name: `${prefix}lpoll create ...`, value: 'Create cross-server live polls' },
                { name: `${prefix}giveaway [prize] [duration]`, value: 'Create giveaways' },
                { name: `${prefix}reroll [giveaway-id]`, value: 'Reroll giveaway winners' },
                { name: `${prefix}birthday set [date]`, value: 'Birthday celebration system' },
                { name: `${prefix}welcome-config`, value: 'Configure welcome messages' },
                { name: `${prefix}broadcast [message]`, value: 'Announce to all servers' },
            ],
            color: config.colors.success,
        },
        admin: {
            title: '⚙️ Sash Administration',
            desc: 'Advanced server configuration via sash (Admin):',
            fields: [
                { name: `${prefix}welcome-enable`, value: 'Enable welcome system' },
                { name: `${prefix}welcome-disable`, value: 'Disable welcome system' },
                { name: `${prefix}welcome-channel #channel`, value: 'Set welcome channel' },
                { name: `${prefix}broadcastsettings`, value: 'Configure broadcast settings' },
                { name: `${prefix}autoreact enable`, value: 'Enable auto-reactions' },
                { name: `${prefix}autoreact disable`, value: 'Disable auto-reactions' },
                { name: `${prefix}autoreact add [word] [emoji]`, value: 'Add auto-reaction trigger' },
                { name: `${prefix}autoreact remove [word]`, value: 'Remove auto-reaction trigger' },
            ],
            color: config.colors.error,
        },
    };

    const backButton = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('help_sash')
                .setLabel('Back to Sash Menu')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('◀️')
        );

    if (category === 'main' || category === 'back') {
        // Main sash menu: category chooser with a back-to-categories button.
        const mainEmbed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('💬 Sash Command Categories')
            .setDescription(
                `Sash commands are classic text commands you run by typing your sash (\`${prefix}\`) followed by the command name.\n\n` +
                `**Usage:** \`${prefix}help [category]\` — choose a category below to browse its sash commands.`
            )
            .addFields(
                { name: '⚡ General', value: `\`${prefix}help general\`\nBasic bot commands`, inline: true },
                { name: '📊 Leveling', value: `\`${prefix}help leveling\`\nXP, ranks, progression`, inline: true },
                { name: '🎮 Games', value: `\`${prefix}help games\`\nFun interactive games`, inline: true },
                { name: '🛡️ Moderation', value: `\`${prefix}help moderation\`\nModeration tools`, inline: true },
                { name: '👥 Community', value: `\`${prefix}help community\`\nSocial features`, inline: true },
                { name: '⚙️ Administration', value: `\`${prefix}help admin\`\nAdvanced config`, inline: true }
            )
            .setFooter({ text: `Sash: ${prefix} • Version: ${config.version}` })
            .setTimestamp();

        const catButtons = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId('help_sash_general').setLabel('General').setStyle(ButtonStyle.Primary).setEmoji('⚡'),
            new ButtonBuilder().setCustomId('help_sash_leveling').setLabel('Leveling').setStyle(ButtonStyle.Primary).setEmoji('📊'),
            new ButtonBuilder().setCustomId('help_sash_games').setLabel('Games').setStyle(ButtonStyle.Primary).setEmoji('🎮'),
            new ButtonBuilder().setCustomId('help_sash_moderation').setLabel('Moderation').setStyle(ButtonStyle.Secondary).setEmoji('🛡️'),
            new ButtonBuilder().setCustomId('help_sash_community').setLabel('Community').setStyle(ButtonStyle.Success).setEmoji('👥'),
        );
        const adminRow = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId('help_sash_admin').setLabel('Administration').setStyle(ButtonStyle.Danger).setEmoji('⚙️'),
            new ButtonBuilder().setCustomId('help_back').setLabel('Back to Categories').setStyle(ButtonStyle.Secondary).setEmoji('↩️'),
        );

        await interaction.update({ embeds: [mainEmbed], components: [catButtons, adminRow] });
        return;
    }

    const cat = SASH_CATEGORIES[category];
    if (!cat) {
        await interaction.update({
            embeds: [new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('❌ Unknown Sash Category')
                .setDescription(`The sash category "${category}" was not found.`)],
            components: [backButton],
        });
        return;
    }

    const embed = new EmbedBuilder()
        .setColor(cat.color)
        .setTitle(cat.title)
        .setDescription(cat.desc)
        .addFields(cat.fields.map(f => ({ ...f, inline: false })))
        .setFooter({ text: `Sash: ${prefix} • Version: ${config.version}` })
        .setTimestamp();

    await interaction.update({ embeds: [embed], components: [backButton] });
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
                .setColor(config.colors.secondary || config.colors.primary)
                .setTitle('🛡️ Moderation Tools')
                .setDescription('Server management and moderation:')
                .addFields(
                    { name: '/ticket', value: 'Ticket system (dashboard-only)', inline: true },
                    { name: '/createticket', value: 'Ticket system (dashboard-only)', inline: true },
                    { name: '/tickethistory', value: 'Ticket system (dashboard-only)', inline: true },
                    { name: '/move', value: 'Move members between voice channels', inline: true },
                    { name: '/end', value: 'End giveaways and other activities', inline: true },
                    { name: '/purge', value: 'Delete messages with messages, user, and between subcommands', inline: true }
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
            // Only the active node should handle interactions.
            if (!global.botActive) return;

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

                // Emit a log event for command use (no-op unless logging is enabled for this guild).
                if (interaction.guildId) {
                    const subcmd = interaction.options?.getSubcommand(false);
                    const cmdLabel = subcmd ? `/${interaction.commandName} ${subcmd}` : `/${interaction.commandName}`;
                    logEvent(client, interaction.guildId, {
                        type: 'commandUse',
                        title: 'Command Used',
                        description: `**${cmdLabel}** by ${interaction.user.tag} (\`${interaction.user.id}\`)`,
                        fields: [
                            { name: 'Channel', value: interaction.channel ? `<#${interaction.channelId}>` : 'DM', inline: true },
                        ],
                        isBot: interaction.user.bot,
                    });
                }

                const command = client.commands.get(interaction.commandName);

                if (!command) {
                    console.error(`No command matching ${interaction.commandName} was found.`);
                    return safeReply(interaction, {
                        content: `Error: No command matching \`${interaction.commandName}\` was found.`,
                        ephemeral: true
                    });
                }

                // Beta gate — block access if the slash command or any of its
                // subcommand parts is a beta feature and this guild hasn't enabled beta.
                const subcommand = interaction.options?.getSubcommand(false);
                const subcommandGroup = interaction.options?.getSubcommandGroup(false);
                if (isBetaFeature(interaction.commandName, subcommand, subcommandGroup, config.betaFeatures)) {
                    const guildId = interaction.guildId;
                    if (!guildId || !(await betaManager.canAccess(guildId))) {
                        const betaEmbed = new EmbedBuilder()
                            .setColor(config.colors.warning)
                            .setTitle('🔬 Beta Feature')
                            .setDescription(
                                `**\`/${interaction.commandName}\` is currently in beta** and is only available to selected servers.\n\n` +
                                `Join our [Support Server](${config.supportServer}) to learn more or request early access.`
                            )
                            .addFields({
                                name: 'Already selected?',
                                value: 'Your server owner can run `$beta enable` to activate beta features.',
                                inline: false
                            })
                            .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                            .setTimestamp();
                        return safeReply(interaction, { embeds: [betaEmbed], ephemeral: true });
                    }
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
                // Handle voting buttons IMMEDIATELY before any other processing
                if (customId.startsWith('vote_')) {
                    try {
                        // IMMEDIATELY acknowledge the interaction to prevent timeout
                        if (!interaction.replied && !interaction.deferred) {
                            await interaction.deferUpdate();
                        } else {
                            return;
                        }

                        const parts = customId.split('_');
                        const pollId = parts[1];
                        const optionIndex = parseInt(parts[2]);

                        if (!client.livePollManager) {
                            await interaction.followUp({
                                content: 'Poll system is not available. Please try again later.',
                                ephemeral: true
                            });
                            return;
                        }

                        const result = await client.livePollManager.vote(pollId, interaction.user.id, optionIndex);

                        if (result && result.success) {
                            const pollResults = await client.livePollManager.getPollResults(pollId);

                            if (pollResults) {
                                const updatedEmbed = client.livePollManager.createPollEmbed(
                                    pollResults.poll,
                                    pollResults.options,
                                    pollResults.totalVotes,
                                    true
                                );
                                const buttons = client.livePollManager.createVoteButtons(pollId, pollResults.options);
                                await interaction.editReply({
                                    embeds: [updatedEmbed],
                                    components: buttons
                                });
                            }
                        } else {
                            await interaction.followUp({
                                content: result ? result.message : 'Failed to record vote',
                                ephemeral: true
                            });
                        }
                    } catch (voteError) {
                        console.error('[POLLS] Vote error:', voteError.message);
                        try {
                            await interaction.followUp({
                                content: 'There was an error processing your vote. Please try again.',
                                ephemeral: true
                            });
                        } catch (_) {}
                    }
                    return; // Exit early for vote buttons to prevent further processing
                }

                // Handle live giveaway Join buttons (customId: lgive_<giveawayId>)
                if (customId.startsWith('lgive_')) {
                    try {
                        if (!interaction.replied && !interaction.deferred) {
                            await interaction.deferUpdate();
                        } else {
                            return;
                        }
                        const giveawayId = customId.slice('lgive_'.length);
                        if (!client.liveGiveawayManager) {
                            await interaction.followUp({ content: 'Giveaway system is not available. Please try again later.', ephemeral: true });
                            return;
                        }
                        const result = await client.liveGiveawayManager.joinGiveaway(giveawayId, interaction.user.id);
                        if (result && result.success) {
                            const giveaway = await client.liveGiveawayManager.getGiveaway(giveawayId);
                            if (giveaway) {
                                const embed = client.liveGiveawayManager.createGiveawayEmbed(giveaway, giveaway.participants.size);
                                const buttons = client.liveGiveawayManager.createJoinButton(giveaway.giveawayId);
                                await interaction.editReply({ embeds: [embed], components: [buttons] });
                            }
                            await interaction.followUp({ content: result.message, ephemeral: true }).catch(() => {});
                        } else {
                            await interaction.followUp({ content: result ? result.message : 'Failed to join giveaway', ephemeral: true }).catch(() => {});
                        }
                    } catch (joinError) {
                        console.error('[LIVE GIVEAWAY] Join error:', joinError.message);
                        try {
                            await interaction.followUp({ content: 'There was an error joining the giveaway. Please try again.', ephemeral: true });
                        } catch (_) {}
                    }
                    return;
                }

                // Log detailed button information for debugging (for non-vote buttons)
                console.log(`[DEBUG] Button pressed with customId: "${customId}"`);

                // Log button interaction
                interactionDebugger.logInteraction(interaction, `Button (${customId})`);

                try {
                    // For other buttons that use colons as separators, extract the parts
                    const [action, ...params] = customId.split(':');
                    // Route to the appropriate handler based on customId or action
                    if (action === 'ticketpanel') {
                        // Premium ticket panels (configured from the dashboard).
                        // customId forms:
                        //   ticketpanel:open:<panelId> | ticketpanel:close
                        //   ticketpanel:closeconfirm:yes|no  (close confirmation)
                        //   ticketpanel:transcript | ticketpanel:delete
                        //   ticketpanel:reopen | ticketpanel:claim | ticketpanel:rename
                        const sub = params[0];
                        const mgr = client.ticketPanelManager || client.ticketManager;
                        if (sub === 'open') {
                            const panelId = params[1];
                            const panel = mgr.getPanelById ? mgr.getPanelById(panelId) : null;
                            if (!panel) {
                                await safeReply(interaction, { content: 'This ticket panel could not be found. It may have been deleted.', ephemeral: true });
                            } else {
                                await safeExecute(mgr.handleOpen.bind(mgr), [interaction, panel], null, 'Ticket panel open');
                            }
                        } else if (sub === 'close') {
                            await safeExecute(mgr.handleClose.bind(mgr), [interaction], null, 'Ticket panel close prompt');
                        } else if (sub === 'closeconfirm') {
                            await safeExecute(mgr.handleCloseConfirm.bind(mgr), [interaction, params[1] || 'no'], null, 'Ticket panel close confirm');
                        } else if (sub === 'transcript') {
                            await safeExecute(mgr.handleTranscript.bind(mgr), [interaction], null, 'Ticket panel transcript');
                        } else if (sub === 'delete') {
                            await safeExecute(mgr.handleDelete.bind(mgr), [interaction], null, 'Ticket panel delete');
                        } else if (sub === 'reopen') {
                            await safeExecute(mgr.handleReopen.bind(mgr), [interaction], null, 'Ticket panel reopen');
                        } else if (sub === 'claim') {
                            await safeExecute(mgr.handleClaim.bind(mgr), [interaction], null, 'Ticket panel claim');
                        } else if (sub === 'rename') {
                            await safeExecute(mgr.handleRename.bind(mgr), [interaction], null, 'Ticket panel rename');
                        } else {
                            await safeReply(interaction, { content: 'Unknown ticket action.', ephemeral: true });
                        }
                    } else if (action === 'create-ticket' || interaction.customId === 'create-ticket' || interaction.customId === 'ticket_create') {
                        // Legacy ticket-create buttons — panels are now dashboard-only.
                        await safeReply(interaction, { content: '🎫 Ticket feature can only be used by dashboard. Configure ticket panels from the PrimeBot dashboard (🎫 Tickets tab).', ephemeral: true });
                    } else if (action === 'close-ticket' || interaction.customId === 'close-ticket' || interaction.customId === 'ticket_close' || action === 'reopen-ticket' || interaction.customId === 'reopen-ticket' || interaction.customId === 'ticket_reopen' || interaction.customId === 'ticket_toggle') {
                        // Legacy ticket-toggle buttons — no longer active.
                        await safeReply(interaction, { content: '🎫 Ticket feature can only be used by dashboard. Configure ticket panels from the PrimeBot dashboard (🎫 Tickets tab).', ephemeral: true });
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
                        } else if (category === 'prefix' || category === 'sash') {
                            // Show the sash (prefix) command menu content, branded "sash".
                            await showSashHelp(interaction, 'main');
                        } else if (category.startsWith('sash_')) {
                            // Sash category drill-down (e.g. help_sash_general).
                            await showSashHelp(interaction, category.replace('sash_', ''));
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
                    } else if (interaction.customId === 'categories_prefix_refresh'
                            || interaction.customId === 'categories_prefix_back') {
                        // Prefix help menu: refresh / back-to-categories → re-render the
                        // main prefix category menu (embed + dropdown + nav buttons).
                        const { mainMenuEmbed, categorySelectRow, navigationButtonsRow } = require('../utils/prefixHelp');
                        const pfx = (interaction.client.serverSettingsManager?.getGuildPrefix?.(interaction.guild?.id)) || '$';
                        try {
                            await interaction.update({
                                embeds: [mainMenuEmbed(pfx, interaction.client)],
                                components: [categorySelectRow(), navigationButtonsRow()],
                            });
                        } catch (_) {}
                        return;
                    } else if (interaction.customId === 'categories_prefix_help') {
                        await interaction.reply({
                            content: 'Use the dropdown menu to browse different command categories. Each category contains specialized commands for different server needs.\n\n**Available Categories:**\n• General - Basic bot commands and info\n• Leveling - XP, ranks, and badges (🧪 beta)\n• Games & Activities - Games, polls, and giveaways\n• Community - Cross-server live polls & giveaways\n• Tickets - Ticket support system\n• Welcome - Welcome system configuration\n• Moderation - Server management, roles, and tickets\n• Administration - Feature configuration',
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
                } else if (interaction.customId === 'ticketpanel:rename') {
                    const mgr = client.ticketPanelManager || client.ticketManager;
                    await safeExecute(
                        mgr.handleRenameSubmit.bind(mgr),
                        [interaction],
                        null,
                        'Ticket panel rename modal'
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

                        // Prefix-command dropdown → render the prefix category help
                        // (the old code routed to the slash-command catalog, which
                        // showed `/help` etc. — wrong for the prefix help menu).
                        const { showPrefixCategoryMenuHelp } = require('../utils/prefixHelp');
                        const prefix = (interaction.client.serverSettingsManager?.getGuildPrefix?.(interaction.guild?.id)) || '$';
                        await showPrefixCategoryMenuHelp(interaction, selectedCategory, prefix);
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