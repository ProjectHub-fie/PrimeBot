const { safeReply, safeExecute, scheduleComponentExpiry } = require('../utils/stabilityUtils');
const interactionDebugger = require('../utils/interactionDebugger');
const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, MessageFlags } = require('discord.js');
const config = require('../config');
const betaManager = require('../utils/betaManager');
const { isBetaFeature } = require('../utils/betaFeatureMatcher');
const { logEvent } = require('../utils/serverLogger');
const { emoji } = require('../utils/emoji');

function helpCategoryLines() {
    try {
        return require('../utils/prefixHelp').mainMenuText();
    } catch (_) {
        return '';
    }
}

/**
 * Helper function to show main help menu for button interactions
 */
async function showMainHelpUpdate(interaction) {
    const { buildHelpPayload, mainMenuText, categorySelectRow, helpActionRow } = require('../utils/prefixHelp');
    await interaction.update(buildHelpPayload({
        text: mainMenuText(),
        rows: [categorySelectRow(null, 'help_select'), helpActionRow()],
    }));
    scheduleComponentExpiry(interaction.message);
}

/**
 * Helper function to show category help for button interactions
 */
function buildSashCategories(prefix) {
    const { CATALOG, CATEGORY_ORDER, categoryIcon, CATEGORY_SEPARATOR } = require('../utils/prefixHelp');
    const out = {};
    for (const key of CATEGORY_ORDER) {
        const cat = CATALOG[key];
        if (!cat) continue;
        out[key] = {
            icon: categoryIcon(key, cat.icon),
            label: `${CATEGORY_SEPARATOR} ${cat.label}`,
            title: `${categoryIcon(key, cat.icon)} ${CATEGORY_SEPARATOR} ${cat.label}`,
            color: cat.color,
            fields: cat.commands.map(c => {
                const aliases = c.names.slice(1);
                const name = aliases.length
                    ? `${prefix}${c.names[0]}${c.args ? ' ' + c.args : ''} (${aliases.map(a => prefix + a).join(', ')})`
                    : `${prefix}${c.names[0]}${c.args ? ' ' + c.args : ''}`;
                return { name, value: c.desc };
            }),
        };
    }
    return out;
}

async function showSashHelp(interaction, page) {
    const category = page || 'main';
    const prefix = config.prefix;
    const SASH_CATEGORIES = buildSashCategories(prefix);
    const ORDER = Object.keys(SASH_CATEGORIES);
    const {
        buildHelpPayload,
        mainMenuText,
        categoryTitle,
        categoryText,
    } = require('../utils/prefixHelp');

    const backButton = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('help_sash')
                .setLabel('Back to Sash Menu')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji(emoji('left', '◀️'))
        );

    if (category === 'main' || category === 'back') {
        // Discord caps 5 buttons per row — chunk the categories across rows.
        const styles = [
            ButtonStyle.Primary, ButtonStyle.Primary, ButtonStyle.Primary,
            ButtonStyle.Secondary, ButtonStyle.Success, ButtonStyle.Secondary,
            ButtonStyle.Secondary, ButtonStyle.Danger,
        ];
        const rows = [];
        for (let i = 0; i < ORDER.length; i += 5) {
            rows.push(new ActionRowBuilder().addComponents(
                ORDER.slice(i, i + 5).map((k, j) => new ButtonBuilder()
                    .setCustomId(`help_sash_${k}`)
                    .setLabel(SASH_CATEGORIES[k].label.slice(0, 80))
                    .setStyle(styles[i + j] || ButtonStyle.Secondary)
                    .setEmoji(SASH_CATEGORIES[k].icon))
            ));
        }
        rows.push(new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId('help_back')
                .setLabel('Back to Categories')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji(emoji('left', '↩️'))
        ));

        await interaction.update(buildHelpPayload({ text: mainMenuText(), rows }));
        scheduleComponentExpiry(interaction.message);
        return;
    }

    const cat = SASH_CATEGORIES[category];
    if (!cat) {
        await interaction.update(buildHelpPayload({
            title: `${emoji('cross', '❌')} –> Unknown Sash Category`,
            text: `The sash category "${category}" was not found.`,
            rows: [backButton],
        }));
        return;
    }

    await interaction.update(buildHelpPayload({
        title: categoryTitle(category),
        text: categoryText(category),
        rows: [backButton],
    }));
    scheduleComponentExpiry(interaction.message);
}

async function showCategoryHelpUpdate(interaction, category) {
    const {
        buildHelpPayload,
        categoryTitle,
        categoryText,
        categorySelectRow,
        helpActionRow,
    } = require('../utils/prefixHelp');
    await interaction.update(buildHelpPayload({
        title: categoryTitle(category),
        text: categoryText(category),
        rows: [categorySelectRow(category, 'help_select'), helpActionRow()],
    }));
    scheduleComponentExpiry(interaction.message);
}

/**
 * Parse the customId of an "Appeal ban" button.
 *
 * Formats:
 *   v2 (current): appeal:open:v2:<guildId>:<action>:<cid>
 *   v1 (legacy, sent before the v2 marker): appeal:open:<guildId>:<action>:<cid>
 *
 * The "open" literal shifts the field positions by 1. Both shapes are routed with
 * the same offset so a stale pre-versioning button (pressed from an old ban DM)
 * still opens the appeal form for the real guild it was attached to.
 *
 * @param {string} customId
 * @param {string} [fallbackGuildId]
 * @returns {{guildId: string|null, subAction: string, cid: number|null}}
 */
function parseAppealCustomId(customId, fallbackGuildId) {
    const params = String(customId || '').split(':');
    if (params[0] !== 'appeal') return { guildId: fallbackGuildId || null, subAction: 'ban', cid: null };
    // v2 (current): appeal:open:v2:<guildId>:<action>:<cid>
    // v1 (legacy, sent before the v2 marker): appeal:open:<guildId>:<action>:<cid>
    // A version marker branches the field layout; a single offset cannot serve both.
    const isV2 = params[2] === 'v2';
    const guildId = params[isV2 ? 3 : 2] || fallbackGuildId || null;
    const subAction = params[isV2 ? 4 : 3] || 'ban';
    const cidRaw = params[isV2 ? 5 : 4] || '';
    const cid = /^\d+$/.test(cidRaw) ? parseInt(cidRaw, 10) : null;
    return { guildId, subAction, cid };
}

module.exports = {
    name: 'interactionCreate',
    parseAppealCustomId,

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

            // Handle slash-command autocomplete (e.g. /embed send).
            if (interaction.isAutocomplete()) {
                const command = client.commands.get(interaction.commandName);
                if (command && typeof command.autocomplete === 'function') {
                    await command.autocomplete(interaction).catch((err) =>
                        console.error(`[AUTOCOMPLETE] /${interaction.commandName} failed:`, err.message));
                } else {
                    await interaction.respond([]).catch(() => {});
                }
                return;
            }

            // Handle slash commands
            if (interaction.isChatInputCommand()) {
                // Linix music slash commands (/play, /247, /bass, …) live in their
                // own tree (`client.slashCommands`) and are dispatched by the
                // Linix router — never merged into `client.commands`, so they can
                // never collide with PrimeBot's own slash commands.
                if (require('../music/interactions').isMusicSlashCommand(client, interaction)) {
                    await require('../music/interactions').handleMusicSlash(client, interaction);
                    return;
                }

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

                // Linix music controls (disable_h + the player's own buttons) are
                // owned by the collector Linix attaches to the now-playing message,
                // which is created in a DIFFERENT interaction context. PrimeBot's
                // generic button switch must therefore leave them untouched.
                if (require('../music/interactions').isMusicCustomId(customId)) return;

                // Event Management buttons (customIds: evjoin:/evleave:/evcheckin:/
                // evparts:/evinfo:/evremind: + <eventId>). The manager rejects any event
                // that does not belong to the interaction's guild.
                if (/^ev(join|leave|interest|checkin|parts|info|remind):/.test(customId)) {
                    const mgr = client.eventMgmtManager;
                    if (!mgr || typeof mgr.handleButton !== 'function') {
                        await safeReply(interaction, { content: 'Event system is unavailable right now.', ephemeral: true });
                        return;
                    }
                    await safeExecute(mgr.handleButton.bind(mgr), [interaction], null, `Event button (${customId})`);
                    return;
                }

                // Log detailed button information for debugging (for non-vote buttons)
                console.log(`[DEBUG] Button pressed with customId: "${customId}"`);

                // Log button interaction
                interactionDebugger.logInteraction(interaction, `Button (${customId})`);

                try {
                    // For other buttons that use colons as separators, extract the parts
                    const [action, ...params] = customId.split(':');

                    // Anti-Nuke setup buttons (customIds: antinuke:setup:automatic
                    // | antinuke:setup:manual | antinuke:setup:progress).
                    if (action === 'antinuke' && params[0] === 'setup') {
                        const mode = params[1];
                        const manager = client.antiNukeManager;
                        if (!manager) {
                            await safeReply(interaction, { content: 'Anti-Nuke is unavailable right now.', ephemeral: true });
                            return;
                        }
                        // Owner-controlled access hierarchy. Starting/confirming a
                        // setup needs `antinuke.setup`; viewing progress needs
                        // `antinuke.view`. The actual guild owner always passes.
                        const required = (mode === 'progress') ? 'antinuke.view' : 'antinuke.setup';
                        const antiNukeAccess = require('../utils/antiNukeAccess');
                        const auth = await antiNukeAccess.authorizeAntiNuke(
                            { id: interaction.guild.id, owner_id: interaction.guild.ownerId },
                            interaction.user.id, required,
                            { requireMember: true, member: { present: true, roles: [] } },
                        );
                        if (!auth.ok) {
                            await safeReply(interaction, {
                                content: `You do not have Anti-Nuke permission to do this. (Required: \`${required}\` — the server owner can grant it in the Anti-Nuke → Access Control page.)`,
                                ephemeral: true,
                            });
                            return;
                        }
                        if (mode === 'progress') {
                            const setup = typeof manager.getSetup === 'function' ? await manager.getSetup(interaction.guild.id) : null;
                            const progress = setup && setup.state ? require('../utils/antiNukeSetup').computeProgress(setup.method || 'automatic', setup.state) : null;
                            await safeReply(interaction, { embeds: [require('../utils/antiNukeEmbed').setupEmbed(progress)], ephemeral: true });
                            return;
                        }
                        if (mode === 'manual') {
                            await safeReply(interaction, {
                                content: '⚙️ Manual setup is done from the dashboard — open **Server settings → Anti-Nuke** and choose *Configure Manually*. Your progress is saved and resumable.',
                                ephemeral: true,
                            });
                            return;
                        }
                        // The confirm button (customId antinuke:setup:automatic:confirm)
                        // must be handled BEFORE the plain automatic branch, which
                        // only shows the confirmation prompt.
                        if (mode === 'automatic' && params[2] === 'confirm') {
                            await interaction.deferReply({ ephemeral: true });
                            try {
                                const { runAll } = require('../utils/antiNukeSetupRunner');
                                // The user pressed the Confirm button, so the
                                // `confirm` step's explicit gate is satisfied.
                                const res = await runAll({ client, guild: interaction.guild, options: { applyRecommended: false, confirmed: true } });
                                if (typeof manager.saveSetup === 'function') {
                                    await manager.saveSetup(interaction.guild.id, {
                                        method: 'automatic',
                                        status: res.state.status,
                                        state: res.state,
                                    }).catch(() => {});
                                }
                                const ok = res.state.status === 'completed';
                                await interaction.editReply({
                                    content: ok
                                        ? '🛡️ **Anti-Nuke setup completed.** Protection is active — dry-run is OFF (live, reversible containment only).'
                                        : '⚠️ Setup finished with issues. Check the progress below, fix the failed step and retry.',
                                    embeds: [require('../utils/antiNukeEmbed').setupEmbed(res.progress)],
                                });
                            } catch (err) {
                                console.error('[ANTINUKE] setup button failed:', err.message);
                                await interaction.editReply({ content: `⚠️ Setup failed: ${err.message}` }).catch(() => {});
                            }
                            return;
                        }
                        if (mode === 'automatic') {
                            // Require an explicit confirm before running (never activate
                            // protection just because the page/command was opened).
                            const confirm = new (require('discord.js').ActionRowBuilder)().addComponents(
                                new (require('discord.js').ButtonBuilder)().setCustomId('antinuke:setup:automatic:confirm').setLabel('Confirm automatic setup').setStyle(require('discord.js').ButtonStyle.Success).setEmoji('✅'),
                                new (require('discord.js').ButtonBuilder)().setCustomId('antinuke:setup:progress').setLabel('View progress').setStyle(require('discord.js').ButtonStyle.Secondary),
                            );
                            await safeReply(interaction, {
                                content: '🛡️ **Automatic setup** will apply the recommended security configuration with dry-run OFF — real (reversible) protection will be active. Existing custom settings are preserved unless you confirm otherwise. Continue?',
                                components: [confirm],
                                ephemeral: true,
                            });
                            return;
                        }
                    }

                    // Route to the appropriate handler based on customId or action
                    if (action === 'ticketpanel') {
                        // Premium ticket panels (configured from the dashboard).
                        // customId forms:
                        //   ticketpanel:open:<panelId> | ticketpanel:<componentId>:button
                        //   ticketpanel:<componentId>:select  (value opt:<optionId>)
                        //   ticketpanel:close | ticketpanel:closeconfirm:yes|no
                        //   ticketpanel:transcript | ticketpanel:delete
                        //   ticketpanel:reopen | ticketpanel:claim | ticketpanel:rename
                        const sub = params[0];
                        const mgr = client.ticketPanelManager || client.ticketManager;
                        if (sub === 'open') {
                            const panelId = params[1];
                            const panel = mgr.getPanelById && mgr.getPanelById(panelId);
                            const guildOk = !panel || !panel.guildId || String(panel.guildId) === String(interaction.guild?.id);
                            if (!panel || !guildOk) {
                                await safeReply(interaction, { content: 'This ticket panel could not be found. It may have been deleted.', ephemeral: true });
                            } else {
                                await safeExecute(mgr.handleOpen.bind(mgr), [interaction, panel], null, 'Ticket panel open');
                            }
                        } else if (sub === 'button' || sub === 'select') {
                            // Panel-builder input (button or select menu). The component's
                            // stable id rides in the customId;the manager loads configuration
                            // from the DB-driven cache and rejects cross-guild use.
                            const componentId = params[1] ? params[1] : null;
                            await safeExecute(
                                mgr.handleComponentOpen.bind(mgr),
                                [interaction, componentId],
                                null,
                                'Ticket panel component open'
                            );
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
                        } else if (sub === 'unclaim') {
                            await safeExecute(mgr.handleUnclaim.bind(mgr), [interaction], null, 'Ticket panel unclaim');
                        } else if (sub === 'transfer') {
                            await safeExecute(mgr.handleTransferPrompt.bind(mgr), [interaction], null, 'Ticket panel transfer');
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
                    } else if (action === 'appeal') {
                        // Ban-DM appeal form (opened from the "Appeal ban" button in a banned member's DM).
                        // customId: appeal:open:v2:<guildId>:<action>:<cid> (v1 legacy: no version marker).
                        const parsed = parseAppealCustomId(interaction.customId, interaction.guild?.id);
                        const guildId = parsed.guildId;
                        const subAction = parsed.subAction;
                        const cid = parsed.cid;
                        if (!interaction.client.appealManager?.handleAppealButton) {

                            await safeReply(interaction, { content: 'Appeals are unavailable right now.', ephemeral: true });
                        } else {
                            await safeExecute(
                                interaction.client.appealManager.handleAppealButton.bind(interaction.client.appealManager),
                                [interaction, guildId, subAction, cid],
                                null,
                                'Ban appeal form'
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
                        } else if (require('../utils/prefixHelp').CATEGORY_ORDER.includes(category)) {
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
                                flags: MessageFlags.Ephemeral,
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
                            content: `Use the dropdown menu to browse different command categories. Each category contains specialized commands for different server needs.\n\n**Available Categories:**\n${helpCategoryLines()}`,
                            flags: MessageFlags.Ephemeral
                        });
                        return;
                    } else if (interaction.customId === 'categories_prefix_refresh'
                            || interaction.customId === 'categories_prefix_back') {
                        // Prefix help menu: refresh / back-to-categories → re-render the
                        // main prefix category menu (embed + dropdown + nav buttons).
                        const { buildHelpPayload, mainMenuText, categorySelectRow, homeButtonRow } = require('../utils/prefixHelp');
                        try {
                            await interaction.update(buildHelpPayload({
                                text: mainMenuText(),
                                rows: [categorySelectRow(null, 'category_select_prefix'), homeButtonRow('categories_prefix_back')],
                            }));
                            scheduleComponentExpiry(interaction.message);
                        } catch (_) {}
                        return;
                    } else if (interaction.customId === 'categories_prefix_help') {
                        await interaction.reply({
                            content: `Use the dropdown menu to browse different command categories. Each category contains specialized commands for different server needs.\n\n**Available Categories:**\n${helpCategoryLines()}`,
                            flags: MessageFlags.Ephemeral
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
                } else if (interaction.customId === 'ticketpanel:transfer') {
                    const mgr = client.ticketPanelManager || client.ticketManager;
                    await safeExecute(
                        mgr.handleTransferSubmit.bind(mgr),
                        [interaction],
                        null,
                        'Ticket panel transfer modal'
                    );
                } else if (interaction.customId.startsWith('ticketpanel:reason:')) {
                    const mgr = client.ticketPanelManager || client.ticketManager;
                    await safeExecute(
                        mgr.handleOpenReasonSubmit.bind(mgr),
                        [interaction],
                        null,
                        'Ticket open reason modal'
                    );
                } else if (interaction.customId.startsWith('appeal_modal:')) {
                    const guildId = interaction.customId.slice('appeal_modal:'.length);
                    const mgr = interaction.client.appealManager;
                    if (!mgr) {
                        await safeReply(interaction, { content: 'Appeals are unavailable right now.', ephemeral: true });
                    } else {
                        await safeExecute(
                            mgr.handleAppealSubmit.bind(mgr),
                            [interaction, guildId],
                            null,
                            'Ban appeal submit'
                        );
                    }
                }
                return;
            }

            // Handle select menus
            if (interaction.isStringSelectMenu()) {
                console.log(`[DEBUG] Select menu interaction with customId: "${interaction.customId}"`);
                interactionDebugger.logInteraction(interaction, `Select Menu (${interaction.customId})`);

                try {
                    // Linix music selects (search result picker, filter picker,
                    // playlist share picker) are owned by the collector Linix
                    // attaches to the message it posted; PrimeBot's generic
                    // select switch leaves them untouched.
                    if (require('../music/interactions').isMusicCustomId(interaction.customId)) return;

                    // Premium ticket-panel select menus (panel builder): thepper
                    // component id rides in the customId, the selected option id in the value.
                    // The manager loads panel/component/option from the DB-driven cache and
                    // rejects cross-guild use — nothing sensitive rides in the customId..
                    const panelSel = /^ticketpanel:(\d+):select$/.exec(interaction.customId);
                    if (panelSel) {
                        const mgr = interaction.client.ticketPanelManager || interaction.client.ticketManager;
                        const componentId = panelSel[1];
                        const rawValue = (interaction.values && interaction.values[0]) || '';
                        const optMatch = /^opt:(\d+)$/.exec(rawValue);
                        const optionId = optMatch ? optMatch[1] : null;
                        if (!optionId) {
                            await interaction.reply({ content: 'This ticket option could not be found. It may have been deleted.', ephemeral: true }).catch(() => {});
                            return;
                        }
                        await safeExecute(
                            mgr.handleComponentOpen.bind(mgr),
                            [interaction, componentId, optionId],
                            null,
                            'Ticket panel select option open'
                        );
                        return;
                    }
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
                    if (interaction.customId === 'help_select') {
                        const selectedCategory = interaction.values[0];
                        const {
                            buildHelpPayload,
                            categoryTitle,
                            categoryText,
                            categorySelectRow,
                            helpActionRow,
                        } = require('../utils/prefixHelp');
                        await interaction.update(buildHelpPayload({
                            title: categoryTitle(selectedCategory),
                            text: categoryText(selectedCategory),
                            rows: [categorySelectRow(selectedCategory, 'help_select'), helpActionRow()],
                        }));
                        scheduleComponentExpiry(interaction.message);
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
                            flags: MessageFlags.Ephemeral,
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