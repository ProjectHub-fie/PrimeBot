const {
    EmbedBuilder,
    ButtonBuilder,
    ButtonStyle,
    ActionRowBuilder,
    StringSelectMenuBuilder,
    PermissionsBitField,
    PermissionFlagsBits,
} = require("discord.js");
const net = require("net");
const config = require("../config");
const nodeFailover = require("../utils/nodeFailover");

// Measures TCP connection time (ms) to a host:port within a 3s timeout.
// Returns null if unreachable or timed out.
function tcpPing(host, port = 443) {
    return new Promise((resolve) => {
        const start = Date.now();
        const socket = net.createConnection({ host, port, timeout: 3000 });
        socket.on("connect", () => { socket.destroy(); resolve(Date.now() - start); });
        socket.on("timeout", () => { socket.destroy(); resolve(null); });
        socket.on("error",   () => { socket.destroy(); resolve(null); });
    });
}
const { pool } = require("../server/db");
const betaManager = require("../utils/betaManager");
const { isBetaFeature } = require("../utils/betaFeatureMatcher");

/**
 * Try to reply in the channel; if the bot lacks permission, fall back to a DM.
 * This ensures beta/betaserver commands always produce visible output on any host.
 */
async function safeBetaReply(message, payload) {
    try {
        const sent = await message.reply(payload);
        console.log('[BETA] Reply sent successfully in channel.');
        return sent;
    } catch (replyErr) {
        console.warn(`[BETA] Channel reply failed (${replyErr.code ?? replyErr.message}). Trying DM fallback.`);
        try {
            const dmNote = `*(Bot couldn't reply in <#${message.channel?.id}> — sending here instead)*\n`;
            const dmPayload = typeof payload === 'string'
                ? dmNote + payload
                : { content: dmNote, ...(payload.embeds ? { embeds: payload.embeds } : {}), ...(payload.components ? { components: payload.components } : {}) };
            const sent = await message.author.send(dmPayload);
            console.log('[BETA] DM fallback sent successfully.');
            return sent;
        } catch (dmErr) {
            console.error(`[BETA] DM fallback also failed (${dmErr.code ?? dmErr.message}). User will not see a reply.`);
        }
    }
}

module.exports = {
    name: "messageCreate",
    async execute(message, client) {
        try {
            // Ignore messages from bots
            if (message.author.bot) return;

            // Snapshots are recorded on the live message path; deletion listener is
            // installed in the same event file through a one-time listener later.

            // Only the active node should respond. If this node is in standby
            // (sn2 waiting for sn1 to go down), silently drop all messages.
            if (!global.botActive) return;
            
            // Prevent infinite recursion from no-prefix command processing
            if (message._processedAsNoPrefix) return;

            const prefix = message.guild?.id
                ? (client.serverSettingsManager?.getGuildPrefix?.(message.guild.id) || config.prefix)
                : config.prefix;

            // Premium Automod: scan guild messages against the configured rules.
            // Runs before command parsing so a rule with a delete/kick/ban action
            // stops the message from being processed as a command. Fire-and-forget
            // failures never abort the message handler.
            if (message.guild && client.automodManager?.isEnabled?.(message.guild.id)) {
                const automodHit = await client.automodManager.scanMessage(message).catch(() => null);
                if (automodHit) return; // message was actioned (e.g. deleted) — stop processing
            }

            // Check for ping (mention)
            if (
                client.user &&
                [`<@${client.user.id}>`, `<@!${client.user.id}>`].includes(message.content.trim())
            ) {                       // Calculate bot uptime
                const uptime = process.uptime();
                const uptimeString = formatUptime(uptime);

                // Get guild count
                const guildCount = client.guilds.cache.size;
                
                // Calculate total users across all guilds
                const totalUsers = client.guilds.cache.reduce((acc, guild) => acc + guild.memberCount, 0);

                // Get command count
                const commandCount = 30; // Updated count

                // Create ping embed
                const inviteButton = new ButtonBuilder()
                    .setLabel("Invite Me")
                    .setStyle(ButtonStyle.Link)
                    .setURL(
                        `https://discord.com/api/oauth2/authorize?client_id=${client.user.id}&permissions=563242011339808&scope=bot%20applications.commands`,
                    );
                    
                const supportServerButton = new ButtonBuilder()
                    .setLabel("Support Server")
                    .setStyle(ButtonStyle.Link)
                    .setURL(config.supportServer);


      const webButton = new ButtonBuilder()
          .setLabel("Website ")
          .setStyle(ButtonStyle.Link)
          .setURL(config.website);
      

      const docButton = new ButtonBuilder()
          .setLabel("Documentation")
          .setStyle(ButtonStyle.Link)
          .setURL(config.doc);
      
                const row = new ActionRowBuilder().addComponents(inviteButton, supportServerButton,webButton,docButton );

                const pingEmbed = new EmbedBuilder()
                    .setColor(config.colors.primary)
                    .setTitle("Hello there! 👋")
                    .setDescription(
                        'Primiaum features in free ',
                    )
                    .addFields(
                        {
                            name: "📋 Prefix",
                            value: `\`${prefix}\``,
                            inline: true,
                        },
                        {
                            name: "🏓 Ping",
                            value: `${client.ws.ping}ms`,
                            inline: true,
                        },
                        {
                            name: "⏱️ Uptime",
                            value: uptimeString,
                            inline: true,
                        },
                        {
                            name: "🌐 Servers",
                            value: `${guildCount} servers`,
                            inline: true,
                        },
                        {
                            name: "👥 Total Users",
                            value: `${totalUsers.toLocaleString()} users`,
                            inline: true,
                        },
                        {
                            name: "🔧 Commands",
                            value: `Type \`${prefix}help\` to see all available commands!`,
                        },
                    )
                    .setThumbnail(
                        client.user.displayAvatarURL({ extension: 'gif', forceStatic: false }),
                    )
                    .setFooter({
                        text: `Requested by ${message.author.username} • Version: ${config.version}`,
                        iconURL: message.author.displayAvatarURL({ extension: 'gif', forceStatic: false }),
                    })
                    .setTimestamp();

                try {
                    await message.reply({
                        embeds: [pingEmbed],
                        components: [row],
                    });
                } catch (error) {
                    console.error("Error handling ping:", error);
                    try {
                        await message.channel.send(
                            "Sorry, I encountered an error while processing your ping. Please try again later.",
                        );
                    } catch (_) {}
                }
                return;
            }

            // Format uptime in a readable format
            function formatUptime(uptime) {
                const seconds = Math.floor(uptime % 60);
                const minutes = Math.floor((uptime / 60) % 60);
                const hours = Math.floor((uptime / 3600) % 24);
                const days = Math.floor(uptime / 86400);

                const parts = [];
                if (days > 0) parts.push(`${days}d`);
                if (hours > 0) parts.push(`${hours}h`);
                if (minutes > 0) parts.push(`${minutes}m`);
                if (seconds > 0) parts.push(`${seconds}s`);

                return parts.join(" ") || "0s";
            }

            // Check if message starts with emoji prefix (A!)
            const emojiPrefix = "#";
            if (message.content.startsWith(emojiPrefix)) {
                // Beta gate — emoji commands are restricted to beta-enrolled servers
                if (isBetaFeature('emoji', null, null, config.betaFeatures) && !(await betaManager.canAccess(message.guild?.id))) {
                    const betaEmojiEmbed = new EmbedBuilder()
                        .setColor(config.colors.warning)
                        .setTitle('🔬 Beta Feature')
                        .setDescription(
                            `**Emoji commands (\`${emojiPrefix}\`) are currently in beta** and are only available to selected servers.\n\n` +
                            `Join our [Support Server](${config.supportServer}) to learn more or request early access.`
                        )
                        .addFields({
                            name: 'Already selected?',
                            value: 'Your server owner can run `$beta enable` to activate beta features.',
                            inline: false
                        })
                        .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                        .setTimestamp();
                    return message.reply({ embeds: [betaEmojiEmbed] });
                }

                // Handle emoji commands
                const args = message.content.slice(emojiPrefix.length).trim().split(/ #/);
                const commandName = args.shift().toLowerCase();

                // Process emoji commands
                switch (commandName) {
                    case "emojis":
                        // Get page number if provided
                        let emojiPage = 1;
                        if (args.length > 0) {
                            const requestedPage = parseInt(args[0]);
                            if (!isNaN(requestedPage) && requestedPage > 0) {
                                emojiPage = requestedPage;
                            }
                        }
                        
                        // Get paginated emojis with buttons
                        const { embed: emojiListEmbed, currentPage, totalPages, components } = client.emojiManager.createEmojiListEmbed(emojiPage);
                        
                        // Display pagination info in the message if there are multiple pages
                        let content = null;
                        if (totalPages > 1) {
                            content = `Showing page ${currentPage} of ${totalPages}`;
                        }
                        
                        // Create message with pagination buttons that expire after 5 minutes
                        const reply = await message.reply({ 
                            content, 
                            embeds: [emojiListEmbed], 
                            components: components || [] 
                        });
                        
                        // Set up collector for button interactions
                        if (components && totalPages > 1) {
                            const filter = i => 
                                (i.customId === 'emoji_prev_page' || i.customId === 'emoji_next_page') && 
                                i.user.id === message.author.id;
                                
                            const collector = reply.createMessageComponentCollector({ 
                                filter, 
                                time: 300000 // 5 minutes
                            });
                            
                            // Store the current page for the collector to track
                            let currentEmojiPage = currentPage;
                            
                            collector.on('collect', async interaction => {
                                try {
                                    // Calculate the new page based on the current tracked page
                                    let newPage = currentEmojiPage;
                                    if (interaction.customId === 'emoji_prev_page') {
                                        newPage = Math.max(1, currentEmojiPage - 1);
                                    } else if (interaction.customId === 'emoji_next_page') {
                                        newPage = Math.min(totalPages, currentEmojiPage + 1);
                                    }
                                    
                                    // Update the current page for future interactions
                                    currentEmojiPage = newPage;
                                    
                                    // Get the updated emoji list
                                    const updatedList = client.emojiManager.createEmojiListEmbed(newPage);
                                    
                                    // Update the message with error handling
                                    if (!interaction.replied && !interaction.deferred) {
                                        await interaction.update({ 
                                            embeds: [updatedList.embed], 
                                            components: updatedList.components || []
                                        });
                                    }
                                } catch (paginationError) {
                                    console.error('Error updating emoji pagination:', paginationError);
                                    // Try to edit the original message as a fallback
                                    try {
                                        const updatedList = client.emojiManager.createEmojiListEmbed(currentEmojiPage);
                                        await reply.edit({
                                            embeds: [updatedList.embed],
                                            components: updatedList.components || []
                                        });
                                    } catch (fallbackError) {
                                        console.error('Failed to update emoji pagination via fallback:', fallbackError);
                                    }
                                }
                            });
                            
                            collector.on('end', () => {
                                // Remove buttons when collector expires
                                reply.edit({ components: [] }).catch(console.error);
                            });
                        }
                        
                        return;
                        
                    case "eadd":
                        // Check permissions
                        if (!message.member.permissions.has("ManageMessages") && !message.member.permissions.has("ManageGuild")) {
                            return message.reply("You need the Manage Messages permission to add custom emojis!");
                        }
                        
                        // Validate arguments
                        if (args.length < 2) {
                            return message.reply(`**Correct Usage:** \`${emojiPrefix}${commandName} [name] [emoji]\``);
                        }
                        
                        // Get emoji name and emoji
                        const emojiName = args[0].toLowerCase();
                        const emojiValue = args[1];
                        
                        // Validate emoji name (no spaces, special characters)
                        if (!/^[a-z0-9_]+$/.test(emojiName)) {
                            return message.reply("Emoji names can only contain lowercase letters, numbers, and underscores.");
                        }
                        
                        // Add the emoji
                        const added = client.emojiManager.addEmoji(emojiName, emojiValue);
                        
                        if (added) {
                            const addEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setDescription(`✅ Added emoji **${emojiName}**: ${emojiValue}`);
                            
                            return message.reply({ embeds: [addEmbed] });
                        } else {
                            return message.reply(`An emoji with the name "${emojiName}" already exists.`);
                        }
                        
                    case "eremove":
                    case "edel":
                        // Check permissions
                        if (!message.member.permissions.has("ManageMessages") && !message.member.permissions.has("ManageGuild")) {
                            return message.reply("You need the Manage Messages permission to remove custom emojis!");
                        }
                        
                        // Validate arguments
                        if (args.length < 1) {
                            return message.reply(`**Correct Usage:** \`${emojiPrefix}${commandName} [name]\``);
                        }
                        
                        // Get emoji name
                        const emojiToRemove = args[0].toLowerCase();
                        
                        // Remove the emoji
                        const removed = client.emojiManager.removeEmoji(emojiToRemove);
                        
                        if (removed) {
                            const removeEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setDescription(`✅ Removed emoji **${emojiToRemove}**`);
                            
                            return message.reply({ embeds: [removeEmbed] });
                        } else {
                            return message.reply(`No emoji with the name "${emojiToRemove}" exists.`);
                        }
                        
                    case "e":
                        // Send an emoji by name
                        if (args.length < 1) {
                            return message.reply(`**Correct Usage:** \`${emojiPrefix}${commandName} [name]\``);
                        }
                        
                        const emojiToSend = args[0].toLowerCase();
                        const emoji = client.emojiManager.getEmoji(emojiToSend);
                        
                        if (emoji) {
                            return message.channel.send(emoji);
                        } else {
                            return message.reply(`No emoji with the name "${emojiToSend}" exists.`);
                        }
                        
                    case "ehelp":
                        // Display help for emoji commands
                        const emojiHelpEmbed = new EmbedBuilder()
                            .setColor(config.colors.primary)
                            .setTitle("Emoji Commands")
                            .setDescription("Here are all available emoji commands:")
                            .addFields(
                                { name: `${emojiPrefix}emojis [page]`, value: "Show all available custom emojis (5 per page)" },
                                { name: `${emojiPrefix}eadd [name] [emoji]`, value: "Add a new custom emoji (requires Manage Messages permission)" },
                                { name: `${emojiPrefix}eremove [name]`, value: "Remove a custom emoji (requires Manage Messages permission)" },
                                { name: `${emojiPrefix}e [name]`, value: "Send a custom emoji in the current channel" },
                                { name: `${emojiPrefix}ehelp`, value: "Show this help message" }
                            )
                            .setFooter({ 
                                text: `Emoji commands use the ${emojiPrefix} prefix • Version: ${config.version}`
                            });
                            
                        return message.reply({ embeds: [emojiHelpEmbed] });
                        
                    default:
                        // Check if it's an emoji name
                        const customEmoji = client.emojiManager.getEmoji(commandName);
                        if (customEmoji) {
                            return message.channel.send(customEmoji);
                        }
                        
                        // Unknown command
                        return message.reply(`Unknown emoji command. Use \`${emojiPrefix}ehelp\` to see available commands.`);
                }
                
                // We don't need to continue processing after emoji commands
                return;
            }

            // Check if message starts with regular prefix
            let isUsingPrefix = message.content.startsWith(prefix);
            let isNoPrefixCommand = false;
            
            // Check for no-prefix mode if in a guild and not using prefix
            if (message.guild && !isUsingPrefix) {
                isNoPrefixCommand = client.serverSettingsManager.hasNoPrefixMode(
                    message.guild.id,
                    message.author.id
                );
                
                // If user has no-prefix mode, process the message as a command
                if (isNoPrefixCommand) {
                    // Parse the command and arguments
                    const args = message.content.trim().split(/ +/);
                    const commandName = args.shift().toLowerCase();
                    
                    console.log(`[NO-PREFIX] Processing command '${commandName}' from ${message.author.tag}`);
                    
                    // Create a simulated prefixed message for the command handler
                    const simulatedContent = `${prefix}${commandName}${args.length > 0 ? ' ' + args.join(' ') : ''}`;
                    
                    // Create a new message object to avoid reference issues
                    const simulatedMessage = Object.create(Object.getPrototypeOf(message));
                    Object.assign(simulatedMessage, message);
                    simulatedMessage.content = simulatedContent;
                    console.log(`[NO-PREFIX] Simulated content: "${simulatedContent}"`);
                    
                    // Process through the normal command switch so no-prefix users
                    // have the same command coverage as prefixed users. The
                    // simulated message already starts with the prefix, so this
                    // does not recurse into no-prefix detection.
                    try {
                        await module.exports.execute(simulatedMessage, client);
                        
                        // NO REACTION - Commands should execute silently in no-prefix mode

                        return; // Stop processing after handling the no-prefix command
                    } catch (error) {
                        console.error('[NO-PREFIX] Error processing no-prefix command:', error);
                        console.error('[NO-PREFIX] Stack trace:', error.stack);
                        await message.reply('There was an error processing that no-prefix command.').catch(() => {});
                    }
                }
            }
            
            if (!isUsingPrefix) {
                // Process counting game messages before returning
                const processed = await client.countingManager.processCountingMessage(message);
                if (processed) return; // Message was processed as a count
                
                // Process message for XP and leveling in servers with leveling enabled
                await client.levelingManager.processMessage(message);
                
                // Check for auto-reactions if in a guild
                if (message.guild) {
                    const triggeredEmojis = client.serverSettingsManager.getTriggeredReactions(
                        message.guild.id,
                        message.content
                    );
                    
                    // Add each reaction with a small delay to avoid rate limiting
                    if (triggeredEmojis.length > 0) {
                        console.log(`[AUTO-REACT] Adding ${triggeredEmojis.length} reactions to message in ${message.guild.name}`);
                        
                        // Add reactions with a small delay between each
                        triggeredEmojis.forEach((emoji, index) => {
                            setTimeout(() => {
                                message.react(emoji).catch(err => {
                                    console.error(`[AUTO-REACT] Failed to react with emoji ${emoji}:`, err);
                                });
                            }, index * 500); // 500ms delay between reactions
                        });
                    }
                }
                
                return; // Not a command or counting-related message
            }

            // Parse command and arguments
            const args = message.content
                .slice(prefix.length)
                .trim()
                .split(/ +/);
            const commandName = args.shift().toLowerCase();
            
            // Debug output to help diagnose command issues
            console.log(`[DEBUG] Command received: ${commandName}, Args: ${args.join(', ')}, From: ${message.author.tag}`);

            // Handle commands
            switch (commandName) {
                case "prefix": {
                    if (!message.member || !message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to change the server prefix.');
                    }

                    if (args.length === 0) {
                        return message.reply(`The current prefix for this server is \`${prefix}\`.`);
                    }

                    const requestedPrefix = args.join(' ').trim();
                    const result = client.serverSettingsManager?.setGuildPrefix
                        ? client.serverSettingsManager.setGuildPrefix(message.guild.id, requestedPrefix)
                        : { success: true, prefix };

                    if (!result?.success) {
                        return message.reply('I could not update the server prefix.');
                    }

                    return message.reply(`✅ Prefix updated to \`${result.prefix}\` for this server.`);
                }

                case "role": {
                    if (!message.member || !message.member.permissions.has(PermissionFlagsBits.ManageRoles)) {
                        return message.reply('You need the Manage Roles permission to manage roles.');
                    }

                    const roleSubcommand = args[0]?.toLowerCase();
                    const roleArgs = args.slice(1);
                    const botMember = message.guild.members.me;

                    if (!botMember) {
                        return message.reply('The bot member details are not available right now.');
                    }

                    if (!roleSubcommand || !['add', 'remove', 'create', 'list'].includes(roleSubcommand)) {
                        return message.reply(`Usage: \`${prefix}role add @user @role\` | \`${prefix}role remove @user @role\` | \`${prefix}role create [name] [color] [hoist] [mentionable]\` | \`${prefix}role list\``);
                    }

                    switch (roleSubcommand) {
                        case 'add': {
                            const targetUser = message.mentions.users.first();
                            const targetRole = message.mentions.roles.first();

                            if (!targetUser || !targetRole) {
                                return message.reply(`Usage: \`${prefix}role add @user @role\``);
                            }

                            const member = await message.guild.members.fetch(targetUser.id).catch(() => null);
                            if (!member) {
                                return message.reply('That user is not a member of this server.');
                            }

                            if (targetRole.position >= botMember.roles.highest.position) {
                                return message.reply('I cannot assign a role that is at or above my highest role.');
                            }

                            if (member.roles.cache.has(targetRole.id)) {
                                return message.reply(`${targetUser} already has ${targetRole}.`);
                            }

                            await member.roles.add(targetRole);
                            return message.reply(`✅ Added ${targetRole} to ${targetUser}.`);
                        }

                        case 'remove': {
                            const targetUser = message.mentions.users.first();
                            const targetRole = message.mentions.roles.first();

                            if (!targetUser || !targetRole) {
                                return message.reply(`Usage: \`${prefix}role remove @user @role\``);
                            }

                            const member = await message.guild.members.fetch(targetUser.id).catch(() => null);
                            if (!member) {
                                return message.reply('That user is not a member of this server.');
                            }

                            if (targetRole.position >= botMember.roles.highest.position) {
                                return message.reply('I cannot remove a role that is at or above my highest role.');
                            }

                            if (member.roles.highest.position >= botMember.roles.highest.position) {
                                return message.reply('I cannot remove roles from a member whose highest role is above my highest role for safety.');
                            }

                            if (!member.roles.cache.has(targetRole.id)) {
                                return message.reply(`${targetUser} does not have ${targetRole}.`);
                            }

                            await member.roles.remove(targetRole);
                            return message.reply(`✅ Removed ${targetRole} from ${targetUser}.`);
                        }

                        case 'create': {
                            const name = roleArgs[0];
                            if (!name) {
                                return message.reply(`Usage: \`${prefix}role create [name] [color] [hoist] [mentionable]\``);
                            }

                            const colorToken = roleArgs[1];
                            const colorValue = colorToken && /^#?[0-9A-Fa-f]{6}$/.test(colorToken)
                                ? (colorToken.startsWith('#') ? colorToken : `#${colorToken}`)
                                : undefined;
                            const hoist = roleArgs.includes('hoist');
                            const mentionable = roleArgs.includes('mentionable');

                            const createdRole = await message.guild.roles.create({
                                name,
                                color: colorValue,
                                hoist,
                                mentionable,
                                reason: `Created by ${message.author.tag}`,
                            });

                            return message.reply(`✅ Created the role ${createdRole}.`);
                        }

                        case 'list': {
                            const roles = [...message.guild.roles.cache.values()]
                                .filter(role => role.id !== message.guild.roles.everyone.id)
                                .sort((a, b) => b.position - a.position)
                                .slice(0, 25);

                            const description = roles.length > 0
                                ? roles.map(role => `${role} • ${role.members.size} member${role.members.size === 1 ? '' : 's'}`).join('\n')
                                : 'No roles found.';

                            const roleListEmbed = new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle('📋 Server Roles')
                                .setDescription(description)
                                .setFooter({ text: `Version ${config.version}` })
                                .setTimestamp();

                            return message.reply({ embeds: [roleListEmbed] });
                        }
                    }
                    break;
                }

                case "rm":
                case "rename": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to rename channels.');
                    }

                    const rmArgs = [...args];
                    let rmChannel = message.channel;
                    let rmIndex = 0;
                    const rmMention = rmArgs[0]?.match(/^<#(\d+)>$/);
                    if (rmMention) {
                        rmChannel = message.guild.channels.cache.get(rmMention[1]);
                        rmIndex = 1;
                    }

                    const rmName = rmArgs.slice(rmIndex).join(' ');
                    if (!rmName) {
                        return message.reply(`Usage: \`${prefix}rm [#channel] new-name\``);
                    }

                    if (!rmChannel || !rmChannel.setName) {
                        return message.reply('That channel could not be found.');
                    }

                    try {
                        await rmChannel.setName(rmName);
                        return message.reply(`Renamed ${rmChannel} to **${rmName}**.`);
                    } catch (err) {
                        console.error('[PREFIX RM] Failed:', err);
                        return message.reply('I could not rename that channel.');
                    }
                }

                case "lock": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to lock channels.');
                    }

                    const lockArgs = [...args];
                    let lockChannel = message.channel;
                    const lockMention = lockArgs[0]?.match(/^<#(\d+)>$/);
                    if (lockMention) {
                        lockChannel = message.guild.channels.cache.get(lockMention[1]);
                    }

                    if (!lockChannel || !lockChannel.permissionOverwrites || !lockChannel.isTextBased?.()) {
                        return message.reply('That channel cannot be locked.');
                    }

                    const everyone = lockChannel.guild.roles.everyone;
                    try {
                        await lockChannel.permissionOverwrites.edit(everyone, { SendMessages: false, AddReactions: false });
                        return message.reply(`Locked **${lockChannel.name}**.`);
                    } catch (err) {
                        console.error('[PREFIX LOCK] Failed:', err);
                        return message.reply('I could not lock that channel.');
                    }
                }

                case "unlock": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to unlock channels.');
                    }

                    const unlockArgs = [...args];
                    let unlockChannel = message.channel;
                    const unlockMention = unlockArgs[0]?.match(/^<#(\d+)>$/);
                    if (unlockMention) {
                        unlockChannel = message.guild.channels.cache.get(unlockMention[1]);
                    }

                    if (!unlockChannel || !unlockChannel.permissionOverwrites || !unlockChannel.isTextBased?.()) {
                        return message.reply('That channel cannot be unlocked.');
                    }

                    const everyone = unlockChannel.guild.roles.everyone;
                    try {
                        await unlockChannel.permissionOverwrites.edit(everyone, { SendMessages: null, AddReactions: null });
                        return message.reply(`Unlocked **${unlockChannel.name}**.`);
                    } catch (err) {
                        console.error('[PREFIX UNLOCK] Failed:', err);
                        return message.reply('I could not unlock that channel.');
                    }
                }

                case "hide": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to hide channels.');
                    }

                    const hideArgs = [...args];
                    let hideChannel = message.channel;
                    const hideMention = hideArgs[0]?.match(/^<#(\d+)>$/);
                    if (hideMention) {
                        hideChannel = message.guild.channels.cache.get(hideMention[1]);
                    }

                    if (!hideChannel || !hideChannel.permissionOverwrites) {
                        return message.reply('That channel cannot be hidden.');
                    }

                    const everyone = hideChannel.guild.roles.everyone;
                    try {
                        await hideChannel.permissionOverwrites.edit(everyone, { ViewChannel: false });
                        return message.reply({
                            content: `Hidden **${hideChannel.name}** from \`@everyone\`.`,
                            allowedMentions: { parse: [] },
                        });
                    } catch (err) {
                        console.error('[PREFIX HIDE] Failed:', err);
                        return message.reply('I could not hide that channel.');
                    }
                }

                case "unhide": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to unhide channels.');
                    }

                    const unhideArgs = [...args];
                    let unhideChannel = message.channel;
                    const unhideMention = unhideArgs[0]?.match(/^<#(\d+)>$/);
                    if (unhideMention) {
                        unhideChannel = message.guild.channels.cache.get(unhideMention[1]);
                    }

                    if (!unhideChannel || !unhideChannel.permissionOverwrites) {
                        return message.reply('That channel cannot be unhidden.');
                    }

                    const everyone = unhideChannel.guild.roles.everyone;
                    try {
                        await unhideChannel.permissionOverwrites.edit(everyone, { ViewChannel: null });
                        return message.reply({
                            content: `Unhidden **${unhideChannel.name}** for everyone in this server.`,
                            allowedMentions: { parse: [] },
                        });
                    } catch (err) {
                        console.error('[PREFIX UNHIDE] Failed:', err);
                        return message.reply('I could not unhide that channel.');
                    }
                }

                case "nuke": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to nuke channels.');
                    }

                    const nukeArgs = [...args];
                    let nukeChannel = message.channel;
                    const nukeMention = nukeArgs[0]?.match(/^<#(\d+)>$/);
                    let nameIndex = 0;
                    if (nukeMention) {
                        nukeChannel = message.guild.channels.cache.get(nukeMention[1]);
                        nameIndex = 1;
                    }

                    const replacementName = nukeArgs.slice(nameIndex).join(' ') || nukeChannel?.name;
                    if (!nukeChannel || !nukeChannel.parent || !nukeChannel.guild) {
                        return message.reply('That channel cannot be nuked.');
                    }

                    try {
                        const oldName = nukeChannel.name;
                        const category = nukeChannel.parent;
                        const position = nukeChannel.position;
                        const topic = nukeChannel.topic || null;
                        const nsfw = Boolean(nukeChannel.nsfw);

                        const newChannel = await nukeChannel.clone({
                            name: replacementName,
                            topic,
                            nsfw,
                            parent: category,
                            position,
                        });

                        await nukeChannel.delete(`Nuke requested by ${message.author.tag}`);
                        await newChannel.setPosition(position);
                        return message.reply(`Nuked **${oldName}** and recreated it as **${newChannel.name}**.`);
                    } catch (err) {
                        console.error('[PREFIX NUKE] Failed:', err);
                        return message.reply('I could not nuke that channel.');
                    }
                }

                case "snipe": {
                    if (!message.guild) {
                        return message.reply('Snipe is only available in a server channel.');
                    }

                    const huntedChannel = message.mentions.channels.first() || message.channel;
                    const record = client.snipeManager?.get(message.guild.id, huntedChannel.id);
                    if (!record) {
                        return message.reply('I do not have a recently deleted message for that channel.');
                    }

                    const content = record.content || '*No text content*';
                    const embed = new EmbedBuilder()
                        .setColor(0xffd700)
                        .setTitle('🗑️ Recently Deleted Message')
                        .setDescription(content)
                        .addFields(
                            { name: 'Author', value: record.authorUsername || 'Unknown', inline: true },
                            { name: 'Channel', value: `<#${huntedChannel.id}>`, inline: true },
                            { name: 'Created', value: new Date(record.createdTimestamp).toLocaleString(), inline: true }
                        );

                    if (record.attachments?.length) {
                        embed.addFields({ name: 'Attachments', value: record.attachments.map(a => a.url).join('\n'), inline: false });
                    }

                    return message.reply({ embeds: [embed] });
                }

                case "kick": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to kick members.');
                    }

                    const target = message.mentions.members?.first();
                    const reason = args.slice(1).join(' ') || 'No reason provided';
                    if (!target) {
                        return message.reply(`Usage: \`${prefix}kick @member [reason]\``);
                    }

                    try {
                        await target.kick(reason);
                        return message.reply(`Kicked **${target.user.tag}** for: ${reason}`);
                    } catch (err) {
                        console.error('[PREFIX KICK] Failed:', err);
                        return message.reply('I could not kick that member.');
                    }
                }

                case "ban": {
                    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return message.reply('You need Administrator permission to ban members.');
                    }

                    const target = message.mentions.users.first();
                    const reason = args.slice(1).join(' ') || 'No reason provided';
                    if (!target) {
                        return message.reply(`Usage: \`${prefix}ban @member [reason]\``);
                    }

                    try {
                        await message.guild.members.ban(target, { reason, deleteMessageSeconds: 0 });
                        return message.reply(`Banned **${target.tag}** for: ${reason}`);
                    } catch (err) {
                        console.error('[PREFIX BAN] Failed:', err);
                        return message.reply('I could not ban that member.');
                    }
                }

                case "warn": {
                    if (!message.member.permissions.has(PermissionFlagsBits.ModerateMembers)) {
                        return message.reply('You need Moderate Members permission to warn members.');
                    }
                    const target = message.mentions.members?.first();
                    if (!target) return message.reply(`Usage: \`${prefix}warn @member [reason]\``);
                    const reason = args.slice(1).join(' ') || 'No reason provided';
                    try {
                        const r = await client.automodManager.warnMember(message, target, reason);
                        if (r.escalated) {
                            return message.reply(`⚠️ Warned **${target.user.tag}** (${r.count}/${r.warnThreshold}). They reached the threshold and were escalated to **${r.warnAction}**.`);
                        }
                        return message.reply(`⚠️ Warned **${target.user.tag}** — warning ${r.count}/${r.warnThreshold}. Reason: ${reason}`);
                    } catch (err) {
                        console.error('[PREFIX WARN] Failed:', err);
                        return message.reply('I could not warn that member.');
                    }
                }

                case "unwarn": {
                    if (!message.member.permissions.has(PermissionFlagsBits.ModerateMembers)) {
                        return message.reply('You need Moderate Members permission to remove warnings.');
                    }
                    const target = message.mentions.members?.first();
                    if (!target) return message.reply(`Usage: \`${prefix}unwarn @member [count|all]\``);
                    const amount = (args[1] || '1').toLowerCase();
                    try {
                        const remaining = await client.automodManager.removeWarnings(message.guild.id, target.id, amount);
                        return message.reply(`✅ Removed warnings from **${target.user.tag}**. ${remaining} warning(s) remaining.`);
                    } catch (err) {
                        console.error('[PREFIX UNWARN] Failed:', err);
                        return message.reply('I could not remove warnings for that member.');
                    }
                }

                case "warnings": {
                    const target = message.mentions.members?.first() || message.member;
                    try {
                        const warnings = await client.automodManager.getWarnings(message.guild.id, target.id);
                        if (warnings.length === 0) {
                            return message.reply(`**${target.user.tag}** has no warnings. ✨`);
                        }
                        const list = warnings.slice(0, 10).map((w, i) =>
                            `**${i + 1}.** ${w.ruleType ? `\`${w.ruleType}\` · ` : ''}${w.reason} — <t:${Math.floor(new Date(w.createdAt).getTime() / 1000)}:R>`
                        ).join('\n');
                        return message.reply(`📋 **${target.user.tag}** has **${warnings.length}** warning(s):\n${list}`);
                    } catch (err) {
                        console.error('[PREFIX WARNINGS] Failed:', err);
                        return message.reply('I could not fetch warnings for that member.');
                    }
                }

                case "mute": {
                    if (!message.member.permissions.has(PermissionFlagsBits.ModerateMembers)) {
                        return message.reply('You need Moderate Members permission to mute members.');
                    }
                    const target = message.mentions.members?.first();
                    if (!target) return message.reply(`Usage: \`${prefix}mute @member [seconds] [reason]\``);
                    const seconds = parseInt(args[1], 10);
                    const reason = args.slice(2).join(' ') || 'Muted by moderator';
                    try {
                        await client.automodManager.muteMember(message, target, Number.isFinite(seconds) ? seconds : null, reason);
                        return message.reply(`🔇 Muted **${target.user.tag}**${Number.isFinite(seconds) ? ` for ${seconds}s` : ''}. Reason: ${reason}`);
                    } catch (err) {
                        console.error('[PREFIX MUTE] Failed:', err);
                        return message.reply('I could not mute that member.');
                    }
                }

                case "unmute": {
                    if (!message.member.permissions.has(PermissionFlagsBits.ModerateMembers)) {
                        return message.reply('You need Moderate Members permission to unmute members.');
                    }
                    const target = message.mentions.members?.first();
                    if (!target) return message.reply(`Usage: \`${prefix}unmute @member\``);
                    try {
                        await client.automodManager.unmuteMember(message, target);
                        return message.reply(`🔊 Unmuted **${target.user.tag}**.`);
                    } catch (err) {
                        console.error('[PREFIX UNMUTE] Failed:', err);
                        return message.reply('I could not unmute that member.');
                    }
                }

                case "commands":
                
                    // Check if user wants a specific category
                    const category = args[0]?.toLowerCase();
                    
                    // If category is provided, show category-specific help
                    if (category && ['general', 'leveling', 'games', 'moderation', 'community', 'admin'].includes(category)) {
                        return showPrefixCategoryHelp(message, category, prefix);
                    }
                    
                    // Show main category menu
                    const categoryEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('📚 Command Categories')
                        .setDescription(`Choose a category to explore available commands:\n\n**Usage:** \`${prefix}commands [category]\``)
                        .addFields(
                            { name: '⚡ General', value: `\`${prefix}commands general\`\nBasic bot commands and information`, inline: true },
                            { name: '📊 Leveling', value: `\`${prefix}commands leveling\`\nXP, ranks, and progression system`, inline: true },
                            { name: '🎮 Games', value: `\`${prefix}commands games\`\nFun interactive games and activities`, inline: true },
                            { name: '🛡️ Moderation', value: `\`${prefix}commands moderation\`\nServer management and moderation tools`, inline: true },
                            { name: '👥 Community', value: `\`${prefix}commands community\`\nEngagement and social features`, inline: true },
                            { name: '⚙️ Administration', value: `\`${prefix}commands admin\`\nAdvanced server configuration`, inline: true }
                        )
                        .setFooter({ text: `Total Commands: 30+ • Version: ${config.version}` })
                        .setTimestamp();

                    return message.reply({ embeds: [categoryEmbed] });

                case "help":
                case "categories": {
                    // Interactive category browser with select menu
                    const interactiveCategoryEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('🗂️ Interactive Category Browser')
                        .setDescription('Use the dropdown menu below to explore different command categories. Each category contains specialized commands for different server needs.')
                        .addFields(
                            { name: '📊 Quick Stats', value: `**Total Commands:** 30+\n**Categories:** 6\n**Active Servers:** ${message.client.guilds.cache.size}`, inline: true },
                            { name: '🚀 Getting Started', value: 'Select a category from the menu to see available commands and their descriptions.', inline: true },
                            { name: '💡 Pro Tip', value: `Use \`${prefix}commands\` for traditional browsing or \`${prefix}help\` for this interactive experience.`, inline: true }
                        )
                        .setFooter({ text: `Version: ${config.version}` })
                        .setTimestamp();

                    const categorySelect = new ActionRowBuilder()
                        .addComponents(
                            new StringSelectMenuBuilder()
                                .setCustomId('category_select_prefix')
                                .setPlaceholder('Choose a category to explore...')
                                .addOptions([
                                    {
                                        label: 'General Commands',
                                        description: 'Basic bot commands and information',
                                        value: 'general',
                                        emoji: '⚡'
                                    },
                                    {
                                        label: 'Leveling System',
                                        description: 'XP, ranks, and progression features',
                                        value: 'leveling',
                                        emoji: '📊'
                                    },
                                    {
                                        label: 'Games & Activities',
                                        description: 'Fun interactive games and entertainment',
                                        value: 'games',
                                        emoji: '🎮'
                                    },
                                    {
                                        label: 'Moderation Tools',
                                        description: 'Server management and moderation',
                                        value: 'moderation',
                                        emoji: '🛡️'
                                    },
                                    {
                                        label: 'Community Features',
                                        description: 'Engagement and social activities',
                                        value: 'community',
                                        emoji: '👥'
                                    },
                                    {
                                        label: 'Administration',
                                        description: 'Advanced server configuration',
                                        value: 'admin',
                                        emoji: '⚙️'
                                    }
                                ])
                        );

                    const actionButtons = new ActionRowBuilder()
                        .addComponents(
                            new ButtonBuilder()
                                .setCustomId('categories_refresh')
                                .setLabel('Refresh')
                                .setStyle(ButtonStyle.Secondary)
                                .setEmoji('🔄'),
                            new ButtonBuilder()
                                .setCustomId('categories_help')
                                .setLabel('Need Help?')
                                .setStyle(ButtonStyle.Primary)
                                .setEmoji('❓')
                        );

                    // Check if user wants a specific category directly
                    const requestedCategory = args[0]?.toLowerCase();
                    
                    if (requestedCategory && ['general', 'leveling', 'games', 'moderation', 'community', 'admin'].includes(requestedCategory)) {
                        return showDetailedCategoryHelp(message, requestedCategory, prefix);
                    }

                    return message.reply({ 
                        embeds: [interactiveCategoryEmbed], 
                        components: [categorySelect, actionButtons] 
                    });
                    
                    // Add admin commands if user has proper permissions
                    if (message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        const adminCommands = [
                            { name: "🔧 Admin - Welcome System", value: "Configure how the bot welcomes new members:" },
                            { name: `${prefix}welcome-enable`, value: "Enable the welcome system" },
                            { name: `${prefix}welcome-disable`, value: "Disable the welcome system" },
                            { name: `${prefix}welcome-channel #channel`, value: "Set the welcome message channel" },
                            { name: "🔧 Admin - Leveling System", value: "Configure the server's leveling system:" },
                            { name: `${prefix}level-enable`, value: "Enable the leveling system" },
                            { name: `${prefix}level-disable`, value: "Disable the leveling system" },
                            { name: `${prefix}level-channel #channel`, value: "Set the level-up notification channel" },
                            { name: `${prefix}level-multiplier 1.5`, value: "Set the XP multiplier (default: 1.0)" },
                            { name: "🔧 Admin - Auto-Reactions", value: "Configure automatic emoji reactions:" },
                            { name: `${prefix}autoreact enable`, value: "Enable auto-reactions to trigger words" },
                            { name: `${prefix}autoreact disable`, value: "Disable auto-reactions" },
                            { name: `${prefix}autoreact add [trigger] [emoji]`, value: "Add a new auto-reaction" },
                            { name: `${prefix}autoreact remove [trigger]`, value: "Remove an auto-reaction" },
                            { name: `${prefix}autoreact list`, value: "View all configured auto-reactions" }
                        ];
                        
                        // Add admin commands to the list
                        allCommands = [...allCommands, ...adminCommands];
                    }
                    
                    // Settings for pagination
                    const commandsPerPage = 5; // 5 commands per page as requested
                    const totalCommands = allCommands.length;
                    const totalPages = Math.ceil(totalCommands / commandsPerPage);
                    
                    // Validate the page number
                    commandPage = Math.max(1, Math.min(commandPage, totalPages));
                    
                    // Calculate start and end indices for the current page
                    const startIndex = (commandPage - 1) * commandsPerPage;
                    const endIndex = Math.min(startIndex + commandsPerPage, totalCommands);
                    
                    // Get the commands for the current page
                    const pageCommands = allCommands.slice(startIndex, endIndex);
                    
                    // Create the embed
                    const commandsEmbed = new EmbedBuilder()
                        .setColor(config.colors.Gold)
                        .setTitle("Available Commands")
                        .setDescription(`Here are commands you can use (Page ${commandPage}/${totalPages}):`)
                        .addFields(...pageCommands)
                        .setTimestamp()
                        .setFooter({
                            text: `Page ${commandPage}/${totalPages} • Use buttons below to navigate • Version: ${config.version}`,
                            iconURL: message.author.displayAvatarURL({
                                dynamic: true,
                            }),
                        });
                    
                    // Display pagination info in the message if there are multiple pages
                    let content = null;
                    if (totalPages > 1) {
                        content = `Showing page ${commandPage} of ${totalPages}`;
                    }
                    
                    // Create buttons for pagination
                    const buttons = [];
                    
                    // Create Previous page button (disabled on first page)
                    const prevButton = new ButtonBuilder()
                        .setCustomId('command_prev_page')
                        .setLabel('⬅️ Previous')
                        .setStyle(ButtonStyle.Secondary)
                        .setDisabled(commandPage === 1);
                    
                    // Create Next page button (disabled on last page)
                    const nextButton = new ButtonBuilder()
                        .setCustomId('command_next_page')
                        .setLabel('Next ➡️')
                        .setStyle(ButtonStyle.Secondary)
                        .setDisabled(commandPage === totalPages);
                    
                    buttons.push(prevButton, nextButton);
                    const row = new ActionRowBuilder().addComponents(buttons);
                    
                    // Components array to include in the message
                    const components = totalPages > 1 ? [row] : [];
                    
                    // Create message with pagination buttons that expire after 5 minutes
                    const reply = await message.reply({ 
                        content, 
                        embeds: [commandsEmbed], 
                        components 
                    });
                    
                    // Set up collector for button interactions if we have multiple pages
                    if (totalPages > 1) {
                        const filter = i => 
                            (i.customId === 'command_prev_page' || i.customId === 'command_next_page') && 
                            i.user.id === message.author.id;
                            
                        const collector = reply.createMessageComponentCollector({ 
                            filter, 
                            time: 300000 // 5 minutes
                        });
                        
                        // Store the current page for the collector to track
                        let currentPage = commandPage;
                        
                        collector.on('collect', async interaction => {
                            try {
                                // Calculate the new page based on the current tracked page
                                let newPage = currentPage;
                                if (interaction.customId === 'command_prev_page') {
                                    newPage = Math.max(1, currentPage - 1);
                                } else if (interaction.customId === 'command_next_page') {
                                    newPage = Math.min(totalPages, currentPage + 1);
                                }
                                
                                // Update the current page for future interactions
                                currentPage = newPage;
                                
                                // Get updated commands (in case server-specific commands need to be filtered)
                                let updatedCommands = [...allCommands]; // Start with all commands
                                
                                // Get the commands for the new page
                                const newPageCommands = updatedCommands.slice(
                                    (newPage - 1) * commandsPerPage, 
                                    Math.min(newPage * commandsPerPage, totalCommands)
                                );
                                
                                // Create the new embed
                                const newEmbed = new EmbedBuilder()
                                    .setColor(config.colors.Gold)
                                    .setTitle("Available Commands")
                                    .setDescription(`Here are commands you can use (Page ${newPage}/${totalPages}):`)
                                    .addFields(...newPageCommands)
                                    .setTimestamp()
                                    .setFooter({
                                        text: `Page ${newPage}/${totalPages} • Use buttons below to navigate • Version: ${config.version}`,
                                        iconURL: message.author.displayAvatarURL({
                                            dynamic: true,
                                        }),
                                    });
                                
                                // Create new buttons with updated disabled states
                                const newButtons = [];
                                
                                const newPrevButton = new ButtonBuilder()
                                    .setCustomId('command_prev_page')
                                    .setLabel('⬅️ Previous')
                                    .setStyle(ButtonStyle.Secondary)
                                    .setDisabled(newPage === 1);
                                
                                const newNextButton = new ButtonBuilder()
                                    .setCustomId('command_next_page')
                                    .setLabel('Next ➡️')
                                    .setStyle(ButtonStyle.Secondary)
                                    .setDisabled(newPage === totalPages);
                                
                                newButtons.push(newPrevButton, newNextButton);
                                const newRow = new ActionRowBuilder().addComponents(newButtons);
                                
                                // Update the message with error handling
                                if (!interaction.replied && !interaction.deferred) {
                                    await interaction.update({ 
                                        embeds: [newEmbed], 
                                        components: [newRow]
                                    });
                                }
                            } catch (paginationError) {
                                console.error('Error updating command pagination:', paginationError);
                                // Try to edit the original message as a fallback
                                try {
                                    // Recreate the embed and buttons for the current page
                                    let updatedCommands = [...allCommands];
                                    const currentPageCommands = updatedCommands.slice(
                                        (currentPage - 1) * commandsPerPage, 
                                        Math.min(currentPage * commandsPerPage, totalCommands)
                                    );
                                    
                                    const fallbackEmbed = new EmbedBuilder()
                                        .setColor(config.colors.Gold)
                                        .setTitle("Available Commands")
                                        .setDescription(`Here are commands you can use (Page ${currentPage}/${totalPages}):`)
                                        .addFields(...currentPageCommands)
                                        .setTimestamp()
                                        .setFooter({
                                            text: `Page ${currentPage}/${totalPages} • Use buttons below to navigate • Version: ${config.version}`,
                                            iconURL: message.author.displayAvatarURL({
                                                dynamic: true,
                                            }),
                                        });
                                    
                                    // Create fallback buttons
                                    const fallbackButtons = [];
                                    
                                    const fallbackPrevButton = new ButtonBuilder()
                                        .setCustomId('command_prev_page')
                                        .setLabel('⬅️ Previous')
                                        .setStyle(ButtonStyle.Secondary)
                                        .setDisabled(currentPage === 1);
                                    
                                    const fallbackNextButton = new ButtonBuilder()
                                        .setCustomId('command_next_page')
                                        .setLabel('Next ➡️')
                                        .setStyle(ButtonStyle.Secondary)
                                        .setDisabled(currentPage === totalPages);
                                    
                                    fallbackButtons.push(fallbackPrevButton, fallbackNextButton);
                                    const fallbackRow = new ActionRowBuilder().addComponents(fallbackButtons);
                                    
                                    await reply.edit({
                                        embeds: [fallbackEmbed],
                                        components: [fallbackRow]
                                    });
                                } catch (fallbackError) {
                                    console.error('Failed to update command pagination via fallback:', fallbackError);
                                }
                            }
                        });
                        
                        collector.on('end', () => {
                            // Remove buttons when collector expires
                            reply.edit({ components: [] }).catch(console.error);
                        });
                    }
                    
                    return;
                }

                case "giveaway":
                    // Show giveaway command help
                    const giveawayHelpEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("🎉 Giveaway Commands")
                        .setDescription("Here are all available giveaway commands:")
                        .addFields(
                            { name: `${prefix}gstart [duration] [winners] [prize]`, value: "Creates a new giveaway in the current channel" },
                            { name: `${prefix}gend [message_id]`, value: "Ends a giveaway early" },
                            { name: `${prefix}reroll [message_id]`, value: "Rerolls the winners for a completed giveaway" }
                        )
                        .addFields({
                            name: "Examples",
                            value:
                                `\`${prefix}gstart 1d 1 Discord Nitro\` - 1 day giveaway for 1 winner\n` +
                                `\`${prefix}gstart 2h 3 Steam Game\` - 2 hour giveaway for 3 winners\n` +
                                `\`${prefix}gend 123456789123456789\` - End giveaway with the specified message ID\n` +
                                `\`${prefix}reroll 123456789123456789\` - Reroll winners for the specified giveaway`
                        })
                        .setFooter({
                            text: `Version: ${config.version}`,
                            iconURL: client.user.displayAvatarURL()
                        });
                    
                    return message.reply({ embeds: [giveawayHelpEmbed] });
                
                case "gstart":
                    // Check permissions
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply(
                            "You need the Manage Server permission to create giveaways!",
                        );
                    }

                    // Validate arguments
                    if (args.length < 3) {
                        const usageEmbed = new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle("Invalid Usage")
                            .setDescription(
                                `**Correct Usage:** \`${prefix}${commandName} [duration] [winners] [prize]\``,
                            )
                            .addFields({
                                name: "Examples",
                                value:
                                    `\`${prefix}${commandName} 1d 1 Discord Nitro\` - 1 day giveaway for 1 winner\n` +
                                    `\`${prefix}${commandName} 12h 3 Steam Game\` - 12 hour giveaway for 3 winners`,
                            });
                        return message.reply({ embeds: [usageEmbed] });
                    }

                    // Parse arguments
                    const duration = args[0];
                    const winnerCount = parseInt(args[1]);
                    const prize = args.slice(2).join(" ");

                    // Validate winner count
                    if (
                        isNaN(winnerCount) ||
                        winnerCount < 1 ||
                        winnerCount > 10
                    ) {
                        return message.reply(
                            "Winner count must be a number between 1 and 10!",
                        );
                    }

                    // Convert duration to milliseconds
                    const ms = require("ms");
                    const ms_duration = ms(duration);

                    if (!ms_duration) {
                        return message.reply(
                            "Please provide a valid duration format (e.g., 1m, 1h, 1d)!",
                        );
                    }

                    // Create giveaway
                    try {
                        await client.giveawayManager.startGiveaway({
                            channelId: message.channel.id,
                            duration: ms_duration,
                            prize,
                            winnerCount,
                        });

                        // Send confirmation
                        const confirmEmbed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription(
                                `✅ Giveaway created successfully for **${prize}**!`,
                            ).setFooter({
                                text: `Version: ${config.version}`,
                                iconURL: client.user.displayAvatarURL()
                            });

                        return message.reply({ embeds: [confirmEmbed] });
                    } catch (error) {
                        console.error("Error creating giveaway:", error);
                        return message.reply(
                            "There was an error creating the giveaway! Please try again later.",
                        );
                    }

                case "end":
                case "gend":
                    // Check permissions
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply(
                            "You need the Manage Server permission to end giveaways!",
                        );
                    }

                    // Validate arguments
                    if (args.length < 1) {
                        return message.reply(
                            `**Correct Usage:** \`${prefix}${commandName} [message_id]\``,
                        );
                    }

                    // Parse arguments
                    const endMessageId = args[0];

                    // End giveaway
                    try {
                        const success =
                            await client.giveawayManager.endGiveaway(
                                endMessageId,
                            );

                        if (success) {
                            const endConfirmEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setDescription(
                                    "✅ Giveaway ended successfully!",
                                )
                            .setFooter({

                            text: `Version: ${config.version}`,

                            iconURL: client.user.displayAvatarURL(),

                        });

                            return message.reply({ embeds: [endConfirmEmbed] });
                        } else {
                            return message.reply(
                                "Could not find an active giveaway with that message ID.",
                            );
                        }
                    } catch (error) {
                        console.error("Error ending giveaway:", error);
                        return message.reply(
                            "There was an error ending the giveaway! Please try again later.",
                        );
                    }

                case "reroll":
                    // Check permissions
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply(
                            "You need the Manage Server permission to reroll giveaways!",
                        );
                    }

                    // Validate arguments
                    if (args.length < 1) {
                        return message.reply(
                            `**Correct Usage:** \`${prefix}${commandName} [message_id]\``,
                        );
                    }

                    // Parse arguments
                    const rerollMessageId = args[0];

                    // Reroll giveaway
                    try {
                        const success =
                            await client.giveawayManager.rerollGiveaway(
                                rerollMessageId,
                            );

                        if (success) {
                            const rerollConfirmEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setDescription(
                                    "✅ Giveaway rerolled successfully!",
                                )
                            .setFooter({

                            text: `Version: ${config.version}`,

                            iconURL: client.user.displayAvatarURL(),

                        });

                            return message.reply({
                                embeds: [rerollConfirmEmbed],
                            });
                        } else {
                            return message.reply(
                                "Could not find a completed giveaway with that message ID.",
                            );
                        }
                    } catch (error) {
                        console.error("Error rerolling giveaway:", error);
                        return message.reply(
                            "There was an error rerolling the giveaway! Please try again later.",
                        );
                    }

                case "echo":
                    // Validate arguments
                    if (args.length < 1) {
                        const usageEmbed = new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle("Invalid Usage")
                            .setDescription(
                                `**Correct Usage:** \`${prefix}${commandName} [message]\``,
                            )
                            .addFields({
                                name: "Examples",
                                value:
                                    `\`${prefix}${commandName} Hello World!\` - Makes the bot say "Hello World!"\n` +
                                    `\`${prefix}${commandName} Welcome to the server!\` - Makes the bot say "Welcome to the server!"`,
                            });
                        return message.reply({ embeds: [usageEmbed] });
                    }

                    // Get message content
                    const echoMessage = args.join(" ");

                    // Send the echo message
                    await message.channel.send(echoMessage);

                    // Send confirmation (optional - can be removed if you don't want this)
                    const confirmEchoEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setDescription("✅ Message echoed successfully!")
                        .setFooter({
                            text: ` • Version: ${config.version}`,
                           iconURL: client.user.displayAvatarURL()
                                
                            
                        });

                    // Delete the confirmation after 3 seconds
                    message
                        .reply({ embeds: [confirmEchoEmbed] })
                        .then((reply) => {
                            setTimeout(() => {
                                reply
                                    .delete()
                                    .catch((err) =>
                                        console.error(
                                            "Could not delete message:",
                                            err,
                                        ),
                                    );
                            }, 3000);
                        })
                        .catch((err) =>
                            console.error("Could not send message:", err),
                        );

                    // Don't return here to allow the confirmation to be sent
                    break;

                case "poll":
                    try {
                        // Parse the simple command format: $poll <question> <option1> <option2> [option3] [duration]
                        if (args.length < 3) {
                            const usageEmbed = new EmbedBuilder()
                                .setColor(config.colors.error)
                                .setTitle("Invalid Usage")
                                .setDescription(
                                    `**Correct Usage:** \`${prefix}${commandName} [question] [option1] [option2] [option3] [duration]\``,
                                )
                                .addFields({
                                    name: "Examples",
                                    value:
                                        `\`${prefix}${commandName} "What's your favorite color?" Red Blue Green\` - Poll with 3 options (24h default)\n` +
                                        `\`${prefix}${commandName} "Best language?" JavaScript Python Java 2h\` - Poll with 2h duration\n` +
                                        `\`${prefix}${commandName} "Pizza topping?" Pepperoni Cheese Mushrooms Sausage 1d\` - 4 options, 1 day`,
                                });
                            return message.reply({ embeds: [usageEmbed] });
                        }

                        // Parse arguments - first is question, rest are options, last might be duration
                        let question, options, duration = "24h"; // Default 24 hours
                        
                        // If first arg has quotes, extract the full quoted question
                        if (args[0].startsWith('"')) {
                            const fullMessage = args.join(' ');
                            const questionMatch = fullMessage.match(/"([^"]+)"/);
                            if (questionMatch) {
                                question = questionMatch[1];
                                // Get remaining args after the quoted question
                                const remainingArgs = fullMessage.replace(questionMatch[0], '').trim().split(/\s+/).filter(arg => arg);
                                options = [...remainingArgs];
                            } else {
                                question = args[0].replace(/"/g, '');
                                options = args.slice(1);
                            }
                        } else {
                            // No quotes - first word is question, rest are options
                            question = args[0];
                            options = args.slice(1);
                        }

                        // Check if last option is actually a duration
                        const ms = require('ms');
                        if (options.length > 0) {
                            const lastOption = options[options.length - 1];
                            const parsedDuration = ms(lastOption);
                            if (parsedDuration && parsedDuration > 0) {
                                duration = lastOption;
                                options = options.slice(0, -1); // Remove duration from options
                            }
                        }

                        // Validate we have enough options
                        if (options.length < 2) {
                            return message.reply(
                                "Please provide at least 2 options for your poll.",
                            );
                        }

                        // Limit to 10 options
                        if (options.length > 10) {
                            return message.reply(
                                "You can only have up to 10 options in a poll.",
                            );
                        }

                        // Create the poll
                        await client.pollManager.createPoll({
                            channelId: message.channel.id,
                            question,
                            options,
                            duration,
                            userId: message.author.id,
                        });

                        // Send confirmation
                        const confirmEmbed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription("✅ Poll created successfully!")
.setFooter({

                            text: `Version: ${config.version}`,

                            iconURL: client.user.displayAvatarURL(),

                        });
                        message
                            .reply({ embeds: [confirmEmbed] })
                            .then((reply) => {
                                setTimeout(() => {
                                    reply
                                        .delete()
                                        .catch((err) =>
                                            console.error(
                                                "Could not delete message:",
                                                err,
                                            ),
                                        );
                                }, 3000);
                            })
                            .catch((err) =>
                                console.error("Could not send message:", err),
                            );
                    } catch (error) {
                        console.error("Error creating poll:", error);
                        return message.reply(
                            error.message ||
                                "There was an error creating the poll! Please try again later.",
                        );
                    }
                    break;

                case "endpoll":
                    try {
                        // Check if user has permission
                        if (
                            !message.member.permissions.has("ManageMessages") &&
                            !message.member.permissions.has("ManageGuild")
                        ) {
                            return message.reply(
                                "You need the Manage Messages permission to end polls early!",
                            );
                        }

                        // Validate arguments
                        if (args.length < 1) {
                            return message.reply(
                                `**Correct Usage:** \`${prefix}${commandName} [message_id]\``,
                            );
                        }

                        // Get message ID
                        const messageId = args[0];

                        // End the poll
                        const success =
                            await client.pollManager.forceEndPoll(messageId);

                        if (success) {
                            const confirmEndEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setDescription("✅ Poll ended successfully!");

                            return message.reply({ embeds: [confirmEndEmbed] });
                        } else {
                            return message.reply(
                                "Could not find an active poll with that message ID.",
                            );
                        }
                    } catch (error) {
                        console.error("Error ending poll:", error);
                        return message.reply(
                            "There was an error ending the poll! Please try again later.",
                        );
                    }
                    break;

                case "lpoll":
                case "livepoll":
                    try {
                        // Handle live poll prefix commands
                        if (args.length < 1) {
                            const usageEmbed = new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle("Live Poll Commands")
                                .setDescription("Cross-server polls with pass code sharing")
                                .addFields(
                                    { name: `${prefix}lpoll create [question] [option1] [option2] [duration] [multiple_votes]`, value: "Create a new cross-server poll" },
                                    { name: `${prefix}lpoll join [poll_id_or_passcode]`, value: "Join an existing poll to vote" },
                                    { name: `${prefix}lpoll results [poll_id_or_passcode]`, value: "View live poll results" },
                                    { name: `${prefix}lpoll end [poll_id]`, value: "End your poll (creator only)" },
                                    { name: `${prefix}lpoll list`, value: "List your created polls with IDs/codes" },
                                    { name: "Examples", value: `\`${prefix}lpoll create "Best pizza?" Pepperoni Cheese Veggie\`\n\`${prefix}lpoll create Gaming? PC Console Mobile 24h true\`` }
                                )
                                .setFooter({ text: `Version: ${config.version}` });
                            return message.reply({ embeds: [usageEmbed] });
                        }

                        const subcommand = args[0].toLowerCase();
                        const subArgs = args.slice(1);

                        switch (subcommand) {
                            case "create":
                                return await handleLivePollCreate(message, subArgs, prefix, client);
                            case "join":
                                return await handleLivePollJoin(message, subArgs, prefix, client);
                            case "results":
                                return await handleLivePollResults(message, subArgs, prefix, client);
                            case "end":
                                return await handleLivePollEnd(message, subArgs, prefix, client);
                            case "list":
                                return await handleLivePollList(message, subArgs, prefix, client);
                            default:
                                return message.reply(`Unknown subcommand. Use \`${prefix}lpoll\` to see available commands.`);
                        }
                    } catch (error) {
                        console.error("Error in live poll command:", error);
                        return message.reply("There was an error processing your live poll command. Please try again later.");
                    }
                    break;

                case "birthday":
                case "bday":
                    try {
                        if (args.length < 1) {
                            const usageEmbed = new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle("Birthday Commands")
                                .setDescription("Here are the available birthday commands:")
                                .addFields(
                                    { name: `${prefix}birthday set [MM/DD/YYYY]`, value: "Set your birthday (year is optional)" },
                                    { name: `${prefix}birthday remove`, value: "Remove your birthday" },
                                    { name: `${prefix}birthday list`, value: "List upcoming birthdays" },
                                    { name: `${prefix}birthday check [@user]`, value: "Check your or someone else's birthday" }
                                );
                                
                            if (message.member.permissions.has("ManageGuild")) {
                                usageEmbed.addFields(
                                    { name: `${prefix}birthday channel [#channel]`, value: "Set the birthday announcement channel" },
                                    { name: `${prefix}birthday role [@role]`, value: "Set the birthday role (given on birthdays)" }
                                );
                            }
                            
                            return message.reply({ embeds: [usageEmbed] });
                        }
                        
                        const subcommand = args[0].toLowerCase();
                        
                        switch (subcommand) {
                            case "set":
                                if (args.length < 2) {
                                    return message.reply(`**Correct Usage:** \`${prefix}${commandName} set [MM/DD/YYYY]\` (year is optional)`);
                                }
                                
                                // Parse the date
                                const dateStr = args[1];
                                const dateParts = dateStr.split("/");
                                
                                if (dateParts.length < 2 || dateParts.length > 3) {
                                    return message.reply("Please provide a valid date format (MM/DD/YYYY or MM/DD).");
                                }
                                
                                const month = parseInt(dateParts[0]);
                                const day = parseInt(dateParts[1]);
                                const year = dateParts.length === 3 ? parseInt(dateParts[2]) : null;
                                
                                // Set the birthday
                                await client.birthdayManager.setBirthday({
                                    guildId: message.guild.id,
                                    userId: message.author.id,
                                    month,
                                    day,
                                    year
                                });
                                
                                // Format the date for display
                                const formattedDate = client.birthdayManager.formatDate(month, day);
                                const yearText = year ? `, ${year}` : "";
                                
                                const setBirthdayEmbed = new EmbedBuilder()
                                    .setColor(config.colors.success)
                                    .setTitle("🎂 Birthday Set")
                                    .setDescription(`Your birthday has been set to **${formattedDate}${yearText}**!`)
                                    .setFooter({ text: "You will receive a celebration on your birthday!" });
                                
                                return message.reply({ embeds: [setBirthdayEmbed] });
                                
                            case "remove":
                                // Remove the birthday
                                const removed = client.birthdayManager.removeBirthday(message.guild.id, message.author.id);
                                
                                if (removed) {
                                    const removeBirthdayEmbed = new EmbedBuilder()
                                        .setColor(config.colors.success)
                                        .setDescription("✅ Your birthday has been removed.");
                                    
                                    return message.reply({ embeds: [removeBirthdayEmbed] });
                                } else {
                                    return message.reply("You don't have a birthday set!");
                                }
                                
                            case "list": {
                                // Fetch ALL birthdays from DB — no day-window filter
                                const allBirthdays = await client.birthdayManager.getAllBirthdays(message.guild.id);

                                if (allBirthdays.length === 0) {
                                    return message.reply("No birthdays have been set in this server yet! Set yours with `" + prefix + "birthday set MM/DD/YYYY`.");
                                }

                                const MONTHS_BD = ['January','February','March','April','May','June','July','August','September','October','November','December'];

                                const upcomingEmbed = new EmbedBuilder()
                                    .setColor("#FFC0CB")
                                    .setTitle("🎂 Server Birthdays")
                                    .setThumbnail("https://i.imgur.com/1XXtUx0.gif");

                                const lines = [];
                                for (const birthday of allBirthdays.slice(0, 25)) {
                                    try {
                                        const member = await message.guild.members.fetch(birthday.userId).catch(() => null);
                                        const displayName = member ? member.displayName : `<@${birthday.userId}>`;
                                        const dateStr = `${MONTHS_BD[birthday.month - 1]} ${birthday.day}${birthday.year ? ` ${birthday.year}` : ''}`;
                                        const countdown = birthday.daysUntil === 0 ? '🎉 Today!' : birthday.daysUntil === 1 ? 'Tomorrow' : `in ${birthday.daysUntil} days`;
                                        lines.push(`**${displayName}** — ${dateStr} *(${countdown})*`);
                                    } catch (err) {
                                        console.error(`Error fetching member ${birthday.userId}:`, err);
                                    }
                                }

                                upcomingEmbed
                                    .setDescription(lines.join('\n'))
                                    .setFooter({ text: `${allBirthdays.length} birthday${allBirthdays.length !== 1 ? 's' : ''} registered` })
                                    .setTimestamp();

                                return message.reply({ embeds: [upcomingEmbed] });
                            }
                                
                            case "check":
                                // Get the target user
                                let targetUser = message.author;
                                let targetMember = message.member;
                                
                                if (message.mentions.users.size > 0) {
                                    targetUser = message.mentions.users.first();
                                    targetMember = message.mentions.members.first();
                                }
                                
                                // Get the birthday
                                const birthday = client.birthdayManager.getBirthday(message.guild.id, targetUser.id);
                                
                                if (!birthday) {
                                    return message.reply(targetUser.id === message.author.id ? 
                                        "You don't have a birthday set! Set it with `" + prefix + "birthday set MM/DD/YYYY`." :
                                        `${targetMember.displayName} doesn't have a birthday set!`
                                    );
                                }
                                
                                // Format the date for display
                                const checkedFormattedDate = client.birthdayManager.formatDate(birthday.month, birthday.day);
                                const checkedYearText = birthday.year ? `, ${birthday.year}` : "";
                                
                                // Calculate days until next birthday
                                const today = new Date();
                                const birthdayThisYear = new Date(today.getFullYear(), birthday.month - 1, birthday.day);
                                const birthdayNextYear = new Date(today.getFullYear() + 1, birthday.month - 1, birthday.day);
                                
                                let daysUntil;
                                if (birthdayThisYear < today) {
                                    daysUntil = Math.ceil((birthdayNextYear - today) / (1000 * 60 * 60 * 24));
                                } else {
                                    daysUntil = Math.ceil((birthdayThisYear - today) / (1000 * 60 * 60 * 24));
                                }
                                
                                const daysText = daysUntil === 0 ? "Today!" : daysUntil === 1 ? "Tomorrow!" : `In ${daysUntil} days`;
                                
                                // Create embed
                                const checkEmbed = new EmbedBuilder()
                                    .setColor("#FFC0CB") // Pink
                                    .setTitle(`🎂 ${targetMember.displayName}'s Birthday`)
                                    .setDescription(`**${checkedFormattedDate}${checkedYearText}**\nComing up: ${daysText}`)
                                    .setThumbnail(targetUser.displayAvatarURL({ dynamic: true }));
                                
                                return message.reply({ embeds: [checkEmbed] });
                                
                            case "channel":
                                // Check permissions
                                if (!message.member.permissions.has("ManageGuild")) {
                                    return message.reply("You need the Manage Server permission to set the birthday channel!");
                                }
                                
                                if (args.length < 2) {
                                    const guildConfig = client.birthdayManager.getGuildConfig(message.guild.id);
                                    
                                    const currentChannel = guildConfig.announcementChannel ? 
                                        `<#${guildConfig.announcementChannel}>` : "None";
                                    
                                    return message.reply(`Current birthday announcement channel: ${currentChannel}\n\nUse \`${prefix}${commandName} channel #channel\` to change it.`);
                                }
                                
                                // Parse the channel
                                const channelMention = args[1];
                                const channelId = channelMention.replace(/[<#>]/g, "");
                                
                                // Verify the channel exists
                                const channel = await message.guild.channels.fetch(channelId).catch(() => null);
                                
                                if (!channel) {
                                    return message.reply("Invalid channel! Please mention a valid channel.");
                                }
                                
                                // Set the channel
                                client.birthdayManager.setAnnouncementChannel(message.guild.id, channelId);
                                
                                const channelEmbed = new EmbedBuilder()
                                    .setColor(config.colors.success)
                                    .setDescription(`✅ Birthday announcements will now be sent to ${channel}.`);
                                
                                return message.reply({ embeds: [channelEmbed] });
                                
                            case "role":
                                // Check permissions
                                if (!message.member.permissions.has("ManageGuild")) {
                                    return message.reply("You need the Manage Server permission to set the birthday role!");
                                }
                                
                                if (args.length < 2) {
                                    const guildConfig = client.birthdayManager.getGuildConfig(message.guild.id);
                                    
                                    const currentRole = guildConfig.role ? 
                                        `<@&${guildConfig.role}>` : "None";
                                    
                                    return message.reply(`Current birthday role: ${currentRole}\n\nUse \`${prefix}${commandName} role @role\` to change it.`);
                                }
                                
                                // Parse the role
                                const roleMention = args[1];
                                const roleId = roleMention.replace(/[<@&>]/g, "");
                                
                                // Verify the role exists
                                const role = await message.guild.roles.fetch(roleId).catch(() => null);
                                
                                if (!role) {
                                    return message.reply("Invalid role! Please mention a valid role.");
                                }
                                
                                // Set the role
                                client.birthdayManager.setBirthdayRole(message.guild.id, roleId);
                                
                                const roleEmbed = new EmbedBuilder()
                                    .setColor(config.colors.success)
                                    .setDescription(`✅ The ${role} role will now be given to members on their birthday.`);
                                
                                return message.reply({ embeds: [roleEmbed] });
                                
                            default:
                                return message.reply(`Unknown subcommand. Use \`${prefix}${commandName}\` to see all available commands.`);
                        }
                        
                    } catch (error) {
                        console.error("Error with birthday command:", error);
                        return message.reply(error.message || "There was an error processing your request! Please try again later.");
                    }
                    break;
                
                case "thelp":
                    // Show ticket command help
                    const ticketHelpEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("🎫 Ticket System Commands")
                        .setDescription("Here are all available ticket commands:")
                        .addFields(
                            { name: `${prefix}ticket [channel] (role-mentions)`, value: "Creates a ticket panel in the specified channel with optional support roles" },
                            { name: `${prefix}tcreate [channel-id] [ticket-name]`, value: "Creates a ticket with a custom name in a specific channel" },
                            { name: `${prefix}thistory (page)`, value: "Shows ticket history with pagination (requires Manage Server permission)" }
                        )
                        .addFields({
                            name: "Examples",
                            value:
                                `\`${prefix}ticket #support\` - Creates a ticket panel in #support channel\n` +
                                `\`${prefix}ticket #help @Moderator @Admin\` - Creates a panel with specified support roles\n` +
                                `\`${prefix}tcreate 123456789012345678 billing\` - Creates a ticket named "billing"\n` +
                                `\`${prefix}thistory 2\` - Shows page 2 of the ticket history`
                        })
                        .setFooter({
                            text: `Version: ${config.version}`,
                            iconURL: client.user.displayAvatarURL()
                        });
                    
                    return message.reply({ embeds: [ticketHelpEmbed] });
                    
                case "ticket":
                    // Check permissions
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply(
                            "You need the Manage Server permission to create ticket panels!",
                        );
                    }

                    // Validate arguments
                    if (args.length < 1) {
                        return message.reply({ embeds: [ticketHelpEmbed] });
                    }

                    // Parse arguments
                    const ticketChannelMention = args[0];
                    const ticketChannelId = ticketChannelMention.replace(/[<#>]/g, "");

                    // Parse support roles
                    const ticketSupportRoles = [];
                    for (let i = 1; i < args.length; i++) {
                        const roleMention = args[i];
                        const roleId = roleMention.replace(/[<@&>]/g, "");
                        ticketSupportRoles.push(roleId);
                    }

                    // Create ticket panel
                    try {
                        await client.ticketManager.sendTicketEmbed({
                            channelId: ticketChannelId,
                            title: "Support Tickets",
                            description:
                                "Need help? Click the button below to create a support ticket!",
                            buttonText: "Create Ticket",
                            supportRoles: ticketSupportRoles,
                        });

                        // Send confirmation
                        const confirmEmbed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription(
                                `✅ Ticket panel created successfully in <#${ticketChannelId}>!`,
                            );

                        return message.reply({ embeds: [confirmEmbed] });
                    } catch (error) {
                        console.error("Error creating ticket panel:", error);
                        return message.reply(
                            "There was an error creating the ticket panel! Make sure the channel exists and I have permissions to send messages there.",
                        );
                    }
                    break;
                
                case "tcreate":
                    // Validate arguments
                    if (args.length < 2) {
                        const usageEmbed = new EmbedBuilder()
                            .setColor(config.colors.error)
                            .setTitle("Invalid Usage")
                            .setDescription(
                                `**Correct Usage:** \`${prefix}${commandName} [channel-id] [ticket-name]\``,
                            )
                            .addFields({
                                name: "Examples",
                                value:
                                    `\`${prefix}${commandName} 123456789012345678 billing\` - Creates a ticket named "billing" in the specified channel\n` +
                                    `\`${prefix}${commandName} 123456789012345678 technical-support\` - Creates a ticket for technical support`,
                            });
                        return message.reply({ embeds: [usageEmbed] });
                    }

                    try {
                        // Get channel ID and ticket name
                        const panelChannelId = args[0];
                        const ticketName = args.slice(1).join("-").toLowerCase().replace(/[^a-z0-9-]/g, "");
                        
                        if (!ticketName) {
                            return message.reply("Please provide a valid ticket name using only letters, numbers, and hyphens.");
                        }
                        
                        // Create a mock interaction object
                        const mockInteraction = {
                            deferReply: async () => {},
                            editReply: async (options) => message.reply(options),
                            user: message.author,
                            member: message.member,
                            channelId: panelChannelId
                        };
                        
                        // Create the ticket with custom name
                        await client.ticketManager.handleTicketCreation(mockInteraction, ticketName);
                        
                    } catch (error) {
                        console.error("Error creating custom ticket:", error);
                        return message.reply("There was an error creating your ticket. Please try again later.");
                    }
                    break;

                case "createt":
                    // Alias for tcreate command
                    return message.reply(`This command has been renamed to \`${prefix}tcreate\`. Please use that instead.`);
                    break;

                case "thistory":
                    // Check permissions
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply(
                            "You need the Manage Server permission to view ticket history!",
                        );
                    }

                    // Get ticket history
                    const history = client.ticketManager.getTicketHistory();

                    if (history.length === 0) {
                        return message.reply("No ticket history found.");
                    }

                    // Create pages of 10 tickets each
                    const ticketPage = args[0] ? parseInt(args[0]) : 1;
                    const ticketPageSize = 10;
                    const ticketTotalPages = Math.ceil(history.length / ticketPageSize);
                    const ticketStartIndex = (ticketPage - 1) * ticketPageSize;
                    const ticketEndIndex = ticketStartIndex + ticketPageSize;
                    const pageHistory = history.slice(ticketStartIndex, ticketEndIndex);

                    // Create embed
                    const historyEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("Ticket History")
                        .setDescription(
                            `Showing ${pageHistory.length} of ${history.length} tickets. Page ${ticketPage}/${ticketTotalPages}`,
                        )
                        .setFooter({
                            text: `Use ${prefix}thistory [page] to view different pages`,
                        });

                    // Add ticket info
                    pageHistory.forEach((ticket, index) => {
                        const createdAt = new Date(
                            ticket.createdAt,
                        ).toLocaleString();
                        const closedAt = new Date(
                            ticket.closedAt,
                        ).toLocaleString();

                        historyEmbed.addFields({
                            name: `#${ticketStartIndex + index + 1} - ${ticket.threadName}`,
                            value:
                                `Created by: ${ticket.userName} on ${createdAt}\n` +
                                `Closed by: ${ticket.closedByName} on ${closedAt}`,
                        });
                    });

                    return message.reply({ embeds: [historyEmbed] });

                case "tictactoe":
                case "tictactoi": // Alternate spelling as requested
                    try {
                        // Start a new TicTacToe game
                        await client.ticTacToeManager.startGame({
                            channelId: message.channel.id,
                            playerId: message.author.id,
                        });

                        // Success message is sent by the manager
                    } catch (error) {
                        console.error("Error starting TicTacToe game:", error);
                        return message.reply(
                            error.message ||
                                "There was an error starting the game! Please try again later.",
                        );
                    }
                    break;

                case "move":
                    try {
                        // Validate arguments
                        if (args.length < 1) {
                            return message.reply(
                                `**Correct Usage:** \`${prefix}${commandName} [position 1-9]\``,
                            );
                        }

                        // Parse position
                        const position = parseInt(args[0]);

                        // Make the move
                        await client.ticTacToeManager.makeMove({
                            channelId: message.channel.id,
                            playerId: message.author.id,
                            position: position,
                        });

                        // Success message is sent by the manager
                    } catch (error) {
                        console.error("Error making TicTacToe move:", error);
                        return message.reply(
                            error.message ||
                                "There was an error making the move! Please try again later.",
                        );
                    }
                    break;

                case "tend":
                    try {
                        // Check if there's a TicTacToe game in this channel
                        const game = client.ticTacToeManager.getGame(
                            message.channel.id,
                        );

                        if (!game) {
                            return message.reply(
                                "There is no TicTacToe game in progress in this channel.",
                            );
                        }

                        // Only allow the game starter or a user with manage messages permission to end the game
                        if (
                            game.startedBy !== message.author.id &&
                            !message.member.permissions.has("ManageMessages")
                        ) {
                            return message.reply(
                                "Only the game starter or a moderator can end the game.",
                            );
                        }

                        // End the game
                        await client.ticTacToeManager.endGame(
                            message.channel.id,
                        );

                        // Success message is sent by the manager
                    } catch (error) {
                        console.error("Error ending TicTacToe game:", error);
                        return message.reply(
                            error.message ||
                                "There was an error ending the game! Please try again later.",
                        );
                    }
                    break;

                case "ab":
                    // Create bot description embed
                    const aboutEmbedAb = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("About this Bot")
                        .setDescription(
                            "AFK Devs Bot is a feature-rich Discord bot designed to enhance server management and user engagement.",
                        )
                        .addFields(
                            {
                                name: "Giveaway System",
                                value: "Create and manage giveaways with customizable duration, prizes, and winners.",
                            },
                            {
                                name: "Welcome System",
                                value: "Greet new members with customizable welcome messages and details.",
                            },
                            {
                                name: "Ticket System",
                                value: "Handle support requests through a ticket system with private threads.",
                            },
                            {
                                name: "Poll System",
                                value: "Create timed polls with multiple options and automated results.",
                            },
                            {
                                name: "TicTacToe Game",
                                value: "Play multiplayer TicTacToe games in your server channels.",
                            },
                            {
                                name: "Utility Commands",
                                value: "Various utility commands to enhance server management.",
                            },
                        )
                        .setTimestamp()
                        .setFooter({
                            text: `Bot Version: ${config.version}`,
                            iconURL: client.user.displayAvatarURL(),
                        });

                    return message.reply({ embeds: [aboutEmbedAb] });

                case "ulog":
                    // Create update log embed
                    const updateEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("Update Log | Updated on 20/04/2025")
                        .setDescription(
                            "Keep track of the latest updates and upcoming features!",
                        )
                        .addFields(
                            {
                                name: "✅ Recent Updates",
                                value:
                                    
   "•   Added slash commands of all available commands.\n" +              
                                   "• Added Birthday celebration system\n" +
                                    "• Added Poll system \n" +
                                    "• Added Multiplayer TicTacToe game\n" +
                                    "• Added ticket system for support requests\n" +
                                    "• Added echo command for fun interactions",
                            },{ name: '🔜 Coming Soon', value: 
                                '• Games.\n' 
                               
                                  
                            },
                        )
                        .setTimestamp()
                        .setFooter({
                            text: `Version: ${config.version}`,
                            iconURL: client.user.displayAvatarURL(),
                        });

                    return message.reply({ embeds: [updateEmbed] });
                    
                case "broadcast": {
                    const broadcastSubCommand = (args[0] || "").toLowerCase();

                    // Server-admin controlled settings: $broadcast enable / disable / channel
                    if (["enable", "disable", "channel"].includes(broadcastSubCommand)) {
                        if (!message.guild) {
                            return message.reply("This command can only be used in a server.");
                        }

                        if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                            return message.reply("You need the Manage Server permission to configure broadcast settings.");
                        }

                        const settingsManager = client.serverSettingsManager;

                        if (broadcastSubCommand === "enable" || broadcastSubCommand === "disable") {
                            const enable = broadcastSubCommand === "enable";
                            const currentSettings = settingsManager.getGuildSettings(message.guild.id);

                            if (currentSettings.receiveBroadcasts === enable) {
                                return message.reply(`Developer broadcasts are already ${enable ? "enabled" : "disabled"} for this server.`);
                            }

                            settingsManager.toggleBroadcastReception(message.guild.id);

                            const broadcastToggleEmbed = new EmbedBuilder()
                                .setColor(enable ? config.colors.success : config.colors.error)
                                .setTitle("Broadcast Settings Updated")
                                .setDescription(
                                    enable
                                        ? "✅ This server will now receive developer broadcasts."
                                        : "🔕 This server has opted out of developer broadcasts."
                                )
                                .setFooter({ text: `Server ID: ${message.guild.id} • Version ${config.version}` })
                                .setTimestamp();

                            return message.reply({ embeds: [broadcastToggleEmbed] });
                        }

                        if (broadcastSubCommand === "channel") {
                            const broadcastChannel = message.mentions.channels.first();

                            if (!broadcastChannel) {
                                return message.reply(`Please specify a channel: \`${prefix}broadcast channel #channel\``);
                            }

                            settingsManager.setBroadcastChannel(message.guild.id, broadcastChannel.id);

                            const broadcastChannelEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setTitle("✅ Broadcast Channel Updated")
                                .setDescription(`Developer broadcasts will now be sent to ${broadcastChannel}.`)
                                .setFooter({ text: `Server ID: ${message.guild.id} • Version ${config.version}` })
                                .setTimestamp();

                            return message.reply({ embeds: [broadcastChannelEmbed] });
                        }
                    }

                    // Check if user is a developer
                    if (!config.developerIds.includes(message.author.id)) {
                        // Silently ignore - this command is hidden from non-developers
                        return;
                    }

                    // ── BROADCAST FORM WIZARD ──────────────────────────────────────────
                    // $broadcast with no extra args opens a step-by-step form.
                    // Any extra args are treated as a legacy inline message (kept for
                    // backwards compat) but the form is the new recommended path.

                    const collectorFilter = m => m.author.id === message.author.id;
                    const STEP_TIMEOUT = 60_000; // 60 s per step

                    // Helper: ask one question and wait for a reply
                    async function askStep(promptEmbed) {
                        const prompt = await message.channel.send({ embeds: [promptEmbed] });
                        try {
                            const collected = await message.channel.awaitMessages({
                                filter: collectorFilter,
                                max: 1,
                                time: STEP_TIMEOUT,
                                errors: ['time']
                            });
                            return { response: collected.first(), prompt };
                        } catch {
                            await prompt.edit({ embeds: [
                                new EmbedBuilder()
                                    .setColor(config.colors.error)
                                    .setDescription('⏰ Form timed out. Run `$broadcast` again to restart.')
                            ]});
                            return { response: null, prompt };
                        }
                    }

                    // ── STEP 1: Title ──────────────────────────────────────────────────
                    const titlePrompt = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('📣 Broadcast Form — Step 1 of 4')
                        .setDescription('**What should the title be?**\nType your title and send it, or type `skip` to use the default.')
                        .setFooter({ text: 'Type "cancel" at any time to abort.' });

                    const { response: titleRes, prompt: titleMsg } = await askStep(titlePrompt);
                    if (!titleRes) break;
                    if (titleRes.content.toLowerCase() === 'cancel') {
                        await titleMsg.edit({ embeds: [new EmbedBuilder().setColor(config.colors.error).setDescription('❌ Broadcast cancelled.')] });
                        break;
                    }
                    const bcTitle = titleRes.content.toLowerCase() === 'skip'
                        ? '📣 Announcement from Developers'
                        : titleRes.content;

                    // ── STEP 2: Message ────────────────────────────────────────────────
                    const msgPrompt = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('📣 Broadcast Form — Step 2 of 4')
                        .setDescription('**What is the broadcast message?**\nType your full announcement and send it.')
                        .setFooter({ text: 'Type "cancel" to abort.' });

                    const { response: msgRes } = await askStep(msgPrompt);
                    if (!msgRes) break;
                    if (msgRes.content.toLowerCase() === 'cancel') {
                        await message.channel.send({ embeds: [new EmbedBuilder().setColor(config.colors.error).setDescription('❌ Broadcast cancelled.')] });
                        break;
                    }
                    const bcMessage = msgRes.content;

                    // ── STEP 3: Image URL ──────────────────────────────────────────────
                    const imgPrompt = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('📣 Broadcast Form — Step 3 of 4')
                        .setDescription('**Image URL?**\nSend a direct image URL (`.jpg`, `.png`, `.gif`) to attach an image, or type `skip` to send without one.')
                        .setFooter({ text: 'Type "cancel" to abort.' });

                    const { response: imgRes } = await askStep(imgPrompt);
                    if (!imgRes) break;
                    if (imgRes.content.toLowerCase() === 'cancel') {
                        await message.channel.send({ embeds: [new EmbedBuilder().setColor(config.colors.error).setDescription('❌ Broadcast cancelled.')] });
                        break;
                    }
                    const bcImage = imgRes.content.toLowerCase() === 'skip' ? null : imgRes.content;

                    // ── STEP 4: Color ──────────────────────────────────────────────────
                    const colorPrompt = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('📣 Broadcast Form — Step 4 of 4')
                        .setDescription('**Embed color?**\nReply with one of: `red`, `green`, `blue`, `yellow`, `purple`, `orange`, `default`\nOr type a hex code like `#FF5733`. Type `skip` for the default bot color.')
                        .setFooter({ text: 'Type "cancel" to abort.' });

                    const { response: colorRes } = await askStep(colorPrompt);
                    if (!colorRes) break;
                    if (colorRes.content.toLowerCase() === 'cancel') {
                        await message.channel.send({ embeds: [new EmbedBuilder().setColor(config.colors.error).setDescription('❌ Broadcast cancelled.')] });
                        break;
                    }

                    const colorMap = {
                        red: '#FF0000', green: '#00FF00', blue: '#0000FF',
                        yellow: '#FFFF00', purple: '#800080', orange: '#FFA500',
                        default: config.colors.primary, skip: config.colors.primary
                    };
                    const colorInput = colorRes.content.toLowerCase();
                    const bcColor = colorMap[colorInput] || (colorRes.content.match(/^#[0-9A-Fa-f]{6}$/) ? colorRes.content : config.colors.primary);

                    // ── BUILD PREVIEW EMBED ────────────────────────────────────────────
                    const totalServersBC = client.guilds.cache.size;
                    const receptiveServersBC = client.serverSettingsManager.getBroadcastReceptionCount
                        ? client.serverSettingsManager.getBroadcastReceptionCount()
                        : totalServersBC;
                    const optedOutCountBC = totalServersBC - receptiveServersBC;

                    const broadcastEmbed = new EmbedBuilder()
                        .setColor(bcColor)
                        .setTitle(bcTitle)
                        .setDescription(bcMessage)
                        .addFields({
                            name: "⚙️ Manage This Server's Broadcasts",
                            value: `Use \`${prefix}broadcast enable\` / \`${prefix}broadcast disable\` to control broadcast. Use \`${prefix}broadcast channel\` to set the channel.`,
                            inline: false
                        })
                        .setTimestamp()
                        .setFooter({
                            text: `Version: ${config.version}`,
                            iconURL: client.user.displayAvatarURL()
                        });

                    if (bcImage) broadcastEmbed.setImage(bcImage);

                    const previewInfoEmbed = new EmbedBuilder()
                        .setColor(config.colors.warning)
                        .setTitle('📋 Broadcast Preview')
                        .setDescription('Review your broadcast below. Click **Send** to deliver it or **Cancel** to abort.')
                        .addFields(
                            { name: '📊 Reach', value: `${receptiveServersBC} servers receiving · ${optedOutCountBC} opted out`, inline: false },
                            { name: '⏱️ Est. Time', value: `~${Math.ceil(receptiveServersBC * 0.5)}s`, inline: true }
                        )
                        .setTimestamp();

                    const sendBtn = new ButtonBuilder()
                        .setCustomId('bc_send')
                        .setLabel('Send Broadcast')
                        .setStyle(ButtonStyle.Success);
                    const cancelBtn = new ButtonBuilder()
                        .setCustomId('bc_cancel')
                        .setLabel('Cancel')
                        .setStyle(ButtonStyle.Danger);
                    const bcRow = new ActionRowBuilder().addComponents(sendBtn, cancelBtn);

                    const previewMsg = await message.channel.send({
                        embeds: [previewInfoEmbed, broadcastEmbed],
                        components: [bcRow]
                    });

                    // ── WAIT FOR CONFIRM / CANCEL ──────────────────────────────────────
                    let confirmed = false;
                    try {
                        const btnInteraction = await previewMsg.awaitMessageComponent({
                            filter: i => i.user.id === message.author.id && ['bc_send', 'bc_cancel'].includes(i.customId),
                            time: 120_000
                        });
                        confirmed = btnInteraction.customId === 'bc_send';
                        await btnInteraction.deferUpdate();
                    } catch {
                        // timed out
                    }

                    await previewMsg.edit({ components: [] });

                    if (!confirmed) {
                        await previewMsg.edit({ embeds: [
                            new EmbedBuilder().setColor(config.colors.error).setDescription('❌ Broadcast cancelled.')
                        ], components: [] });
                        break;
                    }

                    // ── SEND BROADCAST ─────────────────────────────────────────────────
                    console.log(`[BROADCAST] Form-wizard broadcast by ${message.author.tag}`);

                    const confirmationEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setDescription('📣 Broadcasting message to all servers...');

                    const progressMsg = await message.channel.send({ embeds: [confirmationEmbed] });

                    let successCount = 0;
                    let failCount = 0;
                    let skippedOptOut = 0;
                    let processedCount = 0;
                    const totalGuilds = client.guilds.cache.size;

                    for (const guild of client.guilds.cache.values()) {
                        try {
                            processedCount++;

                            if (!client.serverSettingsManager.receivesBroadcasts(guild.id)) {
                                skippedOptOut++;
                                continue;
                            }

                            const customChannelId = client.serverSettingsManager.getBroadcastChannel(guild.id);
                            let channel = customChannelId ? guild.channels.cache.get(customChannelId) : null;

                            if (!channel || channel.type !== 0) {
                                channel = guild.channels.cache
                                    .filter(ch => ch.type === 0)
                                    .sort((a, b) => a.position - b.position)
                                    .first();
                            }

                            if (!channel) { failCount++; continue; }

                            if (channel.permissionsFor(guild.members.me).has('SendMessages')) {
                                await channel.send({ embeds: [broadcastEmbed] });
                                successCount++;
                            } else {
                                failCount++;
                            }

                            // Update progress every 5 guilds
                            if (processedCount % 5 === 0 || processedCount === totalGuilds) {
                                const pct = Math.round((processedCount / totalGuilds) * 100);
                                const bar = '█'.repeat(Math.round(pct / 5)) + '░'.repeat(20 - Math.round(pct / 5));
                                await progressMsg.edit({ embeds: [
                                    new EmbedBuilder()
                                        .setColor(config.colors.primary)
                                        .setDescription(`📣 Broadcasting...\n\`[${bar}]\` ${pct}%\n✅ ${successCount} · ❌ ${failCount} · 🔕 ${skippedOptOut}`)
                                ]}).catch(() => {});
                            }

                        } catch (err) {
                            console.error(`[BROADCAST] Error in guild ${guild.name}:`, err);
                            failCount++;
                        }
                    }

                    const reportEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle('📣 Broadcast Complete')
                        .setDescription(`Delivered to **${successCount}** servers.`)
                        .addFields(
                            { name: '✅ Success', value: `${successCount}`, inline: true },
                            { name: '❌ Failed', value: `${failCount}`, inline: true },
                            { name: '🔕 Opted Out', value: `${skippedOptOut}`, inline: true },
                            { name: '📊 Total', value: `${totalGuilds}`, inline: true }
                        )
                        .setTimestamp()
                        .setFooter({ text: `Broadcast ID: ${Date.now().toString(36)}` });

                    await progressMsg.edit({ embeds: [reportEmbed] });
                    break;
                }
                
                case "cstart":
                    // Check permissions
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply("You need the Manage Server permission to start a counting game!");
                    }

                    // Parse arguments
                    let startNumber = 1;
                    let goalNumber = 100;

                    if (args.length >= 1) {
                        startNumber = parseInt(args[0]);
                        if (isNaN(startNumber)) {
                            return message.reply("Start number must be a valid integer.");
                        }
                    }

                    if (args.length >= 2) {
                        goalNumber = parseInt(args[1]);
                        if (isNaN(goalNumber)) {
                            return message.reply("Goal number must be a valid integer.");
                        }
                    }

                    // Start the counting game
                    try {
                        const game = await client.countingManager.startCountingGame(
                            message.channel.id, startNumber, goalNumber
                        );
                        const startEmbed = client.countingManager.createCountingEmbed(game);
                        await message.reply({ embeds: [startEmbed] });
                    } catch (error) {
                        console.error("Error starting counting game:", error);
                        return message.reply(error.message || "There was an error starting the counting game! Please try again later.");
                    }
                    break;
                    
                case "cstatus":
                    // Get current counting status
                    const countStatus = client.countingManager.getCountingStatus(message.channel.id);
                    
                    if (!countStatus) {
                        return message.reply("There is no active counting game in this channel. Start one with `$cstart`!");
                    }
                    
                    // Create status embed
                    const statusEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("Counting Game Status")
                        .addFields(
                            { name: "Current Number", value: `${countStatus.currentNumber}`, inline: true },
                            { name: "Next Number", value: `${countStatus.currentNumber + 1}`, inline: true },
                            { name: "Goal", value: `${countStatus.goalNumber}`, inline: true },
                            { name: "Progress", value: `${Math.floor((countStatus.currentNumber / countStatus.goalNumber) * 100)}%`, inline: true },
                            { name: "Highest Reached", value: `${countStatus.highestNumber}`, inline: true },
                            { name: "Fail Count", value: `${countStatus.failCount}`, inline: true }
                        );
                        
                    // Send status embed
                    return message.reply({ embeds: [statusEmbed] });
                    
                case "cend":
                    // Check permissions
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply("You need the Manage Server permission to end a counting game!");
                    }
                    
                    // End the counting game — must await since endCountingGame is async
                    // (without await, ended is always a Promise object which is truthy,
                    //  so the success branch fires even when no game exists).
                    {
                        const ended = await client.countingManager.endCountingGame(message.channel.id);
                        
                        if (ended) {
                            const endEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setDescription("✅ Counting game ended successfully!");
                                
                            return message.reply({ embeds: [endEmbed] });
                        } else {
                            return message.reply("There is no active counting game in this channel.");
                        }
                    }
                    
                case "chelp":
                    // Send counting help embed
                    const helpEmbed = client.countingManager.createHelpEmbed();
                    return message.reply({ embeds: [helpEmbed] });
                    
                case "truthdare":
                    // Start a truth or dare game
                    try {
                        await client.truthDareManager.startGame(message.channel);
                        // Message is sent within startGame
                    } catch (error) {
                        console.error("Error starting Truth or Dare game:", error);
                        return message.reply("There was an error starting the Truth or Dare game! Please try again later.");
                    }
                    break;
                    
                case "qadd":
                    // Validate arguments
                    if (args.length < 2) {
                        return message.reply(`**Correct Usage:** \`${prefix}${commandName} [truth/dare] [your question]\``);
                    }
                    
                    const type = args[0].toLowerCase();
                    if (type !== "truth" && type !== "dare") {
                        return message.reply("Type must be either 'truth' or 'dare'.");
                    }
                    
                    const questionText = args.slice(1).join(" ");
                    
                    // Add the question
                    const added = client.truthDareManager.addQuestion(type, questionText);
                    
                    if (added) {
                        const addEmbed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription(`✅ ${type.charAt(0).toUpperCase() + type.slice(1)} question added successfully!`);
                            
                        return message.reply({ embeds: [addEmbed] });
                    } else {
                        return message.reply("This question already exists or is invalid.");
                    }
                    break;
                    
                // Leveling System Commands
                case "leaderboard":
                case "levels":
                case "lb":
                    // Check if leveling is enabled for this server
                    const lbServerSettings = client.serverSettingsManager.getGuildSettings(message.guild.id);
                    if (!lbServerSettings.leveling?.enabled) {
                        message.reply("The leveling system is not enabled in this server. Server administrators can enable it with `/leveling settings setting:enable`.");
                        return;
                    }
                    
                    // Get page number if provided
                    let leaderboardPage = 1;
                    if (args.length > 0) {
                        const requestedPage = parseInt(args[0]);
                        if (!isNaN(requestedPage) && requestedPage > 0) {
                            leaderboardPage = requestedPage;
                        }
                    }
                    
                    // Show a loading message since leaderboard generation can take time
                    const loadingLbMessage = await message.reply("Loading leaderboard data...");
                    
                    // Get the leaderboard embed
                    const leaderboardData = await client.levelingManager.createLeaderboardEmbed(
                        message.guild.id, 
                        leaderboardPage
                    );
                    
                    // Check if there's leaderboard data
                    if (!leaderboardData || !leaderboardData.embed) {
                        loadingLbMessage.edit("No one has earned XP in this server yet.");
                        return;
                    }
                    
                    // Send the message and delete loading message
                    loadingLbMessage.edit({ 
                        content: ' ',
                        embeds: [leaderboardData.embed],
                        components: leaderboardData.maxPage > 1 ? [
                            new ActionRowBuilder().addComponents(
                                new ButtonBuilder()
                                    .setCustomId('lb_prev_page')
                                    .setLabel('Previous')
                                    .setStyle(ButtonStyle.Secondary)
                                    .setDisabled(leaderboardData.currentPage <= 1),
                                new ButtonBuilder()
                                    .setCustomId('lb_next_page')
                                    .setLabel('Next')
                                    .setStyle(ButtonStyle.Secondary)
                                    .setDisabled(leaderboardData.currentPage >= leaderboardData.maxPage)
                            )
                        ] : []
                    });
                    
                    // Handle pagination if there are multiple pages
                    if (leaderboardData.maxPage > 1) {
                        const filter = i => 
                            (i.customId === 'lb_prev_page' || i.customId === 'lb_next_page') && 
                            i.user.id === message.author.id;
                            
                        const collector = leaderboardReply.createMessageComponentCollector({ 
                            filter, 
                            time: 300000 // 5 minutes
                        });
                        
                        // Track current page
                        let currentPage = leaderboardData.currentPage;
                        
                        collector.on('collect', async interaction => {
                            try {
                                // Calculate new page
                                if (interaction.customId === 'lb_prev_page') {
                                    currentPage = Math.max(1, currentPage - 1);
                                } else {
                                    currentPage = Math.min(leaderboardData.maxPage, currentPage + 1);
                                }
                                
                                // Get updated leaderboard
                                const newLeaderboardData = await client.levelingManager.createLeaderboardEmbed(
                                    message.guild.id, 
                                    currentPage
                                );
                                
                                // Update message with error handling
                                if (!interaction.replied && !interaction.deferred) {
                                    await interaction.update({
                                        embeds: [newLeaderboardData.embed],
                                        components: newLeaderboardData.maxPage > 1 ? [
                                            new ActionRowBuilder().addComponents(
                                                new ButtonBuilder()
                                                    .setCustomId('lb_prev_page')
                                                    .setLabel('Previous')
                                                    .setStyle(ButtonStyle.Secondary)
                                                    .setDisabled(currentPage <= 1),
                                                new ButtonBuilder()
                                                    .setCustomId('lb_next_page')
                                                    .setLabel('Next')
                                                    .setStyle(ButtonStyle.Secondary)
                                                    .setDisabled(currentPage >= newLeaderboardData.maxPage)
                                            )
                                        ] : []
                                    });
                                }
                            } catch (paginationError) {
                                console.error('Error updating leaderboard pagination:', paginationError);
                                // Try to edit the original message as a fallback
                                try {
                                    // Create fallback leaderboard
                                    const fallbackLeaderboardData = await client.levelingManager.createLeaderboardEmbed(
                                        message.guild.id, 
                                        currentPage
                                    );
                                    
                                    await reply.edit({
                                        embeds: [fallbackLeaderboardData.embed],
                                        components: fallbackLeaderboardData.maxPage > 1 ? [
                                            new ActionRowBuilder().addComponents(
                                                new ButtonBuilder()
                                                    .setCustomId('lb_prev_page')
                                                    .setLabel('Previous')
                                                    .setStyle(ButtonStyle.Secondary)
                                                    .setDisabled(currentPage <= 1),
                                                new ButtonBuilder()
                                                    .setCustomId('lb_next_page')
                                                    .setLabel('Next')
                                                    .setStyle(ButtonStyle.Secondary)
                                                    .setDisabled(currentPage >= fallbackLeaderboardData.maxPage)
                                            )
                                        ] : []
                                    });
                                } catch (fallbackError) {
                                    console.error('Failed to update leaderboard pagination via fallback:', fallbackError);
                                }
                            }
                        });
                        
                        collector.on('end', () => {
                            // Remove components when collector expires
                            leaderboardReply.edit({ components: [] }).catch(console.error);
                        });
                    }
                    break;
                    
                case "rank":
                case "profile":
                case "exp":
                case "level":
                    // Check if leveling is enabled for this server
                    const rankServerSettings = client.serverSettingsManager.getGuildSettings(message.guild.id);
                    if (!rankServerSettings.leveling?.enabled) {
                        message.reply("The leveling system is not enabled in this server. Server administrators can enable it with `/leveling settings setting:enable`.");
                        return;
                    }
                    
                    // Check if user is specified
                    let targetUser = message.author;
                    if (args.length > 0 && message.mentions.users.size > 0) {
                        targetUser = message.mentions.users.first();
                    }
                    
                    // Show a loading message since profile generation can take time
                    const loadingMessage = await message.reply("Loading profile data...");
                    
                    // Get user's profile
                    const profileData = await client.levelingManager.createProfileEmbed(
                        message.guild.id,
                        targetUser.id
                    );
                    
                    if (!profileData) {
                        loadingMessage.edit(`${targetUser.id === message.author.id ? 'You haven\'t' : `${targetUser.username} hasn't`} earned any XP in this server yet.`);
                        return;
                    }
                    
                    // Send the profile and delete loading message
                    loadingMessage.edit({ content: ' ', embeds: [profileData.embed] });
                    break;
                    
                case "set-level":
                case "setlevel":
                    // Only available to developers
                    if (!config.developerIds.includes(message.author.id)) {
                        return; // Silently ignore for non-developers
                    }
                    
                    // Check if leveling is enabled for this server
                    const setLevelServerSettings = client.serverSettingsManager.getGuildSettings(message.guild.id);
                    if (!setLevelServerSettings.leveling?.enabled) {
                        message.reply("The leveling system is not enabled in this server. Server administrators can enable it with `/leveling settings setting:enable`.");
                        return;
                    }
                    
                    // Validate arguments: $set-level @user [level]
                    if (args.length < 2 || message.mentions.users.size === 0) {
                        message.reply("**Usage:** `$set-level @user [level]`");
                        return;
                    }
                    
                    const targetSetUser = message.mentions.users.first();
                    const newLevel = parseInt(args[1]);
                    
                    if (isNaN(newLevel) || newLevel < 0 || newLevel > 100) {
                        message.reply("Level must be a number between 0 and 100.");
                        return;
                    }
                    
                    // Calculate messages needed for this level
                    const messagesNeeded = client.levelingManager.calculateRequiredMessages(newLevel);
                    
                    // Get or create guild data
                    if (!client.levelingManager.userLevels.has(message.guild.id)) {
                        client.levelingManager.userLevels.set(message.guild.id, new Map());
                    }
                    
                    const guildData = client.levelingManager.userLevels.get(message.guild.id);
                    
                    // Get or create user data
                    if (!guildData.has(targetSetUser.id)) {
                        guildData.set(targetSetUser.id, {
                            xp: 0,
                            level: 0,
                            messages: 0,
                            lastMessage: Date.now(),
                            badges: []
                        });
                    }
                    
                    const userData = guildData.get(targetSetUser.id);
                    
                    // Store the old level for badge check
                    const oldLevel = userData.level;
                    
                    // Update user data
                    userData.level = newLevel;
                    userData.messages = messagesNeeded;
                    userData.xp = newLevel * 100; // Simplified XP calculation
                    
                    // Initialize variables to track badge updates
                    let newBadges = [];
                    
                    // Check for new badges if level increased
                    if (newLevel > oldLevel) {
                        newBadges = client.levelingManager.checkForNewBadges(userData, oldLevel, newLevel);
                        
                        // Log badge updates
                        if (newBadges.length > 0) {
                            console.log(`[LEVELING] User ${targetSetUser.tag} earned ${newBadges.length} new badges from level update`);
                        }
                    }
                    
                    // Save data - critical to ensure changes are persisted
                    client.levelingManager.saveLevels();
                    console.log(`[LEVELING] Saved level data for ${targetSetUser.tag}: Level ${newLevel}, Messages: ${messagesNeeded}, XP: ${userData.xp}`);
                    
                    // Create detailed confirmation embed
                    const setLevelEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("Level Updated")
                        .setDescription(`${targetSetUser}'s level has been set to **Level ${newLevel}**!`)
                        .addFields(
                            { name: "Change", value: `Level ${oldLevel} → **Level ${newLevel}**`, inline: true },
                            { name: "XP", value: `${userData.xp} XP`, inline: true },
                            { name: "Message Count", value: `${messagesNeeded}`, inline: true }
                        )
                        .setThumbnail(targetSetUser.displayAvatarURL({ dynamic: true }))
                        .setTimestamp()
                        .setFooter({
                            text: `Set by ${message.author.tag}`,
                            iconURL: message.author.displayAvatarURL({ dynamic: true })
                        });
                    
                    // Add badge information if new badges were earned
                    if (newBadges.length > 0) {
                        const badgeList = newBadges.map(badge => 
                            `${badge.emoji} **${badge.name}** - ${badge.description}`
                        ).join('\n');
                        
                        setLevelEmbed.addFields({
                            name: '🏅 New Badge' + (newBadges.length > 1 ? 's' : '') + ' Earned!',
                            value: badgeList
                        });
                    }
                    
                    message.reply({ embeds: [setLevelEmbed] });
                    break;
                    
                case "badge":
                case "badges":
                    // Beta gate
                    if (isBetaFeature('badges', null, null, config.betaFeatures) && !(await betaManager.canAccess(message.guild?.id))) {
                        return message.reply({
                            embeds: [new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle('🔬 Beta Feature')
                                .setDescription('The `badges` command is currently in beta and only available to servers enrolled in the beta program.\n\nAsk your server owner to run `$beta enable` if your server has been approved.')
                                .setFooter({ text: `Version: ${config.version}` })
                                .setTimestamp()]
                        });
                    }
                    // Check if leveling is enabled for this server
                    const badgesServerSettings = client.serverSettingsManager.getGuildSettings(message.guild.id);
                    if (!badgesServerSettings.leveling?.enabled) {
                        message.reply("The leveling system is not enabled in this server. Server administrators can enable it with `/leveling settings setting:enable`.");
                        return;
                    }
                    
                    // Get user if specified
                    let badgesUser = message.author;
                    if (args.length > 0 && message.mentions.users.size > 0) {
                        badgesUser = message.mentions.users.first();
                    }
                    
                    // Show loading message
                    const loadingBadgesMessage = await message.reply("Loading badges data...");
                    
                    // Create badges embed
                    const badgesData = await client.levelingManager.createBadgesEmbed(
                        message.guild.id,
                        badgesUser.id
                    );
                    
                    // Check if badges data exists
                    if (!badgesData || !badgesData.embed) {
                        loadingBadgesMessage.edit(`${badgesUser.id === message.author.id ? 'You don\'t' : `${badgesUser.username} doesn't`} have any badges yet.`);
                        return;
                    }
                    
                    // Send the message and delete loading message
                    loadingBadgesMessage.edit({ content: ' ', embeds: [badgesData.embed] });
                    break;
                    
                case "award-badge":
                case "awardbadge":
                case "give-badge":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
                        message.reply("You don't have permission to award badges.");
                        return;
                    }
                    
                    // Check if leveling is enabled for this server
                    const awardBadgeServerSettings = client.serverSettingsManager.getGuildSettings(message.guild.id);
                    if (!awardBadgeServerSettings.leveling?.enabled) {
                        message.reply("The leveling system is not enabled in this server. Server administrators can enable it with `/leveling settings setting:enable`.");
                        return;
                    }
                    
                    // Validate arguments: $award-badge @user [type] [badge_id]
                    if (args.length < 2 || message.mentions.users.size === 0) {
                        const badgeListEmbed = new EmbedBuilder()
                            .setColor(config.colors.primary)
                            .setTitle("🏅 Badge Award System")
                            .setDescription("Award badges to members of the community.")
                            .addFields(
                                { 
                                    name: "Usage", 
                                    value: "`$award-badge @user [type] [badge_id]`\n\n**Types:** `achievement` or `special`" 
                                },
                                {
                                    name: "Achievement Badges",
                                    value: config.leveling.badges.achievementBadges
                                        .map(b => `\`${b.id}\` - ${b.emoji} **${b.name}** - ${b.description}`)
                                        .join('\n')
                                },
                                {
                                    name: "Special Badges",
                                    value: config.leveling.badges.specialBadges
                                        .map(b => `\`${b.id}\` - ${b.emoji} **${b.name}** - ${b.description}`)
                                        .join('\n')
                                }
                            )
                            .setFooter({ 
                                text: "Level badges are automatically awarded based on user levels.", 
                                iconURL: client.user.displayAvatarURL() 
                            });
                            
                        message.reply({ embeds: [badgeListEmbed] });
                        return;
                    }
                    
                    const targetBadgeUser = message.mentions.users.first();
                    const badgeType = args[1].toLowerCase();
                    const badgeId = args[2];
                    
                    // Validate badge type
                    if (badgeType !== 'achievement' && badgeType !== 'special') {
                        message.reply("Invalid badge type. Use `achievement` or `special`.");
                        return;
                    }
                    
                    // Award the badge
                    const awardResult = await client.levelingManager.awardBadge({
                        guildId: message.guild.id,
                        userId: targetBadgeUser.id,
                        badgeType,
                        badgeId
                    });
                    
                    if (awardResult.success) {
                        // Create success embed
                        const successEmbed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setTitle("Badge Awarded!")
                            .setDescription(`${targetBadgeUser} has been awarded the ${awardResult.badge.emoji} **${awardResult.badge.name}** badge!`)
                            .addFields({
                                name: "Badge Details",
                                value: `${awardResult.badge.emoji} **${awardResult.badge.name}** - ${awardResult.badge.description}`
                            })
                            .setThumbnail(targetBadgeUser.displayAvatarURL({ dynamic: true }))
                            .setFooter({ 
                                text: `Awarded by ${message.author.tag}`, 
                                iconURL: message.author.displayAvatarURL({ dynamic: true }) 
                            })
                            .setTimestamp();
                            
                        message.reply({ embeds: [successEmbed] });
                    } else {
                        message.reply(`Error: ${awardResult.message}`);
                    }
                    break;
                    
                case "revoke-badge":
                case "revokebadge":
                case "remove-badge":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
                        message.reply("You don't have permission to revoke badges.");
                        return;
                    }
                    
                    // Check if leveling is enabled for this server
                    const revokeBadgeServerSettings = client.serverSettingsManager.getGuildSettings(message.guild.id);
                    if (!revokeBadgeServerSettings.leveling?.enabled) {
                        message.reply("The leveling system is not enabled in this server. Server administrators can enable it with `/leveling settings setting:enable`.");
                        return;
                    }
                    
                    // Validate arguments: $revoke-badge @user [badge_id]
                    if (args.length < 1 || message.mentions.users.size === 0) {
                        message.reply("**Usage:** `$revoke-badge @user [badge_id]`");
                        return;
                    }
                    
                    const targetRevokeBadgeUser = message.mentions.users.first();
                    const badgeIdToRevoke = args[1];
                    
                    if (!badgeIdToRevoke) {
                        message.reply("You must specify a badge ID to revoke.");
                        return;
                    }
                    
                    // Check if user exists in leveling system
                    if (!client.levelingManager.userLevels.has(message.guild.id) || 
                        !client.levelingManager.userLevels.get(message.guild.id).has(targetRevokeBadgeUser.id)) {
                        message.reply("This user has no badges or is not in the leveling system.");
                        return;
                    }
                    
                    // Get user data
                    const guildBadgeData = client.levelingManager.userLevels.get(message.guild.id);
                    const userBadgeData = guildBadgeData.get(targetRevokeBadgeUser.id);
                    
                    // Find the badge to revoke
                    const badgeIndex = userBadgeData.badges.findIndex(badge => badge.id === badgeIdToRevoke);
                    
                    if (badgeIndex === -1) {
                        message.reply("This user does not have this badge.");
                        return;
                    }
                    
                    // Store badge info before removing
                    const revokedBadge = userBadgeData.badges[badgeIndex];
                    
                    // Remove the badge
                    userBadgeData.badges.splice(badgeIndex, 1);
                    
                    // Save changes
                    client.levelingManager.saveLevels();
                    
                    // Create success embed
                    const revokeEmbed = new EmbedBuilder()
                        .setColor(config.colors.error)
                        .setTitle("Badge Revoked")
                        .setDescription(`${targetRevokeBadgeUser}'s ${revokedBadge.emoji} **${revokedBadge.name}** badge has been revoked.`)
                        .setThumbnail(targetRevokeBadgeUser.displayAvatarURL({ dynamic: true }))
                        .setFooter({ 
                            text: `Revoked by ${message.author.tag}`, 
                            iconURL: message.author.displayAvatarURL({ dynamic: true }) 
                        })
                        .setTimestamp();
                        
                    message.reply({ embeds: [revokeEmbed] });
                    break;
                    
                case "view-badges":
                case "viewbadges":
                case "listbadges":
                case "badgelist":
                    // Beta gate
                    if (betaManager.isBetaFeature('badgelist') && !(await betaManager.canAccess(message.guild?.id))) {
                        return message.reply({
                            embeds: [new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle('🔬 Beta Feature')
                                .setDescription('The `badgelist` command is currently in beta and only available to servers enrolled in the beta program.\n\nAsk your server owner to run `$beta enable` if your server has been approved.')
                                .setFooter({ text: `Version: ${config.version}` })
                                .setTimestamp()]
                        });
                    }
                    // Check if leveling is enabled for this server
                    const viewBadgesServerSettings = client.serverSettingsManager.getGuildSettings(message.guild.id);
                    if (!viewBadgesServerSettings.leveling?.enabled) {
                        message.reply("The leveling system is not enabled in this server. Server administrators can enable it with `/leveling settings setting:enable`.");
                        return;
                    }
                    
                    // Create embeds for each badge category
                    const levelBadgesEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("🌟 Level Badges")
                        .setDescription("Badges automatically awarded for reaching specific levels")
                        .setThumbnail(client.user.displayAvatarURL({ dynamic: true }));
                        
                    let levelBadgesFields = [];
                    for (const badge of config.leveling.badges.levelBadges) {
                        levelBadgesFields.push({
                            name: `${badge.emoji} ${badge.name} (Level ${badge.level})`,
                            value: badge.description,
                            inline: true
                        });
                    }
                    
                    levelBadgesEmbed.addFields(levelBadgesFields);
                    
                    const achievementBadgesEmbed = new EmbedBuilder()
                        .setColor(config.colors.warning)
                        .setTitle("🏆 Achievement Badges")
                        .setDescription("Badges awarded for specific contributions and achievements")
                        .setThumbnail(client.user.displayAvatarURL({ dynamic: true }));
                        
                    let achievementBadgesFields = [];
                    for (const badge of config.leveling.badges.achievementBadges) {
                        achievementBadgesFields.push({
                            name: `${badge.emoji} ${badge.name} (ID: ${badge.id})`,
                            value: badge.description,
                            inline: true
                        });
                    }
                    
                    achievementBadgesEmbed.addFields(achievementBadgesFields);
                    
                    const specialBadgesEmbed = new EmbedBuilder()
                        .setColor(config.colors.gold)
                        .setTitle("💎 Special Badges")
                        .setDescription("Rare badges for extraordinary contributions")
                        .setThumbnail(client.user.displayAvatarURL({ dynamic: true }));
                        
                    let specialBadgesFields = [];
                    for (const badge of config.leveling.badges.specialBadges) {
                        specialBadgesFields.push({
                            name: `${badge.emoji} ${badge.name} (ID: ${badge.id})`,
                            value: badge.description,
                            inline: true
                        });
                    }
                    
                    specialBadgesEmbed.addFields(specialBadgesFields);
                    
                    // Send all embeds
                    message.reply({ embeds: [levelBadgesEmbed, achievementBadgesEmbed, specialBadgesEmbed] });
                    break;
                    
                // Welcome System Settings Commands
                case "welcome-enable":
                case "welcomeenable":
                case "welcome-on":
                    console.log(`[DEBUG] Welcome enable command triggered by ${message.author.tag}`);
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        console.log(`[DEBUG] Permission check failed for ${message.author.tag}`);
                        message.reply("You don't have permission to configure welcome settings.");
                        return;
                    }
                    
                    // Enable welcome system
                    client.welcomeSettingsManager.updateGuildSetting(message.guild.id, 'welcomeEnabled', true);
                    
                    // Create success embed
                    const welcomeEnableEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("✅ Welcome System Enabled")
                        .setDescription("The welcome system has been enabled for this server.")
                        .addFields(
                            { 
                                name: "Additional Configuration", 
                                value: "Use the following commands to further customize the welcome system:\n" +
                                       "• `$welcome-channel #channel` - Set the welcome channel\n" +
                                       "• `$welcome-message your message` - Set a custom welcome message\n" +
                                       "• `/welcomeconfig` - Use slash commands for more options"
                            }
                        )
                        .setFooter({ text: "Server settings updated successfully", iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    
                    message.reply({ embeds: [welcomeEnableEmbed] });
                    break;
                    
                case "welcome-disable":
                case "welcomedisable":
                case "welcome-off":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        message.reply("You don't have permission to configure welcome settings.");
                        return;
                    }
                    
                    // Disable welcome system
                    client.welcomeSettingsManager.updateGuildSetting(message.guild.id, 'welcomeEnabled', false);
                    
                    // Create success embed
                    const welcomeDisableEmbed = new EmbedBuilder()
                        .setColor(config.colors.error)
                        .setTitle("❌ Welcome System Disabled")
                        .setDescription("The welcome system has been disabled for this server.")
                        .setFooter({ text: "Server settings updated successfully", iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    
                    message.reply({ embeds: [welcomeDisableEmbed] });
                    break;
                    
                case "ping":
                    try {
                        const loadingEmbed = new EmbedBuilder()
                            .setColor(config.colors.primary)
                            .setTitle('📡 Measuring latency…')
                            .setDescription('> Pinging Discord gateway and database…');
                            
                        const sentMessage = await message.channel.send({ embeds: [loadingEmbed] });
                        const ping = sentMessage.createdTimestamp - message.createdTimestamp;
                        const apiPing = Math.round(client.ws.ping);
                        
                        // Test database connectivity
                        let dbPing = 'N/A';
                        let dbStatus = '⛔ Offline';
                        try {
                            const dbStartTime = Date.now();
                            if (client.livePollManager && client.livePollManager.drizzleDb) {
                                await client.livePollManager.drizzleDb.execute('SELECT 1 as ping');
                                dbPing = `${Date.now() - dbStartTime}ms`;
                                dbStatus = '✅ Online';
                            } else if (client.db) {
                                await client.db.execute('SELECT 1 as ping');
                                dbPing = `${Date.now() - dbStartTime}ms`;
                                dbStatus = '✅ Online';
                            } else {
                                dbStatus = '⚠️ Not init';
                            }
                        } catch (dbError) {
                            dbStatus = '⛔ Error';
                            dbPing = 'Failed';
                        }
                        
                        // Colour by overall health
                        let color = config.colors.success;
                        if (ping > 500) color = config.colors.error;
                        else if (ping > 200) color = config.colors.warning;

                        // Visual latency bar (10 segments, 1 per 60ms)
                        const makeBar = (ms) => {
                            if (typeof ms !== 'number') return '`░░░░░░░░░░`';
                            const fill = Math.min(Math.ceil(ms / 60), 10);
                            return '`' + '█'.repeat(fill) + '░'.repeat(10 - fill) + '`';
                        };

                        // Fetch all node statuses + lease in parallel
                        let nodesValue = '⚪ Unavailable';
                        try {
                            const [sn1Status, sn2Status, sn3Status, lease] = await Promise.all([
                                nodeFailover.getStatus('sn1'),
                                nodeFailover.getStatus('sn2'),
                                nodeFailover.getStatus('sn3'),
                                nodeFailover.getLease()
                            ]);
                            const nodeRow = (role, status) => {
                                if (!status) return `⚪ **${role}** — never reported`;
                                const ageSec = Math.round(Number(status.age_ms) / 1000);
                                const isHolder = lease && lease.ownerRole === role;
                                if (isHolder) {
                                    const icon = ageSec > nodeFailover.FAILOVER_THRESHOLD_MS / 1000 ? '🔴' : '🟢';
                                    return `${icon} **${role}** \`${status.node_name}\` — Active, ${ageSec}s ago 🔑`;
                                }
                                return `🟠 **${role}** \`${status.node_name}\` — Standby`;
                            };
                            nodesValue = [
                                nodeRow('sn1', sn1Status),
                                nodeRow('sn2', sn2Status),
                                nodeRow('sn3', sn3Status),
                            ].join('\n');
                        } catch (_) {}

                        const overallStatus = ping <= 200
                            ? '🟢 All systems operational'
                            : ping <= 500 ? '🟡 Moderate latency' : '🔴 High latency detected';

                        const pingEmbed = new EmbedBuilder()
                            .setColor(color)
                            .setTitle('📡  Connection Status')
                            .setDescription(`${overallStatus}\n\u200b`)
                            .addFields(
                                {
                                    name: '⚡ Bot Latency',
                                    value: `**${ping}ms**\n${makeBar(ping)}`,
                                    inline: true
                                },
                                {
                                    name: '🔌 Gateway',
                                    value: `**${apiPing}ms**\n${makeBar(apiPing)}`,
                                    inline: true
                                },
                                {
                                    name: '🗄️ Database',
                                    value: `${dbStatus}\n**${dbPing}**`,
                                    inline: true
                                },
                                {
                                    name: '🖥️ Failover Nodes',
                                    value: nodesValue,
                                    inline: false
                                }
                            )
                            .setFooter({ 
                                text: `Requested by ${message.author.tag}`,
                                iconURL: message.author.displayAvatarURL() 
                            })
                            .setTimestamp();
                        
                        sentMessage.edit({ embeds: [pingEmbed] });
                    } catch (error) {
                        console.error("Error handling ping:", error);
                        message.reply(
                            "Sorry, I encountered an error while processing your ping. Please try again later.",
                        );
                    }
                    break;

                case "tokentest": {
                    if (!config.developerIds.includes(message.author.id)) return;

                    const runningEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle('🔑 Token Test')
                        .setDescription('Running `node token-test.js`…');

                    const ttMsg = await message.channel.send({ embeds: [runningEmbed] });

                    const { exec } = require('child_process');
                    exec('node token-test.js', { timeout: 15000, maxBuffer: 1024 * 256, cwd: process.cwd() }, async (err, stdout, stderr) => {
                        const output = (stdout + stderr).trim() || '(no output)';
                        const truncated = output.length > 1900 ? output.slice(0, 1900) + '\n…(truncated)' : output;

                        const resultEmbed = new EmbedBuilder()
                            .setColor(err ? config.colors.error : config.colors.success)
                            .setTitle(err ? '❌ Token Test Failed' : '✅ Token Test Passed')
                            .setDescription(`\`\`\`\n${truncated}\n\`\`\``)
                            .setFooter({ text: `Exit code: ${err ? err.code ?? 1 : 0}` })
                            .setTimestamp();

                        await ttMsg.edit({ embeds: [resultEmbed] }).catch(() => {});
                    });
                    break;
                }

                case "np":
                case "noprefix": {
                    // Developer-only access for the no-prefix administration command
                    if (!config.developerIds.includes(message.author.id)) {
                        return message.reply({
                            embeds: [new EmbedBuilder()
                                .setColor(config.colors.error)
                                .setTitle('❌ Access Denied')
                                .setDescription('This no-prefix command is restricted to bot developers only.')
                                .setFooter({ text: `Version: ${config.version}` })
                                .setTimestamp()]
                        });
                    }

                    // Check if the command is being used in a guild
                    if (!message.guild) {
                        return message.reply({
                            embeds: [new EmbedBuilder()
                                .setColor(config.colors.warning)
                                .setTitle('⚠️ Server Only')
                                .setDescription('This command can only be used in a server.')
                                .setFooter({ text: `Version: ${config.version}` })
                                .setTimestamp()]
                        });
                    }
                    
                    if (args.length === 0) {
                        // Show usage info
                        const npHelpEmbed = new EmbedBuilder()
                            .setColor(config.colors.primary)
                            .setTitle("🪄 No-Prefix Mode")
                            .setDescription("Developer-only no-prefix mode management. Add/remove a target user and let them use commands without the prefix.")
                            .addFields(
                                { name: `${prefix}np add @user [minutes]`, value: "Add/enable a selected user for no-prefix command access" },
                                { name: `${prefix}np remove @user`, value: "Remove/disable a selected user's no-prefix command access" },
                                { name: `${prefix}np status @user`, value: "Check a user's current no-prefix status" },
                                { name: `${prefix}np enable [minutes]`, value: "Enable no-prefix mode for yourself (legacy alias)" },
                                { name: `${prefix}np disable`, value: "Disable no-prefix mode for yourself (legacy alias)" }
                            )
                            .setFooter({ text: "Developer command • Main database-backed no-prefix mode", iconURL: client.user.displayAvatarURL() });
                            
                        return message.reply({ embeds: [npHelpEmbed] });
                    }
                    
                    const npSubCommand = args[0].toLowerCase();
                    
                    switch(npSubCommand) {
                        case "add":
                        case "enable":
                        case "on": {
                            const target = message.mentions.users.first() || message.author;
                            let duration = 10;
                            const requestedPosition = args[1]?.match(/^<@!?\d+>$/) ? 2 : 1;
                            if (args.length > requestedPosition) {
                                const requestedDuration = parseInt(args[requestedPosition]);
                                if (!isNaN(requestedDuration) && requestedDuration > 0 && requestedDuration <= 60) {
                                    duration = requestedDuration;
                                }
                            }

                            const result = client.serverSettingsManager.enableNoPrefixMode(
                                message.guild.id,
                                target.id,
                                duration
                            );

                            if (result.success) {
                                const enableEmbed = new EmbedBuilder()
                                    .setColor(config.colors.success)
                                    .setTitle("🪄 No-Prefix Mode Added")
                                    .setDescription(`No-prefix command access has been added for ${target}.`)
                                    .addFields(
                                        { name: "Duration", value: `${duration} minute${duration !== 1 ? 's' : ''}` },
                                        { name: "Expires", value: `<t:${Math.floor(result.expiresAt / 1000)}:R>` },
                                        { name: "How to use", value: "The selected user can now type command names without the prefix." }
                                    )
                                    .setFooter({ text: "Developer command • Main database", iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                    
                                return message.reply({ embeds: [enableEmbed] });
                            } else {
                                return message.reply(result.message || "Failed to enable no-prefix mode.");
                            }
                        }
                            
                        case "remove":
                        case "disable":
                        case "off": {
                            const target = message.mentions.users.first() || message.author;
                            const disabled = client.serverSettingsManager.disableNoPrefixMode(
                                message.guild.id,
                                target.id
                            );
                            
                            if (disabled) {
                                const disableEmbed = new EmbedBuilder()
                                    .setColor(config.colors.error)
                                    .setTitle("🪄 No-Prefix Mode Removed")
                                    .setDescription(`No-prefix command access has been removed for ${target}.`)
                                    .setFooter({ text: `Prefix: ${prefix}`, iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                    
                                return message.reply({ embeds: [disableEmbed] });
                            } else {
                                return message.reply("That user does not currently have no-prefix mode enabled.");
                            }
                        }
                            
                        case "status":
                        case "check": {
                            const target = message.mentions.users.first() || message.author;
                            const expirationTime = client.serverSettingsManager.getNoPrefixExpiration(
                                message.guild.id,
                                target.id
                            );
                            
                            if (expirationTime) {
                                const statusEmbed = new EmbedBuilder()
                                    .setColor(config.colors.primary)
                                    .setTitle("🪄 No-Prefix Mode Status")
                                    .setDescription(`${target} has no-prefix mode enabled.`)
                                    .addFields(
                                        { name: "Expires", value: `<t:${Math.floor(expirationTime / 1000)}:R>` }
                                    )
                                    .setFooter({ text: "Developer command • Main database", iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                    
                                return message.reply({ embeds: [statusEmbed] });
                            } else {
                                return message.reply(`${target} does not have no-prefix mode enabled.`);
                            }
                        }
                            
                        case "user": {
                            // Legacy compatibility path — map to add semantics.
                            if (message.mentions.users.size === 0) {
                                message.reply("Please mention a user to add no-prefix mode for them.");
                                return;
                            }

                            const targetUser = message.mentions.users.first();
                            let userDuration = 10;
                            if (args.length > 2) {
                                const requestedDuration = parseInt(args[2]);
                                if (!isNaN(requestedDuration) && requestedDuration > 0 && requestedDuration <= 60) {
                                    userDuration = requestedDuration;
                                }
                            }

                            const userResult = client.serverSettingsManager.enableNoPrefixMode(
                                message.guild.id,
                                targetUser.id,
                                userDuration
                            );

                            if (userResult.success) {
                                const userEnableEmbed = new EmbedBuilder()
                                    .setColor(config.colors.success)
                                    .setTitle("🪄 No-Prefix Mode Enabled")
                                    .setDescription(`No-prefix mode has been enabled for ${targetUser}.`)
                                    .addFields(
                                        { name: "Duration", value: `${userDuration} minute${userDuration !== 1 ? 's' : ''}` },
                                        { name: "Expires", value: `<t:${Math.floor(userResult.expiresAt / 1000)}:R>` }
                                    )
                                    .setFooter({ text: `Enabled by ${message.author.tag}`, iconURL: message.author.displayAvatarURL() })
                                    .setTimestamp();
                                    
                                return message.reply({ embeds: [userEnableEmbed] });
                            } else {
                                return message.reply(userResult.message || "Failed to enable no-prefix mode for the user.");
                            }
                        }
                            
                        default:
                            return message.reply(`Unknown no-prefix command: ${npSubCommand}. Use \`${prefix}np\` to see available commands.`);
                    }
                    return;
                }

                case "purge": {
                    if (!message.guild) {
                        return message.reply('This command can only be used in a server.');
                    }

                    if (!message.member.permissions.has(PermissionFlagsBits.ManageMessages)) {
                        return message.reply('You need the Manage Messages permission to purge messages.');
                    }

                    if (!message.channel || !message.channel.isTextBased?.()) {
                        return message.reply('This command can only be used in a text channel.');
                    }

                    const purgeSubCommand = (args[0] || 'messages').toLowerCase();

                    if (!message.channel.permissionsFor(message.client.user).has(PermissionFlagsBits.ManageMessages)) {
                        return message.reply(`I need Manage Messages permission in ${message.channel}.`);
                    }

                    try {
                        if (purgeSubCommand === 'messages' || purgeSubCommand === 'msg' || purgeSubCommand === 'batch') {
                            const count = parseInt(args[1] || '10');
                            if (!Number.isInteger(count) || count < 1 || count > 100) {
                                return message.reply('Usage: `$purge messages <count>` where count is between 1 and 100.');
                            }

                            const deleted = await message.channel.bulkDelete(count, true);
                            return message.reply(`Deleted ${deleted.size || count} message${count === 1 ? '' : 's'} from ${message.channel}.`);
                        }

                        if (purgeSubCommand === 'user' || purgeSubCommand === 'member') {
                            if (!message.mentions.users.size) {
                                return message.reply('Usage: `$purge user @member [count]`');
                            }

                            const targetUser = message.mentions.users.first();
                            const count = Math.min(parseInt(args[2] || '50') || 50, 100);

                            const fetched = await message.channel.messages.fetch({ limit: count });
                            const ids = [...fetched.values()]
                                .filter(msg => msg.author.id === targetUser.id)
                                .map(msg => msg.id);

                            if (ids.length === 0) {
                                return message.reply(`No recent messages from ${targetUser} were found in ${message.channel}.`);
                            }

                            const deleted = await message.channel.bulkDelete(ids, true);
                            return message.reply(`Removed ${deleted.size || ids.length} message${ids.length === 1 ? '' : 's'} from ${targetUser} in ${message.channel}.`);
                        }

                        if (purgeSubCommand === 'between' || purgeSubCommand === 'range') {
                            const startMessageId = args[1];
                            const endMessageId = args[2];
                            if (!startMessageId || !endMessageId) {
                                return message.reply('Usage: `$purge between <startMessageId> <endMessageId>`');
                            }

                            const fetched = await message.channel.messages.fetch({ limit: 100 });
                            const ids = [...fetched.values()]
                                .filter(msg => msg.id >= startMessageId && msg.id <= endMessageId)
                                .map(msg => msg.id);

                            if (ids.length === 0) {
                                return message.reply('No messages were found in that ID range.');
                            }

                            const deleted = await message.channel.bulkDelete(ids, true);
                            return message.reply(`Removed ${deleted.size || ids.length} message${ids.length === 1 ? '' : 's'} in ${message.channel}.`);
                        }

                        return message.reply('Unknown purge subcommand. Try `messages`, `user`, or `between`.');
                    } catch (purgeError) {
                        console.error('[PURGE] Error:', purgeError);
                        return message.reply('I could not complete that purge request.');
                    }
                }
                    
                case "welcome-channel":
                case "welcomechannel":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        message.reply("You don't have permission to configure welcome settings.");
                        return;
                    }
                    
                    // Check if a channel is mentioned
                    if (message.mentions.channels.size === 0) {
                        message.reply("Please specify a channel: `$welcome-channel #channel`");
                        return;
                    }
                    
                    const welcomeChannel = message.mentions.channels.first();
                    
                    // Update welcome channel
                    client.welcomeSettingsManager.setWelcomeChannel(message.guild.id, welcomeChannel.id);
                    
                    // Create success embed
                    const welcomeChannelEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("✅ Welcome Channel Updated")
                        .setDescription(`Welcome messages will now be sent to ${welcomeChannel}.`)
                        .setFooter({ text: "Server settings updated successfully", iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    
                    message.reply({ embeds: [welcomeChannelEmbed] });
                    break;
                    
                // Leveling System Settings Commands
                case "level-enable":
                case "levelenable":
                case "leveling-enable":
                case "levelingon":
                case "leveling-on":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        message.reply("You don't have permission to configure leveling settings.");
                        return;
                    }
                    
                    // Enable leveling system
                    client.serverSettingsManager.updateLevelingSettings(message.guild.id, {
                        enabled: true
                    });
                    
                    // Create success embed
                    const levelEnableEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("✅ Leveling System Enabled")
                        .setDescription("The leveling system has been enabled for this server.")
                        .addFields(
                            { 
                                name: "Additional Configuration", 
                                value: "Use the following commands to further customize the leveling system:\n" +
                                       "• `$level-channel #channel` - Set the level-up notification channel\n" +
                                       "• `$level-multiplier 1.5` - Set XP multiplier (default: 1.0)\n" +
                                       "• `/leveling settings` - Use slash commands for more options"
                            }
                        )
                        .setFooter({ text: "Server settings updated successfully", iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    
                    message.reply({ embeds: [levelEnableEmbed] });
                    break;
                    
                case "level-disable":
                case "leveldisable":
                case "leveling-disable":
                case "levelingoff":
                case "leveling-off":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        message.reply("You don't have permission to configure leveling settings.");
                        return;
                    }
                    
                    // Disable leveling system
                    client.serverSettingsManager.updateLevelingSettings(message.guild.id, {
                        enabled: false
                    });
                    
                    // Create success embed
                    const levelDisableEmbed = new EmbedBuilder()
                        .setColor(config.colors.error)
                        .setTitle("❌ Leveling System Disabled")
                        .setDescription("The leveling system has been disabled for this server.")
                        .setFooter({ text: "Server settings updated successfully", iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    
                    message.reply({ embeds: [levelDisableEmbed] });
                    break;
                    
                case "level-channel":
                case "levelchannel":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        message.reply("You don't have permission to configure leveling settings.");
                        return;
                    }
                    
                    // Check if a channel is mentioned
                    if (message.mentions.channels.size === 0) {
                        message.reply("Please specify a channel: `$level-channel #channel`");
                        return;
                    }
                    
                    const levelChannel = message.mentions.channels.first();
                    
                    // Update level-up channel
                    client.serverSettingsManager.updateLevelingSettings(message.guild.id, {
                        levelUpChannelId: levelChannel.id
                    });
                    
                    // Create success embed
                    const levelChannelEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("✅ Level-Up Channel Updated")
                        .setDescription(`Level-up messages will now be sent to ${levelChannel}.`)
                        .setFooter({ text: "Server settings updated successfully", iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    
                    message.reply({ embeds: [levelChannelEmbed] });
                    break;
                    
                case "level-multiplier":
                case "levelmultiplier":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                        message.reply("You don't have permission to configure leveling settings.");
                        return;
                    }
                    
                    // Check if a multiplier is provided
                    if (args.length === 0) {
                        message.reply("Please specify a multiplier value: `$level-multiplier 1.5`");
                        return;
                    }
                    
                    const multiplier = parseFloat(args[0]);
                    
                    // Validate the multiplier
                    if (isNaN(multiplier) || multiplier <= 0 || multiplier > 5) {
                        message.reply("The multiplier must be a number between 0 and 5.");
                        return;
                    }
                    
                    // Update XP multiplier
                    client.serverSettingsManager.updateLevelingSettings(message.guild.id, {
                        xpMultiplier: multiplier
                    });
                    
                    // Create success embed
                    const multiplierEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("✅ XP Multiplier Updated")
                        .setDescription(`XP multiplier has been set to **${multiplier}x**.`)
                        .addFields({
                            name: "Effect",
                            value: `Members will now earn ${multiplier}x the normal amount of XP for each message.`
                        })
                        .setFooter({ text: "Server settings updated successfully", iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    
                    message.reply({ embeds: [multiplierEmbed] });
                    break;
                    
                // Auto-Reaction Commands
                case "autoreact":
                case "auto-react":
                    if (args.length === 0) {
                        // Show usage info
                        const autoReactHelpEmbed = new EmbedBuilder()
                            .setColor(config.colors.primary)
                            .setTitle("🔄 Auto-Reaction System")
                            .setDescription("Set up automatic emoji reactions to trigger words in messages.")
                            .addFields(
                                { name: `${prefix}autoreact enable`, value: "Enable auto-reactions" },
                                { name: `${prefix}autoreact disable`, value: "Disable auto-reactions" },
                                { name: `${prefix}autoreact add [trigger] [emoji]`, value: "Add a new auto-reaction" },
                                { name: `${prefix}autoreact remove [trigger]`, value: "Remove an auto-reaction" },
                                { name: `${prefix}autoreact list`, value: "List all auto-reactions" }
                            )
                            .setFooter({ text: "Auto-reactions happen when someone sends a message containing a trigger word", iconURL: client.user.displayAvatarURL() });
                            
                        message.reply({ embeds: [autoReactHelpEmbed] });
                        return;
                    }
                    
                    const arSubCommand = args[0].toLowerCase();
                    
                    switch(arSubCommand) {
                        case "enable":
                        case "on":
                            // Only available to admins with proper permissions
                            if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                                message.reply("You don't have permission to configure auto-reactions.");
                                return;
                            }
                            
                            const enabledState = client.serverSettingsManager.toggleAutoReactions(message.guild.id);
                            
                            // Only set to true if toggle didn't already do it
                            if (!enabledState) {
                                client.serverSettingsManager.toggleAutoReactions(message.guild.id);
                            }
                            
                            const enableEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setTitle("✅ Auto-Reactions Enabled")
                                .setDescription("Messages containing trigger words will now receive automatic emoji reactions.")
                                .setFooter({ text: "Use the add command to set up trigger words", iconURL: client.user.displayAvatarURL() })
                                .setTimestamp();
                                
                            message.reply({ embeds: [enableEmbed] });
                            break;
                            
                        case "disable":
                        case "off":
                            // Only available to admins with proper permissions
                            if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                                message.reply("You don't have permission to configure auto-reactions.");
                                return;
                            }
                            
                            const disabledState = client.serverSettingsManager.toggleAutoReactions(message.guild.id);
                            
                            // Only set to false if toggle didn't already do it
                            if (disabledState) {
                                client.serverSettingsManager.toggleAutoReactions(message.guild.id);
                            }
                            
                            const disableEmbed = new EmbedBuilder()
                                .setColor(config.colors.error)
                                .setTitle("❌ Auto-Reactions Disabled")
                                .setDescription("Automatic emoji reactions to trigger words have been disabled.")
                                .setFooter({ text: "Auto-reaction triggers are still saved", iconURL: client.user.displayAvatarURL() })
                                .setTimestamp();
                                
                            message.reply({ embeds: [disableEmbed] });
                            break;
                            
                        case "add":
                            // Only available to admins with proper permissions
                            if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                                message.reply("You don't have permission to configure auto-reactions.");
                                return;
                            }
                            
                            if (args.length < 3) {
                                message.reply(`Please provide both a trigger word and an emoji. Example: \`${prefix}autoreact add hello 👋\``);
                                return;
                            }
                            
                            const trigger = args[1];
                            const emoji = args[2];
                            
                            // Check if the emoji is valid by attempting to react with it
                            try {
                                await message.react(emoji);
                                // Remove the reaction right away
                                const userReactions = message.reactions.cache.filter(reaction => 
                                    reaction.users.cache.has(client.user.id)
                                );
                                for (const reaction of userReactions.values()) {
                                    await reaction.users.remove(client.user.id);
                                }
                            } catch (error) {
                                message.reply("Sorry, that doesn't appear to be a valid emoji that I can use. Please try a different emoji.");
                                return;
                            }
                            
                            // Add the auto-reaction
                            const reaction = client.serverSettingsManager.addAutoReaction(
                                message.guild.id, 
                                trigger, 
                                emoji
                            );
                            
                            // Enable auto-reactions if they're not already enabled
                            const autoReactions = client.serverSettingsManager.getAutoReactions(message.guild.id);
                            if (!autoReactions.enabled) {
                                client.serverSettingsManager.toggleAutoReactions(message.guild.id);
                            }
                            
                            const addEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setTitle("✅ Auto-Reaction Added")
                                .setDescription(`Added new auto-reaction:\nTrigger: **${trigger}**\nEmoji: ${emoji}`)
                                .setFooter({ text: "Bot will now react with this emoji when the trigger appears in messages", iconURL: client.user.displayAvatarURL() })
                                .setTimestamp();
                                
                            message.reply({ embeds: [addEmbed] });
                            break;
                            
                        case "remove":
                        case "delete":
                            // Only available to admins with proper permissions
                            if (!message.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                                message.reply("You don't have permission to configure auto-reactions.");
                                return;
                            }
                            
                            if (args.length < 2) {
                                message.reply(`Please provide the trigger word to remove. Example: \`${prefix}autoreact remove hello\``);
                                return;
                            }
                            
                            const triggerToRemove = args[1];
                            const removed = client.serverSettingsManager.removeAutoReaction(message.guild.id, triggerToRemove);
                            
                            if (removed) {
                                const removeEmbed = new EmbedBuilder()
                                    .setColor(config.colors.success)
                                    .setTitle("✅ Auto-Reaction Removed")
                                    .setDescription(`Removed auto-reaction for trigger: **${triggerToRemove}**`)
                                    .setFooter({ text: "Bot will no longer react to this trigger", iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                    
                                message.reply({ embeds: [removeEmbed] });
                            } else {
                                message.reply(`Couldn't find an auto-reaction with trigger: **${triggerToRemove}**`);
                            }
                            break;
                            
                        case "list":
                            const autoReactionsData = client.serverSettingsManager.getAutoReactions(message.guild.id);
                            
                            if (autoReactionsData.reactions.length === 0) {
                                message.reply("No auto-reactions have been set up for this server yet.");
                                return;
                            }
                            
                            // Create a field for each reaction, max 25 fields
                            const fields = autoReactionsData.reactions.slice(0, 25).map(reaction => {
                                return {
                                    name: `Trigger: ${reaction.trigger}`,
                                    value: `Emoji: ${reaction.emoji}`,
                                    inline: true
                                };
                            });
                            
                            const listEmbed = new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle("🔄 Auto-Reactions List")
                                .setDescription(`Status: **${autoReactionsData.enabled ? 'Enabled' : 'Disabled'}**\nTotal auto-reactions: ${autoReactionsData.reactions.length}`)
                                .addFields(fields)
                                .setFooter({ 
                                    text: autoReactionsData.reactions.length > 25 
                                        ? `Showing first 25 of ${autoReactionsData.reactions.length} auto-reactions` 
                                        : "Server auto-reactions list",
                                    iconURL: client.user.displayAvatarURL()
                                })
                                .setTimestamp();
                                
                            message.reply({ embeds: [listEmbed] });
                            break;
                            
                        default:
                            message.reply(`Unknown auto-reaction command: ${arSubCommand}. Use \`${prefix}autoreact\` to see available commands.`);
                    }
                    break;

                // Broadcasting Settings Commands
                case "broadcastsettings":
                case "bsettings":
                    if (!message.member.permissions.has("Administrator")) {
                        return message.reply("You need Administrator permission to configure broadcast settings!");
                    }
                    
                    const bsEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("📣 Broadcast Settings")
                        .setDescription("Configure how the bot handles broadcasts:")
                        .addFields(
                            { name: "Usage", value: `${prefix}broadcastsettings [enable/disable/status]` },
                            { name: "Examples", value: `${prefix}broadcastsettings enable - Enable broadcasts\n${prefix}broadcastsettings disable - Disable broadcasts\n${prefix}broadcastsettings status - Check current status` }
                        )
                        .setFooter({ text: `Version: ${config.version}` });
                    
                    message.reply({ embeds: [bsEmbed] });
                    break;

                // Ticket System Commands
                case "createticket":
                case "ticket":
                    if (args.length < 1) {
                        return message.reply(`**Correct Usage:** \`${prefix}${commandName} [ticket name]\``);
                    }
                    
                    const ticketName = args.join(' ');
                    
                    try {
                        await client.ticketManager.handleTicketCreation({
                            reply: async (options) => await message.reply(options),
                            options: {
                                getString: () => ticketName
                            },
                            user: message.author,
                            guild: message.guild,
                            channel: message.channel
                        }, ticketName);
                    } catch (error) {
                        console.error('Error creating ticket:', error);
                        message.reply('There was an error creating your ticket! Please try again later.');
                    }
                    break;

                // About Command
                case "about":
                case "ab":
                    const prefixAboutEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("About PrimeBot")
                        .setDescription("A sophisticated Discord bot for community engagement")
                        .addFields(
                            { name: "Version", value: config.version, inline: true },
                            { name: "Servers", value: client.guilds.cache.size.toString(), inline: true },
                            { name: "Uptime", value: formatUptime(process.uptime()), inline: true }
                        )
                        .setFooter({ text: `Version: ${config.version}` })
                        .setTimestamp();

                    // Create buttons for about command
                    const aboutInviteButton = new ButtonBuilder()
                        .setLabel("Invite Me")
                        .setStyle(ButtonStyle.Link)
                        .setURL(
                            `https://discord.com/api/oauth2/authorize?client_id=${client.user.id}&permissions=563242011339808&scope=bot%20applications.commands`
                        )
                        .setEmoji('➕');

                    const aboutSupportButton = new ButtonBuilder()
                        .setLabel("Support Server")
                        .setStyle(ButtonStyle.Link)
                        .setURL(config.supportServer || 'https://discord.gg/primebot')
                        .setEmoji('ℹ️');

                    const aboutVoteButton = new ButtonBuilder()
                        .setLabel("Vote Me")
                        .setStyle(ButtonStyle.Link)
                        .setURL('https://top.gg/bot/1356575287151951943/vote')
                        .setEmoji('✔️');

                    const aboutButtonRow = new ActionRowBuilder().addComponents(
                        aboutInviteButton, 
                        aboutSupportButton, 
                        aboutVoteButton
                    );
                    
                    message.reply({ 
                        embeds: [prefixAboutEmbed],
                        components: [aboutButtonRow]
                    });
                    break;

                // Stats Command
                case "stats":
                case "statistics":
                    const uptime = process.uptime();
                    const uptimeString = formatUptime(uptime);
                    const memoryUsage = process.memoryUsage();
                    const heapUsedMB  = (memoryUsage.heapUsed  / 1024 / 1024).toFixed(1);
                    const heapTotalMB = (memoryUsage.heapTotal / 1024 / 1024).toFixed(1);
                    const rssMB       = (memoryUsage.rss       / 1024 / 1024).toFixed(1);
                    const extMB       = (memoryUsage.external  / 1024 / 1024).toFixed(1);
                    const totalUsers  = client.guilds.cache.reduce((a, g) => a + g.memberCount, 0);
                    const totalChannels = client.channels.cache.size;

                    // Node / lease block
                    let nodesBlock = '⚪ Unavailable';
                    try {
                        const [sn1s, sn2s, sn3s, lease] = await Promise.all([
                            nodeFailover.getStatus('sn1'),
                            nodeFailover.getStatus('sn2'),
                            nodeFailover.getStatus('sn3'),
                            nodeFailover.getLease()
                        ]);
                        const nodeRow = (role, status) => {
                            if (!status) return `⚪ **${role}** — never reported`;
                            const ageSec = Math.round(Number(status.age_ms) / 1000);
                            const isHolder = lease && lease.ownerRole === role;
                            if (isHolder) {
                                const icon = ageSec > nodeFailover.FAILOVER_THRESHOLD_MS / 1000 ? '🔴' : '🟢';
                                return `${icon} **${role}** \`${status.node_name}\` — Active, ${ageSec}s ago 🔑`;
                            }
                            return `🟠 **${role}** \`${status.node_name}\` — Standby`;
                        };
                        const leaseLabel = lease ? `${lease.ownerRole} · \`${lease.ownerNodeName}\`` : '⚠️ none';
                        nodesBlock =
                            `**Lease:** ${leaseLabel}\n` +
                            nodeRow('sn1', sn1s) + '\n' +
                            nodeRow('sn2', sn2s) + '\n' +
                            nodeRow('sn3', sn3s);
                    } catch (_) {}

                    // DB pool line
                    const poolLine = pool
                        ? `${pool.totalCount} conns · ${pool.idleCount} idle · ${pool.waitingCount} waiting`
                        : 'unavailable';

                    const prefixStatsEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle(`📊  ${client.user.username} — Live Statistics`)
                        .setDescription(
                            `**${client.guilds.cache.size.toLocaleString()}** servers · ` +
                            `**${totalUsers.toLocaleString()}** users · ` +
                            `**${totalChannels.toLocaleString()}** channels · ` +
                            `up **${uptimeString}**\n\u200b`
                        )
                        .setThumbnail(client.user.displayAvatarURL({ dynamic: true }))
                        .addFields(
                            {
                                name: '🤖 Bot',
                                value: `**Version:** ${config.version}\n**Prefix:** \`${config.prefix}\`\n**Commands:** ${client.commands.size}\n**WS Ping:** ${client.ws.ping}ms`,
                                inline: true
                            },
                            {
                                name: '💾 Memory',
                                value: `**RSS:** ${rssMB}MB\n**Heap:** ${heapUsedMB}/${heapTotalMB}MB\n**External:** ${extMB}MB\n**DB Pool:** ${poolLine}`,
                                inline: true
                            },
                            {
                                name: '🔧 System',
                                value: `**Node.js:** ${process.version}\n**Platform:** ${process.platform} ${process.arch}\n**PID:** ${process.pid}\n**Env:** ${process.env.NODE_ENV || 'development'}`,
                                inline: true
                            },
                            {
                                name: '🖥️ Failover Nodes',
                                value: nodesBlock,
                                inline: false
                            }
                        )
                        .setFooter({
                            text: `v${config.version} · Last restart ${new Date(Date.now() - uptime * 1000).toLocaleString()}`,
                            iconURL: client.user.displayAvatarURL()
                        })
                        .setTimestamp();

                    message.reply({ embeds: [prefixStatsEmbed] });
                    break;

                // Updates Command
                case "updates":
                case "ulog":
                    const updatesEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle(`🆕 Bot Updates & Features • ${config.version}`)
                        .setDescription("PrimeBot has been extended with developer-only no-prefix access and a moderation cleanup tool.")
                        .addFields(
                            { name: `Version ${config.version}`, value: "• Added developer-only `np` flow for selected users to use commands without a prefix\n• `np add`, `np remove`, and `np status` are surfaced through the main server settings database path\n• Added `/purge` moderation support with `messages`, `user`, and `between` subcommands\n• Refreshed moderation/help category exposure so the new command is visible" },
                            { name: "Next Direction", value: "• Strengthen moderation audits\n• Expand automation and reporting\n• Keep the command shelf aligned with new server workflows" }
                        )
                        .setFooter({ text: `Version: ${config.version}` })
                        .setTimestamp();
                    
                    message.reply({ embeds: [updatesEmbed] });
                    break;

                // Session Command (SES)
                case "ses":
                case "session":
                    const sesEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("🔧 Bot Session Info")
                        .setDescription("Current bot session information:")
                        .addFields(
                            { name: "Uptime", value: formatUptime(process.uptime()), inline: true },
                            { name: "Memory Usage", value: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`, inline: true },
                            { name: "Ping", value: `${client.ws.ping}ms`, inline: true }
                        )
                        .setFooter({ text: `Version: ${config.version}` })
                        .setTimestamp();
                    
                    message.reply({ embeds: [sesEmbed] });
                    break;

                // Leveling System Commands
                case "leveling":
                case "lvl":
                    if (!message.guild) {
                        return message.reply("Leveling commands can only be used in servers.");
                    }
                    
                    const levelingEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("📊 Leveling System")
                        .setDescription("Available leveling commands:")
                        .addFields(
                            { name: "User Commands", value: `${prefix}rank [@user] - Check level/XP\n${prefix}leaderboard - View leaderboard\n${prefix}badges - View available badges` },
                            { name: "Admin Commands", value: `${prefix}level-enable - Enable leveling\n${prefix}level-disable - Disable leveling\n${prefix}level-channel #channel - Set notification channel` }
                        )
                        .setFooter({ text: `Version: ${config.version}` });
                    
                    message.reply({ embeds: [levelingEmbed] });
                    break;

                // Move Command (for moderation)
                case "move":
                    if (!message.member.permissions.has("MoveMembers")) {
                        return message.reply("You need the Move Members permission to use this command!");
                    }
                    
                    const moveEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("🔄 Move Command")
                        .setDescription("Move members between voice channels")
                        .addFields(
                            { name: "Usage", value: `${prefix}move [@user] [#channel]` },
                            { name: "Note", value: "Requires Move Members permission" }
                        )
                        .setFooter({ text: `Version: ${config.version}` });
                    
                    message.reply({ embeds: [moveEmbed] });
                    break;

                // Welcome Configuration
                case "welcomeconfig":
                case "welcome":
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply("You need the Manage Server permission to configure welcome settings!");
                    }
                    
                    const welcomeEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("👋 Welcome Configuration")
                        .setDescription("Configure how the bot welcomes new members:")
                        .addFields(
                            { name: "Commands", value: `${prefix}welcome-enable - Enable welcome system\n${prefix}welcome-disable - Disable welcome system\n${prefix}welcome-channel #channel - Set welcome channel` },
                            { name: "Note", value: "Requires Manage Server permission" }
                        )
                        .setFooter({ text: `Version: ${config.version}` });
                    
                    message.reply({ embeds: [welcomeEmbed] });
                    break;

                // Sync Command
                case "sync":
                    if (!message.member.permissions.has("ManageGuild")) {
                        return message.reply("You need the Manage Server permission to use sync commands!");
                    }
                    // Beta gate
                    if (isBetaFeature('sync', null, null, config.betaFeatures) && !(await betaManager.canAccess(message.guild?.id))) {
                        return message.reply({
                            embeds: [new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle('🔬 Beta Feature')
                                .setDescription('The `sync` command is currently in beta and only available to servers enrolled in the beta program.\n\nAsk your server owner to run `$beta enable` if your server has been approved.')
                                .setFooter({ text: `Version: ${config.version}` })
                                .setTimestamp()]
                        });
                    }
                    
                    const syncEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("🔄 Sync System")
                        .setDescription("Automated role-level-badge synchronization commands:")
                        .addFields(
                            { name: "Available Commands", value: `${prefix}sync roles - Sync all user roles based on levels\n${prefix}sync badges - Sync badges based on achievements\n${prefix}sync all - Complete sync of roles and badges\n${prefix}sync status - Check sync configuration` },
                            { name: "Usage", value: "Use `/sync` slash command for full functionality" },
                            { name: "Note", value: "Requires Manage Server permission" }
                        )
                        .setFooter({ text: `Version: ${config.version}` });
                    
                    message.reply({ embeds: [syncEmbed] });
                    break;

                case 'beta': {
                    try {
                        console.log(`[BETA] Handling $beta from ${message.author.tag} in guild=${message.guild?.id} channel=${message.channel?.id}`);
                        if (!message.guild) {
                            return await safeBetaReply(message, 'This command can only be used in a server.');
                        }

                        const subCmd = (args[0] || '').toLowerCase();
                        const guildId = message.guild.id;

                        // --- Not the server owner ---
                        if (message.author.id !== message.guild.ownerId) {
                            console.log(`[BETA] Rejected: ${message.author.id} is not guild owner ${message.guild.ownerId}`);
                            const ownerOnlyEmbed = new EmbedBuilder()
                                .setColor(config.colors.error)
                                .setTitle('🔒 Owner Only')
                                .setDescription(
                                    'The `$beta` command can only be used by the **server owner**.\n\n' +
                                    'Beta access lets your server try out new features before they are released to everyone.'
                                )
                                .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                .setTimestamp();
                            return await safeBetaReply(message, { embeds: [ownerOnlyEmbed] });
                        }
                        // --- Server not on the allowed list ---
                        console.log(`[BETA] Checking isAllowed for guild ${guildId}...`);
                        const allowed = await betaManager.isAllowed(guildId);
                        console.log(`[BETA] isAllowed result: ${allowed}`);
                        if (!allowed) {
                            const notAllowedEmbed = new EmbedBuilder()
                                .setColor(config.colors.warning)
                                .setTitle('🚫 Beta Access Not Available')
                                .setDescription(
                                    'This server has **not been selected** for the PrimeBot Beta Program.\n\n' +
                                    'Beta access is invite-only and granted by the PrimeBot developers.\n' +
                                    `Join our [Support Server](${config.supportServer}) to learn more or request access.`
                                )
                                .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                .setTimestamp();
                            return await safeBetaReply(message, { embeds: [notAllowedEmbed] });
                        }

                        // --- $beta enable ---
                        if (subCmd === 'enable') {
                            if (await betaManager.isEnabled(guildId)) {
                                const alreadyOnEmbed = new EmbedBuilder()
                                    .setColor(config.colors.warning)
                                    .setTitle('⚠️ Already Enabled')
                                    .setDescription('Beta features are **already enabled** for this server.')
                                    .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                    .setTimestamp();
                                return await safeBetaReply(message, { embeds: [alreadyOnEmbed] });
                            }

                            const enableOk = await betaManager.enable(guildId);
                            if (!enableOk) {
                                const dbErrorEmbed = new EmbedBuilder()
                                    .setColor(config.colors.error)
                                    .setTitle('❌ Database Error')
                                    .setDescription('Failed to save beta settings. Please try again in a moment.')
                                    .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                    .setTimestamp();
                                return await safeBetaReply(message, { embeds: [dbErrorEmbed] });
                            }

                            // Append (beta) to bot nickname in this guild
                            try {
                                const me = message.guild.members.me;
                                const baseName = (me.nickname || client.user.username).replace(/ \(beta\)$/i, '');
                                await me.setNickname(`${baseName} (beta)`);
                            } catch {}

                            const enabledEmbed = new EmbedBuilder()
                                .setColor(config.colors.success)
                                .setTitle('✅ Beta Enabled')
                                .setDescription(
                                    '🎉 **Beta features are now enabled** for this server!\n\n' +
                                    'You now have early access to new features that are still being tested.\n' +
                                    'Please report any bugs in our [Support Server](' + config.supportServer + ').\n\n' +
                                    '> ⚠️ Beta features may be unstable or change at any time.'
                                )
                                .addFields(
                                    { name: '📋 Beta Features', value: (config.betaFeatures.length > 0 ? config.betaFeatures.map(f => `\`${prefix}${f}\``).join(', ') : '*No beta features configured yet.*'), inline: false },
                                    { name: '❌ To Disable', value: `Run \`${prefix}beta disable\``, inline: false }
                                )
                                .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                .setTimestamp();
                            return await safeBetaReply(message, { embeds: [enabledEmbed] });
                        }

                        // --- $beta disable ---
                        if (subCmd === 'disable') {
                            if (!(await betaManager.isEnabled(guildId))) {
                                const alreadyOffEmbed = new EmbedBuilder()
                                    .setColor(config.colors.warning)
                                    .setTitle('⚠️ Already Disabled')
                                    .setDescription('Beta features are **not currently enabled** for this server.')
                                    .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                    .setTimestamp();
                                return await safeBetaReply(message, { embeds: [alreadyOffEmbed] });
                            }

                            const disableOk = await betaManager.disable(guildId);
                            if (!disableOk) {
                                const dbErrorEmbed = new EmbedBuilder()
                                    .setColor(config.colors.error)
                                    .setTitle('❌ Database Error')
                                    .setDescription('Failed to save beta settings. Please try again in a moment.')
                                    .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                    .setTimestamp();
                                return await safeBetaReply(message, { embeds: [dbErrorEmbed] });
                            }

                            // Remove (beta) from bot nickname in this guild
                            try {
                                const me = message.guild.members.me;
                                const cleanName = (me.nickname || client.user.username).replace(/ \(beta\)$/i, '');
                                await me.setNickname(cleanName === client.user.username ? null : cleanName);
                            } catch {}

                            const disabledEmbed = new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle('🔕 Beta Disabled')
                                .setDescription(
                                    'Beta features have been **turned off** for this server.\n\n' +
                                    'You are now back on the standard release. Beta commands will no longer be accessible.\n\n' +
                                    `Run \`${prefix}beta enable\` at any time to re-enable beta.`
                                )
                                .setFooter({ text: `PrimeBot Beta Program • Version: ${config.version}` })
                                .setTimestamp();
                            return await safeBetaReply(message, { embeds: [disabledEmbed] });
                        }

                        // --- No valid subcommand — show status / help ---
                        const betaCurrentlyEnabled = await betaManager.isEnabled(guildId);
                        const statusEmbed = new EmbedBuilder()
                            .setColor(betaCurrentlyEnabled ? config.colors.success : config.colors.primary)
                            .setTitle('🔬 PrimeBot Beta Program')
                            .setDescription(
                                'The beta program gives selected servers early access to new features still in testing.\n\n' +
                                `**Current Status:** ${betaCurrentlyEnabled ? '🟢 Enabled' : '🔴 Disabled'}`
                            )
                            .addFields(
                                { name: `${prefix}beta enable`, value: 'Opt this server in to beta features', inline: true },
                                { name: `${prefix}beta disable`, value: 'Opt this server out of beta features', inline: true },
                                { name: '📋 Beta Features', value: (config.betaFeatures.length > 0 ? config.betaFeatures.map(f => `\`${prefix}${f}\``).join(', ') : '*No beta features configured yet.*'), inline: false }
                            )
                            .setFooter({ text: `PrimeBot Beta Program • Server Owner Only • Version: ${config.version}` })
                            .setTimestamp();
                        return await safeBetaReply(message, { embeds: [statusEmbed] });
                    } catch (betaErr) {
                        console.error('[BETA] Command error:', betaErr);
                        safeBetaReply(message, '❌ An error occurred running the beta command. Check the bot logs for details.').catch(() => {});
                    }
                    break;
                }

                case 'betaserver': {
                    try {
                        console.log(`[BETASERVER] Handling $betaserver from ${message.author.tag} (${message.author.id})`);
                        // Bot owner only
                        if (!config.developerIds.includes(message.author.id)) {
                            console.log(`[BETASERVER] Rejected: ${message.author.id} not in developerIds`);
                            return message.reply({
                                embeds: [new EmbedBuilder()
                                    .setColor(config.colors.error)
                                    .setTitle('❌ Access Denied')
                                    .setDescription('This command is restricted to bot developers only.')
                                    .setFooter({ text: `Version: ${config.version}` })
                                    .setTimestamp()]
                            });
                        }

                        const subCmd = (args[0] || '').toLowerCase();
                        const targetId = (args[1] || '').trim();
                        console.log(`[BETASERVER] subCmd=${subCmd} targetId=${targetId}`);

                        // ── $betaserver add <server_id> ──────────────────────────
                        if (subCmd === 'add') {
                            if (!targetId || !/^\d{17,20}$/.test(targetId)) {
                                return await safeBetaReply(message, {
                                    embeds: [
                                        new EmbedBuilder()
                                            .setColor(config.colors.error)
                                            .setTitle('❌ Invalid Usage')
                                            .setDescription(`Usage: \`${prefix}betaserver add <server_id>\`\nThe server ID must be a 17–20 digit number.`)
                                            .setTimestamp()
                                    ]
                                });
                            }

                            const guild = message.client.guilds.cache.get(targetId);
                            const displayName = guild?.name || `Server \`${targetId}\``;

                            const ok = await betaManager.allowServer(targetId);
                            if (!ok) {
                                return await safeBetaReply(message, {
                                    embeds: [
                                        new EmbedBuilder()
                                            .setColor(config.colors.error)
                                            .setTitle('❌ Database Error')
                                            .setDescription('Failed to add server to the beta allowed list. Please try again.')
                                            .setTimestamp()
                                    ]
                                });
                            }

                            return await safeBetaReply(message, {
                                embeds: [
                                    new EmbedBuilder()
                                        .setColor(config.colors.success)
                                        .setTitle('✅ Server Added to Beta')
                                        .setDescription(`**${displayName}** (\`${targetId}\`) can now opt in to beta features.`)
                                        .addFields({ name: 'Next step', value: `The server owner must run \`${prefix}beta enable\` in their server to activate beta features.`, inline: false })
                                        .setFooter({ text: `Added by ${message.author.tag}` })
                                        .setTimestamp()
                                ]
                            });
                        }

                        // ── $betaserver remove <server_id> ───────────────────────
                        if (subCmd === 'remove') {
                            if (!targetId || !/^\d{17,20}$/.test(targetId)) {
                                return await safeBetaReply(message, {
                                    embeds: [
                                        new EmbedBuilder()
                                            .setColor(config.colors.error)
                                            .setTitle('❌ Invalid Usage')
                                            .setDescription(`Usage: \`${prefix}betaserver remove <server_id>\`\nThe server ID must be a 17–20 digit number.`)
                                            .setTimestamp()
                                    ]
                                });
                            }

                            const guild = message.client.guilds.cache.get(targetId);
                            const displayName = guild?.name || `Server \`${targetId}\``;

                            const ok = await betaManager.denyServer(targetId);
                            if (!ok) {
                                return await safeBetaReply(message, {
                                    embeds: [
                                        new EmbedBuilder()
                                            .setColor(config.colors.error)
                                            .setTitle('❌ Database Error')
                                            .setDescription('Failed to remove server from the beta allowed list. Please try again.')
                                            .setTimestamp()
                                    ]
                                });
                            }

                            return await safeBetaReply(message, {
                                embeds: [
                                    new EmbedBuilder()
                                        .setColor(config.colors.primary)
                                        .setTitle('🚫 Server Removed from Beta')
                                        .setDescription(`**${displayName}** (\`${targetId}\`) has been removed from the beta allowed list.\nBeta features are also disabled for that server.`)
                                        .setFooter({ text: `Removed by ${message.author.tag}` })
                                        .setTimestamp()
                                ]
                            });
                        }

                        // ── $betaserver list ─────────────────────────────────────
                        if (subCmd === 'list') {
                            const rows = await betaManager.listAllowedServers();
                            const configSeeds = Array.isArray(config.betaServers) ? config.betaServers : [];
                            const allIds = [...new Set([...rows.map(r => r.guildId), ...configSeeds])];

                            if (allIds.length === 0) {
                                return await safeBetaReply(message, {
                                    embeds: [
                                        new EmbedBuilder()
                                            .setColor(config.colors.primary)
                                            .setTitle('🔬 Beta Allowed Servers')
                                            .setDescription('No servers are currently on the beta allowed list.')
                                            .setTimestamp()
                                    ]
                                });
                            }

                            const dbIds = new Set(rows.map(r => r.guildId));
                            const lines = allIds.map(id => {
                                const g       = message.client.guilds.cache.get(id);
                                const name    = g ? `**${g.name}**` : '*Unknown Server*';
                                const row     = rows.find(r => r.guildId === id);
                                const enabled = row?.enabled ? '🟢 beta on' : '🔴 beta off';
                                const source  = configSeeds.includes(id) && !dbIds.has(id) ? ' *(config)*' : '';
                                return `• ${name} \`${id}\` — ${enabled}${source}`;
                            });

                            const chunks = [];
                            for (let i = 0; i < lines.length; i += 10) chunks.push(lines.slice(i, i + 10));

                            const listEmbed = new EmbedBuilder()
                                .setColor(config.colors.primary)
                                .setTitle(`🔬 Beta Allowed Servers (${allIds.length})`)
                                .setTimestamp();

                            chunks.forEach((chunk, i) => {
                                listEmbed.addFields({
                                    name: chunks.length > 1 ? `Servers (${i + 1}/${chunks.length})` : 'Servers',
                                    value: chunk.join('\n'),
                                    inline: false
                                });
                            });

                            return await safeBetaReply(message, { embeds: [listEmbed] });
                        }

                        // ── No valid subcommand — show help ──────────────────────
                        return await safeBetaReply(message, {
                            embeds: [
                                new EmbedBuilder()
                                    .setColor(config.colors.primary)
                                    .setTitle('🔬 Beta Server Management')
                                    .addFields(
                                        { name: `${prefix}betaserver add <server_id>`,    value: 'Add a server to the beta allowed list',      inline: false },
                                        { name: `${prefix}betaserver remove <server_id>`, value: 'Remove a server from the beta allowed list',  inline: false },
                                        { name: `${prefix}betaserver list`,               value: 'List all servers on the beta allowed list',   inline: false }
                                    )
                                    .setFooter({ text: 'Bot owner only' })
                                    .setTimestamp()
                            ]
                        });
                    } catch (betaServerErr) {
                        console.error('[BETASERVER] Command error:', betaServerErr);
                        safeBetaReply(message, '❌ An error occurred running the betaserver command. Check the bot logs for details.').catch(() => {});
                    }
                    break;
                }

                default:
                    // Command not found - do nothing
          //          const errorEmbed = new EmbedBuilder()

                        //.setColor(config.colors.primary)

                        //.setTitle("ERROR")
//.setDescription("",)
              //     . addFields(
            //           {
//name: "Command not found",
//value: " The command you entered isn’t available. ",
            //               },
                 //     ), 

                            
     //                      return message.reply({ embeds: [errorEmbed] });
                    break;
            }
        } catch (error) {
            console.error("Error in messageCreate event:", error);
        }
    },
};

/**
 * Process a command with given arguments
 */
async function processCommand(message, client, commandName, args, prefix) {
    const config = require("../config");
    const { EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder } = require("discord.js");
    
    // Handle commands based on commandName
    switch (commandName) {
        case "help":
            // Check if user wants a specific category
            const category = args[0]?.toLowerCase();
            
            // If category is provided, show category-specific help
            if (category && ['general', 'leveling', 'games', 'moderation', 'community', 'admin'].includes(category)) {
                return showPrefixCategoryHelp(message, category, prefix);
            }
            
            // Show main category menu
            const categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('📚 Command Categories')
                .setDescription(`Choose a category to explore available commands:\n\n**Usage:** \`${prefix}help [category]\``)
                .addFields(
                    { name: '⚡ General', value: `\`${prefix}help general\`\nBasic bot commands and information`, inline: true },
                    { name: '📊 Leveling', value: `\`${prefix}help leveling\`\nXP, ranks, and progression system`, inline: true },
                    { name: '🎮 Games', value: `\`${prefix}help games\`\nFun interactive games and activities`, inline: true },
                    { name: '🛡️ Moderation', value: `\`${prefix}help moderation\`\nServer management and moderation tools`, inline: true },
                    { name: '👥 Community', value: `\`${prefix}help community\`\nEngagement and social features`, inline: true },
                    { name: '⚙️ Administration', value: `\`${prefix}help admin\`\nAdvanced server configuration`, inline: true }
                )
                .setFooter({ text: `Total Commands: 30+ • Version: ${config.version}` })
                .setTimestamp();

            return message.reply({ embeds: [categoryEmbed] });
            
        case "ping":
            try {
                const loadingEmbed = new EmbedBuilder()
                    .setColor(config.colors.primary)
                    .setTitle('📡 Measuring latency…')
                    .setDescription('> Pinging Discord gateway and database…');
                    
                const sentMessage = await message.channel.send({ embeds: [loadingEmbed] });
                const ping = sentMessage.createdTimestamp - message.createdTimestamp;
                const apiPing = Math.round(client.ws.ping);

                // Colour by overall health
                let color = config.colors.success;
                if (ping > 500) color = config.colors.error;
                else if (ping > 200) color = config.colors.warning;

                // Visual latency bar (10 segments, 1 per 60ms)
                const makeBar = (ms) => {
                    if (typeof ms !== 'number') return '`░░░░░░░░░░`';
                    const fill = Math.min(Math.ceil(ms / 60), 10);
                    return '`' + '█'.repeat(fill) + '░'.repeat(10 - fill) + '`';
                };

                // Fetch all node statuses + lease in parallel
                let nodesValue = '⚪ Unavailable';
                try {
                    const [sn1Status, sn2Status, sn3Status, lease] = await Promise.all([
                        nodeFailover.getStatus('sn1'),
                        nodeFailover.getStatus('sn2'),
                        nodeFailover.getStatus('sn3'),
                        nodeFailover.getLease()
                    ]);
                    const nodeRow = (role, status) => {
                        if (!status) return `⚪ **${role}** — never reported`;
                        const ageSec = Math.round(Number(status.age_ms) / 1000);
                        const isHolder = lease && lease.ownerRole === role;
                        if (isHolder) {
                            const icon = ageSec > nodeFailover.FAILOVER_THRESHOLD_MS / 1000 ? '🔴' : '🟢';
                            return `${icon} **${role}** \`${status.node_name}\` — Active, ${ageSec}s ago 🔑`;
                        }
                        return `🟠 **${role}** \`${status.node_name}\` — Standby`;
                    };
                    nodesValue = [
                        nodeRow('sn1', sn1Status),
                        nodeRow('sn2', sn2Status),
                        nodeRow('sn3', sn3Status),
                    ].join('\n');
                } catch (_) {}

                const overallStatus = ping <= 200
                    ? '🟢 All systems operational'
                    : ping <= 500 ? '🟡 Moderate latency' : '🔴 High latency detected';

                const pingEmbed = new EmbedBuilder()
                    .setColor(color)
                    .setTitle('📡  Connection Status')
                    .setDescription(`${overallStatus}\n\u200b`)
                    .addFields(
                        { name: '⚡ Bot Latency', value: `**${ping}ms**\n${makeBar(ping)}`, inline: true },
                        { name: '🔌 Gateway',     value: `**${apiPing}ms**\n${makeBar(apiPing)}`, inline: true },
                        { name: '🌐 Servers',     value: `**${client.guilds.cache.size.toLocaleString()}**\n👥 ${client.guilds.cache.reduce((a, g) => a + g.memberCount, 0).toLocaleString()} users`, inline: true },
                        { name: '🖥️ Failover Nodes', value: nodesValue, inline: false }
                    )
                    .setFooter({ 
                        text: `Requested by ${message.author.tag}`,
                        iconURL: message.author.displayAvatarURL() 
                    })
                    .setTimestamp();
                
                return sentMessage.edit({ embeds: [pingEmbed] });
            } catch (error) {
                console.error("Error handling ping:", error);
                return message.reply("Sorry, I encountered an error while processing your ping. Please try again later.");
            }
            
        case "about":
        case "ab":
            const prefixAboutEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle("About PrimeBot")
                .setDescription("A sophisticated Discord bot for community engagement")
                .addFields(
                    { name: "Version", value: config.version, inline: true },
                    { name: "Servers", value: client.guilds.cache.size.toString(), inline: true },
                    { name: "Users", value: client.guilds.cache.reduce((acc, guild) => acc + guild.memberCount, 0).toLocaleString(), inline: true },
                    { name: "Uptime", value: formatUptime(process.uptime()), inline: true }
                )
                .setFooter({ text: `Version: ${config.version}` })
                .setTimestamp();

            return message.reply({ embeds: [prefixAboutEmbed] });
            
        case "echo":
            if (args.length < 1) {
                return message.reply("Please provide a message to echo.");
            }
            
            const echoMessage = args.join(" ");
            await message.channel.send(echoMessage);
            
            const confirmEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setDescription("✅ Message echoed successfully!")
                .setFooter({ text: `Version: ${config.version}` });

            const reply = await message.reply({ embeds: [confirmEmbed] });
            setTimeout(() => {
                reply.delete().catch(() => {});
            }, 3000);
            break;
            
        default:
            // Command not recognized in no-prefix mode
            break;
    }
}

/**
 * Format uptime in a readable format
 */
function formatUptime(uptime) {
    const seconds = Math.floor(uptime % 60);
    const minutes = Math.floor((uptime / 60) % 60);
    const hours = Math.floor((uptime / 3600) % 24);
    const days = Math.floor(uptime / 86400);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (seconds > 0) parts.push(`${seconds}s`);

    return parts.join(" ") || "0s";
}

/**
 * Show category-specific help for prefix commands
 */
async function showPrefixCategoryHelp(message, category, prefix) {
    const config = require('../config');
    const { EmbedBuilder } = require('discord.js');
    
    let categoryEmbed;
    
    switch (category) {
        case 'general':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('⚡ General Commands')
                .setDescription('Basic bot commands and information:')
                .addFields(
                    { name: `${prefix}help [category]`, value: 'Show this categorized command menu', inline: true },
                    { name: `${prefix}about`, value: 'Information about the bot', inline: true },
                    { name: `${prefix}updates`, value: 'Latest bot updates and features', inline: true },
                    { name: `${prefix}ses`, value: 'Bot session and status information', inline: true },
                    { name: `${prefix}ping`, value: 'Check bot latency and response time', inline: true },
                    { name: `${prefix}np [duration]`, value: 'Enable no-prefix mode for easier commands', inline: true }
                );
            break;
            
        case 'leveling':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Leveling System')
                .setDescription('XP, ranks, and progression commands:')
                .addFields(
                    { name: `${prefix}rank [@user]`, value: 'View your or another user\'s level and XP', inline: true },
                    { name: `${prefix}leaderboard [page]`, value: 'Server XP leaderboard with pagination', inline: true },
                    { name: `${prefix}badges [@user]`, value: 'View available and earned badges', inline: true },
                    { name: `${prefix}profile [@user]`, value: 'Detailed user stats and progression', inline: true },
                    { name: `${prefix}level [@user]`, value: 'Alias for rank command', inline: true },
                    { name: `${prefix}exp [@user]`, value: 'Another alias for rank command', inline: true },
                    { name: `${prefix}sync`, value: 'Sync roles and badges with levels (Admin)', inline: true },
                    { name: `${prefix}level-enable`, value: 'Enable leveling system (Admin)', inline: true },
                    { name: `${prefix}level-disable`, value: 'Disable leveling system (Admin)', inline: true }
                );
            break;
            
        case 'games':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.warning)
                .setTitle('🎮 Games & Activities')
                .setDescription('Fun interactive games and entertainment:')
                .addFields(
                    { name: `${prefix}tictactoe`, value: 'Start a TicTacToe game in the channel', inline: true },
                    { name: `${prefix}move [1-9]`, value: 'Make a move in active TicTacToe game', inline: true },
                    { name: `${prefix}tend`, value: 'End current TicTacToe game', inline: true },
                    { name: `${prefix}truthdare`, value: 'Interactive Truth or Dare game', inline: true },
                    { name: `${prefix}qadd [type] [question]`, value: 'Add custom truth/dare questions', inline: true },
                    { name: `${prefix}cstart [start] [goal]`, value: 'Start a number counting game', inline: true },
                    { name: `${prefix}cstatus`, value: 'Check counting game status', inline: true },
                    { name: `${prefix}cend`, value: 'End counting game (Admin)', inline: true },
                    { name: `${prefix}poll [time] [question]`, value: 'Create interactive polls with timer', inline: true }
                );
            break;
            
        case 'moderation':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.secondary)
                .setTitle('🛡️ Moderation Tools')
                .setDescription('Server management and moderation:')
                .addFields(
                    { name: `${prefix}ticket`, value: 'Create ticket support panel', inline: true },
                    { name: `${prefix}createticket [name]`, value: 'Create ticket with custom name', inline: true },
                    { name: `${prefix}thistory [page]`, value: 'View ticket history and logs', inline: true },
                    { name: `${prefix}move`, value: 'Move members between voice channels', inline: true },
                    { name: `${prefix}end [id]`, value: 'End giveaways and other activities', inline: true },
                    { name: `${prefix}endpoll [id]`, value: 'End a poll early', inline: true },
                    { name: `${prefix}autoreact`, value: 'Manage auto-reactions to trigger words', inline: true },
                    { name: `${prefix}snipe`, value: 'Show the last deleted message in a channel', inline: true },
                    { name: `${prefix}kick @member [reason]`, value: 'Kick a member from the server', inline: true },
                    { name: `${prefix}ban @member [reason] [days]`, value: 'Ban a member from the server', inline: true },
                    { name: `${prefix}rm [name] [#channel]`, value: 'Rename a channel (Admin)', inline: true },
                    { name: `${prefix}lock [#channel]`, value: 'Lock a channel (Admin)', inline: true },
                    { name: `${prefix}unlock [#channel]`, value: 'Unlock a channel (Admin)', inline: true },
                    { name: `${prefix}hide [#channel]`, value: 'Hide a channel from @everyone (Admin)', inline: true },
                    { name: `${prefix}unhide [#channel]`, value: 'Unhide a channel for @everyone (Admin)', inline: true },
                    { name: `${prefix}nuke [name] [#channel]`, value: 'Recreate a channel in the same category (Admin)', inline: true }
                );
            break;
            
        case 'community':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('👥 Community Features')
                .setDescription('Engagement and social features:')
                .addFields(
                    { name: `${prefix}poll "[question]" option1 option2`, value: 'Create server polls with voting', inline: true },
                    { name: `${prefix}lpoll create "[question]" option1 option2`, value: 'Create cross-server live polls', inline: true },
                    { name: `${prefix}lpoll join [poll-id]`, value: 'Join existing live poll', inline: true },
                    { name: `${prefix}giveaway`, value: 'View giveaway commands', inline: true },
                    { name: `${prefix}gstart [time] [winners] [prize]`, value: 'Create exciting giveaways', inline: true },
                    { name: `${prefix}reroll [id]`, value: 'Reroll giveaway winners', inline: true },
                    { name: `${prefix}birthday`, value: 'Birthday celebration system', inline: true },
                    { name: `${prefix}birthday set [date]`, value: 'Set your birthday', inline: true },
                    { name: `${prefix}birthday list`, value: 'View upcoming birthdays', inline: true },
                    { name: `${prefix}welcomeconfig`, value: 'Configure welcome messages', inline: true },
                    { name: `${prefix}broadcast`, value: 'Send announcements (Owner)', inline: true }
                );
            break;
            
        case 'admin':
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('⚙️ Administration')
                .setDescription('Advanced server configuration (Admin only):')
                .addFields(
                    { name: `${prefix}welcome-enable`, value: 'Enable welcome system', inline: true },
                    { name: `${prefix}welcome-disable`, value: 'Disable welcome system', inline: true },
                    { name: `${prefix}welcome-channel #channel`, value: 'Set welcome message channel', inline: true },
                    { name: `${prefix}level-enable`, value: 'Enable leveling system', inline: true },
                    { name: `${prefix}level-disable`, value: 'Disable leveling system', inline: true },
                    { name: `${prefix}level-multiplier [number]`, value: 'Set XP multiplier', inline: true },
                    { name: `${prefix}autoreact enable/disable`, value: 'Configure auto-reactions', inline: true },
                    { name: `${prefix}broadcastsettings`, value: 'Configure broadcast settings', inline: true }
                );
            break;
            
        default:
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('❌ Unknown Category')
                .setDescription(`The category "${category}" was not found. Available categories: general, leveling, games, moderation, community, admin`);
    }
    
    categoryEmbed
        .setFooter({ text: `Use ${prefix}help to see all categories • Version: ${config.version}` })
        .setTimestamp();
    
    return message.reply({ embeds: [categoryEmbed] });
}

/**
 * Show detailed category-specific help for prefix commands
 */
async function showDetailedCategoryHelp(message, category, prefix) {
    const config = require('../config');
    const { EmbedBuilder } = require('discord.js');
    
    let categoryEmbed;
    let commandCount = 0;

    switch (category) {
        case 'general':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('⚡ General Commands - Detailed View')
                .setDescription('Essential bot commands for everyday use. These commands provide basic information and utility functions.')
                .addFields(
                    { name: `${prefix}help [category]`, value: '**Shows categorized command menu**\nQuickly browse all available commands by category', inline: false },
                    { name: `${prefix}about`, value: '**Displays bot information and statistics**\nView bot uptime, server count, and version details', inline: false },
                    { name: `${prefix}updates`, value: '**Shows latest bot updates and features**\nStay informed about new features and improvements', inline: false },
                    { name: `${prefix}ses`, value: '**Bot session and status information**\nDetailed technical information about bot performance', inline: false },
                    { name: `${prefix}echo [message]`, value: '**Makes the bot repeat your message**\nUseful for announcements and formatted messages', inline: false }
                );
            break;
            
        case 'leveling':
            commandCount = 9;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Leveling System - Detailed View')
                .setDescription('Comprehensive XP and ranking system to encourage server activity and engagement.')
                .addFields(
                    { name: `${prefix}rank [@user]`, value: '**View user level and XP progress**\nCheck your current level, XP, and progress to next level', inline: false },
                    { name: `${prefix}leaderboard [page]`, value: '**Server XP leaderboard with pagination**\nSee top-ranked members and their achievements', inline: false },
                    { name: `${prefix}badges [@user]`, value: '**View and manage achievement badges**\nDisplay special badges earned through activities', inline: false },
                    { name: `${prefix}level-enable`, value: '**Enable leveling system (Admin)**\nActivate XP tracking and level progression', inline: false },
                    { name: `${prefix}level-disable`, value: '**Disable leveling system (Admin)**\nTurn off XP tracking and level progression', inline: false },
                    { name: `${prefix}level-channel #channel`, value: '**Set level-up notification channel (Admin)**\nConfigure where level-up messages are sent', inline: false },
                    { name: `${prefix}level-multiplier [number]`, value: '**Set XP multiplier (Admin)**\nAdjust how much XP users gain from messages', inline: false },
                    { name: `${prefix}award-xp @user [amount]`, value: '**Award XP to users (Admin)**\nManually give XP to users for special contributions', inline: false },
                    { name: `${prefix}award-badge @user [badge]`, value: '**Award badges to users (Admin)**\nGrant special achievement badges to deserving members', inline: false }
                );
            break;
            
        case 'games':
            commandCount = 4;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.warning)
                .setTitle('🎮 Games & Activities - Detailed View')
                .setDescription('Interactive games and fun activities to boost server engagement and entertainment.')
                .addFields(
                    { name: `${prefix}tictactoe @user`, value: '**Classic Tic-Tac-Toe game**\nPlay against other members with interactive reactions', inline: false },
                    { name: `${prefix}truthdare`, value: '**Truth or Dare game with custom questions**\nAdd your own questions or use the built-in database', inline: false },
                    { name: `${prefix}counting [start]`, value: '**Number counting game**\nServer-wide counting game with streak tracking', inline: false },
                    { name: `${prefix}poll [question] [options]`, value: '**Create interactive polls with timers**\nGather opinions with customizable voting options', inline: false }
                );
            break;
            
        case 'moderation':
            commandCount = 14;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.secondary)
                .setTitle('🛡️ Moderation Tools - Detailed View')
                .setDescription('Comprehensive moderation and server management tools for maintaining order and providing support.')
                .addFields(
                    { name: `${prefix}ticket-setup`, value: '**Create ticket support system**\nSet up support channels with automatic categorization', inline: false },
                    { name: `${prefix}create-ticket [reason]`, value: '**Create ticket with custom name**\nInstantly create a support ticket with specific purpose', inline: false },
                    { name: `${prefix}ticket-history [@user]`, value: '**View ticket history and logs**\nReview past tickets and support interactions', inline: false },
                    { name: `${prefix}move @user #channel`, value: '**Move members between voice channels**\nQuickly relocate users to different voice channels', inline: false },
                    { name: `${prefix}end [activity]`, value: '**End ongoing activities**\nStop giveaways, polls, or other time-based activities', inline: false },
                    { name: `${prefix}snipe [#channel]`, value: '**Inspect the last deleted reply in a channel**\nRecover the last removed message snapshot from the channel cache', inline: false },
                    { name: `${prefix}kick @member [reason]`, value: '**Kick a member**\nRemove a member from the server with a reason', inline: false },
                    { name: `${prefix}ban @member [reason] [days]`, value: '**Ban a member**\nBan a user and optionally purge recent messages', inline: false },
                    { name: `${prefix}rm [name] [#channel]`, value: '**Rename a channel (Admin)**\nChange the target channel name', inline: false },
                    { name: `${prefix}lock [#channel]`, value: '**Lock a channel (Admin)**\nStop @everyone from posting', inline: false },
                    { name: `${prefix}unlock [#channel]`, value: '**Unlock a channel (Admin)**\nRestore posting for @everyone', inline: false },
                    { name: `${prefix}hide [#channel]`, value: '**Hide a channel from @everyone (Admin)**\nRestrict visibility to configured roles', inline: false },
                    { name: `${prefix}unhide [#channel]`, value: '**Unhide a channel for @everyone (Admin)**\nRestore visibility to everyone', inline: false },
                    { name: `${prefix}nuke [name] [#channel]`, value: '**Nuke a channel and recreate it (Admin)**\nDelete and restore the channel in-place', inline: false }
                );
            break;
            
        case 'community':
            commandCount = 8;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('👥 Community Features - Detailed View')
                .setDescription('Tools to build and engage your community with special events and social features.')
                .addFields(
                    { name: `${prefix}poll "[question]" option1 option2 [time]`, value: '**Create server polls with voting**\nEngage members with interactive polls and gather opinions', inline: false },
                    { name: `${prefix}lpoll create "[question]" option1 option2`, value: '**Create cross-server live polls**\nShare polls across multiple servers with unique poll codes', inline: false },
                    { name: `${prefix}lpoll join [poll-id/code]`, value: '**Join existing live polls**\nParticipate in polls from other servers using poll ID or code', inline: false },
                    { name: `${prefix}giveaway [prize] [duration]`, value: '**Create giveaways with role requirements**\nHost exciting giveaways with customizable entry requirements', inline: false },
                    { name: `${prefix}reroll [giveaway-id]`, value: '**Reroll giveaway winners**\nSelect new winners if original winners are unavailable', inline: false },
                    { name: `${prefix}birthday set [date]`, value: '**Birthday celebration system**\nTrack and celebrate member birthdays automatically', inline: false },
                    { name: `${prefix}welcome-config`, value: '**Configure welcome messages**\nCustomize welcome messages for new server members', inline: false },
                    { name: `${prefix}broadcast [message]`, value: '**Send announcements to all servers**\nShare important updates across multiple servers', inline: false }
                );
            break;
            
        case 'admin':
            commandCount = 8;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('⚙️ Administration - Detailed View')
                .setDescription('Advanced server configuration and management tools. Requires administrator permissions.')
                .addFields(
                    { name: `${prefix}welcome-enable`, value: '**Enable welcome system**\nActivate welcome messages for new members', inline: false },
                    { name: `${prefix}welcome-disable`, value: '**Disable welcome system**\nTurn off welcome messages for new members', inline: false },
                    { name: `${prefix}welcome-channel #channel`, value: '**Set welcome message channel**\nConfigure where welcome messages are sent', inline: false },
                    { name: `${prefix}broadcastsettings`, value: '**Configure broadcast system settings**\nSet up cross-server announcement preferences', inline: false },
                    { name: `${prefix}autoreact enable`, value: '**Enable auto-reactions**\nActivate automatic emoji reactions to trigger words', inline: false },
                    { name: `${prefix}autoreact disable`, value: '**Disable auto-reactions**\nTurn off automatic emoji reactions', inline: false },
                    { name: `${prefix}autoreact add [word] [emoji]`, value: '**Add auto-reaction trigger**\nSet up new automatic reactions to specific words', inline: false },
                    { name: `${prefix}autoreact remove [word]`, value: '**Remove auto-reaction trigger**\nRemove existing automatic reaction triggers', inline: false }
                );
            break;
            
        default:
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('❌ Unknown Category')
                .setDescription(`The category "${category}" was not found. Available categories: general, leveling, games, moderation, community, admin`);
    }

    if (categoryEmbed && category !== 'unknown') {
        categoryEmbed.addFields({
            name: '📈 Category Information',
            value: `**Commands in this category:** ${commandCount}\n**Usage Level:** ${getCategoryUsageLevel(category)}\n**Permission Level:** ${getCategoryPermissionLevel(category)}\n**Prefix:** \`${prefix}\``,
            inline: true
        });
    }

    categoryEmbed.setFooter({ text: `Use ${prefix}cat to see all categories • Version: ${config.version}` })
               .setTimestamp();

    return message.reply({ embeds: [categoryEmbed] });
}

/**
 * Get usage level description for category
 */
function getCategoryUsageLevel(category) {
    const levels = {
        'general': 'Beginner Friendly',
        'leveling': 'Intermediate',
        'games': 'Beginner Friendly',
        'moderation': 'Intermediate',
        'community': 'Intermediate',
        'admin': 'Advanced'
    };
    return levels[category] || 'Unknown';
}

/**
 * Get permission level description for category
 */
function getCategoryPermissionLevel(category) {
    const permissions = {
        'general': 'Everyone',
        'leveling': 'Members/Moderators',
        'games': 'Everyone',
        'moderation': 'Moderators',
        'community': 'Moderators',
        'admin': 'Administrators'
    };
    return permissions[category] || 'Unknown';
}

// Live Poll Handler Functions

/**
 * Handle live poll create command
 */
async function handleLivePollCreate(message, args, prefix, client) {
    const ms = require('ms');
    
    if (args.length < 3) {
        return message.reply(`**Correct Usage:** \`${prefix}lpoll create [question] [option1] [option2] [option3] [duration] [multiple_votes]\`\n**Example:** \`${prefix}lpoll create "Favorite game?" Minecraft Fortnite Valorant 2h true\``);
    }

    // Parse arguments similar to regular poll
    let question, options, duration = null, allowMultipleVotes = false; // Live polls don't expire by default
    
    // If first arg has quotes, extract the full quoted question
    if (args[0].startsWith('"')) {
        const fullMessage = args.join(' ');
        const questionMatch = fullMessage.match(/"([^"]+)"/);
        if (questionMatch) {
            question = questionMatch[1];
            // Get remaining args after the quoted question
            const remainingArgs = fullMessage.replace(questionMatch[0], '').trim().split(/\s+/).filter(arg => arg);
            options = [...remainingArgs];
        } else {
            question = args[0].replace(/"/g, '');
            options = args.slice(1);
        }
    } else {
        // No quotes - first word is question, rest are options
        question = args[0];
        options = args.slice(1);
    }

    // Check if last option is actually multiple_votes boolean
    if (options.length > 0) {
        const lastOption = options[options.length - 1].toLowerCase();
        if (lastOption === 'true' || lastOption === 'multi' || lastOption === 'multiple') {
            allowMultipleVotes = true;
            options = options.slice(0, -1); // Remove multiple_votes from options
        } else if (lastOption === 'false' || lastOption === 'single') {
            allowMultipleVotes = false;
            options = options.slice(0, -1); // Remove multiple_votes from options
        }
    }

    // Check if last remaining option is actually a duration
    if (options.length > 0) {
        const lastOption = options[options.length - 1];
        const parsedDuration = ms(lastOption);
        if (parsedDuration && parsedDuration > 60000) { // At least 1 minute
            duration = parsedDuration;
            options = options.slice(0, -1); // Remove duration from options
        }
    }

    if (options.length < 2) {
        return message.reply('Please provide at least 2 options for your live poll.');
    }

    if (options.length > 10) {
        return message.reply('You can have a maximum of 10 options.');
    }

    try {
        const result = await client.livePollManager.createLivePoll({
            question,
            options,
            creatorId: message.author.id,
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
                { name: '🔗 Share Info', value: 'Share the **Poll ID** or **Pass Code** to let others vote!', inline: false },
                { name: '📝 Options', value: options.map((opt, i) => `**${i + 1}.** ${opt}`).join('\n'), inline: false }
            )
            .setFooter({ 
                text: `Created by ${message.author.tag} • Version ${config.version}`, 
                iconURL: message.author.displayAvatarURL({ dynamic: true }) 
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

        // Send confirmation message first
        await message.reply({ embeds: [embed] });

        // Get poll data and create voting interface
        const pollData = await client.livePollManager.getPoll(result.pollId);
        if (pollData) {
            const votingEmbed = client.livePollManager.createPollEmbed(
                pollData, 
                pollData.options, 
                0, 
                false
            );
            const buttons = client.livePollManager.createVoteButtons(result.pollId, pollData.options);

            // Send separate message with voting interface
            const votingMessage = await message.channel.send({
                embeds: [votingEmbed],
                components: buttons
            });

            // Store the message information for expiration updates
            await client.livePollManager.updatePollMessage(
                result.pollId, 
                votingMessage.id, 
                message.channel.id
            );
        }
    } catch (error) {
        console.error('Error creating live poll:', error);
        return message.reply('There was an error creating the live poll. Please try again later.');
    }
}

/**
 * Handle live poll join command
 */
async function handleLivePollJoin(message, args, prefix, client) {
    if (args.length < 1) {
        return message.reply(`**Correct Usage:** \`${prefix}lpoll join <poll_id_or_passcode>\``);
    }

    const identifier = args[0];

    try {
        const pollData = await client.livePollManager.getPoll(identifier);

        if (!pollData) {
            return message.reply('Poll not found. Please check the Poll ID or Pass Code.');
        }

        if (!pollData.isActive) {
            return message.reply('This poll has ended.');
        }

        if (pollData.expiresAt && new Date() > new Date(pollData.expiresAt)) {
            return message.reply('This poll has expired.');
        }

        const embed = client.livePollManager.createPollEmbed(pollData, pollData.options);
        const buttons = client.livePollManager.createVoteButtons(pollData.pollId, pollData.options);

        await message.reply({
            embeds: [embed],
            components: buttons
        });
    } catch (error) {
        console.error('Error joining live poll:', error);
        return message.reply('There was an error accessing the poll. Please try again later.');
    }
}

/**
 * Handle live poll results command
 */
async function handleLivePollResults(message, args, prefix, client) {
    if (args.length < 1) {
        return message.reply(`**Correct Usage:** \`${prefix}lpoll results <poll_id_or_passcode>\``);
    }

    const identifier = args[0];

    try {
        const results = await client.livePollManager.getPollResults(identifier);

        if (!results) {
            return message.reply('Poll not found. Please check the Poll ID or Pass Code.');
        }

        const embed = client.livePollManager.createPollEmbed(
            results.poll, 
            results.options, 
            results.totalVotes, 
            true
        );

        await message.reply({ embeds: [embed] });
    } catch (error) {
        console.error('Error getting live poll results:', error);
        return message.reply('There was an error retrieving poll results. Please try again later.');
    }
}

/**
 * Handle live poll end command
 */
async function handleLivePollEnd(message, args, prefix, client) {
    if (args.length < 1) {
        return message.reply(`**Correct Usage:** \`${prefix}lpoll end <poll_id>\``);
    }

    const pollId = args[0];

    try {
        const result = await client.livePollManager.endPoll(pollId, message.author.id);

        if (!result.success) {
            return message.reply(result.message);
        }

        // Show winning celebration if there are results
        if (result.results && result.results.totalVotes > 0) {
            const winningEmbed = client.livePollManager.createPollEmbed(
                result.results.poll, 
                result.results.options, 
                result.results.totalVotes, 
                true,
                true // Show as winning announcement
            );
            
            await message.reply({ embeds: [winningEmbed] });
        } else {
            // Regular end message if no votes
            const embed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Poll Ended')
                .setDescription(`Poll \`${pollId}\` has been successfully ended.\n\nNo votes were cast for this poll.`)
                .setFooter({ 
                    text: `Ended by ${message.author.tag} • Version ${config.version}`, 
                    iconURL: message.author.displayAvatarURL({ dynamic: true }) 
                })
                .setTimestamp();

            await message.reply({ embeds: [embed] });
        }
    } catch (error) {
        console.error('Error ending live poll:', error);
        return message.reply('There was an error ending the poll. Please try again later.');
    }
}

/**
 * Handle live poll list command
 */
async function handleLivePollList(message, args, prefix, client) {
    try {
        const polls = await client.livePollManager.getUserPolls(message.author.id);

        if (polls.length === 0) {
            return message.reply('You haven\'t created any live polls yet.');
        }

        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('📊 Your Live Polls')
            .setDescription('Here are your created polls:')
            .setFooter({ 
                text: `Requested by ${message.author.tag} • Version ${config.version}`, 
                iconURL: message.author.displayAvatarURL({ dynamic: true }) 
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

        await message.reply({ embeds: [embed] });
    } catch (error) {
        console.error('Error listing live polls:', error);
        return message.reply('There was an error retrieving your polls. Please try again later.');
    }
}

/**
 * Show detailed category help for prefix commands
 */
async function showDetailedCategoryHelp(message, category, prefix) {
    const config = require('../config');
    const { EmbedBuilder } = require('discord.js');
    
    let categoryEmbed;
    let commandCount = 0;

    switch (category) {
        case 'general':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('⚡ General Commands - Detailed View')
                .setDescription('Essential bot commands for everyday use. These commands provide basic information and utility functions.')
                .addFields(
                    { name: `${prefix}help [category]`, value: '**Shows categorized command menu**\nQuickly browse all available commands by category', inline: false },
                    { name: `${prefix}about`, value: '**Displays bot information and statistics**\nView bot uptime, server count, and version details', inline: false },
                    { name: `${prefix}updates`, value: '**Shows latest bot updates and features**\nStay informed about new features and improvements', inline: false },
                    { name: `${prefix}ses`, value: '**Bot session and status information**\nDetailed technical information about bot performance', inline: false },
                    { name: `${prefix}np [duration]`, value: '**Enable no-prefix mode temporarily**\nUse commands without prefix for specified minutes', inline: false }
                );
            break;
            
        case 'leveling':
            commandCount = 9;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Leveling System - Detailed View')
                .setDescription('Comprehensive XP and ranking system to encourage server activity and engagement.')
                .addFields(
                    { name: `${prefix}rank [@user]`, value: '**View user level and XP progress**\nCheck your current level, XP, and progress to next level', inline: false },
                    { name: `${prefix}leaderboard [page]`, value: '**Server XP leaderboard with pagination**\nSee top-ranked members and their achievements', inline: false },
                    { name: `${prefix}badges [@user]`, value: '**View and manage achievement badges**\nDisplay special badges earned through activities', inline: false },
                    { name: `${prefix}set-level @user [level]`, value: '**Set user level (Admin)**\nManually set a user\'s level and XP', inline: false },
                    { name: `${prefix}award-badge @user [type] [id]`, value: '**Award badges to users (Admin)**\nGrant special achievement badges to deserving members', inline: false },
                    { name: `${prefix}revoke-badge @user [id]`, value: '**Revoke badges from users (Admin)**\nRemove badges from users if needed', inline: false }
                );
            break;
            
        case 'games':
            commandCount = 4;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.warning)
                .setTitle('🎮 Games & Activities - Detailed View')
                .setDescription('Interactive games and fun activities to boost server engagement and entertainment.')
                .addFields(
                    { name: `${prefix}tictactoe @user`, value: '**Classic Tic-Tac-Toe game**\nPlay against other members with interactive buttons', inline: false },
                    { name: `${prefix}truthdare`, value: '**Truth or Dare game with custom questions**\nAdd your own questions or use the built-in database', inline: false },
                    { name: `${prefix}cstart [start] [goal]`, value: '**Number counting game**\nServer-wide counting game with streak tracking', inline: false },
                    { name: `${prefix}poll [question] [options]`, value: '**Create interactive polls with timers**\nGather opinions with customizable voting options', inline: false }
                );
            break;
            
        case 'moderation':
            commandCount = 14;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.secondary)
                .setTitle('🛡️ Moderation Tools - Detailed View')
                .setDescription('Comprehensive moderation and server management tools for maintaining order and providing support.')
                .addFields(
                    { name: `${prefix}ticket-setup`, value: '**Create ticket support system**\nSet up support channels with automatic categorization', inline: false },
                    { name: `${prefix}create-ticket [reason]`, value: '**Create ticket with custom name**\nInstantly create a support ticket with specific purpose', inline: false },
                    { name: `${prefix}ticket-history [@user]`, value: '**View ticket history and logs**\nReview past tickets and support interactions', inline: false },
                    { name: `${prefix}move @user #channel`, value: '**Move members between voice channels**\nQuickly relocate users to different voice channels', inline: false },
                    { name: `${prefix}end [activity]`, value: '**End ongoing activities**\nStop giveaways, polls, or other time-based activities', inline: false },
                    { name: `${prefix}snipe [#channel]`, value: '**Inspect the last deleted reply in a channel**\nRecover the last removed message snapshot from the channel cache', inline: false },
                    { name: `${prefix}kick @member [reason]`, value: '**Kick a member**\nRemove a member from the server with a reason', inline: false },
                    { name: `${prefix}ban @member [reason] [days]`, value: '**Ban a member**\nBan a user and optionally purge recent messages', inline: false },
                    { name: `${prefix}rm [name] [#channel]`, value: '**Rename a channel (Admin)**\nChange the target channel name', inline: false },
                    { name: `${prefix}lock [#channel]`, value: '**Lock a channel (Admin)**\nStop @everyone from posting', inline: false },
                    { name: `${prefix}unlock [#channel]`, value: '**Unlock a channel (Admin)**\nRestore posting for @everyone', inline: false },
                    { name: `${prefix}hide [#channel]`, value: '**Hide a channel from @everyone (Admin)**\nRestrict visibility to configured roles', inline: false },
                    { name: `${prefix}unhide [#channel]`, value: '**Unhide a channel for @everyone (Admin)**\nRestore visibility to everyone', inline: false },
                    { name: `${prefix}nuke [name] [#channel]`, value: '**Nuke a channel and recreate it (Admin)**\nDelete and restore the channel in-place', inline: false }
                );
            break;
            
        case 'community':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('👥 Community Features - Detailed View')
                .setDescription('Tools to build and engage your community with special events and social features.')
                .addFields(
                    { name: `${prefix}gstart [duration] [winners] [prize]`, value: '**Create giveaways with role requirements**\nHost exciting giveaways with customizable entry requirements', inline: false },
                    { name: `${prefix}reroll [message_id]`, value: '**Reroll giveaway winners**\nSelect new winners if original winners are unavailable', inline: false },
                    { name: `${prefix}welcome-config`, value: '**Configure welcome messages**\nCustomize welcome messages for new server members', inline: false },
                    { name: `${prefix}broadcast [message]`, value: '**Send announcements to all servers**\nShare important updates across multiple servers', inline: false }
                );
            break;
            
        case 'admin':
            commandCount = 8;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('⚙️ Administration - Detailed View')
                .setDescription('Advanced server configuration and management tools. Requires administrator permissions.')
                .addFields(
                    { name: `${prefix}welcome-enable`, value: '**Enable welcome system**\nActivate welcome messages for new members', inline: false },
                    { name: `${prefix}welcome-disable`, value: '**Disable welcome system**\nTurn off welcome messages for new members', inline: false },
                    { name: `${prefix}welcome-channel #channel`, value: '**Set welcome message channel**\nConfigure where welcome messages are sent', inline: false },
                    { name: `${prefix}broadcastsettings`, value: '**Configure broadcast system settings**\nSet up cross-server announcement preferences', inline: false },
                    { name: `${prefix}autoreact enable`, value: '**Enable auto-reactions**\nAutomatic emoji reactions to trigger words', inline: false },
                    { name: `${prefix}autoreact disable`, value: '**Disable auto-reactions**\nTurn off automatic emoji reactions', inline: false },
                    { name: `${prefix}autoreact add [word] [emoji]`, value: '**Add auto-reaction trigger**\nSet up new automatic reactions to specific words', inline: false },
                    { name: `${prefix}autoreact remove [word]`, value: '**Remove auto-reaction trigger**\nRemove existing automatic reactions', inline: false }
                );
            break;
            
        default:
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('❌ Unknown Category')
                .setDescription(`The category "${category}" was not found. Available categories: general, leveling, games, moderation, community, admin`);
    }
    
    if (categoryEmbed && category !== 'unknown') {
        categoryEmbed.addFields({
            name: '📈 Category Stats',
            value: `**Commands in this category:** ${commandCount}\n**Usage Level:** ${getCategoryUsageLevel(category)}\n**Permission Level:** ${getCategoryPermissionLevel(category)}`,
            inline: true
        });
    }
    
    categoryEmbed
        .setFooter({ text: `Use ${prefix}help to see all categories • Version: ${config.version}` })
        .setTimestamp();

    return message.reply({ embeds: [categoryEmbed] });
}

/**
 * Get usage level description for category
 */
function getCategoryUsageLevel(category) {
    const levels = {
        'general': 'Beginner Friendly',
        'leveling': 'Intermediate',
        'games': 'Beginner Friendly',
        'moderation': 'Intermediate',
        'community': 'Intermediate',
        'admin': 'Advanced'
    };
    return levels[category] || 'Unknown';
}

/**
 * Get permission level description for category
 */
function getCategoryPermissionLevel(category) {
    const permissions = {
        'general': 'Everyone',
        'leveling': 'Members/Moderators',
        'games': 'Everyone',
        'moderation': 'Moderators',
        'community': 'Moderators',
        'admin': 'Administrators'
    };
    return permissions[category] || 'Unknown';
}
