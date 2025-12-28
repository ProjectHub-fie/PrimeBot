const {
    EmbedBuilder,
    ButtonBuilder,
    ButtonStyle,
    ActionRowBuilder,
    PermissionsBitField,
} = require("discord.js");
const config = require("../config");

module.exports = {
    name: "messageCreate",
    async execute(message, client) {
        try {
            // Ignore messages from bots
            if (message.author.bot) return;

            const prefix = config.prefix;

            // Check for ping (mention)
            if (
                message.mentions.has(client.user.id) &&
                client.ws.status === 0
            ) {
                // Calculate bot uptime
                const uptime = process.uptime();
                const uptimeString = formatUptime(uptime);

                // Get guild count
                const guildCount = client.guilds.cache.size;

                // Get command count
                const commandCount = 9; // Update this manually when adding commands (giveaway, end, reroll, gstart, gend, commands, help, echo)

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

                const row = new ActionRowBuilder().addComponents(inviteButton, supportServerButton);

                const pingEmbed = new EmbedBuilder()
                    .setColor(config.colors.primary)
                    .setTitle("Hello there! 👋")
                    .setDescription(
                        `I'm **${client.user.username}**, your personal digital assistant (PDA)`,
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
                            name: "🔧 Commands",
                            value: `Type \`${prefix}help\` to see all available commands!`,
                        },
                    )
                    .setThumbnail(
                        client.user.displayAvatarURL({ dynamic: true }),
                    )
                    .setFooter({
                        text: `Requested by ${message.author.tag}`,
                        iconURL: message.author.displayAvatarURL({
                            dynamic: true,
                        }),
                       
                          

                            iconURL: client.user.displayAvatarURL(),

                        text: `Version: ${config.version}`,
                    })
                    .setTimestamp();

                try {
                    await message.reply({
                        embeds: [pingEmbed],
                        components: [row],
                    });
                } catch (error) {
                    console.error("Error handling ping:", error);
                    await message.reply(
                        "Sorry, I encountered an error while processing your ping. Please try again later.",
                    );
                }
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
            const emojiPrefix = "+";
            if (message.content.startsWith(emojiPrefix)) {
                // Handle emoji commands
                const args = message.content.slice(emojiPrefix.length).trim().split(/ +/);
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
                                
                                // Update the message
                                await interaction.update({ 
                                    embeds: [updatedList.embed], 
                                    components: updatedList.components || []
                                });
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
            if (!message.content.startsWith(prefix)) {
                // Process counting game messages before returning
                const processed = await client.countingManager.processCountingMessage(message);
                if (processed) return; // Message was processed as a count
                
                // Process message for XP and leveling (only in support server)
                await client.levelingManager.processMessage(message);
                
                return; // Not a command or counting-related message
            }

            // Parse command and arguments
            const args = message.content
                .slice(prefix.length)
                .trim()
                .split(/ +/);
            const commandName = args.shift().toLowerCase();

            // Handle commands
            switch (commandName) {
                case "help":
                case "commands":
                    // Get page number if provided
                    let commandPage = 1;
                    if (args.length > 0) {
                        const requestedPage = parseInt(args[0]);
                        if (!isNaN(requestedPage) && requestedPage > 0) {
                            commandPage = requestedPage;
                        }
                    }
                    
                    // Define basic commands available in all servers
                    let allCommands = [
                        { name: `${prefix}help [page]`, value: "Shows this list of commands" },
                        { name: `${prefix}commands [page]`, value: "Alias for help command" },
                        { name: `${prefix}giveaway`, value: "Shows all giveaway commands" },
                        { name: `${prefix}gstart [duration] [winners] [prize]`, value: "Creates a new giveaway" },
                        { name: `${prefix}gend [message_id]`, value: "Ends a giveaway early" },
                        { name: `${prefix}reroll [message_id]`, value: "Rerolls winners for a giveaway" },
                        { name: `${prefix}echo [message]`, value: "Makes the bot repeat a message" },
                        { name: `${prefix}ping`, value: "Shows the bot's latency" },
                        { name: `${prefix}thelp`, value: "Shows all ticket system commands" },
                        { name: `${prefix}ticket [channel] (roles)`, value: "Creates a ticket panel" },
                        
                        { name: `${prefix}thistory (page)`, value: "Shows ticket history" },
                        { name: `${prefix}ab`, value: "Shows information about the bot" },
                        { name: `${prefix}ulog`, value: "Shows updates and upcoming features" },
                        { name: `${prefix}tictactoe`, value: "Starts a new TicTacToe game in the channel" },
                        { name: `${prefix}move [1-9]`, value: "Makes a move in an active TicTacToe game" },
                        { name: `${prefix}tend`, value: "Ends the current TicTacToe game in the channel" },
                        { name: `${prefix}poll [duration] [question] | [options]`, value: "Creates a poll with a timer" },
                        { name: `${prefix}endpoll [message_id]`, value: "Ends a poll early" },
                        { name: `${prefix}birthday`, value: "Shows all birthday commands" },
                        { name: `${prefix}birthday set [MM/DD/YYYY]`, value: "Sets your birthday (year is optional)" },
                        { name: `${prefix}birthday remove`, value: "Removes your birthday" },
                        { name: `${prefix}birthday list`, value: "Shows upcoming birthdays" },
                        { name: `${prefix}birthday check [@user]`, value: "Check your or someone else's birthday" },
                        { name: `${prefix}birthday channel [#channel]`, value: "Sets the birthday announcement channel (requires Manage Server permission)" },
                        { name: `${prefix}birthday role [@role]`, value: "Sets the birthday role (requires Manage Server permission)" },
                        { name: `Emoji Commands ${emojiPrefix} prefix`, value: `Use ${emojiPrefix}help to see all emoji commands`, },
                        { name: `${prefix}cstart [start] [goal]`, value: "Start a number counting game (requires Manage Server permission)" },
                        { name: `${prefix}cstatus`, value: "Check the status of the current counting game" },
                        { name: `${prefix}cend`, value: "End the current counting game (requires Manage Server permission)" },
                        { name: `${prefix}chelp`, value: "Show help for the counting game" },
                        { name: `${prefix}truthdare`, value: "Start a Truth or Dare game with interactive buttons" },
                        { name: `${prefix}qadd [truth/dare] [question]`, value: "Add a custom truth or dare question to the collection" },
                    ];
                    
                    // If we're in the support server, add the leveling commands to the list
                    if (message.guild && message.guild.id === config.leveling.supportServerId) {
                        // Leveling System Commands (only shown in support server)
                        const levelingCommands = [
                            { name: `${prefix}leaderboard [page]`, value: "Shows the community XP leaderboard" },
                            { name: `${prefix}rank [@user]`, value: "Shows your or another user's level and XP" },
                            { name: `${prefix}profile [@user]`, value: "Shows detailed stats and badges" },
                            { name: `${prefix}badges [@user]`, value: "Shows available and earned badges" },
                            { name: `${prefix}level [@user]`, value: "Alias for rank command" },
                            { name: `${prefix}exp [@user]`, value: "Alias for rank command" },
                        ];
                        
                        // Add leveling commands to the main commands list
                        allCommands = [...allCommands, ...levelingCommands];
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
                            
                            // Update the message
                            await interaction.update({ 
                                embeds: [newEmbed], 
                                components: [newRow]
                            });
                        });
                        
                        collector.on('end', () => {
                            // Remove buttons when collector expires
                            reply.edit({ components: [] }).catch(console.error);
                        });
                    }
                    
                    return;

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
                                `\`${prefix}gstart 12h 3 Steam Game\` - 12 hour giveaway for 3 winners\n` +
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
                        // Parse the command format: $poll <duration> <question> | <option1> | <option2> | ...
                        if (args.length < 3) {
                            const usageEmbed = new EmbedBuilder()
                                .setColor(config.colors.error)
                                .setTitle("Invalid Usage")
                                .setDescription(
                                    `**Correct Usage:** \`${prefix}${commandName} [duration] [question] | [option1] | [option2] | ...\``,
                                )
                                .addFields({
                                    name: "Examples",
                                    value:
                                        `\`${prefix}${commandName} 1d What's your favorite color? | Red | Blue | Green\` - 1 day poll with 3 options\n` +
                                        `\`${prefix}${commandName} 12h Best programming language? | JavaScript | Python | Java | C++\` - 12 hour poll with 4 options`,
                                });
                            return message.reply({ embeds: [usageEmbed] });
                        }

                        // Get the duration
                        const duration = args[0];

                        // Get the full content after the duration
                        const fullContent = message.content
                            .slice(
                                message.content.indexOf(args[0]) +
                                    args[0].length,
                            )
                            .trim();

                        // Split by pipe character
                        const parts = fullContent
                            .split("|")
                            .map((part) => part.trim());

                        if (parts.length < 3) {
                            return message.reply(
                                "Please provide a question and at least 2 options separated by | characters.",
                            );
                        }

                        // The first part is the question
                        const question = parts[0];

                        // The rest are options
                        const options = parts.slice(1);

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
                                
                            case "list":
                                // Get upcoming birthdays
                                const upcomingBirthdays = client.birthdayManager.getUpcomingBirthdays(message.guild.id, 10);
                                
                                if (upcomingBirthdays.length === 0) {
                                    return message.reply("No upcoming birthdays found! Set your birthday with `" + prefix + "birthday set MM/DD/YYYY`.");
                                }
                                
                                // Create embed
                                const upcomingEmbed = new EmbedBuilder()
                                    .setColor("#FFC0CB") // Pink
                                    .setTitle("🎂 Upcoming Birthdays")
                                    .setDescription("Here are the upcoming birthdays in this server:")
                                    .setThumbnail("https://i.imgur.com/1XXtUx0.gif");
                                
                                // Add each birthday to the embed
                                for (const birthday of upcomingBirthdays) {
                                    try {
                                        const member = await message.guild.members.fetch(birthday.userId);
                                        const formattedDate = client.birthdayManager.formatDate(birthday.month, birthday.day);
                                        const yearText = birthday.year ? ` (Born: ${birthday.year})` : "";
                                        const daysText = birthday.daysUntil === 0 ? "Today!" : birthday.daysUntil === 1 ? "Tomorrow!" : `In ${birthday.daysUntil} days`;
                                        
                                        upcomingEmbed.addFields({
                                            name: `${member.displayName}${yearText}`,
                                            value: `${formattedDate} - ${daysText}`
                                        });
                                    } catch (err) {
                                        console.error(`Error fetching member ${birthday.userId}:`, err);
                                    }
                                }
                                
                                return message.reply({ embeds: [upcomingEmbed] });
                                
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
                    const aboutEmbed = new EmbedBuilder()
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
                            text: `Bot Version: 1.1.0`,
                            iconURL: client.user.displayAvatarURL(),
                        });

                    return message.reply({ embeds: [aboutEmbed] });

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
                    
                case "broadcast":
                    // Check if user is a developer
                    if (!config.developerIds.includes(message.author.id)) {
                        // Silently ignore - this command is hidden from non-developers
                        return;
                    }
                    
                    // Validate arguments
                    if (args.length < 1) {
                        return message.reply("Please provide a message to broadcast.");
                    }
                    
                    // Get the broadcast message
                    const broadcastMessage = args.join(" ");
                    
                    // Debug logging
                    console.log(`[DEBUG] Broadcast command triggered by ${message.author.tag} with message: ${broadcastMessage}`);
                    
                    // Create the broadcast embed
                    const broadcastEmbed = new EmbedBuilder()
                        .setColor(config.colors.primary)
                        .setTitle("📣 Announcement from Developers")
                        .setDescription(broadcastMessage)
                        .setTimestamp()
                        .setFooter({ 
                            text: `Version: ${config.version}`,
                            iconURL: client.user.displayAvatarURL()
                        });
                    
                    // Send confirmation
                    const confirmationEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setDescription("📣 Broadcasting message to all servers...");
                    
                    await message.reply({ embeds: [confirmationEmbed] });
                    
                    // Track statistics
                    let successCount = 0;
                    let failCount = 0;
                    let totalGuilds = client.guilds.cache.size;
                    
                    // Broadcast to all guilds
                    console.log(`[DEBUG] Starting broadcast to ${client.guilds.cache.size} guilds`);
                    
                    for (const guild of client.guilds.cache.values()) {
                        try {
                            console.log(`[DEBUG] Processing guild: ${guild.name} (${guild.id})`);
                            
                            // Find the first available text channel
                            const channel = guild.channels.cache
                                .filter(ch => ch.type === 0) // 0 is GuildText channel type
                                .sort((a, b) => a.position - b.position)
                                .first();
                            
                            if (!channel) {
                                console.log(`[DEBUG] No suitable text channel found in guild: ${guild.name}`);
                                failCount++;
                                continue;
                            }
                            
                            console.log(`[DEBUG] Selected channel: ${channel.name} (${channel.id})`);
                            
                            // Check bot permissions
                            const hasPermission = channel.permissionsFor(guild.members.me).has("SendMessages");
                            console.log(`[DEBUG] Bot has SendMessages permission: ${hasPermission}`);
                            
                            if (hasPermission) {
                                await channel.send({ embeds: [broadcastEmbed] });
                                console.log(`[DEBUG] Successfully sent broadcast to guild: ${guild.name}`);
                                successCount++;
                            } else {
                                console.log(`[DEBUG] Missing permissions to send in channel: ${channel.name}`);
                                failCount++;
                            }
                        } catch (error) {
                            console.error(`Error broadcasting to guild ${guild.name}:`, error);
                            failCount++;
                        }
                    }
                    
                    // Send status report
                    const reportEmbed = new EmbedBuilder()
                        .setColor(config.colors.success)
                        .setTitle("📣 Broadcast Complete")
                        .setDescription(`Message has been sent to servers.`)
                        .addFields(
                            { name: "Success", value: `${successCount} servers`, inline: true },
                            { name: "Failed", value: `${failCount} servers`, inline: true },
                            { name: "Total", value: `${totalGuilds} servers`, inline: true }
                        );
                    
                    await message.channel.send({ embeds: [reportEmbed] });
                    break;
                
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
                        await client.countingManager.startCountingGame({
                            channelId: message.channel.id,
                            startNumber: startNumber,
                            goalNumber: goalNumber
                        });
                        
                        // Send confirmation is handled within startCountingGame
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
                    
                    // End the counting game
                    const ended = client.countingManager.endCountingGame(message.channel.id);
                    
                    if (ended) {
                        const endEmbed = new EmbedBuilder()
                            .setColor(config.colors.success)
                            .setDescription("✅ Counting game ended successfully!");
                            
                        return message.reply({ embeds: [endEmbed] });
                    } else {
                        return message.reply("There is no active counting game in this channel.");
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
                    // Only available in support server
                    if (message.guild.id !== config.leveling.supportServerId) {
                        message.reply("This command is only available in the support server.");
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
                    
                    // Get the leaderboard embed
                    const leaderboardData = await client.levelingManager.createLeaderboardEmbed(
                        message.guild.id, 
                        leaderboardPage
                    );
                    
                    // Send the message
                    const leaderboardReply = await message.reply({ 
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
                            
                            // Update message
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
                    // Only available in support server
                    if (message.guild.id !== config.leveling.supportServerId) {
                        message.reply("This command is only available in the support server.");
                        return;
                    }
                    
                    // Check if user is specified
                    let targetUser = message.author;
                    if (args.length > 0 && message.mentions.users.size > 0) {
                        targetUser = message.mentions.users.first();
                    }
                    
                    // Get user's profile
                    const profileData = await client.levelingManager.createProfileEmbed(
                        message.guild.id,
                        targetUser.id
                    );
                    
                    if (!profileData) {
                        message.reply("Could not retrieve user profile data.");
                        return;
                    }
                    
                    // Send the profile
                    message.reply({ embeds: [profileData.embed] });
                    break;
                    
                case "set-level":
                case "setlevel":
                    // Only available to developers
                    if (!config.developerIds.includes(message.author.id)) {
                        return; // Silently ignore for non-developers
                    }
                    
                    // Only available in support server
                    if (message.guild.id !== config.leveling.supportServerId) {
                        message.reply("This command is only available in the support server.");
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
                    
                case "badges":
                    // Only available in support server
                    if (message.guild.id !== config.leveling.supportServerId) {
                        message.reply("This command is only available in the support server.");
                        return;
                    }
                    
                    // Get user if specified
                    let badgesUser = null;
                    if (args.length > 0 && message.mentions.users.size > 0) {
                        badgesUser = message.mentions.users.first();
                    }
                    
                    // Create badges embed
                    const badgesData = await client.levelingManager.createBadgesEmbed(
                        message.guild.id,
                        badgesUser ? badgesUser.id : message.author.id
                    );
                    
                    // Send the message
                    message.reply({ embeds: [badgesData.embed] });
                    break;
                    
                case "award-badge":
                case "awardbadge":
                case "give-badge":
                    // Only available to admins with proper permissions
                    if (!message.member.permissions.has(PermissionsBitField.Flags.ManageGuild)) {
                        message.reply("You don't have permission to award badges.");
                        return;
                    }
                    
                    // Only available in support server
                    if (message.guild.id !== config.leveling.supportServerId) {
                        message.reply("This command is only available in the support server.");
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
                    
                    // Only available in support server
                    if (message.guild.id !== config.leveling.supportServerId) {
                        message.reply("This command is only available in the support server.");
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
                    // Only available in support server
                    if (message.guild.id !== config.leveling.supportServerId) {
                        message.reply("This command is only available in the support server.");
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
