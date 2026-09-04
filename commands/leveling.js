const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('leveling')
        .setDescription('Interact with the server\'s leveling system')
        
        // Rank/Profile Subcommand
        .addSubcommand(subcommand => 
            subcommand
                .setName('rank')
                .setDescription('View your or another user\'s level and XP')
                .addUserOption(option => 
                    option.setName('user')
                        .setDescription('The user to view (defaults to yourself)')
                        .setRequired(false))
        )
        
        // Leaderboard Subcommand
        .addSubcommand(subcommand => 
            subcommand
                .setName('leaderboard')
                .setDescription('View the server\'s XP leaderboard')
                .addIntegerOption(option => 
                    option.setName('page')
                        .setDescription('The page number to view')
                        .setRequired(false)
                        .setMinValue(1))
        )
        
        // Badges Subcommand
        .addSubcommand(subcommand => 
            subcommand
                .setName('badges')
                .setDescription('View available badges and your earned badges')
                .addUserOption(option => 
                    option.setName('user')
                        .setDescription('The user to view badges for (defaults to yourself)')
                        .setRequired(false))
        )
        
        // Settings Subcommand (Admin only)
        .addSubcommand(subcommand => 
            subcommand
                .setName('settings')
                .setDescription('Configure leveling system settings for the server')
                .addStringOption(option => 
                    option.setName('setting')
                        .setDescription('The setting to change')
                        .setRequired(true)
                        .addChoices(
                            { name: 'Enable leveling', value: 'enable' },
                            { name: 'Disable leveling', value: 'disable' },
                            { name: 'Set level-up channel', value: 'channel' },
                            { name: 'Set XP multiplier', value: 'multiplier' },
                            { name: 'Set XP cooldown', value: 'cooldown' },
                            { name: 'Reset all user XP', value: 'reset' }
                        ))
                .addChannelOption(option => 
                    option.setName('channel')
                        .setDescription('The channel for level-up announcements (when setting channel)')
                        .setRequired(false))
                .addNumberOption(option => 
                    option.setName('value')
                        .setDescription('The value for multiplier or cooldown settings')
                        .setRequired(false))
        )
        
        // Role Rewards Management Subcommands (Admin only)
        .addSubcommand(subcommand => 
            subcommand
                .setName('addrole')
                .setDescription('Add a role reward for reaching a specific level')
                .addIntegerOption(option => 
                    option.setName('level')
                        .setDescription('The level required to earn this role')
                        .setRequired(true)
                        .setMinValue(1)
                        .setMaxValue(100))
                .addRoleOption(option => 
                    option.setName('role')
                        .setDescription('The role to award at this level')
                        .setRequired(true))
        )
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('removerole')
                .setDescription('Remove a role reward for a specific level')
                .addIntegerOption(option => 
                    option.setName('level')
                        .setDescription('The level to remove the role reward from')
                        .setRequired(true)
                        .setMinValue(1)
                        .setMaxValue(100))
        )
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('listroles')
                .setDescription('List all role rewards configured for this server')
        )
        
        // Award XP Subcommand (Admin only)
        .addSubcommand(subcommand => 
            subcommand
                .setName('award')
                .setDescription('Award XP to a user')
                .addUserOption(option => 
                    option.setName('user')
                        .setDescription('The user to award XP to')
                        .setRequired(true))
                .addIntegerOption(option => 
                    option.setName('amount')
                        .setDescription('The amount of XP to award')
                        .setRequired(true)
                        .setMinValue(1)
                        .setMaxValue(10000))
        )
        
        // Award Badge Subcommand (Admin only)
        .addSubcommand(subcommand => 
            subcommand
                .setName('awardbadge')
                .setDescription('Award a badge to a user')
                .addUserOption(option => 
                    option.setName('user')
                        .setDescription('The user to award the badge to')
                        .setRequired(true))
                .addStringOption(option => 
                    option.setName('badgetype')
                        .setDescription('The type of badge to award')
                        .setRequired(true)
                        .addChoices(
                            { name: 'Achievement Badge', value: 'achievement' },
                            { name: 'Special Badge', value: 'special' }
                        ))
                .addStringOption(option => 
                    option.setName('badgeid')
                        .setDescription('The ID of the badge to award')
                        .setRequired(true)
                        .addChoices(
                            // Achievement badges
                            { name: '🤝 Helpful Hand', value: 'helper' },
                            { name: '🛠️ Contributor', value: 'contributor' },
                            { name: '🎉 Event Participant', value: 'event' },
                            { name: '🎨 Creative Mind', value: 'creative' },
                            { name: '🛡️ Community Guardian', value: 'moderator' },
                            // Special badges
                            { name: '🏛️ Community Founder', value: 'founder' },
                            { name: '💡 Innovator', value: 'innovator' },
                            { name: '💖 Generous Patron', value: 'patron' }
                        ))
        ),
    
    async execute(interaction) {
        try {
            const { client, guild, user, options } = interaction;
            const subcommand = options.getSubcommand();
            
            console.log(`[LEVELING] Processing subcommand: ${subcommand} for user: ${user.tag}`);
            
            // Get server leveling settings — getGuildSettings initialises defaults if needed
            const serverSettings = client.serverSettingsManager.getGuildSettings(guild.id);
            const levelingSettings = client.serverSettingsManager.getLevelingSettings(guild.id);
            
            // Handle different subcommands
            switch (subcommand) {
            case 'rank':
                await handleRankCommand(interaction, client);
                break;
                
            case 'leaderboard':
                await handleLeaderboardCommand(interaction, client);
                break;
                
            case 'badges':
                await handleBadgesCommand(interaction, client);
                break;
                
            case 'settings':
                // Check if user has permission to change settings
                if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                    return interaction.reply({
                        content: '❌ You need the **Manage Server** permission to change leveling settings.',
                        ephemeral: true
                    });
                }
                
                await handleSettingsCommand(interaction, client);
                break;
                
            case 'award':
                // Check if user has permission to award XP
                if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                    return interaction.reply({
                        content: '❌ You need the **Manage Server** permission to award XP.',
                        ephemeral: true
                    });
                }
                
                await handleAwardCommand(interaction, client);
                break;
                
            case 'awardbadge':
                // Check if user has permission to award badges
                if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                    return interaction.reply({
                        content: '❌ You need the **Manage Server** permission to award badges.',
                        ephemeral: true
                    });
                }
                
                await handleAwardBadgeCommand(interaction, client);
                break;
                
            case 'addrole':
                // Check if user has permission to manage role rewards
                if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                    return interaction.reply({
                        content: '❌ You need the **Manage Server** permission to manage role rewards.',
                        ephemeral: true
                    });
                }
                
                await handleAddRoleCommand(interaction, client);
                break;
                
            case 'removerole':
                // Check if user has permission to manage role rewards
                if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                    return interaction.reply({
                        content: '❌ You need the **Manage Server** permission to manage role rewards.',
                        ephemeral: true
                    });
                }
                
                await handleRemoveRoleCommand(interaction, client);
                break;
                
            case 'listroles':
                await handleListRolesCommand(interaction, client);
                break;
                
            default:
                await interaction.reply({
                    content: `❌ Unknown subcommand: ${subcommand}`,
                    ephemeral: true
                });
                break;
        }
        } catch (error) {
            console.error('[LEVELING] Error executing leveling command:', error);
            if (!interaction.replied && !interaction.deferred) {
                await interaction.reply({
                    content: '❌ There was an error processing your leveling command. Please try again later.',
                    ephemeral: true
                });
            }
        }
    }
};

/**
 * Handle the add role reward subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleAddRoleCommand(interaction, client) {
    const level = interaction.options.getInteger('level');
    const role = interaction.options.getRole('role');
    
    // Check if bot can manage this role
    const botMember = interaction.guild.members.me;
    if (role.position >= botMember.roles.highest.position) {
        return interaction.reply({
            content: `❌ I cannot manage the role **${role.name}** because it's higher than or equal to my highest role.`,
            ephemeral: true
        });
    }
    
    // Add the role reward
    const success = await client.levelingManager.addRoleReward(interaction.guild.id, level, role.id);
    
    if (success) {
        const embed = new EmbedBuilder()
            .setColor(config.colors.success)
            .setTitle('✅ Role Reward Added')
            .setDescription(`Users who reach **Level ${level}** will now automatically receive the **${role.name}** role!`)
            .addFields(
                { name: '📊 Level', value: `${level}`, inline: true },
                { name: '🎭 Role', value: `${role}`, inline: true }
            )
            .setFooter({ text: `Version ${config.version}`, iconURL: this.client?.user?.displayAvatarURL() || client?.user?.displayAvatarURL() }).setTimestamp();
            
        await interaction.reply({ embeds: [embed] });
    } else {
        await interaction.reply({
            content: '❌ Failed to add role reward. Please try again.',
            ephemeral: true
        });
    }
}

/**
 * Handle the remove role reward subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleRemoveRoleCommand(interaction, client) {
    const level = interaction.options.getInteger('level');
    
    // Remove the role reward
    const success = await client.levelingManager.removeRoleReward(interaction.guild.id, level);
    
    if (success) {
        const embed = new EmbedBuilder()
            .setColor(config.colors.success)
            .setTitle('✅ Role Reward Removed')
            .setDescription(`The role reward for **Level ${level}** has been removed.`)
            .setFooter({ text: `Version ${config.version}`, iconURL: this.client?.user?.displayAvatarURL() || client?.user?.displayAvatarURL() }).setTimestamp();
            
        await interaction.reply({ embeds: [embed] });
    } else {
        await interaction.reply({
            content: `❌ No role reward found for Level ${level}.`,
            ephemeral: true
        });
    }
}

/**
 * Handle the list role rewards subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleListRolesCommand(interaction, client) {
    const roleRewards = client.levelingManager.getRoleRewards(interaction.guild.id);
    
    if (roleRewards.length === 0) {
        return interaction.reply({
            content: '📝 No role rewards are currently configured for this server.\n\nUse `/leveling addrole` to set up automatic role rewards for leveling up!',
            ephemeral: true
        });
    }
    
    // Sort role rewards by level
    roleRewards.sort((a, b) => a.level - b.level);
    
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🎭 Role Rewards')
        .setDescription('Here are all the role rewards configured for this server:')
        .setFooter({ text: `Version ${config.version}`, iconURL: this.client?.user?.displayAvatarURL() || client?.user?.displayAvatarURL() }).setTimestamp();
    
    let description = '';
    for (const reward of roleRewards) {
        const role = interaction.guild.roles.cache.get(reward.roleId);
        if (role) {
            description += `**Level ${reward.level}** → ${role}\n`;
        } else {
            description += `**Level ${reward.level}** → *Role not found* (${reward.roleId})\n`;
        }
    }
    
    embed.addFields({
        name: '📊 Level Requirements',
        value: description || 'No role rewards configured.'
    });
    
    await interaction.reply({ embeds: [embed] });
}

/**
 * Handle the rank/profile subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleRankCommand(interaction, client) {
    const { guild, user, options } = interaction;
    
    // Get target user (defaults to command user)
    const targetUser = options.getUser('user') || user;
    
    // Get user profile data
    await interaction.deferReply();
    
    try {
        // Get user data from database
        const userData = await client.levelingManager.getUserProfile(guild.id, targetUser.id);
        
        if (!userData) {
            return interaction.editReply({
                content: `${targetUser.id === user.id ? 'You haven\'t' : `${targetUser.username} hasn't`} earned any XP in this server yet.`,
                ephemeral: false
            });
        }

        // Get user's rank position
        const leaderboard = await client.levelingManager.getLeaderboard(guild.id, 1000);
        const userRank = leaderboard.findIndex(u => u.userId === targetUser.id) + 1;

        // Calculate progress to next level
        const currentLevel = userData.level;
        const nextLevel = currentLevel + 1;
        const currentLevelMessages = client.levelingManager.calculateRequiredMessages(currentLevel);
        const nextLevelMessages = client.levelingManager.calculateRequiredMessages(nextLevel);
        const messagesForCurrentLevel = nextLevelMessages - currentLevelMessages;
        const currentProgress = userData.messages - currentLevelMessages;
        const progressPercentage = Math.floor((currentProgress / messagesForCurrentLevel) * 100);

        // Create progress bar
        const progressBarLength = 20;
        const filledSquares = Math.floor((progressPercentage / 100) * progressBarLength);
        const emptySquares = progressBarLength - filledSquares;
        const progressBar = '█'.repeat(filledSquares) + '░'.repeat(emptySquares);

        // Get rank medal emoji
        let rankEmoji = '🏅';
        if (userRank === 1) rankEmoji = '🥇';
        else if (userRank === 2) rankEmoji = '🥈';
        else if (userRank === 3) rankEmoji = '🥉';
        else if (userRank <= 10) rankEmoji = '⭐';

        // Create enhanced embed
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setAuthor({ 
                name: `${targetUser.username}'s Level Stats`,
                iconURL: targetUser.displayAvatarURL({ dynamic: true })
            })
            .setThumbnail(targetUser.displayAvatarURL({ dynamic: true, size: 256 }))
            .addFields(
                { 
                    name: `${rankEmoji} Server Rank`, 
                    value: `**#${userRank}** out of ${leaderboard.length}`, 
                    inline: true 
                },
                { 
                    name: '📊 Level', 
                    value: `**${userData.level}**`, 
                    inline: true 
                },
                { 
                    name: '✨ Total XP', 
                    value: `**${userData.xp.toLocaleString()}**`, 
                    inline: true 
                },
                { 
                    name: '💬 Messages', 
                    value: `**${userData.messages.toLocaleString()}**`, 
                    inline: true 
                },
                { 
                    name: '🎯 Next Level', 
                    value: `**${messagesForCurrentLevel - currentProgress}** messages`, 
                    inline: true 
                },
                { 
                    name: '📈 Progress', 
                    value: `**${progressPercentage}%**`, 
                    inline: true 
                },
                {
                    name: '▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬',
                    value: `\`${progressBar}\` ${currentProgress}/${messagesForCurrentLevel}`,
                    inline: false
                }
            );

        // Add badges section if user has badges
        if (userData.badges && userData.badges.length > 0) {
            const badgeDisplay = userData.badges
                .slice(0, 10) // Limit to 10 badges
                .map(badge => badge.badgeEmoji)
                .join(' ');
            
            embed.addFields({
                name: `🏆 Badges (${userData.badges.length})`,
                value: badgeDisplay || 'None',
                inline: false
            });
        }

        embed.setFooter({ 
            text: `Keep chatting to level up! • ${guild.name}`,
            iconURL: guild.iconURL({ dynamic: true })
        });
        embed.setTimestamp();

        interaction.editReply({ embeds: [embed] });
    } catch (error) {
        console.error('[LEVELING] Error displaying rank:', error);
        interaction.editReply({
            content: '❌ An error occurred while retrieving the rank information.',
            ephemeral: true
        });
    }
}

/**
 * Handle the leaderboard subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleLeaderboardCommand(interaction, client) {
    const { guild, options } = interaction;
    
    // Get page number (defaults to 1)
    const page = options.getInteger('page') || 1;
    
    await interaction.deferReply();
    
    try {
        // Get leaderboard data (top 100 users)
        const leaderboard = await client.levelingManager.getLeaderboard(guild.id, 100);
        
        if (!leaderboard || leaderboard.length === 0) {
            return interaction.editReply({
                content: 'No one has earned XP in this server yet.',
                ephemeral: false
            });
        }
        
        // Calculate pagination
        const usersPerPage = 10;
        const totalPages = Math.ceil(leaderboard.length / usersPerPage);
        const validPage = Math.max(1, Math.min(page, totalPages));
        
        const startIndex = (validPage - 1) * usersPerPage;
        const endIndex = Math.min(startIndex + usersPerPage, leaderboard.length);
        
        const pageUsers = leaderboard.slice(startIndex, endIndex);
        
        // Create leaderboard embed
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle(`🏆 ${guild.name} XP Leaderboard`)
            .setDescription(`Top members ranked by experience points`)
            .setFooter({ text: `Page ${validPage}/${totalPages} • ${leaderboard.length} members ranked • Version ${config.version}`, iconURL: client.user.displayAvatarURL() })
            .setTimestamp();
        
        // Add leaderboard entries
        let leaderboardText = '';
        
        for (let i = 0; i < pageUsers.length; i++) {
            const index = startIndex + i;
            const entry = pageUsers[i];
            const position = index + 1;
            
            // Get medal emoji for top 3
            let medal = '';
            if (position === 1) medal = '🥇 ';
            else if (position === 2) medal = '🥈 ';
            else if (position === 3) medal = '🥉 ';
            
            // Format leaderboard entry
            try {
                const member = await guild.members.fetch(entry.userId);
                const username = member ? member.displayName : 'Unknown User';
                
                leaderboardText += `**${medal}${position}.** ${username}\n`;
                leaderboardText += `➜ Level ${entry.level} • ${entry.xp} XP • ${entry.messages} messages\n\n`;
            } catch (error) {
                leaderboardText += `**${medal}${position}.** Unknown User\n`;
                leaderboardText += `➜ Level ${entry.level} • ${entry.xp} XP • ${entry.messages} messages\n\n`;
            }
        }
        
        embed.setDescription(leaderboardText);
        
        // Add navigation instructions if there are multiple pages
        if (totalPages > 1) {
            embed.setFooter({ text: `Page ${validPage}/${totalPages} • Use /leveling leaderboard page:[number] to see more • Version ${config.version}`, iconURL: client.user.displayAvatarURL() });
        }
        
        interaction.editReply({ embeds: [embed] });
    } catch (error) {
        console.error('[LEVELING] Error displaying leaderboard:', error);
        interaction.editReply({
            content: '❌ An error occurred while retrieving the leaderboard.',
            ephemeral: true
        });
    }
}

/**
 * Handle the badges subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleBadgesCommand(interaction, client) {
    const { guild, user, options } = interaction;
    
    // Get target user (defaults to command user)
    const targetUser = options.getUser('user') || user;
    
    await interaction.deferReply();
    
    try {
        const badgesData = await client.levelingManager.createBadgesEmbed(
            guild.id,
            targetUser.id
        );
        
        if (!badgesData) {
            return interaction.editReply({
                content: `Could not retrieve badge information.`,
                ephemeral: true
            });
        }
        
        interaction.editReply({ embeds: [badgesData.embed] });
    } catch (error) {
        console.error('[LEVELING] Error displaying badges:', error);
        interaction.editReply({
            content: '❌ An error occurred while retrieving the badge information.',
            ephemeral: true
        });
    }
}

/**
 * Handle the settings subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleSettingsCommand(interaction, client) {
    const { guild, options } = interaction;
    
    // Get setting to change
    const setting = options.getString('setting');
    
    // Get current server settings — getGuildSettings initialises defaults if needed
    const serverSettings = client.serverSettingsManager.getGuildSettings(guild.id);
    const levelingSettings = client.serverSettingsManager.getLevelingSettings(guild.id);
    
    await interaction.deferReply({ ephemeral: true });
    
    try {
        switch (setting) {
            case 'enable':
                // Enable leveling for the server
                levelingSettings.enabled = true;
                client.serverSettingsManager._saveGuildSettings(guild.id);
                
                interaction.editReply({
                    content: '✅ Leveling system has been **enabled** for this server.',
                    ephemeral: true
                });
                break;
                
            case 'disable':
                // Disable leveling for the server
                levelingSettings.enabled = false;
                client.serverSettingsManager._saveGuildSettings(guild.id);
                
                interaction.editReply({
                    content: '✅ Leveling system has been **disabled** for this server.',
                    ephemeral: true
                });
                break;
                
            case 'channel':
                // Set level-up channel
                const channel = options.getChannel('channel');
                
                if (!channel) {
                    // If no channel specified, show current setting
                    const currentChannel = levelingSettings.levelUpChannelId
                        ? guild.channels.cache.get(levelingSettings.levelUpChannelId)?.toString() || 'Unknown Channel'
                        : 'Same channel as message';
                    
                    return interaction.editReply({
                        content: `Current level-up announcement channel: **${currentChannel}**\n\nTo change it, use \`/leveling settings setting:channel channel:[#channel]\``,
                        ephemeral: true
                    });
                }
                
                // Verify channel is a text-based channel
                if (!channel.isTextBased()) {
                    return interaction.editReply({
                        content: '❌ The channel must be a text channel.',
                        ephemeral: true
                    });
                }
                
                // Update channel setting
                levelingSettings.levelUpChannelId = channel.id;
                client.serverSettingsManager._saveGuildSettings(guild.id);
                
                interaction.editReply({
                    content: `✅ Level-up announcements will now be sent to ${channel}.`,
                    ephemeral: true
                });
                break;
                
            case 'multiplier':
                // Set XP multiplier
                const multiplier = options.getNumber('value');
                
                if (!multiplier) {
                    // If no value specified, show current setting
                    return interaction.editReply({
                        content: `Current XP multiplier: **${levelingSettings.xpMultiplier}x**\n\nTo change it, use \`/leveling settings setting:multiplier value:[number]\``,
                        ephemeral: true
                    });
                }
                
                // Validate multiplier
                if (multiplier <= 0 || multiplier > 5) {
                    return interaction.editReply({
                        content: '❌ XP multiplier must be between 0.1 and 5.',
                        ephemeral: true
                    });
                }
                
                // Update multiplier setting
                levelingSettings.xpMultiplier = parseFloat(multiplier.toFixed(2));
                client.serverSettingsManager._saveGuildSettings(guild.id);
                
                interaction.editReply({
                    content: `✅ XP multiplier has been set to **${levelingSettings.xpMultiplier}x**.`,
                    ephemeral: true
                });
                break;
                
            case 'cooldown':
                // Set XP cooldown
                const cooldown = options.getNumber('value');
                
                if (!cooldown) {
                    // If no value specified, show current setting
                    const currentCooldown = (levelingSettings.xpCooldown / 1000).toFixed(0);
                    
                    return interaction.editReply({
                        content: `Current XP cooldown: **${currentCooldown} seconds**\n\nTo change it, use \`/leveling settings setting:cooldown value:[seconds]\``,
                        ephemeral: true
                    });
                }
                
                // Validate cooldown
                if (cooldown < 5 || cooldown > 300) {
                    return interaction.editReply({
                        content: '❌ XP cooldown must be between 5 and 300 seconds.',
                        ephemeral: true
                    });
                }
                
                // Update cooldown setting (convert to milliseconds)
                levelingSettings.xpCooldown = Math.floor(cooldown * 1000);
                client.serverSettingsManager._saveGuildSettings(guild.id);
                
                interaction.editReply({
                    content: `✅ XP cooldown has been set to **${cooldown} seconds**.`,
                    ephemeral: true
                });
                break;
                
            case 'reset':
                // Reset all user XP - ask for confirmation first
                const confirmEmbed = new EmbedBuilder()
                    .setColor(config.colors.error)
                    .setTitle('⚠️ Reset All XP Data?')
                    .setDescription('**WARNING:** This will delete all user XP, levels, and progress in this server.\n\nThis action cannot be undone. Are you sure you want to proceed?')
                    .setFooter({ text: `This confirmation will expire in 30 seconds • Version ${config.version}` });
                
                interaction.editReply({
                    content: 'Please confirm:',
                    embeds: [confirmEmbed],
                    ephemeral: true
                });
                
                // We'll need to enhance this with buttons in the future
                // For now, just warn the user
                break;
        }
    } catch (error) {
        console.error('[LEVELING] Error updating settings:', error);
        interaction.editReply({
            content: '❌ An error occurred while updating leveling settings.',
            ephemeral: true
        });
    }
}

/**
 * Handle the award XP subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleAwardCommand(interaction, client) {
    const { guild, options } = interaction;

    // Get target user and XP amount
    const targetUser = options.getUser("user");
    const amount = options.getInteger("amount");

    await interaction.deferReply({ ephemeral: true });

    try {
        const oldProfile = await client.levelingManager.getUserProfile(guild.id, targetUser.id);
        const oldLevel = oldProfile?.level ?? 0;
        const oldMessages = oldProfile?.messages ?? 0;
        const oldXp = oldProfile?.xp ?? 0;

        // Persist the XP bump via the DB-backed manager.
        const awarded = await client.levelingManager.awardXPDirect(guild.id, targetUser.id, amount);

        if (!awarded) {
            return interaction.editReply({
                content: "❌ An error occurred while awarding XP.",
                ephemeral: true
            });
        }

        // Recompute level/messages to match the DB model (level is message-based).
        const newMessages = oldMessages + Math.floor(amount / 15); // Rough estimate of messages based on XP
        const newLevel = client.levelingManager.calculateLevel(newMessages);

        // Persist the recomputed level/messages too, so rank/level stay consistent with XP awarded.
        const setResult = await client.levelingManager.setLevel(guild.id, targetUser.id, newLevel);

        if (!setResult.success) {
            console.error("[LEVELING] XP awarded but level sync failed:", setResult.message);
        }

        const userData = { xp: oldXp + amount, level: newLevel, messages: newMessages };
        const newBadges = [];

        // Check for new badges if user leveled up (DB-backed,, correct signature).
        if (newLevel > oldLevel) {
            const levelBadges = await client.levelingManager.checkForNewBadges(
                guild.id,
                targetUser.id,
                oldLevel,
                newLevel
            );
            newBadges.push(...levelBadges);
        }

        const embed = new EmbedBuilder()
            .setColor(config.colors.success)
            .setTitle("✅ XP Awarded")
            .setDescription(`Successfully awarded **${amount} XP** to ${targetUser}.`)
            .addFields(
                { name: "Previous XP", value: `${oldXp} XP`, inline: true },
                { name: "New XP", value: `${userData.xp} XP`, inline: true },
                { name: "Previous Level", value: `Level ${oldLevel}`, inline: true },
                { name: "New Level", value: `Level ${newLevel}`, inline: true },
                { name: "Previous Messages", value: `${oldMessages}`, inline: true },
                { name: "New Messages", value: `${userData.messages}`, inline: true }
            )
            .setFooter({ text: `Version ${config.version}` }).setTimestamp();

        if (newLevel > oldLevel) {
            embed.addFields({
                name: "🎉 Level Up!",
                value: `User leveled up from **Level ${oldLevel}** to **Level ${newLevel}**!`
            });

            if (newBadges.length > 0) {
                const badgeList = newBadges.map(badge =>
                    `${badge.emoji} **${badge.name}** - ${badge.description}`
                ).join("\n");

                embed.addFields({
                    name: "🏅 New Badge" + (newBadges.length > 1 ? "s" : "") + " Earned!",
                    value: badgeList
                });
            }
        }

        interaction.editReply({ embeds: [embed], ephemeral: true });
    } catch (error) {
        console.error("[LEVELING] Error awarding XP:", error);
        interaction.editReply({
            content: "❌ An error occurred while awarding XP.",
            ephemeral: true
        });
    }
}

/**
 * Handle the award badge subcommand
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleAwardBadgeCommand(interaction, client) {
    const { guild, options } = interaction;
    
    // Get target user, badge type, and badge ID
    const targetUser = options.getUser('user');
    const badgeType = options.getString('badgetype');
    const badgeId = options.getString('badgeid');
    
    await interaction.deferReply({ ephemeral: true });
    
    try {
        // Award the badge
        const result = await client.levelingManager.awardBadge({
            guildId: guild.id,
            userId: targetUser.id,
            badgeType,
            badgeId
        });
        
        if (result.success) {
            // Badge awarded successfully
            const badge = result.badge;
            
            const embed = new EmbedBuilder()
                .setColor(config.colors[badge.color] || config.colors.primary)
                .setTitle('🏅 Badge Awarded')
                .setDescription(`Successfully awarded the **${badge.name}** badge to ${targetUser}.`)
                .addFields(
                    { name: 'Badge', value: `${badge.emoji} **${badge.name}**`, inline: true },
                    { name: 'Description', value: badge.description, inline: true },
                    { name: 'Type', value: badgeType.charAt(0).toUpperCase() + badgeType.slice(1), inline: true }
                )
                .setFooter({ text: `Version ${config.version}`, iconURL: this.client?.user?.displayAvatarURL() || client?.user?.displayAvatarURL() }).setTimestamp();
            
            interaction.editReply({ embeds: [embed], ephemeral: true });
        } else {
            // Error awarding badge
            interaction.editReply({
                content: `❌ Error: ${result.message}`,
                ephemeral: true
            });
        }
    } catch (error) {
        console.error('[LEVELING] Error awarding badge:', error);
        interaction.editReply({
            content: '❌ An error occurred while awarding the badge.',
            ephemeral: true
        });
    }
}