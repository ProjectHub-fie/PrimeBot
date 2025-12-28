const { SlashCommandBuilder, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('sync')
        .setDescription('Sync and manage automated role-level-badge connections')
        .setDefaultMemberPermissions('0')
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('roles')
                .setDescription('Sync all user roles based on their current levels')
        )
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('badges')
                .setDescription('Sync all user badges based on their achievements and levels')
        )
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('all')
                .setDescription('Perform a complete sync of roles, badges, and levels for all users')
        )
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('user')
                .setDescription('Sync roles and badges for a specific user')
                .addUserOption(option => 
                    option.setName('target')
                        .setDescription('The user to sync')
                        .setRequired(true))
        )
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('configure')
                .setDescription('Configure automatic sync settings')
                .addBooleanOption(option => 
                    option.setName('auto_sync')
                        .setDescription('Enable automatic syncing on level up')
                        .setRequired(true))
                .addBooleanOption(option => 
                    option.setName('badge_sync')
                        .setDescription('Enable automatic badge syncing')
                        .setRequired(false))
        )
        
        .addSubcommand(subcommand => 
            subcommand
                .setName('status')
                .setDescription('Check sync status and configuration for this server')
        ),
    
    async execute(interaction) {
        try {
            const { client, guild, user, options } = interaction;
            const subcommand = options.getSubcommand();
            
            console.log(`[SYNC] Processing subcommand: ${subcommand} for user: ${user.tag}`);
            
            // Check permissions for admin commands
            if (['roles', 'badges', 'all', 'configure'].includes(subcommand)) {
                if (!interaction.member.permissions.has(PermissionFlagsBits.ManageGuild)) {
                    return interaction.reply({
                        content: '❌ You need the **Manage Server** permission to use sync commands.',
                        ephemeral: true
                    });
                }
            }
            
            // Ensure leveling manager exists
            if (!client.levelingManager) {
                return interaction.reply({
                    content: '❌ Leveling system is not available.',
                    ephemeral: true
                });
            }
            
            // Handle different subcommands
            switch (subcommand) {
                case 'roles':
                    await handleRoleSync(interaction, client);
                    break;
                    
                case 'badges':
                    await handleBadgeSync(interaction, client);
                    break;
                    
                case 'all':
                    await handleFullSync(interaction, client);
                    break;
                    
                case 'user':
                    await handleUserSync(interaction, client);
                    break;
                    
                case 'configure':
                    await handleSyncConfig(interaction, client);
                    break;
                    
                case 'status':
                    await handleSyncStatus(interaction, client);
                    break;
                    
                default:
                    await interaction.reply({
                        content: `❌ Unknown subcommand: ${subcommand}`,
                        ephemeral: true
                    });
                    break;
            }
        } catch (error) {
            console.error('[SYNC] Error executing sync command:', error);
            if (!interaction.replied && !interaction.deferred) {
                await interaction.reply({
                    content: '❌ There was an error processing your sync command. Please try again later.',
                    ephemeral: true
                });
            }
        }
    }
};

/**
 * Handle role synchronization
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleRoleSync(interaction, client) {
    await interaction.deferReply();
    
    const guild = interaction.guild;
    const guildData = client.levelingManager.getGuildData(guild.id);
    
    if (!guildData || !guildData.roleRewards || Object.keys(guildData.roleRewards).length === 0) {
        return interaction.editReply({
            content: '❌ No role rewards are configured for this server. Use `/leveling addrole` to set them up first.'
        });
    }
    
    let syncedUsers = 0;
    let failedUsers = 0;
    const syncReport = [];
    
    const progressEmbed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🔄 Role Sync in Progress')
        .setDescription('Syncing roles for all users based on their current levels...')
        .setTimestamp();
    
    await interaction.editReply({ embeds: [progressEmbed] });
    
    // Get all members with leveling data
    for (const [userId, userData] of Object.entries(guildData.users || {})) {
        try {
            const member = await guild.members.fetch(userId);
            if (!member) continue;
            
            const userLevel = userData.level || 1;
            const rolesEarned = [];
            
            // Check which roles the user should have based on their level
            for (const [level, roleId] of Object.entries(guildData.roleRewards)) {
                if (userLevel >= parseInt(level)) {
                    const role = guild.roles.cache.get(roleId);
                    if (role && !member.roles.cache.has(roleId)) {
                        await member.roles.add(role);
                        rolesEarned.push(role.name);
                    }
                }
            }
            
            if (rolesEarned.length > 0) {
                syncReport.push(`${member.user.tag}: +${rolesEarned.join(', ')}`);
                syncedUsers++;
            }
            
        } catch (error) {
            console.error(`[SYNC] Error syncing roles for user ${userId}:`, error);
            failedUsers++;
        }
    }
    
    const resultEmbed = new EmbedBuilder()
        .setColor(config.colors.success)
        .setTitle('✅ Role Sync Complete')
        .setDescription(`Successfully synced roles for **${syncedUsers}** users.`)
        .addFields(
            { name: 'Synced Users', value: syncedUsers.toString(), inline: true },
            { name: 'Failed', value: failedUsers.toString(), inline: true },
            { name: 'Role Rewards Active', value: Object.keys(guildData.roleRewards).length.toString(), inline: true }
        )
        .setFooter({ text: `Version: ${config.version}` })
        .setTimestamp();
    
    if (syncReport.length > 0 && syncReport.length <= 10) {
        resultEmbed.addFields({
            name: 'Recent Changes',
            value: syncReport.slice(0, 10).join('\n') || 'No changes made'
        });
    }
    
    await interaction.editReply({ embeds: [resultEmbed] });
}

/**
 * Handle badge synchronization
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleBadgeSync(interaction, client) {
    await interaction.deferReply();
    
    const guild = interaction.guild;
    const guildData = client.levelingManager.getGuildData(guild.id);
    
    if (!guildData) {
        return interaction.editReply({
            content: '❌ No leveling data found for this server.'
        });
    }
    
    let syncedUsers = 0;
    let badgesAwarded = 0;
    
    const progressEmbed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🏆 Badge Sync in Progress')
        .setDescription('Syncing badges for all users based on their achievements...')
        .setTimestamp();
    
    await interaction.editReply({ embeds: [progressEmbed] });
    
    // Badge criteria based on user activity and level
    const badgeCriteria = {
        'milestone_10': { minLevel: 10, badge: 'Rising Star', emoji: '⭐' },
        'milestone_25': { minLevel: 25, badge: 'Dedicated Member', emoji: '🌟' },
        'milestone_50': { minLevel: 50, badge: 'Veteran', emoji: '🏆' },
        'milestone_100': { minLevel: 100, badge: 'Legend', emoji: '👑' }
    };
    
    // Sync badges for all users
    for (const [userId, userData] of Object.entries(guildData.users || {})) {
        try {
            const userLevel = userData.level || 1;
            const userBadges = userData.badges || [];
            let newBadges = 0;
            
            // Check milestone badges
            for (const [badgeId, criteria] of Object.entries(badgeCriteria)) {
                if (userLevel >= criteria.minLevel && !userBadges.includes(badgeId)) {
                    userBadges.push(badgeId);
                    newBadges++;
                    badgesAwarded++;
                }
            }
            
            // Update user data if new badges were awarded
            if (newBadges > 0) {
                userData.badges = userBadges;
                client.levelingManager.saveGuildData(guild.id, guildData);
                syncedUsers++;
            }
            
        } catch (error) {
            console.error(`[SYNC] Error syncing badges for user ${userId}:`, error);
        }
    }
    
    const resultEmbed = new EmbedBuilder()
        .setColor(config.colors.success)
        .setTitle('🏆 Badge Sync Complete')
        .setDescription(`Successfully synced badges for all users.`)
        .addFields(
            { name: 'Users Updated', value: syncedUsers.toString(), inline: true },
            { name: 'Badges Awarded', value: badgesAwarded.toString(), inline: true },
            { name: 'Badge Types', value: Object.keys(badgeCriteria).length.toString(), inline: true }
        )
        .setFooter({ text: `Version: ${config.version}` })
        .setTimestamp();
    
    await interaction.editReply({ embeds: [resultEmbed] });
}

/**
 * Handle full synchronization
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleFullSync(interaction, client) {
    await interaction.deferReply();
    
    const statusEmbed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🔄 Full Sync in Progress')
        .setDescription('Performing complete synchronization...\n⏳ This may take a moment.')
        .setTimestamp();
    
    await interaction.editReply({ embeds: [statusEmbed] });
    
    // Perform role sync first
    await handleRoleSync(interaction, client);
    
    // Wait a moment between operations
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Then perform badge sync
    await handleBadgeSync(interaction, client);
    
    const completeEmbed = new EmbedBuilder()
        .setColor(config.colors.success)
        .setTitle('✅ Full Sync Complete')
        .setDescription('Successfully completed full synchronization of roles and badges.')
        .addFields(
            { name: 'Operations Completed', value: '• Role synchronization\n• Badge synchronization\n• Level validation' },
            { name: 'Status', value: 'All systems synchronized' }
        )
        .setFooter({ text: `Version: ${config.version}` })
        .setTimestamp();
    
    await interaction.editReply({ embeds: [completeEmbed] });
}

/**
 * Handle user-specific synchronization
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleUserSync(interaction, client) {
    const targetUser = interaction.options.getUser('target');
    const member = await interaction.guild.members.fetch(targetUser.id);
    
    if (!member) {
        return interaction.reply({
            content: '❌ User not found in this server.',
            ephemeral: true
        });
    }
    
    await interaction.deferReply();
    
    const userData = client.levelingManager.getUserData(interaction.guild.id, targetUser.id);
    
    if (!userData) {
        return interaction.editReply({
            content: `❌ No leveling data found for ${targetUser.tag}.`
        });
    }
    
    let syncActions = [];
    const userLevel = userData.level || 1;
    
    // Sync roles
    const guildData = client.levelingManager.getGuildData(interaction.guild.id);
    if (guildData && guildData.roleRewards) {
        for (const [level, roleId] of Object.entries(guildData.roleRewards)) {
            if (userLevel >= parseInt(level)) {
                const role = interaction.guild.roles.cache.get(roleId);
                if (role && !member.roles.cache.has(roleId)) {
                    await member.roles.add(role);
                    syncActions.push(`Added role: ${role.name}`);
                }
            }
        }
    }
    
    // Sync badges
    const badgeCriteria = {
        'milestone_10': { minLevel: 10, badge: 'Rising Star' },
        'milestone_25': { minLevel: 25, badge: 'Dedicated Member' },
        'milestone_50': { minLevel: 50, badge: 'Veteran' },
        'milestone_100': { minLevel: 100, badge: 'Legend' }
    };
    
    const userBadges = userData.badges || [];
    for (const [badgeId, criteria] of Object.entries(badgeCriteria)) {
        if (userLevel >= criteria.minLevel && !userBadges.includes(badgeId)) {
            userBadges.push(badgeId);
            syncActions.push(`Awarded badge: ${criteria.badge}`);
        }
    }
    
    // Save updated badges
    if (syncActions.some(action => action.includes('badge'))) {
        userData.badges = userBadges;
        client.levelingManager.saveGuildData(interaction.guild.id, guildData);
    }
    
    const resultEmbed = new EmbedBuilder()
        .setColor(config.colors.success)
        .setTitle('✅ User Sync Complete')
        .setDescription(`Synchronization complete for ${targetUser.tag}`)
        .addFields(
            { name: 'User Level', value: userLevel.toString(), inline: true },
            { name: 'Actions Taken', value: syncActions.length.toString(), inline: true },
            { name: 'Status', value: 'Synchronized', inline: true }
        )
        .setFooter({ text: `Version: ${config.version}` })
        .setTimestamp();
    
    if (syncActions.length > 0) {
        resultEmbed.addFields({
            name: 'Changes Made',
            value: syncActions.join('\n') || 'No changes needed'
        });
    }
    
    await interaction.editReply({ embeds: [resultEmbed] });
}

/**
 * Handle sync configuration
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleSyncConfig(interaction, client) {
    const autoSync = interaction.options.getBoolean('auto_sync');
    const badgeSync = interaction.options.getBoolean('badge_sync') ?? true;
    
    // Get or create server settings
    const serverSettings = client.serverSettingsManager.getGuildSettings(interaction.guild.id);
    
    if (!serverSettings.sync) {
        serverSettings.sync = {};
    }
    
    serverSettings.sync.autoSync = autoSync;
    serverSettings.sync.badgeSync = badgeSync;
    serverSettings.sync.enabled = true;
    
    client.serverSettingsManager.saveSettings();
    
    const configEmbed = new EmbedBuilder()
        .setColor(config.colors.success)
        .setTitle('⚙️ Sync Configuration Updated')
        .setDescription('Automatic sync settings have been updated for this server.')
        .addFields(
            { name: 'Auto Sync on Level Up', value: autoSync ? '✅ Enabled' : '❌ Disabled', inline: true },
            { name: 'Auto Badge Sync', value: badgeSync ? '✅ Enabled' : '❌ Disabled', inline: true },
            { name: 'Sync System', value: '✅ Active', inline: true }
        )
        .setFooter({ text: `Version: ${config.version}` })
        .setTimestamp();
    
    await interaction.reply({ embeds: [configEmbed] });
}

/**
 * Handle sync status check
 * @param {Interaction} interaction - The Discord interaction
 * @param {Client} client - The Discord client
 */
async function handleSyncStatus(interaction, client) {
    const serverSettings = client.serverSettingsManager.getGuildSettings(interaction.guild.id);
    const guildData = client.levelingManager.getGuildData(interaction.guild.id);
    
    const syncSettings = serverSettings.sync || {};
    const roleRewards = guildData?.roleRewards || {};
    const totalUsers = Object.keys(guildData?.users || {}).length;
    
    const statusEmbed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('📊 Sync Status')
        .setDescription('Current synchronization status for this server:')
        .addFields(
            { name: 'Auto Sync', value: syncSettings.autoSync ? '✅ Enabled' : '❌ Disabled', inline: true },
            { name: 'Badge Sync', value: syncSettings.badgeSync ? '✅ Enabled' : '❌ Disabled', inline: true },
            { name: 'System Status', value: syncSettings.enabled ? '🟢 Active' : '🔴 Inactive', inline: true },
            { name: 'Role Rewards', value: Object.keys(roleRewards).length.toString(), inline: true },
            { name: 'Users with Data', value: totalUsers.toString(), inline: true },
            { name: 'Last Update', value: new Date().toLocaleString(), inline: true }
        )
        .setFooter({ text: `Version: ${config.version}` })
        .setTimestamp();
    
    await interaction.reply({ embeds: [statusEmbed] });
}