const { EmbedBuilder, ActionRowBuilder, StringSelectMenuBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');

/**
 * Show detailed category help for select menu interactions
 */
async function showDetailedCategoryMenuHelp(interaction, category) {
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
                    { name: '/help [category]', value: '**Shows categorized command menu**\nQuickly browse all available commands by category', inline: false },
                    { name: '/about', value: '**Displays bot information and statistics**\nView bot uptime, server count, and version details', inline: false },
                    { name: '/updates', value: '**Shows latest bot updates and features**\nStay informed about new features and improvements', inline: false },
                    { name: '/ses', value: '**Bot session and status information**\nDetailed technical information about bot performance', inline: false },
                    { name: '/echo [message]', value: '**Makes the bot repeat your message**\nUseful for announcements and formatted messages', inline: false }
                );
            break;
            
        case 'leveling':
            commandCount = 9;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Leveling System - Detailed View')
                .setDescription('Comprehensive XP and ranking system to encourage server activity and engagement.')
                .addFields(
                    { name: '/leveling rank [@user]', value: '**View user level and XP progress**\nCheck your current level, XP, and progress to next level', inline: false },
                    { name: '/leveling leaderboard [page]', value: '**Server XP leaderboard with pagination**\nSee top-ranked members and their achievements', inline: false },
                    { name: '/leveling badges [@user]', value: '**View and manage achievement badges**\nDisplay special badges earned through activities', inline: false },
                    { name: '/leveling settings', value: '**Configure leveling system (Admin)**\nCustomize XP rates, level-up notifications, and rewards', inline: false },
                    { name: '/leveling add-role [level] [role]', value: '**Add role rewards for levels (Admin)**\nSet up automatic role assignments for reaching levels', inline: false },
                    { name: '/leveling remove-role [level]', value: '**Remove role rewards (Admin)**\nRemove existing level-based role rewards', inline: false },
                    { name: '/leveling list-roles', value: '**List all role rewards**\nView all configured level-based role rewards', inline: false },
                    { name: '/leveling award [@user] [amount]', value: '**Award XP to users (Admin)**\nManually give XP to users for special contributions', inline: false },
                    { name: '/leveling award-badge [@user] [badge]', value: '**Award badges to users (Admin)**\nGrant special achievement badges to deserving members', inline: false }
                );
            break;
            
        case 'games':
            commandCount = 4;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.warning)
                .setTitle('🎮 Games & Activities - Detailed View')
                .setDescription('Interactive games and fun activities to boost server engagement and entertainment.')
                .addFields(
                    { name: '/tictactoe [@user]', value: '**Classic Tic-Tac-Toe game**\nPlay against other members with interactive buttons', inline: false },
                    { name: '/truthdare', value: '**Truth or Dare game with custom questions**\nAdd your own questions or use the built-in database', inline: false },
                    { name: '/counting [start]', value: '**Number counting game**\nServer-wide counting game with streak tracking', inline: false },
                    { name: '/poll [question] [options]', value: '**Create interactive polls with timers**\nGather opinions with customizable voting options', inline: false }
                );
            break;
            
        case 'moderation':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.secondary)
                .setTitle('🛡️ Moderation Tools - Detailed View')
                .setDescription('Comprehensive moderation and server management tools for maintaining order and providing support.')
                .addFields(
                    { name: '/ticket', value: '**Create ticket support system**\nSet up support channels with automatic categorization', inline: false },
                    { name: '/createticket [reason]', value: '**Create ticket with custom name**\nInstantly create a support ticket with specific purpose', inline: false },
                    { name: '/tickethistory [@user]', value: '**View ticket history and logs**\nReview past tickets and support interactions', inline: false },
                    { name: '/move [@user] [channel]', value: '**Move members between voice channels**\nQuickly relocate users to different voice channels', inline: false },
                    { name: '/end [activity]', value: '**End ongoing activities**\nStop giveaways, polls, or other time-based activities', inline: false }
                );
            break;
            
        case 'community':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('👥 Community Features - Detailed View')
                .setDescription('Tools to build and engage your community with special events and social features.')
                .addFields(
                    { name: '/giveaway [prize] [duration]', value: '**Create giveaways with role requirements**\nHost exciting giveaways with customizable entry requirements', inline: false },
                    { name: '/reroll [giveaway-id]', value: '**Reroll giveaway winners**\nSelect new winners if original winners are unavailable', inline: false },
                    { name: '/birthday [action]', value: '**Birthday celebration system**\nTrack and celebrate member birthdays automatically', inline: false },
                    { name: '/welcomeconfig', value: '**Configure welcome messages**\nCustomize welcome messages for new server members', inline: false },
                    { name: '/broadcast [message]', value: '**Send announcements to all servers**\nShare important updates across multiple servers', inline: false }
                );
            break;
            
        case 'admin':
            commandCount = 6;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('⚙️ Administration - Detailed View')
                .setDescription('Advanced server configuration and management tools. Requires administrator permissions.')
                .addFields(
                    { name: '/broadcastsettings', value: '**Configure broadcast system settings**\nSet up cross-server announcement preferences', inline: false },
                    { name: '/sync configure', value: '**Set up automatic role/badge syncing**\nAutomate role assignments based on levels and achievements', inline: false },
                    { name: '/sync roles', value: '**Sync role rewards manually**\nApply role rewards to all eligible members', inline: false },
                    { name: '/sync badges', value: '**Sync badge rewards manually**\nUpdate badge assignments for all members', inline: false },
                    { name: '/sync full', value: '**Complete system synchronization**\nPerform full sync of all leveling rewards and badges', inline: false },
                    { name: '/sync status', value: '**Check synchronization status**\nView current sync settings and last sync times', inline: false }
                );
            break;
            
        default:
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('❌ Unknown Category')
                .setDescription('The requested category was not found. Please select a valid category from the dropdown menu.');
    }

    if (categoryEmbed && category !== 'unknown') {
        categoryEmbed.addFields({
            name: '📈 Category Information',
            value: `**Commands in this category:** ${commandCount}\n**Usage Level:** ${getCategoryUsageLevel(category)}\n**Permission Level:** ${getCategoryPermissionLevel(category)}\n**Interaction Type:** Slash Commands`,
            inline: true
        });
    }

    // Create new select menu with current selection
    const backSelect = new ActionRowBuilder()
        .addComponents(
            new StringSelectMenuBuilder()
                .setCustomId('category_select')
                .setPlaceholder('Choose another category...')
                .addOptions([
                    {
                        label: 'General Commands',
                        description: 'Basic bot commands and information',
                        value: 'general',
                        emoji: '⚡',
                        default: category === 'general'
                    },
                    {
                        label: 'Leveling System',
                        description: 'XP, ranks, and progression features',
                        value: 'leveling',
                        emoji: '📊',
                        default: category === 'leveling'
                    },
                    {
                        label: 'Games & Activities',
                        description: 'Fun interactive games and entertainment',
                        value: 'games',
                        emoji: '🎮',
                        default: category === 'games'
                    },
                    {
                        label: 'Moderation Tools',
                        description: 'Server management and moderation',
                        value: 'moderation',
                        emoji: '🛡️',
                        default: category === 'moderation'
                    },
                    {
                        label: 'Community Features',
                        description: 'Engagement and social activities',
                        value: 'community',
                        emoji: '👥',
                        default: category === 'community'
                    },
                    {
                        label: 'Administration',
                        description: 'Advanced server configuration',
                        value: 'admin',
                        emoji: '⚙️',
                        default: category === 'admin'
                    }
                ])
        );

    const navigationButtons = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('categories_main')
                .setLabel('Back to Main')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('🏠'),
            new ButtonBuilder()
                .setCustomId('categories_help')
                .setLabel('Need Help?')
                .setStyle(ButtonStyle.Primary)
                .setEmoji('❓')
        );

    categoryEmbed.setFooter({ text: `Version: ${config.version} • Category: ${category.charAt(0).toUpperCase() + category.slice(1)}` })
               .setTimestamp();

    try {
        await interaction.update({
            embeds: [categoryEmbed],
            components: [backSelect, navigationButtons]
        });
    } catch (error) {
        console.error('Error updating interaction:', error);
        // Fallback to reply if update fails
        if (!interaction.replied) {
            await interaction.reply({
                embeds: [categoryEmbed],
                components: [backSelect, navigationButtons]
            });
        }
    }
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

module.exports = {
    showDetailedCategoryMenuHelp,
    getCategoryUsageLevel,
    getCategoryPermissionLevel
};