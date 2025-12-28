const { SlashCommandBuilder, EmbedBuilder, ActionRowBuilder, StringSelectMenuBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('categories')
        .setDescription('Browse commands by category with interactive menus')
        .setDefaultMemberPermissions('0'),

    async execute(interaction) {
        await showCategorySelector(interaction);
    }
};

/**
 * Show the main category selector with select menu
 */
async function showCategorySelector(interaction) {
    const mainEmbed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('🗂️ Interactive Category Browser')
        .setDescription('Use the dropdown menu below to explore different command categories. Each category contains specialized commands for different server needs.')
        .addFields(
            { name: '📊 Quick Stats', value: `**Total Commands:** 25\n**Categories:** 6\n**Active Servers:** ${interaction.client.guilds.cache.size}`, inline: true },
            { name: '🚀 Getting Started', value: 'Select a category from the menu to see available commands and their descriptions.', inline: true },
            { name: '💡 Pro Tip', value: 'Use `/help` for traditional category browsing or `/categories` for this interactive experience.', inline: true }
        )
        .setFooter({ text: `Version: ${config.version}` })
        .setTimestamp();

    const categorySelect = new ActionRowBuilder()
        .addComponents(
            new StringSelectMenuBuilder()
                .setCustomId('category_select')
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
                .setEmoji('❓'),
            new ButtonBuilder()
                .setLabel('Support Server')
                .setStyle(ButtonStyle.Link)
                .setURL(config.supportServer || 'https://discord.gg/primebot')
                .setEmoji('🆘')
        );

    await interaction.reply({
        embeds: [mainEmbed],
        components: [categorySelect, actionButtons]
    });
}

/**
 * Handle category selection and show detailed command list
 */
async function showCategoryDetails(interaction, category) {
    let categoryEmbed;
    let commandCount = 0;

    switch (category) {
        case 'general':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('⚡ General Commands')
                .setDescription('Essential bot commands for everyday use. These commands provide basic information and utility functions.')
                .addFields(
                    { name: '</help:0>', value: '`Shows categorized command menu`\nQuickly browse all available commands by category', inline: false },
                    { name: '</about:0>', value: '`Displays bot information and statistics`\nView bot uptime, server count, and version details', inline: false },
                    { name: '</updates:0>', value: '`Shows latest bot updates and features`\nStay informed about new features and improvements', inline: false },
                    { name: '</ses:0>', value: '`Bot session and status information`\nDetailed technical information about bot performance', inline: false },
                    { name: '</echo:0>', value: '`Makes the bot repeat your message`\nUseful for announcements and formatted messages', inline: false }
                );
            break;

        case 'leveling':
            commandCount = 9;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('📊 Leveling System')
                .setDescription('Comprehensive XP and ranking system to encourage server activity and engagement.')
                .addFields(
                    { name: '</leveling rank:0>', value: '`View user level and XP progress`\nCheck your current level, XP, and progress to next level', inline: false },
                    { name: '</leveling leaderboard:0>', value: '`Server XP leaderboard with pagination`\nSee top-ranked members and their achievements', inline: false },
                    { name: '</leveling badges:0>', value: '`View and manage achievement badges`\nDisplay special badges earned through activities', inline: false },
                    { name: '</leveling settings:0>', value: '`Configure leveling system (Admin)`\nCustomize XP rates, level-up notifications, and rewards', inline: false },
                    { name: '</leveling add-role:0>', value: '`Add role rewards for levels (Admin)`\nSet up automatic role assignments for reaching levels', inline: false },
                    { name: '</leveling remove-role:0>', value: '`Remove role rewards (Admin)`\nRemove existing level-based role rewards', inline: false },
                    { name: '</leveling list-roles:0>', value: '`List all role rewards`\nView all configured level-based role rewards', inline: false },
                    { name: '</leveling award:0>', value: '`Award XP to users (Admin)`\nManually give XP to users for special contributions', inline: false },
                    { name: '</leveling award-badge:0>', value: '`Award badges to users (Admin)`\nGrant special achievement badges to deserving members', inline: false }
                );
            break;

        case 'games':
            commandCount = 4;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.warning)
                .setTitle('🎮 Games & Activities')
                .setDescription('Interactive games and fun activities to boost server engagement and entertainment.')
                .addFields(
                    { name: '</tictactoe:0>', value: '`Classic Tic-Tac-Toe game`\nPlay against other members with interactive buttons', inline: false },
                    { name: '</truthdare:0>', value: '`Truth or Dare game with custom questions`\nAdd your own questions or use the built-in database', inline: false },
                    { name: '</counting:0>', value: '`Number counting game`\nServer-wide counting game with streak tracking', inline: false },
                    { name: '</poll:0>', value: '`Create interactive polls with timers`\nGather opinions with customizable voting options', inline: false }
                );
            break;

        case 'moderation':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.secondary)
                .setTitle('🛡️ Moderation Tools')
                .setDescription('Comprehensive moderation and server management tools for maintaining order and providing support.')
                .addFields(
                    { name: '</ticket:0>', value: '`Create ticket support system`\nSet up support channels with automatic categorization', inline: false },
                    { name: '</createticket:0>', value: '`Create ticket with custom name`\nInstantly create a support ticket with specific purpose', inline: false },
                    { name: '</tickethistory:0>', value: '`View ticket history and logs`\nReview past tickets and support interactions', inline: false },
                    { name: '</move:0>', value: '`Move members between voice channels`\nQuickly relocate users to different voice channels', inline: false },
                    { name: '</end:0>', value: '`End ongoing activities`\nStop giveaways, polls, or other time-based activities', inline: false }
                );
            break;

        case 'community':
            commandCount = 5;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('👥 Community Features')
                .setDescription('Tools to build and engage your community with special events and social features.')
                .addFields(
                    { name: '</giveaway:0>', value: '`Create giveaways with role requirements`\nHost exciting giveaways with customizable entry requirements', inline: false },
                    { name: '</reroll:0>', value: '`Reroll giveaway winners`\nSelect new winners if original winners are unavailable', inline: false },
                    { name: '</birthday:0>', value: '`Birthday celebration system`\nTrack and celebrate member birthdays automatically', inline: false },
                    { name: '</welcomeconfig:0>', value: '`Configure welcome messages`\nCustomize welcome messages for new server members', inline: false },
                    { name: '</broadcast:0>', value: '`Send announcements to all servers`\nShare important updates across multiple servers', inline: false }
                );
            break;

        case 'admin':
            commandCount = 6;
            categoryEmbed = new EmbedBuilder()
                .setColor(config.colors.error)
                .setTitle('⚙️ Administration')
                .setDescription('Advanced server configuration and management tools. Requires administrator permissions.')
                .addFields(
                    { name: '</broadcastsettings:0>', value: '`Configure broadcast system settings`\nSet up cross-server announcement preferences', inline: false },
                    { name: '</sync configure:0>', value: '`Set up automatic role/badge syncing`\nAutomate role assignments based on levels and achievements', inline: false },
                    { name: '</sync roles:0>', value: '`Sync role rewards manually`\nApply role rewards to all eligible members', inline: false },
                    { name: '</sync badges:0>', value: '`Sync badge rewards manually`\nUpdate badge assignments for all members', inline: false },
                    { name: '</sync full:0>', value: '`Complete system synchronization`\nPerform full sync of all leveling rewards and badges', inline: false },
                    { name: '</sync status:0>', value: '`Check synchronization status`\nView current sync settings and last sync times', inline: false }
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
            name: '📈 Category Stats',
            value: `**Commands in this category:** ${commandCount}\n**Usage Level:** ${getCategoryUsageLevel(category)}\n**Permission Level:** ${getCategoryPermissionLevel(category)}`,
            inline: true
        });
    }

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
                .setEmoji('❓'),
            new ButtonBuilder()
                .setLabel('Documentation')
                .setStyle(ButtonStyle.Link)
                .setURL('https://discord.js.org/')
                .setEmoji('📚')
        );

    categoryEmbed.setFooter({ text: `Version: ${config.version} • Category: ${category.charAt(0).toUpperCase() + category.slice(1)}` })
               .setTimestamp();

    await interaction.update({
        embeds: [categoryEmbed],
        components: [backSelect, navigationButtons]
    });
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

// Export the handler functions for use in interaction handling
module.exports.showCategorySelector = showCategorySelector;
module.exports.showCategoryDetails = showCategoryDetails;