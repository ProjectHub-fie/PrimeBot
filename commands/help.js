const { SlashCommandBuilder, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, PermissionFlagsBits } = require('discord.js');
const config = require('../config');

module.exports = {
    data: new SlashCommandBuilder()
        .setName('help')
        .setDescription('Shows a categorized list of all available commands')
        .setDefaultMemberPermissions('0')
        .addStringOption(option =>
            option.setName('category')
                .setDescription('Choose a specific category to view')
                .setRequired(false)
                .addChoices(
                    { name: 'General', value: 'general' },
                    { name: 'Leveling', value: 'leveling' },
                    { name: 'Games', value: 'games' },
                    { name: 'Moderation', value: 'moderation' },
                    { name: 'Community', value: 'community' },
                    { name: 'Administration', value: 'admin' }
                )),
    
    async execute(interaction) {
        try {
            const category = interaction.options.getString('category');
            
            if (category) {
                await showCategoryHelp(interaction, category);
            } else {
                await showMainHelp(interaction);
            }
        } catch (error) {
            console.error('[HELP] Error executing help command:', error);
            if (!interaction.replied && !interaction.deferred) {
                await interaction.reply({
                    content: 'There was an error displaying the help menu. Please try again later.',
                    ephemeral: true
                });
            }
        }
    }
};

/**
 * Show the main help menu with categories
 */
async function showMainHelp(interaction) {
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
        .setFooter({ text: `Total Commands: 30+ • Version: ${config.version}` })
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

    await interaction.reply({
        embeds: [mainEmbed],
        components: [categoryButtons, adminButton]
    });
}

/**
 * Show category-specific help
 */
async function showCategoryHelp(interaction, category) {
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
                    { name: '/echo', value: 'Make the bot repeat a message', inline: true }
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
                    { name: '/leveling awardbadge', value: 'Award badges to users (Admin)', inline: true },
                    { name: '/sync', value: 'Synchronize roles and badges with levels', inline: true }
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
    
    await interaction.reply({
        embeds: [categoryEmbed],
        components: [backButton]
    });
}

// Export the functions for use in interaction handling
module.exports.showMainHelp = showMainHelp;
module.exports.showCategoryHelp = showCategoryHelp;