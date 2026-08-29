const { EmbedBuilder, ActionRowBuilder, StringSelectMenuBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');

// ───────────────────────────────────────────────────────────────────────────
// Prefix command catalog — single source of truth for `$help` / `$commands`
//
// Categories (per the remade help):
//   • General            — basic info + the category browser itself
//   • Leveling           — XP/ranks/badges (badges are 🧪 BETA)
//   • Games & Activities — games + in-server polls/giveaways/birthdays
//   • Community          — cross-server live polls & live giveaways
//   • Tickets            — ticket support commands
//   • Welcome            — welcome system configuration
//   • Moderation         — mod tools + self-roles ($role) + $beta
//   • Administration     — feature configuration
//
// Excluded by design: broadcast, session ($ses), sync, tokentest, np/noprefix,
// and $betaserver (internal developer tool). Role content was merged into
// Moderation; the category-browser command lives in General.
//
// A command is tagged 🧪 BETA when its canonical name (or any alias) appears in
// `config.betaFeatures` — the same list the bot gates on at runtime.
// ───────────────────────────────────────────────────────────────────────────

const BETA_FEATURES = Array.isArray(config.betaFeatures) ? config.betaFeatures : [];

function isBeta(names) {
    if (!Array.isArray(names)) names = [names];
    return names.some(n => BETA_FEATURES.includes(n));
}

// Each entry: { names: [primary, ...aliases], desc, beta?: true }
// `beta: true` is set manually for commands that are part of a beta feature
// family even when the exact alias isn't in config.betaFeatures (e.g. the badge
// sub-commands), so the 🧪 badge stays accurate.
const CATALOG = {
    general: {
        icon: '⚡',
        label: 'General',
        title: '⚡ General Commands',
        color: config.colors.primary,
        description: 'Basic bot commands and information:',
        commands: [
            { names: ['help'], args: '[category]', desc: 'Show the categorized command menu' },
            { names: ['commands', 'categories'], desc: 'Browse all command categories' },
            { names: ['about', 'ab'], desc: 'Information about the bot' },
            { names: ['stats', 'statistics'], desc: 'Bot statistics and server count' },
            { names: ['updates', 'ulog'], desc: 'Latest bot updates and features' },
            { names: ['ping'], desc: 'Check bot latency and connection status' },
            { names: ['echo'], args: '[message]', desc: 'Make the bot repeat a message' },
            { names: ['prefix'], args: '[new prefix]', desc: 'View or set the server prefix (Admin)' },
        ],
    },

    leveling: {
        icon: '📊',
        label: 'Leveling',
        title: '📊 Leveling System',
        color: config.colors.success,
        description: 'XP, ranks, badges, and progression:',
        commands: [
            { names: ['rank', 'level', 'exp', 'profile'], args: '[@user]', desc: 'View your or another user\'s level and XP' },
            { names: ['leaderboard', 'levels', 'lb'], args: '[page]', desc: 'Server XP leaderboard with pagination' },
            { names: ['set-level', 'setlevel'], args: '@user [level]', desc: 'Set a user\'s level (Admin)' },
            { names: ['leveling', 'lvl'], desc: 'Leveling configuration overview' },
            { names: ['badge', 'badges'], args: '[@user]', desc: 'View available and earned badges', beta: true },
            { names: ['award-badge', 'awardbadge', 'give-badge'], args: '@user [badge]', desc: 'Award a badge to a user (Admin)', beta: true },
            { names: ['revoke-badge', 'revokebadge', 'remove-badge'], args: '@user [badge]', desc: 'Revoke a badge from a user (Admin)', beta: true },
            { names: ['view-badges', 'viewbadges', 'listbadges', 'badgelist'], desc: 'List all available badges', beta: true },
        ],
    },

    games: {
        icon: '🎮',
        label: 'Games & Activities',
        title: '🎮 Games & Activities',
        color: config.colors.warning,
        description: 'Games, activities, polls, and giveaways:',
        commands: [
            { names: ['tictactoe', 'tictactoi'], args: '@user', desc: 'Start a Tic-Tac-Toe game' },
            { names: ['move'], args: '[1-9]', desc: 'Make a move in an active Tic-Tac-Toe game' },
            { names: ['tend'], desc: 'End the current Tic-Tac-Toe game' },
            { names: ['truthdare'], desc: 'Interactive Truth or Dare game' },
            { names: ['qadd'], args: '[type] [question]', desc: 'Add a custom truth/dare question' },
            { names: ['cstart'], args: '[start] [goal]', desc: 'Start a number counting game' },
            { names: ['cstatus'], desc: 'Check the counting game status' },
            { names: ['cend'], desc: 'End the counting game (Admin)' },
            { names: ['chelp'], desc: 'Counting game help' },
            { names: ['poll'], args: '[time] [question] [options]', desc: 'Create an interactive poll with a timer' },
            { names: ['endpoll'], args: '[id]', desc: 'End a poll early' },
            { names: ['giveaway', 'gstart'], args: '[time] [winners] [prize]', desc: 'Create a giveaway' },
            { names: ['end', 'gend'], args: '[id]', desc: 'End a giveaway' },
            { names: ['reroll'], args: '[id]', desc: 'Reroll giveaway winners' },
            { names: ['birthday', 'bday'], args: '<set|remove|list|check|channel|role>', desc: 'Birthday celebration system' },
        ],
    },

    community: {
        icon: '🌐',
        label: 'Community',
        title: '🌐 Community — Live Polls & Giveaways',
        color: config.colors.success,
        description: 'Cross-server live polls and live giveaways — share a pass code to let members from any PrimeBot server join:',
        selectDesc: 'Cross-server live polls & giveaways',
        commands: [
            { names: ['lpoll', 'livepoll'], args: '<create|join|results|end|list>', desc: 'Cross-server live polls' },
            { names: ['lgiveway', 'lgiveaway', 'livegiveaway'], args: '<create|join|results|end|list>', desc: 'Cross-server live giveaways' },
        ],
    },

    moderation: {
        icon: '🛡️',
        label: 'Moderation',
        title: '🛡️ Moderation Tools',
        color: config.colors.secondary,
        description: 'Moderation, channel management, self-roles, and tickets:',
        commands: [
            { names: ['kick'], args: '@member [reason]', desc: 'Kick a member from the server' },
            { names: ['ban'], args: '@member|userid [reason] [days]', desc: 'Ban a member from the server' },
            { names: ['unban'], args: 'userid [reason]', desc: 'Unban a member by user id' },
            { names: ['warn'], args: '@member [reason]', desc: 'Warn a member' },
            { names: ['unwarn'], args: '@member', desc: 'Remove a member\'s warnings' },
            { names: ['warnings'], args: '[@member]', desc: 'View a member\'s warnings' },
            { names: ['mute'], args: '@member [duration]', desc: 'Mute a member' },
            { names: ['unmute'], args: '@member', desc: 'Unmute a member' },
            { names: ['purge'], args: '<count|user @member|between id1 id2|messages count>', desc: 'Bulk-delete messages' },
            { names: ['lock'], args: '[#channel]', desc: 'Lock a channel (Admin)' },
            { names: ['unlock'], args: '[#channel]', desc: 'Unlock a channel (Admin)' },
            { names: ['hide'], args: '[#channel]', desc: 'Hide a channel from @everyone (Admin)' },
            { names: ['unhide'], args: '[#channel]', desc: 'Unhide a channel for @everyone (Admin)' },
            { names: ['nuke'], args: '[name] [#channel]', desc: 'Recreate a channel in place (Admin)' },
            { names: ['snipe'], args: '[#channel]', desc: 'Show the last deleted message in a channel' },
            { names: ['rm', 'rename'], args: '[name] [#channel]', desc: 'Rename a channel (Admin)' },
            { names: ['move'], args: '@user #channel', desc: 'Move members between voice channels' },
            { names: ['role'], args: '<add|remove|create|list>', desc: 'Self-assignable roles' },
            { names: ['beta'], args: '<enable|disable|status>', desc: 'Opt in/out of beta features (server owner)' },
        ],
    },

    admin: {
        icon: '⚙️',
        label: 'Administration',
        title: '⚙️ Administration',
        color: config.colors.error,
        description: 'Feature configuration (Admin only):',
        commands: [
            { names: ['autoreact', 'auto-react'], args: '<enable|disable|add|remove|list>', desc: 'Configure auto-reactions' },
            { names: ['autoresponder', 'auto-responder', 'aresponder', 'ar'], args: '<enable|disable|add|exact|remove|list>', desc: 'Configure the auto-responder' },
            { names: ['level-enable', 'levelenable', 'leveling-enable', 'levelingon'], desc: 'Enable the leveling system' },
            { names: ['level-disable', 'leveldisable', 'leveling-disable', 'levelingoff'], desc: 'Disable the leveling system' },
            { names: ['level-channel', 'levelchannel'], args: '#channel', desc: 'Set the level-up notification channel' },
            { names: ['level-multiplier', 'levelmultiplier'], args: '[number]', desc: 'Set the XP multiplier' },
        ],
    },

    tickets: {
        icon: '🎫',
        label: 'Tickets',
        title: '🎫 Tickets',
        color: config.colors.secondary,
        description: 'Ticket support system — panels are configured from the dashboard; these commands reply with a pointer to the dashboard:',
        selectDesc: 'Ticket support system',
        commands: [
            { names: ['ticket', 'thelp'], desc: 'Ticket help (dashboard-only)' },
            { names: ['tcreate', 'createt', 'createticket'], args: '[name]', desc: 'Create a ticket (dashboard-only)' },
            { names: ['thistory'], args: '[page]', desc: 'View ticket history (dashboard-only)' },
        ],
    },

    welcome: {
        icon: '👋',
        label: 'Welcome',
        title: '👋 Welcome System',
        color: config.colors.success,
        description: 'Configure how PrimeBot greets new members:',
        commands: [
            { names: ['welcome-enable', 'welcomeenable', 'welcome-on'], desc: 'Enable the welcome system (Admin)' },
            { names: ['welcome-disable', 'welcomedisable', 'welcome-off'], desc: 'Disable the welcome system (Admin)' },
            { names: ['welcome-channel', 'welcomechannel'], args: '#channel', desc: 'Set the welcome message channel (Admin)' },
            { names: ['welcomeconfig', 'welcome'], desc: 'View / configure welcome messages' },
        ],
    },
};

const CATEGORY_ORDER = ['general', 'leveling', 'games', 'community', 'tickets', 'welcome', 'moderation', 'admin'];

const BETA_TAG = '🧪';

function commandField(prefix, cmd) {
    const primary = cmd.names[0];
    const aliases = cmd.names.slice(1);
    const name = aliases.length
        ? `${prefix}${primary}${cmd.args ? ' ' + cmd.args : ''} *(${aliases.map(a => prefix + a).join(', ')})*`
        : `${prefix}${primary}${cmd.args ? ' ' + cmd.args : ''}`;
    const beta = (cmd.beta || isBeta(cmd.names)) ? ` ${BETA_TAG}` : '';
    return { name: `${name}${beta}`, value: cmd.desc, inline: true };
}

function categoryEmbed(category, prefix) {
    const cat = CATALOG[category];
    if (!cat) {
        return new EmbedBuilder()
            .setColor(config.colors.error)
            .setTitle('❌ Unknown Category')
            .setDescription(`The category "${category}" was not found. Available categories: ${CATEGORY_ORDER.join(', ')}`);
    }
    const embed = new EmbedBuilder()
        .setColor(cat.color)
        .setTitle(cat.title)
        .setDescription(cat.description)
        .addFields(cat.commands.map(c => commandField(prefix, c)));

    const betaCount = cat.commands.filter(c => c.beta || isBeta(c.names)).length;
    const info = [
        `**Commands:** ${cat.commands.length}`,
        `**Usage Level:** ${getCategoryUsageLevel(category)}`,
        `**Permission:** ${getCategoryPermissionLevel(category)}`,
    ];
    if (betaCount > 0) info.push(`${BETA_TAG} **Beta:** ${betaCount}`);
    embed.addFields({ name: '📈 Category Info', value: info.join('\n'), inline: true });

    embed.setFooter({ text: `Use ${prefix}help to see all categories • Version: ${config.version}` }).setTimestamp();
    return embed;
}

function mainMenuEmbed(prefix, client) {
    const totalCommands = CATEGORY_ORDER.reduce((sum, k) => sum + CATALOG[k].commands.length, 0);
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('📚 Command Categories')
        .setDescription(`Choose a category to explore available commands:\n\n**Usage:** \`${prefix}help [category]\`\n\n${BETA_TAG} = beta feature (gated behind the beta program)`)
        .addFields(
            CATEGORY_ORDER.map(k => {
                const cat = CATALOG[k];
                return { name: `${cat.icon} ${cat.label}`, value: `\`${prefix}help ${k}\`\n${cat.description.replace(/:$/, '')}`, inline: true };
            })
        )
        .setFooter({ text: `Total Commands: ${totalCommands} • Version: ${config.version}` })
        .setTimestamp();
    return embed;
}

function categorySelectRow(currentCategory = null) {
    return new ActionRowBuilder()
        .addComponents(
            new StringSelectMenuBuilder()
                .setCustomId('category_select_prefix')
                .setPlaceholder('Choose a category to explore...')
                .addOptions(CATEGORY_ORDER.map(k => {
                    const cat = CATALOG[k];
                    // Select-menu descriptions are capped at 100 chars.
                    let desc = cat.selectDesc || cat.description.replace(/:$/, '');
                    if (desc.length > 100) desc = desc.slice(0, 97) + '...';
                    return {
                        label: `${cat.label} Commands`,
                        description: desc,
                        value: k,
                        emoji: cat.icon,
                        default: k === currentCategory,
                    };
                }))
        );
}

function navigationButtonsRow() {
    return new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('categories_prefix_refresh')
                .setLabel('Refresh')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('🔄'),
            new ButtonBuilder()
                .setCustomId('categories_prefix_help')
                .setLabel('Need Help?')
                .setStyle(ButtonStyle.Primary)
                .setEmoji('❓')
        );
}

// ── Renderers for the two entry points ──────────────────────────────────────

// Prefix `$help`/`$commands` (message-based). `category` optional.
async function showPrefixCategoryHelp(message, category, prefix) {
    if (category && CATALOG[category]) {
        return message.reply({ embeds: [categoryEmbed(category, prefix)] });
    }
    return message.reply({
        embeds: [mainMenuEmbed(prefix, message.client)],
        components: [categorySelectRow(), navigationButtonsRow()],
    });
}

// Select-menu interaction (`category_select_prefix`). Updates in place.
async function showPrefixCategoryMenuHelp(interaction, category, prefix) {
    const embed = categoryEmbed(category, prefix);
    const backSelect = categorySelectRow(category);
    const navButtons = new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('categories_prefix_back')
                .setLabel('Back to Categories')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji('🏠'),
            new ButtonBuilder()
                .setCustomId('categories_prefix_help')
                .setLabel('Need Help?')
                .setStyle(ButtonStyle.Primary)
                .setEmoji('❓')
        );
    try {
        await interaction.update({ embeds: [embed], components: [backSelect, navButtons] });
    } catch (err) {
        if (!interaction.replied && !interaction.deferred) {
            await interaction.reply({ embeds: [embed], components: [backSelect, navButtons], ephemeral: true }).catch(() => {});
        }
    }
}

function getCategoryUsageLevel(category) {
    return {
        general: 'Beginner Friendly',
        leveling: 'Intermediate',
        games: 'Beginner Friendly',
        community: 'Beginner Friendly',
        tickets: 'Beginner Friendly',
        welcome: 'Intermediate',
        moderation: 'Intermediate',
        admin: 'Advanced',
    }[category] || 'Unknown';
}

function getCategoryPermissionLevel(category) {
    return {
        general: 'Everyone',
        leveling: 'Members / Mods',
        games: 'Everyone',
        community: 'Everyone',
        tickets: 'Everyone',
        welcome: 'Admins',
        moderation: 'Moderators',
        admin: 'Administrators',
    }[category] || 'Unknown';
}

module.exports = {
    CATALOG,
    CATEGORY_ORDER,
    BETA_FEATURES,
    isBeta,
    commandField,
    categoryEmbed,
    mainMenuEmbed,
    categorySelectRow,
    navigationButtonsRow,
    showPrefixCategoryHelp,
    showPrefixCategoryMenuHelp,
    getCategoryUsageLevel,
    getCategoryPermissionLevel,
};
