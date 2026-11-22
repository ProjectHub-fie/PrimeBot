const {
    ActionRowBuilder,
    StringSelectMenuBuilder,
    ButtonBuilder,
    ButtonStyle,
    ContainerBuilder,
    SeparatorBuilder,
    TextDisplayBuilder,
    MessageFlags,
} = require('discord.js');
const config = require('../config');
const { emoji } = require('./emoji');
const { HELP_CATEGORY_EMOJI, EMOJI_FALLBACKS } = require('../shared/emojiCatalog');
const { scheduleComponentExpiry } = require('./stabilityUtils');
const { linixEmbed } = require('./linixEmbed');

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
// Excluded by design: broadcast, session ($ses), sync, tokentest, test, np/noprefix,
// and $betaserver (internal developer tool). Role content was merged into
// Moderation; the category-browser command lives in General.
//
// A command is tagged 🧪 BETA when its canonical name (or any alias) appears in
// `config.betaFeatures` — the same list the bot gates on at runtime.
// ───────────────────────────────────────────────────────────────────────────

function categoryIcon(category, fallback = '') {
    const key = HELP_CATEGORY_EMOJI[category] || category;
    return emoji(key, EMOJI_FALLBACKS[key] || fallback || '');
}

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
        icon: 'home',
        label: 'General',
        title: 'General Commands',
        color: config.colors.primary,
        commands: [
            { names: ['help'], args: '[category]', desc: 'Show the categorized command menu' },
            { names: ['commands', 'categories'], desc: 'Browse all command categories' },
            { names: ['echo'], args: '[message]', desc: 'Make the bot repeat a message' },
            { names: ['prefix'], args: '[new prefix]', desc: 'View or set the server prefix (Admin)' },
        ],
    },

    information: {
        icon: 'information',
        label: 'Information',
        title: 'Bot Information',
        color: config.colors.primary,
        commands: [
            { names: ['about', 'ab'], desc: 'Information about the bot' },
            { names: ['stats', 'statistics'], desc: 'Bot statistics and server count' },
            { names: ['updates', 'ulog'], desc: 'Latest bot updates and features' },
            { names: ['ping'], desc: 'Check bot latency and connection status' },
        ],
    },

    leveling: {
        icon: 'profile',
        label: 'Leveling',
        title: 'Leveling System',
        color: config.colors.success,
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
        icon: 'fun',
        label: 'Games & Activities',
        title: 'Games & Activities',
        color: config.colors.warning,
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
        ],
    },

    community: {
        icon: 'extra',
        label: 'Community',
        title: 'Community — Live Polls & Giveaways',
        color: config.colors.success,
        commands: [
            { names: ['lpoll', 'livepoll'], args: '<create|join|results|end|list>', desc: 'Cross-server live polls' },
            { names: ['lgiveway', 'lgiveaway', 'livegiveaway'], args: '<create|join|results|end|list>', desc: 'Cross-server live giveaways' },
        ],
    },

    birthdays: {
        icon: 'welc',
        label: 'Birthdays',
        title: 'Birthday Celebrations',
        color: config.colors.success,
        commands: [
            { names: ['birthday', 'bday'], args: '<set|remove|list|check|channel|role>', desc: 'Birthday celebration system' },
        ],
    },

    moderation: {
        icon: 'moderation',
        label: 'Moderation',
        title: 'Moderation Tools',
        color: config.colors.secondary,
        commands: [
            { names: ['kick'], args: '@member [reason]', desc: 'Kick a member from the server' },
            { names: ['ban'], args: '@member|userid [reason] [days]', desc: 'Ban a member from the server' },
            { names: ['unban'], args: 'userid [reason]', desc: 'Unban a member by user id' },
            { names: ['warn'], args: '@member [reason]', desc: 'Warn a member' },
            { names: ['unwarn'], args: '@member', desc: 'Remove a member\'s warnings' },
            { names: ['warnings'], args: '[@member]', desc: 'View a member\'s warnings' },
            { names: ['mute'], args: '@member [duration]', desc: 'Mute a member' },
            { names: ['unmute'], args: '@member', desc: 'Unmute a member' },
            { names: ['rmr'], args: '<CID> [reason]', desc: 'Edit or clear the reason on an automod embed (Moderate Members)' },
            { names: ['appealchannel', 'appealchannelid'], args: '[#channel|off]', desc: 'View or set the automod appeal channel (Moderate Members)' },
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

    automation: {
        icon: 'autoresponder',
        label: 'Automation',
        title: 'Automation',
        color: config.colors.secondary,
        commands: [
            { names: ['autoreact', 'auto-react'], args: '<enable|disable|add|remove|list>', desc: 'Configure auto-reactions' },
            { names: ['autoresponder', 'auto-responder', 'aresponder', 'ar'], args: '<enable|disable|add|exact|remove|list>', desc: 'Configure the auto-responder' },
        ],
    },

    antinuke: {
        icon: 'antinuke',
        label: 'Anti-Nuke',
        title: 'Anti-Nuke Protection',
        color: config.colors.error,
        commands: [
            { names: ['antinuke', 'an'], args: '<status|setup|progress|enable|disable|dryrun|thresholds|whitelist|unwhitelist|lockdown|restore|access|grant|revoke>', desc: 'Configure Anti-Nuke protection and the owner-controlled access hierarchy' },
        ],
    },

    admin: {
        icon: 'config',
        label: 'Administration',
        title: 'Administration',
        color: config.colors.error,
        commands: [
            { names: ['embed'], args: '<send|list>', desc: 'Send an embed saved in the dashboard Embed Builder' },
            { names: ['level-enable', 'levelenable', 'leveling-enable', 'levelingon', 'leveling-on'], desc: 'Enable the leveling system' },
            { names: ['level-disable', 'leveldisable', 'leveling-disable', 'levelingoff', 'leveling-off'], desc: 'Disable the leveling system' },
            { names: ['level-channel', 'levelchannel'], args: '#channel', desc: 'Set the level-up notification channel' },
            { names: ['level-multiplier', 'levelmultiplier'], args: '[number]', desc: 'Set the XP multiplier' },
            { names: ['dev'], args: '[@user]', desc: 'PrimeBot staff-role service (owner assigns/modifies/removes roles)' },
            { names: ['broadcastsettings', 'bsettings'], desc: 'View broadcast settings' },
        ],
    },

    tickets: {
        icon: 'utility',
        label: 'Tickets',
        title: 'Tickets',
        color: config.colors.secondary,
        commands: [
            { names: ['ticket', 'thelp'], desc: 'Ticket help (dashboard-only)' },
            { names: ['tcreate', 'createt', 'createticket'], args: '[name]', desc: 'Create a ticket (dashboard-only)' },
            { names: ['thistory'], args: '[page]', desc: 'View ticket history (dashboard-only)' },
        ],
    },

    youtube: {
        icon: 'playing',
        label: 'YouTube',
        title: 'YouTube Notifications',
        color: config.colors.error,
        commands: [
            { names: ['youtube', 'yt'], desc: 'YouTube notifications (dashboard-only)' },
        ],
    },

    music: {
        icon: 'music',
        label: 'Music',
        title: 'Music',
        color: config.colors.primary,
        commands: [
            { names: ['music'], args: 'play <song or URL>', desc: 'Play a song or add it to the queue (`$play`/`$p` also work)' },
            { names: ['music'], args: 'search <query>', desc: 'Search and pick a result to play' },
            { names: ['music'], args: 'pause', desc: 'Pause playback' },
            { names: ['music'], args: 'resume', desc: 'Resume playback' },
            { names: ['music'], args: 'skip', desc: 'Skip the current track' },
            { names: ['music'], args: 'stop', desc: 'Stop playback and clear the queue' },
            { names: ['music'], args: 'seek <timestamp>', desc: 'Jump to a position (e.g. 1:30)' },
            { names: ['music'], args: 'skipto <position>', desc: 'Skip directly to a queue position' },
            { names: ['music'], args: 'queue', desc: 'Show the queue' },
            { names: ['music'], args: 'remove <position>', desc: 'Remove a track from the queue' },
            { names: ['music'], args: 'clear', desc: 'Clear the queue' },
            { names: ['music'], args: 'shuffle', desc: 'Shuffle the queue' },
            { names: ['music'], args: 'loop <off|track|queue>', desc: 'Set the repeat mode' },
            { names: ['music'], args: 'autoplay', desc: 'Keep music playing when the queue ends' },
            { names: ['music'], args: 'filter <preset>', desc: 'Apply an audio filter (bassboost/nightcore/8d/…)' },
            { names: ['music'], args: 'nowplaying', desc: 'Show what is playing' },
            { names: ['music'], args: 'lyrics [song]', desc: 'Show the lyrics of the current song' },
            { names: ['music'], args: 'grab', desc: 'DM yourself the current track' },
            { names: ['music'], args: 'volume <1-100>', desc: 'Set the volume' },
            { names: ['music'], args: 'join', desc: 'Join your voice channel' },
            { names: ['music'], args: 'leave', desc: 'Leave the voice channel' },
            { names: ['music'], args: '247 <enable|disable|status>', desc: 'Persistent 24/7 voice connection, Admin' },
            { names: ['music'], args: 'playlist <create|delete|info|list|load|rename|share>', desc: 'Manage your playlists' },
        ],
    },

    welcome: {
        icon: 'welc',
        label: 'Welcome',
        title: 'Welcome System',
        color: config.colors.success,
        commands: [
            { names: ['welcome-enable', 'welcomeenable', 'welcome-on'], desc: 'Enable the welcome system (Admin)' },
            { names: ['welcome-disable', 'welcomedisable', 'welcome-off'], desc: 'Disable the welcome system (Admin)' },
            { names: ['welcome-channel', 'welcomechannel'], args: '#channel', desc: 'Set the welcome message channel (Admin)' },
            { names: ['welcomeconfig', 'welcome'], desc: 'View / configure welcome messages' },
        ],
    },
};

const CATEGORY_ORDER = ['general', 'information', 'leveling', 'games', 'community', 'birthdays', 'music', 'tickets', 'youtube', 'welcome', 'moderation', 'automation', 'antinuke', 'admin'];

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

const CATEGORY_SEPARATOR = '–>';

function categoryLine(key) {
    const cat = CATALOG[key];
    return cat ? `${categoryIcon(key)} ${CATEGORY_SEPARATOR} ${cat.label}` : '';
}

function mainMenuText() {
    return CATEGORY_ORDER.map(categoryLine).filter(Boolean).join('\n');
}

function categoryTitle(category) {
    const cat = CATALOG[category];
    if (!cat) return `${emoji('cross', '❌')} ${CATEGORY_SEPARATOR} Unknown Category`;
    return `${categoryIcon(category)} ${CATEGORY_SEPARATOR} ${cat.label}`;
}

function categoryCommandNames(category, options = {}) {
    const cat = CATALOG[category];
    if (!cat) return [];
    const commandNames = Array.isArray(options.commands) ? [...options.commands] : [];
    if (!commandNames.length) {
        const seen = new Set();
        for (const c of cat.commands) {
            let name = c.names[0];
            if (name === 'music' && c.args) name = `music ${c.args.split(' ')[0]}`;
            if (!seen.has(name)) {
                seen.add(name);
                commandNames.push(name);
            }
        }
    }
    return commandNames;
}

function categoryText(category, options = {}) {
    const names = categoryCommandNames(category, options).map(name => `\`${name}\``);
    return names.join(', ') || 'No commands found for this category.';
}

function categoryEmbed(category, prefix, options = {}) {
    if (!CATALOG[category]) {
        return linixEmbed()
            .t(categoryTitle(category))
            .d(`The category "${category}" was not found. Available categories: ${CATEGORY_ORDER.join(', ')}`)
            .f('PrimeBot Help');
    }

    return linixEmbed()
        .t(categoryTitle(category))
        .d(categoryText(category, options));
}

function mainMenuEmbed(prefix, client, options = {}) {
    // Help is intentionally only the category list: no intro, no field title,
    // no thumbnail/footer/image, and no category descriptions.
    return linixEmbed().d(mainMenuText());
}

function categorySelectRow(currentCategory = null, customId = 'help_select') {
    return new ActionRowBuilder()
        .addComponents(
            new StringSelectMenuBuilder()
                .setCustomId(customId)
                .setPlaceholder('Select a command category')
                .addOptions(CATEGORY_ORDER.map(k => {
                    const cat = CATALOG[k];
                    return {
                        // The select renders its emoji before the label, so the
                        // visible text is "<emoji> –> Category".
                        label: `${CATEGORY_SEPARATOR} ${cat.label}`,
                        value: k,
                        emoji: categoryIcon(k) || undefined,
                        default: k === currentCategory,
                    };
                }))
        );
}

function homeButtonRow(customId = 'help_back') {
    return new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId(customId)
                .setStyle(ButtonStyle.Secondary)
                .setEmoji(categoryIcon('home', '🏠'))
        );
}

function helpActionRow() {
    const row = homeButtonRow('help_back');
    row.addComponents(
        new ButtonBuilder()
            .setCustomId('help_prefix')
            .setLabel('Sash')
            .setStyle(ButtonStyle.Secondary)
            .setEmoji(categoryIcon('utility', '💬')),
        new ButtonBuilder()
            .setLabel('Support')
            .setStyle(ButtonStyle.Link)
            .setURL(config.supportServer || 'https://discord.gg/primebot')
            .setEmoji(categoryIcon('information', '🆘')),
    );
    return row;
}

function navigationButtonsRow() {
    return new ActionRowBuilder()
        .addComponents(
            new ButtonBuilder()
                .setCustomId('categories_prefix_refresh')
                .setLabel('Refresh')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji(categoryIcon('refresh', '🔄')),
            new ButtonBuilder()
                .setCustomId('categories_prefix_help')
                .setLabel('Need Help?')
                .setStyle(ButtonStyle.Primary)
                .setEmoji(categoryIcon('information', '❓'))
        );
}

/**
 * Build the Help menu as a true Components V2 payload. It deliberately has no
 * `embeds` or `content` keys: Discord rejects either one alongside
 * MessageFlags.IsComponentsV2 (error 50035).
 */
function buildHelpPayload({ title, text, rows = [] } = {}) {
    const container = new ContainerBuilder();
    if (title) container.addTextDisplayComponents(new TextDisplayBuilder().setContent(title));
    if (title && text) container.addSeparatorComponents(new SeparatorBuilder().setDivider(true));
    if (text) container.addTextDisplayComponents(new TextDisplayBuilder().setContent(text));
    for (const row of rows) {
        if (row) container.addActionRowComponents(row);
    }
    return {
        components: [container.toJSON()],
        flags: MessageFlags.IsComponentsV2,
    };
}

// ── Renderers for the two entry points ──────────────────────────────────────

// Prefix `$help`/`$commands` (message-based). `category` optional.
async function showPrefixCategoryHelp(message, category, prefix) {
    if (category && CATALOG[category]) {
        return message.reply(buildHelpPayload({
            title: categoryTitle(category),
            text: categoryText(category),
            rows: [categorySelectRow(category, 'category_select_prefix'), homeButtonRow('categories_prefix_back')],
        }));
    }
    const sent = await message.reply(buildHelpPayload({
        text: mainMenuText(),
        rows: [categorySelectRow(null, 'category_select_prefix'), homeButtonRow('categories_prefix_back')],
    }));
    scheduleComponentExpiry(sent);
    return sent;
}

// Select-menu interaction (`category_select_prefix`). Updates in place.
async function showPrefixCategoryMenuHelp(interaction, category, prefix) {
    const payload = buildHelpPayload({
        title: categoryTitle(category),
        text: categoryText(category),
        rows: [categorySelectRow(category, 'category_select_prefix'), homeButtonRow('categories_prefix_back')],
    });
    try {
        await interaction.update(payload);
        scheduleComponentExpiry(interaction.message);
    } catch (err) {
        if (!interaction.replied && !interaction.deferred) {
            await interaction.reply({
                ...payload,
                flags: payload.flags | MessageFlags.Ephemeral,
            }).catch(() => {});
        }
    }
}

function getCategoryUsageLevel(category) {
    return {
        general: 'Beginner Friendly',
        information: 'Beginner Friendly',
        leveling: 'Intermediate',
        games: 'Beginner Friendly',
        community: 'Beginner Friendly',
        birthdays: 'Beginner Friendly',
        radio: 'Intermediate',
        music: 'Beginner Friendly',
        tickets: 'Beginner Friendly',
        youtube: 'Intermediate',
        welcome: 'Intermediate',
        moderation: 'Intermediate',
        automation: 'Intermediate',
        antinuke: 'Advanced',
        admin: 'Advanced',
    }[category] || 'Unknown';
}

function getCategoryPermissionLevel(category) {
    return {
        general: 'Everyone',
        information: 'Everyone',
        leveling: 'Members / Mods',
        games: 'Everyone',
        community: 'Everyone',
        birthdays: 'Everyone',
        radio: 'Everyone (Admins to configure)',
        music: 'Everyone (Admins to configure 24/7)',
        tickets: 'Everyone',
        youtube: 'Admins',
        welcome: 'Admins',
        moderation: 'Moderators',
        automation: 'Admins',
        antinuke: 'Server owner',
        admin: 'Administrators',
    }[category] || 'Unknown';
}

module.exports = {
    CATALOG,
    CATEGORY_SEPARATOR,
    categoryIcon,
    categoryLine,
    categoryTitle,
    categoryText,
    mainMenuText,
    buildHelpPayload,
    CATEGORY_ORDER,
    BETA_FEATURES,
    isBeta,
    commandField,
    categoryEmbed,
    mainMenuEmbed,
    categorySelectRow,
    homeButtonRow,
    helpActionRow,
    navigationButtonsRow,
    showPrefixCategoryHelp,
    showPrefixCategoryMenuHelp,
    getCategoryUsageLevel,
    getCategoryPermissionLevel,
};
