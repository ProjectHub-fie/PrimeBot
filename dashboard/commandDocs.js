/**
 * Auto-generated prefix-command documentation.
 *
 * The authoritative list of text/prefix commands is parsed at require time
 * from the top-level `switch (commandName)` in events/messageCreate.js, so the
 * docs page can never fall behind the actual bot: add a command there and it
 * appears in the docs automatically. Developer/diagnostic commands listed in
 * EXCLUDE are never documented. Curated descriptions/usage/permissions live in
 * METADATA below (keyed by the command's primary name); a command without
 * metadata still renders with a generic entry.
 */

const fs = require('fs');
const path = require('path');

const EVENT_SOURCE = path.join(__dirname, '..', 'events', 'messageCreate.js');

// Developer/diagnostic commands intentionally left out of the public docs.
const EXCLUDE = new Set(['tokentest', 'ses', 'sync', 'betaserver']);

// Display order + icon (from dashboard/public/js/icons.js) for each category.
const CATEGORIES = [
    { name: 'Moderation', icon: 'shield' },
    { name: 'Configuration', icon: 'settings' },
    { name: 'Welcome', icon: 'hand' },
    { name: 'Leveling', icon: 'trendingUp' },
    { name: 'Polls', icon: 'barChart' },
    { name: 'Giveaways', icon: 'gift' },
    { name: 'Games', icon: 'trophy' },
    { name: 'Tickets', icon: 'ticket' },
    { name: 'Automation', icon: 'zap' },
    { name: 'Engagement', icon: 'star' },
    { name: 'Utility', icon: 'terminal' },
    { name: 'Beta', icon: 'flask' },
];

const MANAGE_GUILD = 'Manage Server';
const MODERATE_MEMBERS = 'Moderate Members';
const ADMINISTRATOR = 'Administrator';
const MANAGE_MESSAGES = 'Manage Messages';
const MANAGE_ROLES = 'Manage Roles';

const METADATA = {
    prefix: {
        category: 'Configuration', permission: ADMINISTRATOR,
        description: "View the server's current text prefix or change it.",
        usage: ['prefix [new prefix]'],
    },
    dev: {
        category: 'Configuration',
        description: 'PrimeBot bot-management role service. Shows your role (or another user\'s); the owner assigns user/moderator/admin/developer roles. The owner role is reserved for config developerIds.',
        usage: ['dev [@user]', 'dev add @user <role>', 'dev remove @user', 'dev list'],
        note: 'add/remove/list are owner-only',
    },
    role: {
        category: 'Moderation', permission: MANAGE_ROLES,
        description: 'Manage roles: add or remove a role for a member, create a new role, or list the server roles.',
        usage: ['role add @user @role', 'role remove @user @role', 'role create [name] [color] [hoist] [mentionable]', 'role list'],
    },
    rm: {
        category: 'Utility', permission: ADMINISTRATOR,
        description: 'Rename a channel (defaults to the current channel).',
        usage: ['rm [#channel] <new name>'],
    },
    lock: {
        category: 'Moderation', permission: ADMINISTRATOR,
        description: 'Lock a channel so regular members can no longer send messages in it.',
        usage: ['lock [#channel]'],
    },
    unlock: {
        category: 'Moderation', permission: ADMINISTRATOR,
        description: 'Unlock a previously locked channel.',
        usage: ['unlock [#channel]'],
    },
    hide: {
        category: 'Moderation', permission: ADMINISTRATOR,
        description: 'Hide a channel from regular members.',
        usage: ['hide [#channel]'],
    },
    unhide: {
        category: 'Moderation', permission: ADMINISTRATOR,
        description: 'Make a hidden channel visible to regular members again.',
        usage: ['unhide [#channel]'],
    },
    nuke: {
        category: 'Moderation', permission: ADMINISTRATOR,
        description: 'Delete and recreate a channel to wipe its entire message history.',
        usage: ['nuke'],
    },
    snipe: {
        category: 'Utility',
        description: 'Show the most recently deleted message in a channel.',
        usage: ['snipe [#channel]'],
    },
    kick: {
        category: 'Moderation', permission: ADMINISTRATOR,
        description: 'Kick a member from the server.',
        usage: ['kick @member [reason]'],
    },
    ban: {
        category: 'Moderation', permission: ADMINISTRATOR,
        description: 'Ban a member from the server.',
        usage: ['ban @member [reason]'],
    },
    warn: {
        category: 'Moderation', permission: MODERATE_MEMBERS,
        description: 'Warn a member. When they reach the configured warning threshold, the escalation actions run automatically.',
        usage: ['warn @member [reason]'],
    },
    unwarn: {
        category: 'Moderation', permission: MODERATE_MEMBERS,
        description: 'Remove one, several, or all of a member\u2019s warnings.',
        usage: ['unwarn @member [count|all]'],
    },
    warnings: {
        category: 'Moderation',
        description: 'List the warnings a member has (your own if no member is given).',
        usage: ['warnings [@member]'],
    },
    mute: {
        category: 'Moderation', permission: MODERATE_MEMBERS,
        description: 'Timeout a member, or apply the configured mute role when a timeout is not possible.',
        usage: ['mute @member [seconds] [reason]'],
    },
    unmute: {
        category: 'Moderation', permission: MODERATE_MEMBERS,
        description: 'Remove a member\u2019s timeout or the configured mute role.',
        usage: ['unmute @member'],
    },
    commands: {
        category: 'Utility',
        description: 'Browse all commands by category, or open one category\u2019s list directly.',
        usage: ['commands [category]'],
    },
    help: {
        category: 'Utility',
        description: 'Show the animated help menu with every command category.',
        usage: ['help [category]'],
    },
    giveaway: {
        category: 'Giveaways',
        description: 'Show the giveaway command help (start, end and reroll).',
        usage: ['giveaway'],
    },
    gstart: {
        category: 'Giveaways', permission: MANAGE_GUILD,
        description: 'Start a giveaway in the current channel.',
        usage: ['gstart <duration> <winners> <prize>'],
    },
    end: {
        category: 'Giveaways', permission: MANAGE_GUILD,
        description: 'End a running giveaway early, picking the winners immediately.',
        usage: ['gend <message_id>'],
    },
    reroll: {
        category: 'Giveaways', permission: MANAGE_GUILD,
        description: 'Pick a new winner for a completed giveaway.',
        usage: ['reroll <message_id>'],
    },
    echo: {
        category: 'Utility',
        description: 'Make the bot repeat a message in the channel.',
        usage: ['echo <message>'],
    },
    poll: {
        category: 'Polls',
        description: 'Create a timed reaction poll with two or more options (24 hours by default).',
        usage: ['poll <question> <option1> <option2> [options\u2026] [duration]'],
    },
    endpoll: {
        category: 'Polls', permission: MANAGE_MESSAGES,
        description: 'End an active poll early and post the results.',
        usage: ['endpoll <message_id>'],
    },
    lpoll: {
        category: 'Polls',
        description: 'Cross-server live polls shared with a poll ID and pass code.',
        usage: ['lpoll create <question> <option1> <option2> [duration] [multiple_votes]',
                'lpoll join <poll_id|pass_code>',
                'lpoll results <poll_id|pass_code>',
                'lpoll end <poll_id>',
                'lpoll list'],
    },
    lgiveway: {
        category: 'Giveaways',
        description: 'Cross-server giveaways joinable from any server with the pass code.',
        usage: ['lgiveway create <prize> <duration> <winners> [description]',
                'lgiveway join <giveaway_id|pass_code>',
                'lgiveway results <giveaway_id|pass_code>',
                'lgiveway end <giveaway_id>',
                'lgiveway list'],
    },
    birthday: {
        category: 'Engagement',
        description: 'Set your birthday, check someone\u2019s, or list upcoming birthdays. Admins can also set the announcement channel and the birthday role.',
        usage: ['birthday set <MM/DD/YYYY>', 'birthday remove', 'birthday list',
                'birthday check [@user]', 'birthday channel [#channel]', 'birthday role [@role]'],
    },
    thelp: {
        category: 'Tickets',
        description: 'Ticket panels are configured only from the dashboard (\ud83c\udfab Tickets tab); this command explains that.',
        usage: ['thelp'],
    },
    tictactoe: {
        category: 'Games',
        description: 'Start a multiplayer Tic-Tac-Toe game in the current channel.',
        usage: ['tictactoe'],
    },
    move: {
        category: 'Games',
        description: 'Make a move in the channel\u2019s active Tic-Tac-Toe game.',
        usage: ['move <position 1\u20139>'],
    },
    tend: {
        category: 'Games',
        description: 'End the current Tic-Tac-Toe game (game starter or moderators only).',
        usage: ['tend'],
    },
    ab: {
        category: 'Utility',
        description: 'Show the legacy about page describing the bot and its features.',
        usage: ['ab'],
    },
    ulog: {
        category: 'Utility',
        description: 'Show the legacy update log.',
        usage: ['ulog'],
    },
    broadcast: {
        category: 'Configuration', permission: MANAGE_GUILD,
        description: 'Opt the server in or out of developer broadcasts, or choose the broadcast channel. Bot developers use the bare command to send a bot-wide broadcast.',
        usage: ['broadcast <enable|disable|channel #channel>'],
    },
    cstart: {
        category: 'Games', permission: MANAGE_GUILD,
        description: 'Start a counting game in the current channel.',
        usage: ['cstart [start number] [goal number]'],
    },
    cstatus: {
        category: 'Games',
        description: 'Show the status of this channel\u2019s counting game.',
        usage: ['cstatus'],
    },
    cend: {
        category: 'Games', permission: MANAGE_GUILD,
        description: 'End the counting game running in this channel.',
        usage: ['cend'],
    },
    chelp: {
        category: 'Games',
        description: 'Show the counting-game help.',
        usage: ['chelp'],
    },
    truthdare: {
        category: 'Games',
        description: 'Start a round of Truth or Dare.',
        usage: ['truthdare'],
    },
    qadd: {
        category: 'Games',
        description: 'Add a custom truth or dare question to the pool.',
        usage: ['qadd <truth|dare> <question>'],
    },
    leaderboard: {
        category: 'Leveling',
        description: 'Show the server\u2019s XP leaderboard.',
        usage: ['leaderboard'],
    },
    rank: {
        category: 'Leveling',
        description: 'Show your (or another member\u2019s) rank card with level, XP and progress.',
        usage: ['rank [@user]'],
    },
    'set-level': {
        category: 'Leveling', permission: 'Bot developer',
        description: 'Set a member\u2019s level directly.',
        usage: ['set-level @user <level>'],
    },
    badge: {
        category: 'Leveling', note: 'Beta program only',
        description: 'Show your (or another member\u2019s) earned badges.',
        usage: ['badges [@user]'],
    },
    'award-badge': {
        category: 'Leveling', permission: MANAGE_GUILD,
        description: 'Award a badge to a member.',
        usage: ['award-badge @user <achievement|special> <badge_id>'],
    },
    'revoke-badge': {
        category: 'Leveling', permission: MANAGE_GUILD,
        description: 'Revoke a badge from a member.',
        usage: ['revoke-badge @user <badge_id>'],
    },
    'view-badges': {
        category: 'Leveling', note: 'Beta program only',
        description: 'List every available badge (level, achievement and special).',
        usage: ['view-badges'],
    },
    'welcome-enable': {
        category: 'Welcome', permission: MANAGE_GUILD,
        description: 'Enable the welcome system for this server.',
        usage: ['welcome-enable'],
    },
    'welcome-disable': {
        category: 'Welcome', permission: MANAGE_GUILD,
        description: 'Disable the welcome system for this server.',
        usage: ['welcome-disable'],
    },
    ping: {
        category: 'Utility',
        description: 'Measure gateway latency and database connectivity.',
        usage: ['ping'],
    },
    np: {
        category: 'Configuration', permission: 'Bot developer',
        description: 'Grant, revoke or check no-prefix mode so a user can run commands without the prefix.',
        usage: ['np add @user [minutes]', 'np remove @user', 'np status [@user]', 'np enable [minutes]', 'np disable'],
    },
    purge: {
        category: 'Moderation', permission: MANAGE_MESSAGES,
        description: 'Bulk-delete recent messages, only one member\u2019s messages, or everything between two message IDs.',
        usage: ['purge <count>', 'purge @member <count>', 'purge between <start_id> <end_id>'],
    },
    'welcome-channel': {
        category: 'Welcome', permission: MANAGE_GUILD,
        description: 'Set the channel welcome messages are posted to.',
        usage: ['welcome-channel #channel'],
    },
    'level-enable': {
        category: 'Leveling', permission: MANAGE_GUILD,
        description: 'Enable the XP leveling system for this server.',
        usage: ['level-enable'],
    },
    'level-disable': {
        category: 'Leveling', permission: MANAGE_GUILD,
        description: 'Disable the XP leveling system for this server.',
        usage: ['level-disable'],
    },
    'level-channel': {
        category: 'Leveling', permission: MANAGE_GUILD,
        description: 'Set the channel level-up announcements are posted to.',
        usage: ['level-channel #channel'],
    },
    'level-multiplier': {
        category: 'Leveling', permission: MANAGE_GUILD,
        description: 'Set the server-wide XP multiplier (0\u20135).',
        usage: ['level-multiplier <value>'],
    },
    autoreact: {
        category: 'Automation', permission: MANAGE_GUILD,
        description: 'Automatically react with an emoji to messages containing a trigger word.',
        usage: ['autoreact enable|disable', 'autoreact add <trigger> <emoji>', 'autoreact remove <trigger>', 'autoreact list'],
    },
    autoresponder: {
        category: 'Automation', permission: MANAGE_GUILD,
        description: 'Automatically reply with a text response when a message contains (or exactly matches) a trigger.',
        usage: ['autoresponder enable|disable', 'autoresponder add <trigger> | <response>', 'autoresponder exact <trigger> | <response>', 'autoresponder remove <trigger>', 'autoresponder list'],
    },
    broadcastsettings: {
        category: 'Configuration', permission: ADMINISTRATOR,
        description: 'Show the broadcast settings help and current status.',
        usage: ['broadcastsettings [enable|disable|status]'],
    },
    createticket: {
        category: 'Tickets',
        description: 'Ticket panels are configured only from the dashboard (\ud83c\udfab Tickets tab); this command explains that.',
        usage: ['createticket'],
    },
    about: {
        category: 'Utility',
        description: 'Show information about PrimeBot and its features.',
        usage: ['about'],
    },
    stats: {
        category: 'Utility',
        description: 'Show live bot statistics: uptime, memory, servers, users and failover-node health.',
        usage: ['stats'],
    },
    updates: {
        category: 'Utility',
        description: 'Show the latest update log.',
        usage: ['updates'],
    },
    leveling: {
        category: 'Leveling',
        description: 'Show an overview of the leveling commands.',
        usage: ['leveling'],
    },
    welcomeconfig: {
        category: 'Welcome', permission: MANAGE_GUILD,
        description: 'Show an overview of the welcome configuration commands.',
        usage: ['welcomeconfig'],
    },
    beta: {
        category: 'Beta', permission: 'Server Owner',
        description: 'Enable, disable or check beta features for this server (the server must already be on the developer-approved allowed list).',
        usage: ['beta <enable|disable|status>'],
    },
};

/**
 * Parse events/messageCreate.js and return the top-level prefix commands of
 * the main command switch, in source order. Each entry is an alias group:
 * { primary, aliases: [] }. Aliases that were already claimed by an earlier
 * group (fallthrough duplicates in the switch) are dropped so no command
 * appears twice.
 */
function extractCommandGroups() {
    let source = '';
    try {
        source = fs.readFileSync(EVENT_SOURCE, 'utf8');
    } catch {
        return [];
    }

    const switchRe = /switch \(commandName\) \{/g;
    let match;
    const switchIdx = [];
    while ((match = switchRe.exec(source))) switchIdx.push(match.index);
    if (switchIdx.length === 0) return [];

    // The main (prefix) command switch is the last `switch (commandName)` in
    // the file; the earlier one handles the emoji-prefixed commands.
    const start = switchIdx[switchIdx.length - 1];

    const caseRe = /case\s+(["'])([a-zA-Z0-9_-]+)\1\s*:/y;
    const groups = [];
    let pending = null;
    let lastCaseEnd = -1;
    let depth = 0;
    let i = source.indexOf('{', start);

    while (i < source.length) {
        const ch = source[i];
        if (ch === '{') {
            depth++;
        } else if (ch === '}') {
            depth--;
            if (depth === 0) break;
        } else if (depth === 1) {
            caseRe.lastIndex = i;
            const cm = caseRe.exec(source);
            if (cm) {
                const between = source.slice(lastCaseEnd, i).trim();
                if (between === '' && pending) {
                    pending.push(cm[2]); // fallthrough alias
                } else {
                    pending = [cm[2]];
                    groups.push(pending);
                }
                lastCaseEnd = caseRe.lastIndex;
                i = caseRe.lastIndex;
                continue;
            }
        }
        i++;
    }

    const claimed = new Set();
    const result = [];
    for (const group of groups) {
        const aliases = group.filter((name) => !claimed.has(name));
        if (aliases.length === 0 || EXCLUDE.has(aliases[0])) {
            group.forEach((name) => claimed.add(name));
            continue;
        }
        aliases.forEach((name) => claimed.add(name));
        result.push({ primary: aliases[0], aliases });
    }
    return result;
}

const CATEGORY_LOOKUP = new Map(CATEGORIES.map((c) => [c.name, c]));
const DOCS_VERSION_ID = '_primebotCommandDocs'; // cache marker for test visibility

let _cache = null;
function buildCommandDocs() {
    if (_cache) return _cache;
    const cmds = extractCommandGroups().map(({ primary, aliases }) => {
        const meta = METADATA[primary] || {};
        const category = CATEGORY_LOOKUP.get(meta.category) || CATEGORY_LOOKUP.get('Utility');
        return {
            name: primary,
            aliases,
            category: category.name,
            icon: category.icon,
            description: meta.description || `Run the ${primary} prefix command.`,
            usage: meta.usage || [primary],
            permission: meta.permission || null,
            note: meta.note || null,
        };
    });
    _cache = { id: DOCS_VERSION_ID, categories: CATEGORIES, commands: cmds };
    return _cache;
}

module.exports = { buildCommandDocs, extractCommandGroups, CATEGORIES, EXCLUDE };
