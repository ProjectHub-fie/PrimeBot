const debug = require('debug')('bot:main');

const { Client, GatewayIntentBits, Collection, ActivityType, Options } = require('discord.js');
const fs = require('fs');
const path = require('path');
const { resolveDiscordToken } = require('./utils/tokenResolver');
require('dotenv').config();

// Detect secondary/standby role BEFORE initialising any managers so we can
// skip the heavy ones that are never needed on a standby-only node.
const IS_SECONDARY = process.env.BOT_FAILOVER_ENABLED !== 'false' &&
                     (process.env.NODE_ROLE === 'sn2' || process.env.NODE_ROLE === 'secondary');

if (IS_SECONDARY) {
    console.log('[BOOT] Running as SECONDARY node — skipping heavy managers to save memory.');
}

// Run GC aggressively if --expose-gc was passed (added by start-bot.cjs).
if (typeof global.gc === 'function') {
    setInterval(() => {
        try { global.gc(); } catch (_) {}
    }, IS_SECONDARY ? 30_000 : 120_000);
}

const token = resolveDiscordToken();
if (!token) {
    console.error('❌ No Discord token found. Set DISCORD_TOKEN, BOT_TOKEN, TOKEN, or CLIENT_TOKEN in the environment or .env file.');
    process.exit(1);
}
process.env.DISCORD_TOKEN = token;

// Create a new client instance
// On secondary we use minimal intents — the bot never connects in normal
// operation, so this client exists only as a stub that may take over if the
// primary goes down.  On primary we keep full intents but cap the caches so
// we don't accumulate unbounded memory.
const client = new Client({
    intents: IS_SECONDARY
        ? [GatewayIntentBits.Guilds]
        : [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMembers,
            GatewayIntentBits.GuildMessages,
            GatewayIntentBits.GuildMessageReactions,
            GatewayIntentBits.DirectMessages,
            GatewayIntentBits.DirectMessageReactions,
            GatewayIntentBits.MessageContent,
        ],
    makeCache: Options.cacheWithLimits({
        ...Options.DefaultMakeCacheSettings,
        MessageManager:      { maxSize: 50  }, // keep only 50 messages per channel
        GuildMemberManager:  { maxSize: 200 }, // keep 200 members per guild
        UserManager:         { maxSize: 200 },
        ReactionManager:     { maxSize: 0   }, // reactions fetched on-demand
        GuildInviteManager:  { maxSize: 0   },
        StageInstanceManager:{ maxSize: 0   },
        VoiceStateManager:   { maxSize: 0   },
    }),
});
// Connection enhancer disabled as it may interfere with prefix commands
// const enhanceConnection = require('./connection-enhancer');
// enhanceConnection(client);


// Initialize collections for commands
client.commands = new Collection();

// Initialize database connection (needed by both primary and secondary)
const { db } = require('./server/db');
const schema = require('./shared/schema');
client.db = db;
client.schema = schema;

// Initialize beta features manager (lightweight — DB only, no intervals)
const betaManager = require('./utils/betaManager');
client.betaManager = betaManager;

// ── Lightweight stubs for standby period ─────────────────────────────────
// These prevent crashes if event handlers fire before real managers are up.
// They are replaced with real instances inside initializeManagers() the
// moment this node actually connects to Discord (primary at boot, secondary
// on takeover).
{
    const noop = () => {};
    const noopAsync = async () => {};
    client.giveawayManager  = { giveaways: new Map(), startGiveaway: noopAsync, endGiveaway: noopAsync };
    client.ticketManager    = { tickets: new Map() };
    client.ticTacToeManager = { games: new Map() };
    client.pollManager      = { polls: new Map() };
    client.livePollManager  = { polls: new Map() };
    client.birthdayManager  = { getBirthday: noop, setBirthday: noop, removeBirthday: noop,
                                 getAllBirthdays: () => new Map(), getUpcomingBirthdays: () => [],
                                 setAnnouncementChannel: noop, setBirthdayRole: noop,
                                 getGuildConfig: () => ({ announcementChannel: null, birthdayRole: null }) };
    client.emojiManager     = { getEmoji: noop, getAllEmojis: () => [] };
    client.countingManager  = { isCountingChannel: () => false, processCountingMessage: noopAsync };
    client.truthDareManager = { startGame: noopAsync };
    client.levelingManager  = null;
    client.serverSettingsManager = { getGuildSettings: () => ({}), updateGuildSetting: noop };
}

// ── Real manager boot — runs exactly once when this node connects ─────────
// Called by connectBot() so it works for both:
//   • primary  : connects immediately on startup
//   • secondary: connects later on takeover (primary went down)
let managersInitialized = false;
async function initializeManagers() {
    if (managersInitialized) return;
    managersInitialized = true;
    console.log('[MANAGERS] Initializing all managers...');

    const GiveawayManager   = require('./utils/giveawayManager');
    const TicketManager     = require('./utils/ticketManager');
    const TicTacToeManager  = require('./utils/ticTacToeManager');
    const PollManager       = require('./utils/pollManager');
    const LivePollManager   = require('./utils/livePollManager');
    const EmojiManager      = require('./utils/emojiManager');
    const CountingManager   = require('./utils/countingManager');
    const TruthDareManager  = require('./utils/truthDareManager');
    const LevelingManager   = require('./utils/levelingManager');
    const ServerSettingsManager = require('./utils/serverSettingsManager');

    client.giveawayManager  = new GiveawayManager(client);
    client.ticketManager    = new TicketManager(client);
    client.ticTacToeManager = new TicTacToeManager(client);
    client.pollManager      = new PollManager(client);
    client.livePollManager  = new LivePollManager(client);
    client.emojiManager     = new EmojiManager();
    client.countingManager  = new CountingManager(client);
    client.truthDareManager = new TruthDareManager(client);
    client.serverSettingsManager = new ServerSettingsManager(client);

    try {
        const BirthdayManager = require('./utils/birthdayManager');
        client.birthdayManager = new BirthdayManager(client);
        console.log('[MANAGERS] BirthdayManager loaded.');
    } catch (err) {
        console.error('[MANAGERS] Failed to load BirthdayManager:', err.message);
    }

    // LevelingManager needs the DB fully ready — brief delay is intentional
    setTimeout(() => {
        client.levelingManager = new LevelingManager(client);
    }, 2000);

    console.log('[MANAGERS] All managers initialized.');
}

// Live poll manager already initialized above


// Load command files
const commandsPath = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));

// Load commands into collection
for (const file of commandFiles) {
    const filePath = path.join(commandsPath, file);
    const command = require(filePath);

    // Set a new item in the Collection with the key as the command name and the value as the exported module
    if ('data' in command && 'execute' in command) {
        client.commands.set(command.data.name, command);
    } else {
        console.log(`[WARNING] The command at ${filePath} is missing a required "data" or "execute" property.`);
    }
}

console.log(`\n===== SLASH COMMANDS ENABLED =====`);
console.log(`Loaded ${client.commands.size} slash commands.`);
console.log(`Run deploy-commands.js to update registered commands.`);
console.log(`============================\n`);

// Load event handlers
const eventsPath = path.join(__dirname, 'events');
const eventFiles = fs.readdirSync(eventsPath).filter(file => file.endsWith('.js'));

// Debug event loading
console.log('\n===== LOADING EVENTS =====');
console.log(`Found ${eventFiles.length} event files`);

for (const file of eventFiles) {
    const filePath = path.join(eventsPath, file);
    const event = require(filePath);

    console.log(`Loading event: ${file} (${event.name}, once: ${event.once ? 'true' : 'false'})`);

    if (event.once) {
        client.once(event.name, (...args) => {
            console.log(`[EVENT] Executing once event: ${event.name}`);
            try {
                event.execute(...args, client);
            } catch (error) {
                console.error(`[EVENT ERROR] Error in once event ${event.name}:`, error);
            }
        });
    } else {
        client.on(event.name, (...args) => {
            // Always log message events for debugging
            console.log(`[EVENT] Executing event: ${event.name}`);

            try {
                // For message events, log key details
                if (event.name === 'messageCreate') {
                    const message = args[0];
                    console.log(`[MESSAGE DEBUG] Content: "${message.content}", Author: ${message.author.tag}, Channel: ${message.channel.type === 'DM' ? 'DM' : message.channel.name}, Guild: ${message.guild ? message.guild.name : 'None'}`);
                }

                event.execute(...args, client);
            } catch (error) {
                console.error(`[EVENT ERROR] Error in event ${event.name}:`, error);
            }
        });
    }
}
console.log('===== EVENTS LOADED =====\n');

// Add event handlers for guild join/leave to update status
client.on('guildCreate', (guild) => {
    console.log(`Joined guild: ${guild.name} (${guild.id})`);
    // Update bot status with new server count
    if (client.user) {
        client.user.setPresence({
            activities: [
                {
                    name: `${client.guilds.cache.size} servers | $help`,
                    type: ActivityType.Watching,
                },
            ],
            status: "online",
        });
    }
});

client.on('guildDelete', (guild) => {
    console.log(`Left guild: ${guild.name} (${guild.id})`);
    // Update bot status with new server count
    if (client.user) {
        client.user.setPresence({
            activities: [
                {
                    name: `${client.guilds.cache.size} servers | $help`,
                    type: ActivityType.Watching,
                },
            ],
            status: "online",
        });
    }
});

// Make client globally available for the website
global.client = client;

// Two-host failover (panel.visionhost.com = primary, wispbyte.com = secondary).
// Controlled via NODE_ROLE env var on each host. By default this is now disabled
// so regular hosts can connect normally; enable it explicitly with BOT_FAILOVER_ENABLED=true.
const nodeFailover = require('./utils/nodeFailover');
const failoverEnabled = process.env.BOT_FAILOVER_ENABLED !== 'false';

// Function to handle reconnection
async function connectBot() {
    try {
        const resolvedToken = resolveDiscordToken();
        if (!resolvedToken) {
            console.error('❌ No Discord token found. Cannot connect to Discord.');
            process.exit(1);
        }

        process.env.DISCORD_TOKEN = resolvedToken;
        await initializeManagers();
        console.log('Attempting to connect to Discord...');
        await client.login(resolvedToken);
        console.log('✅ Bot successfully logged in and is now online!');
        debug('Bot successfully logged in');

        if (failoverEnabled) {
            const lease = await nodeFailover.acquireLease(nodeFailover.NODE_ROLE, nodeFailover.NODE_NAME);
            if (!lease.acquired) {
                console.warn(`[FAILOVER] Could not acquire active-node lease; another host is still active (${lease.ownerNodeName}).`);
                nodeFailover.stopHeartbeatLoop();
                return;
            }
            nodeFailover.startHeartbeatLoop(nodeFailover.NODE_ROLE);
            console.log(`[FAILOVER] Host ready: role=${nodeFailover.NODE_ROLE} node=${nodeFailover.NODE_NAME} leaseOwner=${lease.ownerNodeName}`);
        } else {
            console.log('[FAILOVER] Failover disabled; skipping heartbeat loop so this host can stay online normally.');
        }
    } catch (error) {
        console.error('[ERROR] Failed to login to Discord:', error);
        if (error.code === 'TOKEN_INVALID' || error.message?.includes('token')) {
            console.error('❌ Invalid Discord token. Please check your DISCORD_TOKEN/BOT_TOKEN/TOKEN/CLIENT_TOKEN in secrets.');
            process.exit(1);
        }
        console.log('Attempting to reconnect in 5 seconds...');
        setTimeout(connectBot, 5000);
    }
}

// Generalized standby loop. Used whenever this node detects that ANOTHER node
// (identified by a different node_name) is already active with a fresh
// heartbeat — regardless of which role each host is configured with. This
// guards against duplicate replies if NODE_ROLE is ever misconfigured (e.g.
// both hosts left unset/defaulting to "primary"): only one node will ever
// actually call connectBot(), whichever detects no other healthy active node.
let standbyTookOver = false;
async function startStandbyMonitor() {
    if (!failoverEnabled) {
        console.log('[FAILOVER] Standby monitor disabled because failover is off.');
        return;
    }

    console.log(`[FAILOVER] Running as STANDBY node (${nodeFailover.NODE_NAME}, configured role: ${nodeFailover.NODE_ROLE}). Watching for another active node...`);
    setInterval(async () => {
        try {
            const other = await nodeFailover.getOtherActiveNode(nodeFailover.NODE_NAME);

            if (!standbyTookOver && !other) {
                console.warn('[FAILOVER] No other active node detected. Taking over as the active node.');
                standbyTookOver = true;
                await connectBot();
            } else if (standbyTookOver && other) {
                console.log(`[FAILOVER] Another node (${other.nodeName}) is back online. Stepping this node back down.`);
                nodeFailover.stopHeartbeatLoop();
                await nodeFailover.markInactive(nodeFailover.NODE_ROLE);
                process.exit(0);
            }
        } catch (error) {
            console.error('[FAILOVER] Monitor loop error:', error.message);
        }
    }, nodeFailover.MONITOR_INTERVAL_MS);
}

// Before connecting, check whether another host is already online and
// healthy. Behavior depends on this host's configured role:
//   - "primary" always wins: it connects/takes over even if a "secondary" is
//     currently active. The active secondary will notice the primary's
//     heartbeat on its next standby check (~10s) and step itself down, so
//     there's only a brief overlap during a deliberate handover, not a
//     permanent duplicate.
//   - "secondary" defers to any already-active node and only connects if
//     nothing else is currently healthy (unchanged failover behavior).
async function startWithFailoverCheck() {
    if (!failoverEnabled) {
        console.log('[FAILOVER] Failover guard disabled; connecting directly from this host.');
        await connectBot();
        return;
    }

    try {
        const lease = await nodeFailover.acquireLease(nodeFailover.NODE_ROLE, nodeFailover.NODE_NAME);
        if (!lease.acquired) {
            console.warn(`[FAILOVER] Another host already holds the active-node lease (${lease.ownerNodeName}). Standing by.`);
            startStandbyMonitor();
            return;
        }
        if (lease.stolen) {
            console.warn(`[FAILOVER] Reclaimed the active-node lease from ${lease.ownerNodeName}.`);
        }
    } catch (error) {
        console.error('[FAILOVER] Startup check failed, proceeding to connect:', error.message);
    }
    await connectBot();
}

async function gracefulShutdown() {
    nodeFailover.stopHeartbeatLoop();
    await nodeFailover.releaseLease(nodeFailover.NODE_NAME);
    await nodeFailover.markInactive(nodeFailover.NODE_ROLE);
    process.exit(0);
}
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);



process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    // Log the error but don't exit unless absolutely necessary
    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
        console.log('Network error occurred, but the bot will continue running');
    } else if (error.message && error.message.includes('getaddrinfo')) {
        console.log('DNS resolution error occurred, but the bot will continue running');
    } else if (error.code === 'TOKEN_INVALID') {
        console.error('Invalid token. The bot must restart with a valid token');
        process.exit(1);
    }
    // For other errors, log but don't crash
});

process.on('warning', (warning) => {
    console.warn('Warning:', warning.name, warning.message);
});

// Connect the bot, but only after confirming no other host is already
// online. Whichever host detects a healthy heartbeat from the other stands
// down and monitors instead of connecting, so two hosts never both reply to
// the same command — even if NODE_ROLE is misconfigured on one/both hosts.
{
    startWithFailoverCheck();
}