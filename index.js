const debug = require('debug')('bot:main');

const { Client, GatewayIntentBits, Collection, ActivityType, Options } = require('discord.js');
const fs = require('fs');
const path = require('path');
const { resolveDiscordToken } = require('./utils/tokenResolver');
require('dotenv').config();

// Detect secondary/standby role BEFORE initialising any managers so we can
// skip the heavy ones that are never needed on a standby-only node.
const IS_SECONDARY = process.env.BOT_FAILOVER_ENABLED !== 'false' &&
                     (['sn2', 'sn3', 'secondary', 'tertiary'].includes(process.env.NODE_ROLE));

if (IS_SECONDARY) {
    console.log('[BOOT] Running as SECONDARY node — skipping heavy managers to save memory.');
}

// Run GC aggressively if --expose-gc was passed (added by start-bot.js).
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
// Always use full intents on both nodes so that if a standby node takes over
// it has all the permissions it needs to handle messages and reactions.
// Cache limits are applied on both nodes to keep memory bounded.
const client = new Client({
    intents: [
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
                                 getAllBirthdays: () => new Map(), getUpcomingBirthdays: async () => [],
                                 getGuildBirthdays: async () => ({ channel: null, role: null, users: new Map() }),
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

// ── Shard-disconnect guard ────────────────────────────────────────────────
// When a higher-priority node (e.g. sn1) calls client.login() it kicks the
// lower-priority node's WebSocket (same token → Discord closes with code 4000).
// discord.js treats 4000 as recoverable and auto-reconnects, which would start
// a battle. We short-circuit that: the moment a shard disconnects we check the
// DB lease; if we no longer hold it we call stepDown() before discord.js can
// reconnect us and create double-interaction.
client.on('shardDisconnect', async (closeEvent, shardId) => {
    if (!failoverEnabled || !global.botActive) return;
    // Pause further interaction handling immediately while we verify the lease.
    // Setting botActive=false stops the TOKEN_INVALID handler from treating
    // a later 4004 as a real token error; we restore it if the lease is still ours.
    global.botActive = false;
    try {
        const stillHaveLease = await nodeFailover.refreshLease(nodeFailover.NODE_NAME, nodeFailover.NODE_ROLE);
        if (!stillHaveLease) {
            console.warn(`[FAILOVER] Shard ${shardId} disconnected (code ${closeEvent?.code}) and lease is gone — higher-priority node has taken over. Stepping down.`);
            await stepDown(`shard ${shardId} disconnect + lease gone`);
        } else {
            // False alarm (transient network drop) — restore active flag so
            // discord.js can reconnect normally.
            global.botActive = true;
        }
    } catch (err) {
        console.error('[FAILOVER] shardDisconnect lease-check failed:', err.message);
        global.botActive = true; // restore on DB error to avoid silent shutdown
    }
});

// Three-host failover (sn1 = primary, sn2 = secondary, sn3 = tertiary).
// Controlled via NODE_ROLE env var on each host. By default this is now disabled
// so regular hosts can connect normally; enable it explicitly with BOT_FAILOVER_ENABLED=true.
const nodeFailover = require('./utils/nodeFailover');
const failoverEnabled = process.env.BOT_FAILOVER_ENABLED !== 'false';

// Webhook logger — sends shard-node events to Discord channel.
// Reads FAILOVER_WEBHOOK_URL from env; silently no-ops when not set.
const wh = require('./utils/webhookLogger');

// ── Consolidated step-down ─────────────────────────────────────────────────
// Called from any path that determines this node should yield to another.
// Guards against double-invocation with `steppingDown`.
let steppingDown = false;
async function stepDown(reason) {
    if (steppingDown) return;
    steppingDown = true;
    console.warn(`[FAILOVER] Stepping down (${reason}). Releasing lease and disconnecting.`);
    wh.send({
        title: '🔴 Shard Node Offline',
        description: 'This node is stepping down and releasing the active lease.',
        type: 'offline',
        reason,
    });
    global.botActive = false;
    nodeFailover.stopHeartbeatLoop();
    await nodeFailover.markInactive(nodeFailover.NODE_ROLE).catch(() => {});
    await nodeFailover.releaseLease(nodeFailover.NODE_NAME).catch(() => {});
    try { client.destroy(); } catch (_) {}
    setTimeout(() => process.exit(0), 500);
}

// ── Connect bot ────────────────────────────────────────────────────────────
// leaseAlreadyAcquired: true when startWithFailoverCheck already confirmed the
// lease before calling us, so we skip the pre-login check (but still confirm
// after login to catch any race between our acquire and our login).
let connectingBot = false;
async function connectBot(leaseAlreadyAcquired = false) {
    if (connectingBot) {
        console.warn('[FAILOVER] connectBot already in progress — skipping duplicate call.');
        return;
    }
    connectingBot = true;

    try {
        // ── Step 1: acquire the lease BEFORE logging in ────────────────────
        // This is the key guard against dual-active: we only call client.login()
        // once we hold the DB lease. A node that cannot get the lease never
        // touches Discord, so there is no window where two nodes both handle events.
        if (failoverEnabled && !leaseAlreadyAcquired) {
            const lease = await nodeFailover.acquireLease(nodeFailover.NODE_ROLE, nodeFailover.NODE_NAME);
            if (!lease.acquired) {
                console.warn(`[FAILOVER] Could not acquire lease before connecting — ${lease.ownerNodeName} is still active. Returning to standby.`);
                connectingBot = false;
                standbyTookOver = false; // allow the monitor to retry next tick
                return;
            }
            if (lease.stolen) {
                console.log(`[FAILOVER] Acquired lease from ${lease.ownerNodeName} (role=${nodeFailover.NODE_ROLE}); connecting now.`);
            }
        }

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
            // ── Step 2: confirm we still hold the lease after login ────────
            // Another higher-priority node might have stolen it during the login
            // round-trip (e.g. sn1 arrived while sn2/sn3 was mid-login).
            const confirmed = await nodeFailover.refreshLease(nodeFailover.NODE_NAME, nodeFailover.NODE_ROLE);
            if (!confirmed) {
                console.warn('[FAILOVER] Lost lease during login — a higher-priority node took over. Stepping down immediately.');
                connectingBot = false;
                await stepDown('lease lost during login');
                return;
            }
            // ── Step 3: start heartbeat; step down the moment lease is stolen
            nodeFailover.startHeartbeatLoop(
                nodeFailover.NODE_ROLE,
                () => stepDown('lease stolen — detected via heartbeat refresh')
            );
            console.log(`[FAILOVER] Host ready: role=${nodeFailover.NODE_ROLE} node=${nodeFailover.NODE_NAME}`);
            wh.send({
                title: '🟢 Shard Node Online',
                description: 'This node has acquired the active lease and is now handling Discord events.',
                type: 'online',
            });
        } else {
            console.log('[FAILOVER] Failover disabled; skipping heartbeat loop so this host can stay online normally.');
        }

        global.botActive = true;
        steppingDown = false; // clear any stale flag from a previous cycle
    } catch (error) {
        connectingBot = false;
        console.error('[ERROR] Failed to login to Discord:', error);
        if (error.code === 'TOKEN_INVALID' || error.message?.includes('token')) {
            console.error('❌ Invalid Discord token. Please check your DISCORD_TOKEN/BOT_TOKEN/TOKEN/CLIENT_TOKEN in secrets.');
            process.exit(1);
        }
        console.log('Attempting to reconnect in 5 seconds...');
        setTimeout(() => connectBot(false), 5000);
        return;
    }
    connectingBot = false;
}

// Generalized standby loop. Used whenever this node detects that ANOTHER node
// (identified by a different node_name) is already active with a fresh
// heartbeat. When no higher-priority node is alive this node takes over by
// acquiring the lease BEFORE logging into Discord (prevents dual-active).
// Once this node is active it polls more frequently so it can step back down
// quickly when a higher-priority node returns.
let standbyTookOver = false;
// Interval handle kept so we can swap between slow (pre-takeover) and fast
// (post-takeover) check cadences.
let standbyMonitorTimer = null;
function startStandbyMonitor() {
    if (!failoverEnabled) {
        console.log('[FAILOVER] Standby monitor disabled because failover is off.');
        return;
    }

    console.log(`[FAILOVER] Running as STANDBY node (${nodeFailover.NODE_NAME}, configured role: ${nodeFailover.NODE_ROLE}). Watching for another active node...`);
    wh.send({
        title: '🟡 Shard Node Standby',
        description: 'This node started in standby mode. It will take over if no higher-priority node is active.',
        type: 'standby',
    });

    async function monitorTick() {
        try {
            const other = await nodeFailover.getOtherActiveNode(nodeFailover.NODE_NAME, nodeFailover.NODE_ROLE);

            if (!standbyTookOver && !other) {
                // No higher-priority node is alive — take over.
                // connectBot() will attempt to acquire the lease before logging
                // in; if it succeeds it sets standbyTookOver back to true via
                // the global.botActive path, so we set it here to block
                // duplicate calls while connectBot() is in-flight.
                standbyTookOver = true;
                console.warn('[FAILOVER] No other active node detected. Acquiring lease and taking over.');
                await connectBot(false); // acquires lease before login

            } else if (standbyTookOver) {
                // A higher-priority node may be back. Check two independent signals:
                //
                // 1. bot_node_status heartbeat (other != null) — the returning node
                //    has already logged in and started writing heartbeats.
                // 2. bot_failover_lock lease owner (isLeaseHeldByHigherPriority) —
                //    the returning node stole the lease but hasn't logged in yet.
                //
                // Signal #2 fires FIRST (lease is stolen before client.login()),
                // so we step down immediately instead of waiting up to 15 s for
                // the next heartbeat tick to notice via onLeaseStolen().
                const leaseTaken = await nodeFailover.isLeaseHeldByHigherPriority(
                    nodeFailover.NODE_ROLE, nodeFailover.NODE_NAME
                );

                if (other || leaseTaken) {
                    const reason = other
                        ? `higher-priority node ${other.role} (${other.nodeName}) returned`
                        : `higher-priority node reclaimed the lease (not yet heartbeating)`;
                    console.log(`[FAILOVER] Stepping down — ${reason}.`);
                    await stepDown(reason);
                }
            }
        } catch (error) {
            console.error('[FAILOVER] Monitor loop error:', error.message);
        }
    }

    // Use a faster cadence once this node has taken over so it can step down
    // quickly (within ~3 s) when a higher-priority node returns — preventing
    // the ~10 s double-interaction window that existed with a single interval.
    const STANDBY_INTERVAL  = nodeFailover.MONITOR_INTERVAL_MS;      // 10 s — pre-takeover
    const ACTIVE_INTERVAL   = Math.min(3000, nodeFailover.MONITOR_INTERVAL_MS); // 3 s — post-takeover

    function scheduleNext() {
        const delay = standbyTookOver ? ACTIVE_INTERVAL : STANDBY_INTERVAL;
        standbyMonitorTimer = setTimeout(async () => {
            await monitorTick();
            scheduleNext();
        }, delay);
    }

    scheduleNext();
}

// Before connecting, check whether another host is already online and healthy.
// sn1 always steals the lease (highest priority); sn2/sn3 defer to whoever
// holds a fresh lease and enter the standby monitor instead.
// leaseAlreadyAcquired=true is passed to connectBot() so it skips a redundant
// second acquireLease call at the start of connectBot().
async function startWithFailoverCheck() {
    if (!failoverEnabled) {
        console.log('[FAILOVER] Failover guard disabled; connecting directly from this host.');
        await connectBot(false);
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
            if (lease.wasCovering) {
                console.log(`[FAILOVER] ${nodeFailover.NODE_ROLE} is back online. ${lease.ownerNodeName} was covering and will step down shortly.`);
                wh.send({
                    title: '🔁 Primary Node Returning',
                    description: 'This node is back online and reclaiming the lease from the covering node.',
                    type: 'warning',
                    fromNode: lease.ownerNodeName,
                    reason: 'Covering node will step down shortly.',
                });
            } else {
                console.warn(`[FAILOVER] Reclaimed stale lease from ${lease.ownerNodeName}.`);
                wh.send({
                    title: '⚠️ Stale Lease Reclaimed',
                    description: 'Reclaimed an expired lease. The previous holder appears to have gone silent.',
                    type: 'warning',
                    fromNode: lease.ownerNodeName,
                    reason: `Lease was stale (no heartbeat for >${Math.round(nodeFailover.FAILOVER_THRESHOLD_MS / 1000)}s).`,
                });
            }
        }
    } catch (error) {
        console.error('[FAILOVER] Startup check failed, proceeding to connect:', error.message);
    }
    // Pass leaseAlreadyAcquired=true so connectBot() doesn't call acquireLease
    // a second time — the lease is already ours from the check above.
    await connectBot(true);
}

async function gracefulShutdown() {
    await stepDown('SIGTERM/SIGINT received');
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
        // When a higher-priority node logs in with the same token, Discord
        // eventually sends this node a 4004 close which discord.js surfaces as
        // TOKEN_INVALID — but the token itself is fine; only our session was
        // displaced. If the lease is gone a higher-priority node took over and
        // we exit cleanly. If we still hold the lease it is a genuine bad token.
        if (failoverEnabled && !steppingDown) {
            nodeFailover.refreshLease(nodeFailover.NODE_NAME, nodeFailover.NODE_ROLE)
                .then(stillHaveLease => {
                    if (!stillHaveLease) {
                        console.warn('[FAILOVER] TOKEN_INVALID but lease is gone — session displaced by higher-priority node. Stepping down cleanly.');
                        stepDown('TOKEN_INVALID + lease gone');
                    } else {
                        console.error('Invalid token. The bot must restart with a valid token');
                        process.exit(1);
                    }
                })
                .catch(() => {
                    console.error('Invalid token. The bot must restart with a valid token');
                    process.exit(1);
                });
            return; // wait for the async lease check above
        }
        if (!steppingDown) {
            console.error('Invalid token. The bot must restart with a valid token');
            process.exit(1);
        }
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