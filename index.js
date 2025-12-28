const debug = require('debug')('bot:main');

const { Client, GatewayIntentBits, Collection, ActivityType } = require('discord.js');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Create a new client instance
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.GuildMessageReactions,
        GatewayIntentBits.DirectMessages,
        GatewayIntentBits.DirectMessageReactions,
        GatewayIntentBits.MessageContent
    ]
});
// Connection enhancer disabled as it may interfere with prefix commands
// const enhanceConnection = require('./connection-enhancer');
// enhanceConnection(client);


// Initialize collections for commands
client.commands = new Collection();

// Initialize managers first (before events)
const GiveawayManager = require('./utils/giveawayManager');
client.giveawayManager = new GiveawayManager(client);

const TicketManager = require('./utils/ticketManager');
client.ticketManager = new TicketManager(client);

const TicTacToeManager = require('./utils/ticTacToeManager');
client.ticTacToeManager = new TicTacToeManager(client);

const PollManager = require('./utils/pollManager');
client.pollManager = new PollManager(client);

// Initialize birthday manager
try {
    const BirthdayManager = require('./utils/birthdayManager');
    client.birthdayManager = new BirthdayManager(client);
    console.log('Successfully loaded BirthdayManager');
} catch (error) {
    console.error('Failed to load BirthdayManager:', error.message);
    // Create a temporary birthday manager to prevent crashes
    client.birthdayManager = {
        getBirthday: () => null,
        setBirthday: () => false,
        removeBirthday: () => false,
        getAllBirthdays: () => new Map(),
        getUpcomingBirthdays: () => [],
        setAnnouncementChannel: () => false,
        setBirthdayRole: () => false,
        getGuildConfig: () => ({ announcementChannel: null, birthdayRole: null })
    };
}

// Initialize emoji manager
const EmojiManager = require('./utils/emojiManager');
client.emojiManager = new EmojiManager();

// Initialize counting game manager
const CountingManager = require('./utils/countingManager');
client.countingManager = new CountingManager(client);

// Initialize truth or dare game manager
const TruthDareManager = require('./utils/truthDareManager');
client.truthDareManager = new TruthDareManager(client);

// Initialize database connection FIRST (before LevelingManager)
const { db } = require('./server/db');
const schema = require('./shared/schema');
client.db = db;
client.schema = schema;

// Initialize leveling and badges manager (after database is available)
const LevelingManager = require('./utils/levelingManager');

// Initialize Live Poll Manager
const LivePollManager = require('./utils/livePollManager');

// Initialize managers (with database)
    client.giveawayManager = new GiveawayManager(client);
    client.pollManager = new PollManager(client);
    client.livePollManager = new LivePollManager(client);

    // Wait a bit to ensure database is fully ready before initializing leveling
    setTimeout(() => {
        client.levelingManager = new LevelingManager(client);
    }, 2000);


// Initialize server settings manager for broadcast opt-outs
const ServerSettingsManager = require('./utils/serverSettingsManager');
client.serverSettingsManager = new ServerSettingsManager(client);

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

// Start website
const website = require('./website');

// Function to handle reconnection
async function connectBot() {
    try {
        console.log('Attempting to connect to Discord...');
        await client.login(process.env.DISCORD_TOKEN);
        console.log('✅ Bot successfully logged in and is now online!');
        debug('Bot successfully logged in');
    } catch (error) {
        console.error('[ERROR] Failed to login to Discord:', error);
        if (error.code === 'TOKEN_INVALID') {
            console.error('❌ Invalid Discord token. Please check your DISCORD_TOKEN in secrets.');
            process.exit(1);
        }
        console.log('Attempting to reconnect in 5 seconds...');
        setTimeout(connectBot, 5000);
    }
}



process.on('unhandledRejection', error => {
    console.error('Unhandled promise rejection:', error);
});


// Enhanced error handling for process events
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't crash on unhandled rejections
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

// Connect the bot
connectBot();