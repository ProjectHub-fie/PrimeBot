/**
 * Linix music subsystem — bootstrap.
 *
 * Mirrors Linix's `index.js` music wiring, in the same order:
 *   client surface → player manager → node events → player events →
 *   prefix + slash command trees → 247 reconnect on ready.
 *
 * PrimeBot keeps its own discord.js client, shard manager and every unrelated
 * feature; this module only attaches the music subsystem to it. It is
 * idempotent, and it degrades to a clearly logged "unconfigured" state (never a
 * crash) when no Lavalink node is configured — the rest of PrimeBot boots
 * normally either way.
 */

const { installMusicClientSurface } = require('./clientBridge');
const loadPlayerManager = require('./loaders/loadPlayerManager');
const loadNodes = require('./loaders/loadNodes');
const loadPlayers = require('./loaders/loadPlayers');
const loadCommands = require('./loaders/loadCommands');
const { getMusicConfig } = require('./config');

/**
 * Initialize the music subsystem on a logged-in client.
 * @returns {{enabled:boolean, reason?:string, nodes?:number, commands?:object}}
 */
function initMusic(client) {
    if (client.__musicInitialized) return client.__musicState || { enabled: false, reason: 'already initialized' };
    client.__musicInitialized = true;

    installMusicClientSurface(client);

    const cfg = getMusicConfig();
    if (!cfg.nodes.length) {
        client.logger.log(
            'Music is not configured: set NODE_URL/NODE_AUTH/NODE_NAME/NODE_SECURE (or LAVALINK_NODES). Music commands will report the missing node.',
            'warn',
        );
        client.__musicState = { enabled: false, reason: 'no_lavalink_node', nodes: 0 };
        return client.__musicState;
    }

    try {
        // State object is created BEFORE the loaders bind the node/player
        // events, so a node that connects (or fails) right away is tracked.
        // `connected` flips true only from the Lavalink node `ready` event.
        client.__musicState = { enabled: true, nodes: cfg.nodes.length, commands: null, connected: false };
        loadPlayerManager(client);
        loadNodes(client);
        loadPlayers(client);
        const commands = loadCommands(client);
        client.__musicState.commands = commands;
        client.logger.log(`Music initialized with ${cfg.nodes.length} Lavalink node(s)`, 'log');
        return client.__musicState;
    } catch (err) {
        console.error('[MUSIC] Initialization failed:', err);
        client.__musicState = { enabled: false, reason: err.message, nodes: cfg.nodes.length };
        return client.__musicState;
    }
}

/** Reconnect the persisted 24/7 sessions (Linix `events/Node/ready.js`). */
async function restore247(client) {
    try {
        const { restoreAutoReconnect } = require('./loaders/restore247');
        return await restoreAutoReconnect(client);
    } catch (err) {
        console.error('[MUSIC] 247 restore failed:', err.message);
        return 0;
    }
}

module.exports = { initMusic, restore247 };
