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
const { getMusicConfig, DEFAULT_NODE_NAME } = require('./config');
const { buildBootReport, buildConnectDiagnostic, describeNode, stateName } = require('./nodeDiagnostics');
const availability = require('./nodeAvailability');

const NODE_UNAVAILABLE = availability.NODE_UNAVAILABLE;
const hasUsableNode = availability.hasUsableNode;
const isNodeUnavailableError = availability.isNodeUnavailableError;
const describeNodes = availability.describeNodes;

/**
 * A typed, user-safe "music is unavailable" error. Thrown *before* Kazagumo
 * touches voice, so a missing node never joins a channel or creates a player.
 */
function nodeUnavailableError(client) {
    return availability.nodeUnavailableError(client, musicNodeStatus(client));
}

/**
 * Initialize the music subsystem on a logged-in client.
 * @returns {{enabled:boolean, reason?:string, nodes?:number, commands?:object}}
 */
function initMusic(client) {
    if (client.__musicInitialized) {
        client.logger && client.logger.log('Music already initialized on this client — skipping the second init.', 'debug');
        return client.__musicState || { enabled: false, reason: 'already initialized' };
    }
    client.__musicInitialized = true;

    installMusicClientSurface(client);

    const cfg = getMusicConfig();
    if (!cfg.nodes.length) {
        client.logger.log(
            'Music is not configured: set NODE_URL/NODE_AUTH/NODE_SECURE (or LAVALINK_NODES). '
            + 'The Lavalink node is named LNODE by default (override with LAVALINK_NAME); '
            + 'NODE_NAME is the shard cluster identity and is not used for it. '
            + 'Music commands will report the missing node.',
            'warn',
        );
        for (const problem of cfg.problems || []) {
            client.logger.log(`[MUSIC] Lavalink config: ${problem}`, 'warn');
        }
        client.__musicState = { enabled: false, reason: 'no_lavalink_node', nodes: 0 };
        return client.__musicState;
    }

    try {
        // State object is created BEFORE the loaders bind the node/player
        // events, so a node that connects (or fails) right away is tracked.
        // `connected` flips true only from the Lavalink node `ready` event.
        client.__musicState = { enabled: true, nodes: cfg.nodes.length, commands: null, connected: false };
        loadPlayerManager(client);
        // Node/player event handlers MUST be bound before the first node is
        // registered: `addNode` connects immediately, and a failed connection
        // emits `error` on the Shoukaku manager. With no listener yet that is
        // an unhandled 'error' event → the whole process dies and restarts
        // (the "SN1/SN3 report restarts" symptom).
        loadNodes(client);
        loadPlayers(client);
        if (client.manager && typeof client.manager.startNodes === 'function') {
            client.manager.startNodes();
        }
        const commands = loadCommands(client);
        client.__musicState.commands = commands;
        // Name + endpoint + password PRESENCE only — the password is never logged.
        const report = buildBootReport(cfg.nodes);
        client.logger.log(`Music initialized with ${cfg.nodes.length} Lavalink node(s): ${report.line}`, 'log');
        for (const problem of [...cfg.problems, ...report.problems]) {
            client.logger.log(`[MUSIC] Lavalink config: ${problem}`, 'warn');
        }
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

/**
 * Music-node status for displays (`$stats`, `$music`). Reports the CONFIGURED
 * node name (LNODE unless LAVALINK_NAME overrides it), the exact WebSocket
 * endpoint, whether the node has actually connected, and never a credential.
 */
function musicNodeStatus(client) {
    const cfg = getMusicConfig();
    const configured = cfg.nodes.map(n => n.name);
    const node = cfg.nodes[0] || null;
    const liveNodes = client && client.manager && client.manager.shoukaku && client.manager.shoukaku.nodes
        ? [...client.manager.shoukaku.nodes.values()]
        : [];
    const described = node ? describeNode(node) : null;
    const liveState = liveNodes.length ? Number(liveNodes[0].state) : null;
    // Shoukaku's `State.CONNECTED` is 1 (see its default nodeResolver, which
    // only ever picks `state === 1`). Reading the live state keeps this honest
    // when a node drops after it has connected once.
    return {
        configured,
        name: configured[0] || DEFAULT_NODE_NAME,
        registered: liveNodes.length,
        connected: liveNodes.some(n => Number(n.state) === 1)
            || Boolean(client && client.__musicState && client.__musicState.connected),
        enabled: Boolean(client && client.__musicState && client.__musicState.enabled),
        // Shoukaku's own state: 0 = connecting, 1 = connected, 3 = disconnected.
        state: liveState,
        stateName: stateName(liveState),
        // Sanitized configuration (host/port/TLS/password presence only).
        endpoint: described ? described.endpoint : null,
        host: described ? described.host : null,
        port: described ? described.port : null,
        secure: described ? described.secure : null,
        hasAuth: described ? described.hasAuth : false,
        authSource: described ? described.authSource : 'unknown',
        lastError: (client && client.__musicState && client.__musicState.lastError) || null,
        lastErrorAt: (client && client.__musicState && client.__musicState.lastErrorAt) || null,
    };
}

/**
 * Say, ~20s in (and once more at 60s), that the node has still not connected,
 * with the exact resolved endpoint, the node state and whether a password was
 * configured. A blocked port, a wrong scheme and a wrong password otherwise
 * look identical ("the music commands just do not work").
 */
function startConnectDiagnostic(client, delayMs = 20000, { setTimer = setTimeout, extraDelays = [40000] } = {}) {
    if (!client || client.__musicConnectDiag) return;
    client.__musicConnectDiag = true;

    const report = () => {
        const status = musicNodeStatus(client);
        if (status.connected) {
            client.__musicConnectDiagDone = true;
            return;
        }
        const cfg = getMusicConfig();
        const message = buildConnectDiagnostic({
            node: cfg.nodes[0],
            status,
            elapsedMs: delayMs,
            lastError: status.lastError,
        });
        // Store it so `$stats` / the dashboard can show the same reason.
        if (client.__musicState) client.__musicState.connectDiagnostic = message;
        console.warn(message);
    };

    const schedule = (wait) => {
        const timer = setTimer(() => {
            try { report(); } catch (_) { /* diagnostics must never throw */ }
        }, wait);
        if (timer && timer.unref) timer.unref();
        return timer;
    };

    schedule(delayMs);
    // One follow-up: a node that connects late (slow provider) should not be
    // reported once and forgotten, and a node stuck CONNECTING gets a second,
    // equally sanitized line.
    for (const extra of extraDelays) {
        const timer = setTimer(() => {
            try {
                if (client.__musicConnectDiagDone) return;
                if (musicNodeStatus(client).connected) return;
                report();
            } catch (_) { /* ignore */ }
        }, delayMs + extra);
        if (timer && timer.unref) timer.unref();
    }
}

/** Self-heal the Lavalink registration before a command needs a node. */
function ensureMusicNodes(client) {
    try {
        const manager = client && client.manager;
        if (!manager || !manager.shoukaku) return false;
        if (manager.shoukaku.nodes.size > 0) return true;
        if (typeof manager.ensureNodes === 'function') manager.ensureNodes();
        return manager.shoukaku.nodes.size > 0;
    } catch (_) {
        return false;
    }
}

module.exports = {
    initMusic,
    restore247,
    musicNodeStatus,
    ensureMusicNodes,
    describeNodes,
    startConnectDiagnostic,
    hasUsableNode,
    nodeUnavailableError,
    isNodeUnavailableError,
    NODE_UNAVAILABLE,
    DEFAULT_NODE_NAME,
};
