/**
 * Linix `src/loaders/loadPlayerManager.js` — Kazagumo (Lavalink) player manager.
 *
 * Preserved from Linix: the `Kazagumo` construction with `Connectors.DiscordJS`,
 * the `searchEngines` map, the overridden `manager.search` that resolves through
 * the node REST API and wraps results in `KazagumoTrack`, and the Spotify plugin.
 *
 * PrimeBot adaptations (integration only):
 *   • node list / default search engine come from PrimeBot env config
 *     (`music/config.js`) instead of Linix's hardcoded `client.config.nodes`;
 *   • the Spotify plugin is enabled only when credentials are configured;
 *   • `guild.shard.send` is guarded — PrimeBot runs a plain discord.js client
 *     (no discord-hybrid-sharding ClusterClient), so `guild.shard` may be a
 *     plain shard without `send`.
 */

const { Kazagumo, KazagumoTrack } = require('kazagumo');
const { Connectors, LoadType } = require('shoukaku');
const musicConfig = require('../config');
const { sanitizeText, describeNode } = require('../nodeDiagnostics');
const availability = require('../nodeAvailability');

/**
 * Backoff for re-registering a node after Shoukaku gives up on it. Shoukaku
 * retries a live socket itself (`reconnectTries`); it only removes a node from
 * the pool once every attempt failed, so this is the "provider was down for a
 * while" path. Bounded so a permanently wrong host cannot reconnect-storm.
 */
const NODE_RECONNECT_DELAYS_MS = [2000, 5000, 15000, 30000, 60000];

const searchEngines = {
    DEEZER: 'dzsearch',
    SPOTIFY: 'spsearch',
    YOUTUBE: 'ytsearch',
    JIO_SAAVAN: 'jssearch',
    SOUNDCLOUD: 'scsearch',
    YOUTUBE_MUSIC: 'ytmsearch',
};

module.exports = function loadPlayerManager(client, { reconnectDelays = NODE_RECONNECT_DELAYS_MS } = {}) {
    const cfg = musicConfig.getMusicConfig();

    const plugins = [];
    if (cfg.spotify.clientId && cfg.spotify.clientSecret) {
        try {
            const Spotify = require('kazagumo-spotify');
            plugins.push(new Spotify({
                clientId: cfg.spotify.clientId,
                clientSecret: cfg.spotify.clientSecret,
                playlistPageLimit: cfg.spotify.playlistPageLimit,
                albumPageLimit: cfg.spotify.albumPageLimit,
                searchLimit: cfg.spotify.searchLimit,
                searchMarket: cfg.spotify.searchMarket,
            }));
        } catch (err) {
            console.error('[MUSIC] Spotify plugin unavailable:', err.message);
        }
    }

    const manager = new Kazagumo(
        {
            plugins,
            defaultSearchEngine: cfg.nodeSource,
            send: (guildId, payload) => {
                const guild = client.guilds.cache.get(guildId);
                const shard = guild && guild.shard;
                if (shard && typeof shard.send === 'function') shard.send(payload);
            },
        },
        new Connectors.DiscordJS(client),
        cfg.nodes,
        cfg.nodeOptions,
    );

    // Shoukaku's connector registers the nodes from its own
    // `once('clientReady')` listener. PrimeBot can boot the subsystem *after*
    // that event (a standby node taking over, a reconnect, a hot reload), in
    // which case the listener never runs and Lavalink is never contacted.
    // Registering is idempotent, so whichever path runs first wins and the
    // node is never added twice (two addNode calls would open two sockets).
    const connector = manager.shoukaku.connector;
    const registerNodes = connector.ready.bind(connector);
    let nodesRegistered = false;
    let lastAttempt = 0;

    /**
     * Shoukaku emits `error` on the manager, and Node treats an `error` event
     * with no listener as fatal. The real handler is bound by
     * `music/loaders/loadNodes.js`, which runs after this module — so a
     * connection that fails *immediately* (client already ready, provider
     * unreachable) used to crash the whole process before any listener
     * existed, which is what made the clusters restart in a loop. This guard
     * is bound before the first node is registered and only records the
     * sanitized reason; the real handler still logs it once.
     */
    const recordBootstrapError = (name, error) => {
        if (!client.__musicState) return;
        client.__musicState.connected = false;
        client.__musicState.lastError = sanitizeText(
            error && error.message ? error.message : error,
            cfg.nodes.find(n => n.name === name) || cfg.nodes[0],
        ).slice(0, 200);
        client.__musicState.lastErrorAt = Date.now();
    };
    manager.shoukaku.on('error', recordBootstrapError);

    const log = (message, level) => {
        if (client.logger && typeof client.logger.log === 'function') client.logger.log(message, level);
    };

    let reconnectAttempts = 0;
    let reconnectTimer = null;

    const clearReconnectTimer = () => {
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
    };

    /** Schedule ONE bounded re-registration after Shoukaku dropped the node. */
    const scheduleNodeReconnect = (reason) => {
        if (reconnectTimer) return reconnectTimer;
        if (reconnectAttempts >= reconnectDelays.length) {
            log(
                `[MUSIC] Lavalink re-registration gave up after ${reconnectAttempts} attempts — `
                + `music stays unavailable until the next command retries (${reason}).`,
                'warn',
            );
            return null;
        }
        const delay = reconnectDelays[reconnectAttempts];
        reconnectAttempts += 1;
        reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            nodesRegistered = false;
            const ok = registerAll({ force: true });
            log(
                `[MUSIC] Lavalink re-registration attempt ${reconnectAttempts}/${reconnectDelays.length} `
                + `(${reason}) → ${ok ? 'registered' : 'not registered'}; nodes: ${availability.describeNodes(client)}`,
                'warn',
            );
        }, delay);
        if (reconnectTimer.unref) reconnectTimer.unref();
        return reconnectTimer;
    };

    /**
     * Attach the "Shoukaku gave up on this node" hook once per node object.
     * `addNode` deletes the node from the pool on `disconnect`, so without this
     * a provider blip left music dead until a command happened to self-heal.
     */
    const watchNode = (node) => {
        if (!node || node.__musicReconnectWatched) return;
        node.__musicReconnectWatched = true;
        if (typeof node.once === 'function') {
            node.once('disconnect', () => scheduleNodeReconnect(`node "${node.name}" disconnected`));
        }
    };

    /**
     * Register the configured nodes exactly once.
     *
     * `nodesRegistered` is only set AFTER a successful call: the old code set it
     * first, so a single throw (the client's user id not being available yet, a
     * transient Shoukaku error) permanently disabled registration and every
     * music command failed with `No node found` for the life of the process.
     */
    const registerAll = ({ force = false } = {}) => {
        if (nodesRegistered) return true;
        if (manager.shoukaku.nodes.size > 0) {
            nodesRegistered = true;
            for (const node of manager.shoukaku.nodes.values()) watchNode(node);
            return true;
        }
        // Never hammer addNode: two successful calls would open two sockets.
        if (!force && Date.now() - lastAttempt < 5000) return false;
        lastAttempt = Date.now();
        try {
            registerNodes(cfg.nodes);
            nodesRegistered = true;
            for (const node of manager.shoukaku.nodes.values()) watchNode(node);
            return true;
        } catch (err) {
            console.error('[MUSIC] Lavalink node registration failed:', sanitizeText(err.message, cfg.nodes[0]));
            return false;
        }
    };

    connector.ready = (nodes) => registerAll({ force: true });

    // A node that finally connects resets the reconnect backoff.
    manager.shoukaku.on('ready', () => {
        reconnectAttempts = 0;
        clearReconnectTimer();
        nodesRegistered = true;
    });

    /**
     * Called by `music/index.js` AFTER the node/player event handlers are
     * bound. Registering before that (the old behaviour) let an immediate
     * connection failure emit an `error` with no listener → process crash.
     */
    manager.startNodes = () => {
        if (!(client.user && typeof client.isReady === 'function' && client.isReady())) {
            // Not logged in yet: the connector's own `clientReady` hook (or the
            // retries below) will register once the id is available.
            return false;
        }
        return registerAll({ force: true });
    };

    // Belt and braces: if the node is still not registered a few seconds after
    // the subsystem booted (the client was not ready yet, or Shoukaku's own
    // `clientReady` hook never ran), try again. Unref'd so it never keeps the
    // process alive, and bounded so a broken config does not retry forever.
    for (const delayMs of [5000, 15000]) {
        const timer = setTimeout(() => registerAll(), delayMs);
        if (timer.unref) timer.unref();
    }

    /**
     * Lazy self-heal used by the command paths: if no node is registered yet,
     * try once more (throttled inside `registerAll`).
     */
    manager.ensureNodes = () => registerAll();

    /**
     * Kazagumo resolves a node lazily inside `createPlayer` and then throws
     * `No node found`. Fail earlier, with a typed error, so the command paths
     * can answer with the user-friendly message and nothing ever joins voice
     * while no node is usable.
     */
    const originalCreatePlayer = manager.createPlayer.bind(manager);
    manager.createPlayer = async (options = {}) => {
        if (!availability.hasUsableNode(client)) {
            const configured = (musicConfig.getMusicConfig().nodes || [])[0];
            const endpoint = describeNode(configured).endpoint;
            if (client.logger && client.logger.log) {
                client.logger.log(
                    `[MUSIC] Refusing to create a player — no usable Lavalink node `
                    + `(registered: ${availability.describeNodes(client)}, endpoint: ${endpoint}).`,
                    'warn',
                );
            }
            throw availability.nodeUnavailableError(client);
        }
        return originalCreatePlayer(options);
    };

    manager.scheduleNodeReconnect = scheduleNodeReconnect;

    manager.searchEngines = searchEngines;
    manager.defaultSearchEngine = cfg.nodeSource;

    manager.search = async function search(query, options = {}) {
        const prefix = options.engine || this.defaultSearchEngine;

        const node = [...this.shoukaku.nodes.values()][0];
        if (!node) return { type: 'SEARCH', tracks: [] };

        const isUrl = /^https?:\/\//.test(query);
        const searchQuery = isUrl ? query : `${prefix}:${query}`;

        const res = await node.rest.resolve(searchQuery).catch(() => null);
        if (!res) return { type: 'SEARCH', tracks: [] };

        switch (res.loadType) {
            case LoadType.TRACK:
                return { type: 'TRACK', tracks: [new KazagumoTrack(res.data, options.requester)] };
            case LoadType.PLAYLIST:
                return {
                    type: 'PLAYLIST',
                    playlistName: res.data.info.name,
                    tracks: res.data.tracks.map((track) => new KazagumoTrack(track, options.requester)),
                };
            case LoadType.SEARCH:
                return { type: 'SEARCH', tracks: res.data.map((track) => new KazagumoTrack(track, options.requester)) };
            default:
                return { type: 'SEARCH', tracks: [] };
        }
    };

    client.manager = manager;
    return manager;
};
