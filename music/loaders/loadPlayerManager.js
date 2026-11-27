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

const searchEngines = {
    DEEZER: 'dzsearch',
    SPOTIFY: 'spsearch',
    YOUTUBE: 'ytsearch',
    JIO_SAAVAN: 'jssearch',
    SOUNDCLOUD: 'scsearch',
    YOUTUBE_MUSIC: 'ytmsearch',
};

module.exports = function loadPlayerManager(client) {
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
    // Registering here is idempotent, so whichever path runs first wins and the
    // node is never added twice (two addNode calls would open two sockets).
    const connector = manager.shoukaku.connector;
    const registerNodes = connector.ready.bind(connector);
    let nodesRegistered = false;
    let lastAttempt = 0;

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
            return true;
        }
        // Never hammer addNode: two successful calls would open two sockets.
        if (!force && Date.now() - lastAttempt < 5000) return false;
        lastAttempt = Date.now();
        try {
            registerNodes(cfg.nodes);
            nodesRegistered = true;
            return true;
        } catch (err) {
            console.error('[MUSIC] Lavalink node registration failed:', err.message);
            return false;
        }
    };

    connector.ready = (nodes) => registerAll({ force: true });

    if (client.user && typeof client.isReady === 'function' && client.isReady()) {
        registerAll({ force: true });
    }
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
