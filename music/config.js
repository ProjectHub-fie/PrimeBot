/**
 * Linix `src/config.js` — music-relevant portion, resolved from PrimeBot env.
 *
 * Linix hardcodes the bot token, Spotify keys, Mongo URL and webhook URLs. None
 * of that is copied: every credential comes from the environment, and the
 * non-secret display values fall back to PrimeBot's own brand settings.
 *
 * Lavalink node resolution mirrors Linix's `nodes` array exactly (url / name /
 * auth / secure) and additionally accepts the `LAVALINK_*` aliases so both the
 * Linix names (`NODE_URL`, `NODE_AUTH`, `NODE_NAME`, `NODE_SECURE`) and the
 * PrimeBot names work.
 *
 * NOTE on the node name: the Lavalink node identifier is `LNODE` (a constant —
 * see DEFAULT_NODE_NAME). It is NOT derived from `NODE_NAME`, because
 * `NODE_NAME` is PrimeBot's *shard cluster* identity (`utils/nodeIdentity.js`)
 * and the audio node must never be confused with the shard clusters. Override
 * the audio label with `LAVALINK_NAME` (or an explicit `name` in
 * `LAVALINK_NODES`); everything else about the connection (host, port,
 * password, TLS) is untouched by this naming.
 */

const primeConfig = require('../config');

/**
 * The Lavalink (music) node identifier. Deliberately a constant: the shard
 * cluster identity lives in NODE_NAME/NODE_ID and must never leak into the
 * audio node label.
 */
const DEFAULT_NODE_NAME = 'LNODE';

function parseBoolean(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'boolean') return value;
    const v = String(value).trim().toLowerCase();
    return v === 'true' || v === '1' || v === 'yes' || v === 'on';
}

function intEnv(value, fallback) {
    const n = parseInt(value, 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}

/**
 * Shoukaku builds `ws(s)://<url>/v4/websocket` from the node `url` + `secure`
 * flag, so `url` must be bare `host:port`. A full `ws://`/`wss://` URL in
 * NODE_URL (or LAVALINK_NODES) is unwrapped here: the scheme decides `secure`
 * and is stripped from the host.
 */
function normalizeNode(node) {
    let url = String(node.url || '').trim();
    // Default to PLAINTEXT (secure:false), matching Shoukaku's NodeDefaults
    // and the authorized CloudWave node. The old default of `true` made an
    // unset NODE_SECURE dial wss:// against a plaintext host, which surfaced
    // as `EPROTO wrong version number` in the boot log.
    let secure = parseBoolean(node.secure, false);

    const schemeMatch = /^(ws|wss|http|https):\/\//i.exec(url);
    if (schemeMatch) {
        const scheme = schemeMatch[1].toLowerCase();
        url = url.slice(schemeMatch[0].length);
        if (scheme === 'wss' || scheme === 'https') secure = true;
        if (scheme === 'ws' || scheme === 'http') secure = false;
        // A scheme'd URL may carry a path (e.g. wss://host:443/); Shoukaku
        // appends its own /v4/websocket, so drop any path.
        url = url.split('/')[0];
    }

    return {
        url,
        name: String(node.name || DEFAULT_NODE_NAME),
        auth: String(node.auth || ''),
        secure,
    };
}

/**
 * Build the node URL from host/port env vars (Linix's `NODE_URL` / the
 * `LAVALINK_HOST` aliases). A bare host gets the `NODE_PORT` /
 * `LAVALINK_PORT` (default 2333) appended — the URL is what Shoukaku
 * connects to, so dropping the port silently routes the socket to :80.
 */
function resolveNodeUrl() {
    const host = process.env.NODE_URL || process.env.LAVALINK_HOST || '';
    if (!host) return null;
    // A full URL (with scheme) is passed through untouched.
    if (/^(ws|wss|http|https):\/\//i.test(host)) return host;
    // A bare host with an explicit port already embedded is passed through;
    // only a bare host:port-less value gets the configured port appended.
    const hasPort = /:[0-9]+$/.test(host);
    const port = process.env.NODE_PORT || process.env.LAVALINK_PORT || 2333;
    return hasPort ? host : `${host}:${port}`;
}

/** Linix `config.nodes` — the authorized Lavalink node(s). */
function resolveNodes() {
    const url = resolveNodeUrl();

    if (process.env.LAVALINK_NODES) {
        try {
            const parsed = JSON.parse(process.env.LAVALINK_NODES);
            if (Array.isArray(parsed) && parsed.length) return parsed.map(normalizeNode);
        } catch (err) {
            console.error('[MUSIC] LAVALINK_NODES is not valid JSON:', err.message);
        }
    }
    if (!url) return [];
    return [normalizeNode({
        url,
        // Lavalink node identifier: `LAVALINK_NAME` when explicitly set,
        // otherwise `LNODE`. `NODE_NAME` is intentionally NOT consulted — it
        // is the shard cluster identity, not an audio-node label.
        name: process.env.LAVALINK_NAME || DEFAULT_NODE_NAME,
        auth: process.env.NODE_AUTH || process.env.LAVALINK_PASSWORD || '',
        secure: process.env.NODE_SECURE || process.env.LAVALINK_SECURE,
    })];
}

/** Shoukaku options — Linix's values, overridable per deployment. */
function resolveNodeOptions() {
    return {
        moveOnDisconnect: parseBoolean(process.env.LAVALINK_MOVE_ON_DISCONNECT, false),
        resume: parseBoolean(process.env.LAVALINK_RESUME, false),
        resumeTimeout: intEnv(process.env.LAVALINK_RESUME_TIMEOUT, 30),
        reconnectTries: intEnv(process.env.LAVALINK_RECONNECT_TRIES, 3),
        // Shoukaku measures these in SECONDS; the env vars are the friendlier
        // millisecond / second forms documented in .env.example. Passing ms
        // straight through would make the REST timeout ~2.8 hours.
        reconnectInterval: Math.max(1, Math.round(intEnv(process.env.LAVALINK_RECONNECT_INTERVAL_MS, 5000) / 1000)),
        restTimeout: Math.max(1, Math.round(intEnv(process.env.LAVALINK_REST_TIMEOUT_MS, 10000) / 1000)),
        voiceConnectionTimeout: intEnv(process.env.LAVALINK_VOICE_TIMEOUT_S, 20),
        userAgent: process.env.LAVALINK_USER_AGENT || 'PrimeBot',
    };
}

/**
 * Display emojis. The custom emoji itself is resolved at runtime by
 * `utils/emojiManager.js` (validated against the three emoji guilds) and
 * overlaid in `music/clientBridge.js`. This function only produces the fallback
 * map: an optional `MUSIC_EMOJI_<KEY>` override, else the shared Unicode
 * fallback from `shared/emojiCatalog.js` — never a hardcoded custom id.
 */
function resolveEmoji() {
    const { EMOJI_FALLBACKS } = require('../shared/emojiCatalog');
    // One central fallback map (shared/emojiCatalog.js) — no duplicated literal
    // emoji table here. The custom emoji itself is resolved at runtime by
    // utils/emojiManager.js and overlaid in music/clientBridge.js.
    const keys = [
        'mute', 'volumemiddle', 'volumelow', 'volumehigh', 'stop', 'previous',
        'skip', 'shuffle', 'rewind', 'resume', 'remove', 'queue', 'playlist',
        'play', 'pause', 'loop', 'forward', 'filter', 'autoplay', 'addsong',
        'music', 'warn', 'join', 'leave', 'about', 'jump', 'tick', 'cross',
        'dot', 'playing', 'left', 'right', 'delete', 'replay',
    ];
    const unicodeDefaults = {};
    for (const key of keys) {
        unicodeDefaults[key] = EMOJI_FALLBACKS[key] || '';
    }
    const emoji = {};
    for (const [key, fallback] of Object.entries(unicodeDefaults)) {
        const value = process.env[`MUSIC_EMOJI_${key.toUpperCase()}`] || fallback;
        emoji[key] = String(value);
    }
    return emoji;
}

/**
 * Optional "Quick Playlists" demo catalog shown by `$playlist`. Linix embeds a
 * hardcoded Arrkiii-branded menu with fixed Spotify/YouTube links; PrimeBot
 * ships the feature free and lets each deployment configure its own playlist
 * area via env. `enabled` requires at least one configured entry.
 */
function resolvePlaylistMenu() {
    const menuLabel = process.env.MUSIC_PLAYLIST_MENU_LABEL || 'PrimeBot Quick Playlists';
    const entries = [];
    const raw = process.env.MUSIC_PLAYLISTS; // JSON array of {id,label,query}
    if (raw) {
        try {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) {
                for (const entry of parsed) {
                    if (entry && entry.id && entry.label && entry.query) {
                        entries.push({ id: String(entry.id), label: String(entry.label), query: String(entry.query) });
                    }
                }
            }
        } catch (err) {
            console.error('[MUSIC] MUSIC_PLAYLISTS is not valid JSON:', err.message);
        }
    }
    // Single-entry convenience form: MUSIC_PLAYLIST_LABEL + MUSIC_PLAYLIST_URL.
    if (!entries.length && process.env.MUSIC_PLAYLIST_URL) {
        entries.push({
            id: 'prime1',
            label: process.env.MUSIC_PLAYLIST_LABEL || 'PrimeBot Playlist',
            query: process.env.MUSIC_PLAYLIST_URL,
        });
    }
    return { enabled: entries.length > 0, label: menuLabel, entries };
}

function getMusicConfig() {
    return {
        nodes: resolveNodes(),
        nodeOptions: resolveNodeOptions(),
        nodeSource: process.env.LAVALINK_SEARCH_ENGINE || process.env.NODE_SOURCE || 'ytsearch',
        spotify: {
            clientId: process.env.SPOTIFY_CLIENT_ID || process.env.SpotifyID || '',
            clientSecret: process.env.SPOTIFY_CLIENT_SECRET || process.env.SpotifySecret || '',
            playlistPageLimit: intEnv(process.env.SPOTIFY_PLAYLIST_PAGE_LIMIT, 1),
            albumPageLimit: intEnv(process.env.SPOTIFY_ALBUM_PAGE_LIMIT, 1),
            searchLimit: intEnv(process.env.SPOTIFY_SEARCH_LIMIT, 10),
            searchMarket: process.env.SPOTIFY_SEARCH_MARKET || 'US',
        },
        emoji: resolveEmoji(),
        // Display-only values used by the vendored embeds, all env-resolvable.
        links: {
            support: process.env.MUSIC_SUPPORT_URL || primeConfig.supportServer,
            invite: process.env.BOT_INVITE_URL || primeConfig.website,
            power: process.env.MUSIC_POWERED_BY || 'PrimeBot',
            image: process.env.MUSIC_CARD_IMAGE || primeConfig.website,
            vote: process.env.BOT_VOTE_URL || primeConfig.website,
        },
        // Optional Avatar used where Linix hardcoded its bot owner's avatar.
        // Unset → the sending user's avatar is used instead (see clientBridge).
        ownerId: process.env.MUSIC_OWNER_ID || '',
        // Attachment filename for the generated now-playing card image (Linix
        // hardcoded `arrkiii.png`; the name also drives the `attachment://`
        // embed reference, so both follow this value).
        cardName: process.env.MUSIC_CARD_NAME || 'primebot-music.png',
        playlistMenu: resolvePlaylistMenu(),
        embedColor: primeConfig.colors.primary,
    };
}

module.exports = { getMusicConfig,
    resolveNodes,
    resolveNodeUrl,
    resolveNodeOptions,
    resolveEmoji,
    parseBoolean, DEFAULT_NODE_NAME };
