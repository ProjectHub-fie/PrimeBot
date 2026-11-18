/**
 * Lavalink playback engine.
 *
 * Presents the same interface as the direct engine (utils/music/engines/direct)
 * so the Music engine is transport-agnostic. Audio is played by the Lavalink
 * node; PrimeBot never touches ffmpeg or the raw stream.
 *
 * Key invariants:
 *   • Player state is independent of node state. A node death does not clear
 *     the engine's queue — the engine re-creates the player on a healthy node
 *     and re-plays the current track from its last position.
 *   • The queue/track metadata the engine persists is PrimeBot's own shape; the
 *     Lavalink encoded track lives only in memory and is re-resolved after a
 *     node restart (never persisted).
 *   • Audio ALWAYS restarts after a node failover — a Lavalink node cannot hand
 *     a live stream to another node. The queue is preserved; the stream is not.
 */

const { PROVIDERS } = require('../../../shared/musicConstants');
const { LavalinkManager } = require('../lavalink/manager');
const lavalinkFilters = require('../lavalink/lavalinkFilters');
const { toTrack, trackKey } = require('../lavalink/lavalinkProviders');

/** 15-band equalizer reset (all gains 0) — used to clear filters. */
const CLEAR_FILTERS = {
    equalizer: Array.from({ length: 15 }, (_, i) => ({ band: i, gain: 0 })),
    timescale: null,
    rotation: null,
    karaoke: null,
    tremolo: null,
    vibrato: null,
    distortion: null,
    channelMix: null,
    lowPass: null,
};

class LavalinkEngine {
    constructor(client, deps = {}) {
        this.name = 'lavalink';
        this.client = client;
        this.filters = deps.filters || require('../musicFilters');
        this.providers = deps.providers || null; // set after manager.start()
        this.manager = deps.manager || LavalinkManager.getOrCreate(client, deps.managerOptions || {});
        this.capabilities = {
            filters: true,
            seek: true,
            nativeSpotify: false, // upgraded to true once a node advertises a Spotify source
            serverSideAudio: true,
        };
    }

    /** Create the player manager + connect nodes. Idempotent. */
    async start() {
        await this.manager.start();
        this.providers = this.providers || this.manager.providers;
        // Reflect the node's real source support (never claim native Spotify
        // audio unless a node actually advertises a Spotify source).
        try { this.capabilities.nativeSpotify = !!this.manager.supportsSource(PROVIDERS.SPOTIFY); } catch (_) {}
        return this;
    }

    /** The provider adapter (resolveQuery/searchQuery/resolveCollection). */
    get providerAdapter() { return this.providers || this.manager.providers; }

    // ── connection ──────────────────────────────────────────────────────────

    isVoiceChannel(channel) {
        // Mirrors @discordjs/voice: GuildVoice (2) / GuildStageVoice (13).
        return !!channel && (channel.type === 2 || channel.type === 13
            || (typeof channel.isVoiceBased === 'function' && channel.isVoiceBased()));
    }

    /**
     * Is the guild's voice connection REALLY up?
     *
     * Read from the Shoukaku Connection — never from `KazagumoPlayer.state`,
     * which Kazagumo never advances past CONNECTING (it never calls
     * `player.connect()`), so it is always false. A "connected" guild must have
     * a live connection state, a captured voice `sessionId` and a server
     * endpoint; otherwise Lavalink has nothing to send audio to.
     */
    isConnectionActive(session) {
        if (!session) return false;
        try {
            const state = this.manager.connectionState
                ? this.manager.connectionState(session.guildId)
                : null;
            if (state) return !!state.connected;
        } catch (_) {}
        // Fallback for a manager double that lacks connectionState().
        const player = this.manager.getPlayer(session.guildId);
        return !!(player && player.state === 1);
    }

    getConnectionState(session) {
        if (!session) return { connected: false, status: 'destroyed' };
        try {
            if (this.manager.connectionState) {
                const st = this.manager.connectionState(session.guildId);
                return { connected: !!st.connected, status: st.status, ping: st.ping, position: st.position };
            }
        } catch (_) {}
        const player = this.manager.getPlayer(session.guildId);
        if (!player) return { connected: false, status: 'destroyed' };
        const map = ['connecting', 'ready', 'disconnecting', 'disconnected', 'destroying', 'destroyed'];
        return { connected: player.state === 1, status: map[player.state] || 'unknown' };
    }

    /** Credential-free diagnostics for a guild (connection, ping, frame stats). */
    diagnostics(session) {
        if (!session) return null;
        try {
            if (typeof this.manager.playerDiagnostics === 'function') {
                return this.manager.playerDiagnostics(session.guildId);
            }
        } catch (_) {}
        return null;
    }

    /**
     * Create/connect the Lavalink player. `session.connection` is set to the
     * player so the rest of the engine has a stable handle; it is NOT a
     * @discordjs/voice connection.
     *
     * Voice-close recovery is NOT wired here: the manager forwards Kazagumo's
     * `playerClosed` event globally (see `_wireEvents`), and MusicManager's
     * `_wireEngineRecovery` reacts to it. Adding a second per-player `closed`
     * listener would double every recovery attempt.
     */
    async join({ session }) {
        const player = await this.manager.createPlayer({
            guildId: session.guildId,
            voiceId: session.channelId,
            textId: session.textChannelId || null,
            deaf: true,
            volume: session.volume != null ? session.volume : 100,
        });
        session.connection = player;
        session.player = player;
        return player;
    }

    leave(session) {
        const player = this.manager.getPlayer(session.guildId) || session.player;
        if (!player) return;
        try { player.disconnect(); } catch (_) {}
    }

    /**
     * Tear down a player that was created but must NOT be adopted (the session
     * was disabled/stopped while the player was being created). Distinct from
     * `leave(session)` because `session.connection` is only assigned once the
     * caller adopts the result.
     */
    abortConnection(connection, guildId) {
        if (guildId) { try { this.manager.destroyPlayer(guildId); } catch (_) {} }
        else if (connection) { try { connection.disconnect(); } catch (_) {} }
    }

    // ── player ──────────────────────────────────────────────────────────────

    createPlayer({ session }) {
        // The player is created during join(); return the live handle.
        return this.manager.getPlayer(session.guildId) || session.player || null;
    }

    /** Create/attach the session's Lavalink player (created in join()). */
    ensurePlayer(session) {
        const player = this.manager.getPlayer(session.guildId) || session.player;
        if (player) { session.player = player; session.connection = player; }
        return player;
    }

    subscribe() { /* Lavalink owns the voice subscription */ }

    pausePlayer(session) { try { const p = this._player(session); if (p) p.pause(true); } catch (_) {} }
    resumePlayer(session) { try { const p = this._player(session); if (p) p.pause(false); } catch (_) {} }
    stopPlayer(session) { try { const p = this._player(session); if (p) p.shoukaku.stopTrack(); } catch (_) {} }
    destroyPlayer(session) {
        // Go through the manager so its registry is updated too — a bare
        // `player.destroy()` would leave a stale entry in `manager.players`.
        try { this.manager.destroyPlayer(session.guildId); } catch (_) {}
        session.player = null;
        session.connection = null;
    }

    setVolume(session, volume) {
        const p = this._player(session);
        if (p) { try { p.setVolume(Math.max(0, Math.min(100, volume))); } catch (_) {} }
    }

    getPlaybackPosition(session) {
        const p = this._player(session);
        if (!p) return 0;
        try { return Number(p.shoukaku.position) || 0; } catch (_) { return 0; }
    }

    /** Lavalink streams the track itself — no separate stream URL. */
    async resolveStream(track) {
        return { streamUrl: null, durationMs: track.durationMs || null, lavalink: true };
    }

    /**
     * Play a PrimeBot track on Lavalink. Resolves the encoded track (via search
     * or the in-memory cache), applies the active filter, seeks, and starts
     * playback. Returns `true` on success.
     */
    async playTrack(session, track, { seekSeconds = 0, filter = null } = {}) {
        const player = this._player(session);
        if (!player) throw new Error('No Lavalink player for this guild.');
        const kt = await this._resolveEncoded(track);
        if (!kt) throw new Error(`Lavalink could not resolve “${track.title || track.id}”.`);
        this.manager.rememberEncoded(track, kt);
        // Apply the filter before playback so the first frames are processed.
        await this._applyFilter(player, filter).catch(() => {});
        await player.play(kt, { replaceCurrent: true });
        if (seekSeconds > 0) {
            try { await player.seek(Math.max(0, Math.floor(seekSeconds))); } catch (_) {}
        }
        return true;
    }

    /** Alias used by the engine for the direct pipeline's resource playback. */
    async playResource(session) { return true; }

    createResource() { return null; }

    async setFilter(session, filterId) {
        const player = this._player(session);
        if (!player) return false;
        await this._applyFilter(player, filterId);
        return true;
    }

    async seek(session, seconds) {
        const player = this._player(session);
        if (!player) throw new Error('No Lavalink player for this guild.');
        await player.seek(Math.max(0, Math.floor(seconds)));
        return { seeked: true, seconds };
    }

    /** Stop the current track; the engine's queue decides what plays next. */
    async skip(session) { this.stopPlayer(session); }

    supportsFilter(id) { return lavalinkFilters.supportsFilter(id); }
    supportsSource(provider) { return !!this.manager.supportsSource(provider); }

    /** Apply a Lavalink filter preset (or clear). */
    async _applyFilter(player, filterId) {
        if (!player) return;
        if (!filterId || filterId === 'clear') {
            try { await player.shoukaku.setFilters(CLEAR_FILTERS); } catch (_) {}
            return;
        }
        const settings = lavalinkFilters.lavalinkFilterFor(filterId);
        if (!settings) {
            throw new Error(`The filter “${filterId}” is not supported by the Lavalink node.`);
        }
        try { await player.shoukaku.setFilters({ ...CLEAR_FILTERS, ...settings }); } catch (_) {}
    }

    /**
     * Resolve a PrimeBot track to a KazagumoTrack the node can play.
     *
     * `KazagumoPlayer#play()` requires a real KazagumoTrack instance (it throws
     * on a plain object), so the cached path returns the exact object the search
     * produced. Only a cache miss performs a node search.
     */
    async _resolveEncoded(track) {
        const cached = this.manager.encodedFor(track);
        if (cached) return cached;
        const query = this._queryFor(track);
        const res = await this.manager.search(query, { limit: 5 });
        const kts = res.tracks || [];
        if (!kts.length) return null;
        // Prefer an exact provider:id (or identifier) match, else the first hit.
        const wantId = String(track.id || '');
        return kts.find(k => String(k.identifier) === wantId) || kts[0];
    }

    /** A Lavalink search query for a track: its URL when present, else title. */
    _queryFor(track) {
        if (track.url && /^https?:\/\//i.test(track.url)) return track.url;
        if (track.provider === PROVIDERS.SOUNDCLOUD && track.url) return track.url;
        const parts = [track.title, track.artist].filter(Boolean);
        return parts.join(' ');
    }

    _player(session) {
        return this.manager.getPlayer(session.guildId) || session.player || null;
    }

    /** Credential-free status for logs / the dashboard. */
    nodeStatus() { return this.manager.describe(); }

    async shutdown() { await this.manager.shutdown(); }
}

module.exports = { LavalinkEngine, CLEAR_FILTERS, toTrack, trackKey };
