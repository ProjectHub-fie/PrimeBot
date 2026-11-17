/**
 * Direct playback engine — the original PrimeBot pipeline.
 *
 * Audio is fetched by PrimeBot itself (youtube-sr + @distube/ytdl-core,
 * soundcloud-core, direct HTTP), decoded/transcoded by a local ffmpeg process
 * and streamed into `@discordjs/voice`. This engine is a THIN, behaviour-
 * preserving wrapper over `utils/music/musicVoice` and the provider registry:
 * every method delegates verbatim, so the direct path is byte-for-byte the same
 * as before the engine abstraction was introduced.
 *
 * It exists so `MUSIC_ENGINE=direct` (the default) keeps working exactly as it
 * did, and so the Lavalink engine can be swapped in behind the same interface.
 */

class DirectEngine {
    /**
     * @param {object} [deps]
     * @param {object} [deps.voice] the voice layer (defaults to utils/music/musicVoice)
     * @param {object} [deps.providers] the provider registry (defaults to providers/registry)
     * @param {object} [deps.filters] the filter catalog (defaults to musicFilters)
     */
    constructor(deps = {}) {
        this.name = 'direct';
        this.voice = deps.voice || require('../musicVoice');
        this.providers = deps.providers || require('../providers/registry');
        this.filters = deps.filters || require('../musicFilters');
        this.capabilities = {
            // Local ffmpeg applies real `-af` chains, so every preset works.
            filters: true,
            seek: true,
            // Spotify is metadata-only here (DRM) — matched to YouTube/SoundCloud.
            nativeSpotify: false,
            // Audio processing happens in this process (local ffmpeg).
            serverSideAudio: false,
        };
    }

    // ── connection ──────────────────────────────────────────────────────────
    isVoiceChannel(channel) { return this.voice.isVoiceChannel(channel); }
    isConnectionActive(session) { return this.voice.isConnectionActive(session.connection); }
    getConnectionState(session) { return this.voice.getConnectionState(session.connection); }

    async join({ client, session, onDisconnect }) {
        return this.voice.join({
            client,
            guildId: session.guildId,
            channelId: session.channelId,
            onDisconnect,
        });
    }

    leave(session) { this.voice.leave(session.connection, session.guildId); }

    /**
     * Tear down a connection that was established but must NOT be adopted
     * (the session was disabled/stopped while the handshake was in flight).
     * Distinct from `leave(session)` because `session.connection` is only
     * assigned once the caller adopts the result.
     */
    abortConnection(connection, guildId) {
        try { this.voice.leave(connection, guildId); } catch (_) {}
    }

    // ── player ──────────────────────────────────────────────────────────────
    createPlayer({ onError, onIdle, onStateChange }) {
        // The direct pipeline keeps the voice connection and the audio player
        // separate; the session holds both.
        return this.voice.createPlayer({ onError, onIdle, onStateChange });
    }

    /** Create the session's audio player once and subscribe it to the connection. */
    ensurePlayer(session, callbacks = {}) {
        if (session.player) return session.player;
        session.player = this.voice.createPlayer({
            onError: callbacks.onError,
            onIdle: callbacks.onIdle,
            onStateChange: callbacks.onStateChange,
        });
        try { this.voice.subscribe(session.connection, session.player); } catch (_) {}
        return session.player;
    }

    subscribe(session) {
        try { this.voice.subscribe(session.connection, session.player); } catch (_) {}
    }

    pausePlayer(session) { if (session.player) this.voice.pausePlayer(session.player); }
    resumePlayer(session) { if (session.player) this.voice.resumePlayer(session.player); }
    stopPlayer(session) { if (session.player) this.voice.stopPlayer(session.player); }
    destroyPlayer(session) {
        if (!session.player) return;
        try { this.voice.stopPlayer(session.player); } catch (_) {}
        try { this.voice.destroyPlayer(session.player); } catch (_) {}
    }

    setVolume(session, volume) { this.voice.setVolume(session.player, volume); }
    getPlaybackPosition(session) {
        if (!this.voice.getPlaybackPosition || !session.player) return 0;
        return this.voice.getPlaybackPosition(session.player);
    }

    /** Re-resolve a fresh stream URL for a track (short-lived provider URLs). */
    async resolveStream(track) { return this.providers.resolveStream(track); }

    /** Build the ffmpeg-backed audio resource (seek + real audio filters). */
    createResource(streamUrl, opts = {}) {
        return this.voice.createResource(streamUrl, {
            track: opts.track,
            seekSeconds: opts.seekSeconds || 0,
            filter: opts.filter || null,
        });
    }

    /** Start (or restart) playback of `resource` on the session's player. */
    async playResource(session, resource) {
        this.voice.playResource(session.player, resource);
        this.voice.setVolume(session.player, session.volume);
    }

    /** Apply an audio filter (local ffmpeg re-transcode on the next play). */
    async setFilter() {
        // Nothing to do on the node: the filter is baked into the resource the
        // engine builds in createResource(). The manager re-plays the track.
        return true;
    }

    /** Skip the current track. The manager drives the queue, so stopping the
     *  player is enough for the next `_playTrack` to take over. */
    async skip(session) { this.stopPlayer(session); }

    supportsFilter(id) { return this.filters.isFilter(id); }
    supportsSource() { return true; }

    /** Credential-free status for logs / the dashboard. */
    nodeStatus() {
        return {
            engine: this.name,
            audioProcessing: 'local-ffmpeg',
            capabilities: this.capabilities,
            nodes: [],
        };
    }

    async shutdown() { /* the manager destroys its own connections/players */ }
}

module.exports = { DirectEngine };
