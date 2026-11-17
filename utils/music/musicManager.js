/**
 * MusicManager — the on-demand music playback engine.
 *
 * Responsibilities
 *   • one authoritative player per guild (no duplicate players/streams),
 *   • a queue with add / remove / clear / shuffle / repeat / seek / volume,
 *   • continuous playback with bounded retries and safe skipping of unplayable
 *     tracks (one bad stream never stops the queue),
 *   • an admin-controlled 24/7 persistent voice connection that stays connected
 *     with an empty queue and nobody listening (no auto-disconnect timers),
 *   • voice-connection recovery that never overrides an intentional /247 disable,
 *   • shard ownership: only the node that has the guild cached drives it.
 *
 * Playback state is deliberately independent of connection state: pausing,
 * stopping, an empty queue or a finished track never disconnect the bot.
 *
 * The engine is provider-agnostic — it talks to `utils/music/providers/registry`
 * and to `utils/music/musicVoice` (both injectable for tests).
 */

const { REPEAT_MODES, PLAYBACK_STATES, formatDuration, autoplayQuery } = require('../../shared/musicConstants');
const musicFilters = require('./musicFilters');

const MAX_TRACK_RETRIES = Math.max(0, parseInt(process.env.MUSIC_MAX_TRACK_RETRIES, 10) || 2);
const RECONNECT_DELAY_MS = Math.max(1000, parseInt(process.env.MUSIC_RECONNECT_DELAY_MS, 10) || 5000);
const DEFAULT_MAX_QUEUE = Math.max(10, parseInt(process.env.MUSIC_MAX_QUEUE, 10) || 500);
const RELOAD_INTERVAL_MS = Math.max(5000, parseInt(process.env.MUSIC_RELOAD_INTERVAL_MS, 10) || 30000);
const HISTORY_LIMIT = 50;
// Autoplay: how many candidates to consider and how similar a candidate may be
// to the track that just finished before it is rejected (avoids replaying the
// same song / a re-upload of it).
const AUTOPLAY_CANDIDATES = Math.max(3, parseInt(process.env.MUSIC_AUTOPLAY_CANDIDATES, 10) || 10);
const AUTOPLAY_MAX_SIMILARITY = 0.75;

/** Strip volatile fields (stream URLs) before a track is persisted. */
function stripTrackForPersist(track) {
    if (!track) return null;
    const { streamUrl, ...rest } = track;
    return rest;
}

/** Remove duplicate track ids (same provider + id) while preserving order. */
function dedupeTracks(tracks) {
    const seen = new Set();
    const out = [];
    for (const t of tracks || []) {
        if (!t || t.id == null) continue;
        const key = `${t.provider}:${t.id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(t);
    }
    return out;
}

function normalizeTitle(s) {
    return String(s || '')
        .toLowerCase()
        .replace(/\([^)]*\)|\[[^\]]*\]/g, ' ')
        .replace(/\b(official|lyrics?|audio|video|hd|hq|mv|4k|8k|full)\b/g, ' ')
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();
}

/** Token-overlap similarity (0..1) between two titles. */
function titleSimilarity(a, b) {
    const ta = new Set(normalizeTitle(a).split(' ').filter(Boolean));
    const tb = new Set(normalizeTitle(b).split(' ').filter(Boolean));
    if (!ta.size || !tb.size) return 0;
    let overlap = 0;
    for (const t of ta) if (tb.has(t)) overlap++;
    return overlap / Math.max(ta.size, tb.size);
}

class MusicManager {
    constructor(client, deps = {}) {
        this.client = client;
        // The playback engine owns voice + audio transport. It defaults to the
        // direct pipeline (unchanged behaviour) unless MUSIC_ENGINE=lavalink.
        // Injecting `voice`/`providers` (as the tests do) always selects direct.
        const { createEngine } = require('./engines');
        const built = createEngine(client, {
            engineName: deps.engineName,
            voice: deps.voice,
            providers: deps.providers,
            filters: deps.filters,
            managerOptions: deps.managerOptions,
        });
        this.engine = deps.engine || built.engine;
        this.engineName = deps.engine ? (this.engine.name || built.name) : built.name;
        this.engineFallbackReason = built.fallbackReason || null;
        // Compatibility shims: the engine exposes the same surface the manager
        // used to get from `musicVoice` / the provider registry.
        this.voice = this.engine;
        this._providers = deps.providers || null;
        this.store = deps.store || null; // { getSettings, saveSettings, addHistory }
        this._nodeId = deps.nodeId || this._resolveNodeId();
        this.sessions = new Map(); // guildId -> session
        this._reloadHandle = null;
        this._started = false;
        this._connectGate = deps.connectGate || new (require('../voiceConnectGate').VoiceConnectGate)();
    }

    _resolveNodeId() {
        try {
            const { NODE_ID } = require('../nodeFailover');
            if (NODE_ID) return NODE_ID;
        } catch (_) {}
        return process.env.NODE_ID || process.env.NODE_NAME || 'local';
    }

    /**
     * The active provider adapter (resolveQuery / searchQuery / …).
     *
     * Resolved lazily on EVERY access: the Lavalink engine builds its adapter
     * during start(), and a caller that reaches here before start() completes
     * must still get the right adapter once it exists. The direct engine's
     * adapter is stable, so this is a cheap property read for it.
     */
    get providers() {
        if (this._providers) return this._providers;
        const adapter = this.engine.providerAdapter || this.engine.providers;
        if (adapter) return adapter;
        return require('./providers/registry');
    }

    set providers(adapter) { this._providers = adapter || null; }

    // ── lifecycle ───────────────────────────────────────────────────────────

    async start() {
        if (this._started) return;
        this._started = true;
        // Bring up the playback engine (Lavalink connects its nodes; direct is a
        // no-op). Never let an engine boot failure take the manager down — the
        // direct engine stays usable as the fallback.
        try {
            if (this.engine && typeof this.engine.start === 'function') {
                await this.engine.start();
            }
        } catch (err) {
            console.error(`[MUSIC] ${this.engineName} engine start failed:`, err.message);
        }
        // The Lavalink engine only builds its provider adapter during start(),
        // so refresh the cached reference now (the direct engine's adapter is
        // available at construction time and this is a no-op for it).
        this.providers = this.engine.providerAdapter || this.engine.providers || this.providers;
        if (this.engineName === 'lavalink') {
            this._wireEngineRecovery();
        }
        this._startReload();
    }

    _startReload() {
        if (this._reloadHandle) return;
        const timer = setInterval(() => {
            this._reload().catch(err => console.error('[MUSIC] reload failed:', err.message));
        }, RELOAD_INTERVAL_MS);
        timer.unref?.();
        this._reloadHandle = { stop: () => clearInterval(timer) };
    }

    /** Re-read persisted settings so dashboard edits apply without a restart. */
    async _reload() {
        if (!this.store) return;
        let rows = [];
        try { rows = await this.store.listEnabledSettings(); } catch (_) { return; }
        for (const row of rows) {
            const existing = this.sessions.get(String(row.guildId));
            if (existing) {
                // Adopt channel / DJ / 24/7 changes without disturbing playback.
                existing.djRoleId = row.djRoleId || null;
                existing.maxQueue = row.maxQueue || DEFAULT_MAX_QUEUE;
                if (row.twentyFourSevenChannelId && row.twentyFourSevenChannelId !== existing.channelId && row.twentyFourSevenEnabled) {
                    await this.set247Channel(existing.guildId, row.twentyFourSevenChannelId, { actor: 'reload' }).catch(() => {});
                }
                continue;
            }
            if (row.twentyFourSevenEnabled && row.twentyFourSevenChannelId && !row.disabledIntentionally) {
                // A 24/7 session we do not hold yet (e.g. enabled from another node
                // or the dashboard) — bring it up if this node owns the guild.
                await this.restoreOne(row).catch(err => console.error(`[MUSIC] restore ${row.guildId} failed:`, err.message));
            }
        }
    }

    // ── session helpers ─────────────────────────────────────────────────────

    ownsGuild(guildId) {
        try {
            return !!(this.client.guilds && this.client.guilds.cache && this.client.guilds.cache.has(guildId));
        } catch (_) { return false; }
    }

    getSession(guildId) { return this.sessions.get(String(guildId)) || null; }

    _newSession(guildId, channelId, settings = {}) {
        return {
            guildId: String(guildId),
            channelId: channelId || null,
            // Lavalink needs a text channel id for the player; the engine ignores
            // it on the direct path.
            textChannelId: settings.textChannelId || null,
            connection: null,
            player: null,
            queue: [],            // upcoming tracks (does NOT include current)
            history: [],          // previous tracks (for /previous)
            current: null,
            positionIndex: 0,
            repeat: REPEAT_MODES.OFF,
            shuffle: false,
            volume: settings.defaultVolume != null ? settings.defaultVolume : 100,
            djRoleId: settings.djRoleId || null,
            maxQueue: settings.maxQueue || DEFAULT_MAX_QUEUE,
            twentyFourSeven: !!settings.twentyFourSevenEnabled,
            disabledIntentionally: !!settings.disabledIntentionally,
            state: PLAYBACK_STATES.IDLE,
            manualPause: false,
            retries: 0,
            failedTracks: new Set(),
            _advancing: false,
            _playToken: 0,
            reconnecting: false,
            ownerNode: this._nodeId,
            _seekSeconds: 0,
            // ── Linix-style additions ───────────────────────────────────────
            filter: null,          // active filter id (null = none)
            autoplay: false,       // keep the music going when the queue empties
            autoplaySeed: null,    // the track autoplay expands from
            autoplaySeen: new Set(), // provider:id keys autoplay already queued
            positionMs: 0,         // playback position (from the voice player)
            startedAt: null,       // wall-clock when the current track started
        };
    }

    /**
     * Ensure a session exists for a guild and is owned by this node. A session
     * already owned by ANOTHER live node is never stolen.
     */
    _ensureSession(guildId, channelId, settings = {}) {
        let session = this.sessions.get(String(guildId));
        if (session) return session;
        if (!this.ownsGuild(guildId)) return null;
        session = this._newSession(guildId, channelId, settings);
        this.sessions.set(String(guildId), session);
        return session;
    }

    countListeners(session) {
        try {
            const guild = this.client.guilds.cache.get(session.guildId);
            if (!guild) return 0;
            if (guild.voiceStates && guild.voiceStates.cache) {
                let humans = 0;
                for (const state of guild.voiceStates.cache.values()) {
                    if (state.channelId !== session.channelId) continue;
                    const member = state.member;
                    if (member && member.user && member.user.bot) continue;
                    humans++;
                }
                return humans;
            }
            const channel = guild.channels.cache.get(session.channelId);
            if (!channel || !channel.members) return 0;
            return channel.members.filter(m => !m.user.bot).size;
        } catch (_) { return 0; }
    }

    /** Snapshot for commands / dashboard / status. */
    describe(guildId, { queueLimit = 25 } = {}) {
        const s = this.sessions.get(String(guildId));
        if (!s) return null;
        const voiceState = this.voice.getConnectionState(s);
        const positionMs = this.positionMs(s);
        return {
            guildId: s.guildId,
            channelId: s.channelId,
            connected: voiceState.connected,
            connectionStatus: voiceState.status,
            state: s.state,
            current: s.current,
            queueLength: s.queue.length,
            queue: s.queue.slice(0, Math.max(1, queueLimit)),
            history: s.history.slice(0, 25),
            repeat: s.repeat,
            shuffle: s.shuffle,
            volume: s.volume,
            manualPause: s.manualPause,
            twentyFourSeven: s.twentyFourSeven,
            listeners: this.countListeners(s),
            ownerNode: s.ownerNode,
            ownsHere: s.ownerNode === this._nodeId,
            djRoleId: s.djRoleId,
            filter: s.filter,
            autoplay: s.autoplay,
            positionMs,
            durationMs: s.current ? s.current.durationMs || null : null,
        };
    }

    /**
     * The current track's playback position in ms. Prefers the live voice player
     * position (exact); otherwise the seek baseline plus wall-clock elapsed since
     * playback started.
     */
    positionMs(session) {
        try {
            if (this.voice.getPlaybackPosition && session.player) {
                const p = this.voice.getPlaybackPosition(session);
                if (Number.isFinite(p) && p > 0) return p;
            }
        } catch (_) {}
        const base = session.positionMs || 0;
        if (session.startedAt && session.state === PLAYBACK_STATES.PLAYING) {
            return base + Math.max(0, Date.now() - session.startedAt);
        }
        return base;
    }

    // ── connection ──────────────────────────────────────────────────────────

    async _connect(session) {
        if (this.voice.isConnectionActive(session)) return session.connection;
        // Single-flight: two commands arriving close together (/join then
        // /247 enable, a repeated 247 enable, or /play mid-handshake) must share
        // ONE handshake. A second join() destroys the first in-flight
        // connection, and the first handshake's entersState(Ready) then rejects
        // with "The operation was aborted" even though nothing was wrong.
        return this._connectGate.run(session.guildId, async ({ id, reused }) => {
            // Re-check inside the gate — an attempt may have just completed.
            if (this.voice.isConnectionActive(session)) return session.connection;
            const before = this.voice.getConnectionState(session);
            const connection = await this.voice.join({
                client: this.client,
                session,
                onDisconnect: () => this._onConnectionLost(session),
            });
            // Stale-operation guard: if 24/7 was disabled (or the session torn
            // down) while the handshake was in flight, do NOT adopt the new
            // connection — otherwise /247 disable during a slow connect leaves
            // the bot connected to a session it just deleted.
            if (session.disabledIntentionally) {
                try {
                    if (typeof this.voice.abortConnection === 'function') {
                        this.voice.abortConnection(connection, session.guildId);
                    } else {
                        this.voice.leave(session);
                    }
                } catch (_) {}
                throw new Error('24/7 was disabled while the connection was being established.');
            }
            session.connection = connection;
            console.log(`[MUSIC] voice connect ${reused ? '(shared attempt)' : `#${id}`} engine=${this.engineName} node=${this._nodeId} guild=${session.guildId} channel=${session.channelId} ${before.status} -> ${this.voice.getConnectionState(session).status}`);
            return connection;
        });
    }

    async _ensureConnected(session) {
        if (!session.channelId) throw new Error('No voice channel is configured.');
        await this._connect(session);
        this._ensurePlayer(session);
        return session.connection;
    }

    _ensurePlayer(session) {
        if (session.player) return session.player;
        session.player = this.voice.ensurePlayer
            ? this.voice.ensurePlayer(session, {
                onError: (err) => this._onStreamError(session, err),
                onIdle: () => this._onPlayerIdle(session),
                onStateChange: (oldState, newState) => this._onPlayerStateChange(session, oldState, newState),
            })
            : this.voice.createPlayer({
                onError: (err) => this._onStreamError(session, err),
                onIdle: () => this._onPlayerIdle(session),
                onStateChange: (oldState, newState) => this._onPlayerStateChange(session, oldState, newState),
            });
        if (session.player && !this.voice.ensurePlayer) {
            try { this.voice.subscribe(session); } catch (_) {}
        }
        return session.player;
    }

    _destroyPlayer(session) {
        if (!session.player) return;
        try { this.voice.destroyPlayer(session); } catch (_) {}
        session.player = null;
        session.connection = null;
    }

    _pausePlayer(session) {
        try { this.voice.pausePlayer(session); } catch (_) {}
    }

    // ── queue + playback ────────────────────────────────────────────────────

    /**
     * Enqueue one or more resolved tracks. Returns the number actually queued.
     */
    enqueue(session, tracks, { requesterId = null, at = null } = {}) {
        const list = (Array.isArray(tracks) ? tracks : [tracks]).filter(Boolean).map(t => ({
            ...stripTrackForPersist(t),
            requesterId: requesterId || t.requesterId || null,
            _key: `${t.provider}:${t.id}`,
        }));
        const room = session.maxQueue - session.queue.length - (session.current ? 1 : 0);
        const accepted = list.slice(0, Math.max(0, room));
        if (at != null && at >= 0 && at <= session.queue.length) session.queue.splice(at, 0, ...accepted);
        else session.queue.push(...accepted);
        return accepted.length;
    }

    /**
     * Play the given track immediately (or the queue head if omitted).
     *
     * The direct engine resolves a FRESH stream URL (short-lived provider URLs)
     * and feeds ffmpeg; the Lavalink engine asks the node to play the encoded
     * track. Both paths apply bounded retries and the active audio filter.
     */
    async _playTrack(session, track) {
        const token = ++session._playToken;
        session.trackEndHandled = false;
        const seekSeconds = session._seekSeconds || 0;
        session._seekSeconds = 0;
        // Set `current` BEFORE resolving so error handling (and the queue walk)
        // always knows which track is in flight.
        session.current = track;
        try {
            if (this.engineName === 'lavalink') {
                // Resolve/connect the Lavalink player, then hand it the track.
                await this._ensureConnected(session);
                await this.engine.playTrack(session, track, { seekSeconds, filter: session.filter });
            } else {
                const { streamUrl, durationMs } = await this.providers.resolveStream(track);
                if (token !== session._playToken) return false; // superseded by a newer play
                if (durationMs && !track.durationMs) track.durationMs = durationMs;
                const resource = this.voice.createResource(streamUrl, { track, seekSeconds, filter: session.filter });
                await this._ensureConnected(session);
                this._ensurePlayer(session);
                this.voice.playResource(session, resource);
                this.voice.setVolume(session, session.volume);
            }
            session.state = PLAYBACK_STATES.PLAYING;
            session.manualPause = false;
            session.retries = 0;
            session.startedAt = Date.now();
            session.positionMs = seekSeconds * 1000;
            session.failedTracks.delete(track._key || `${track.provider}:${track.id}`);
            await this._recordHistory(session, track);
            return true;
        } catch (err) {
            console.error(`[MUSIC] Failed to play ${track && track.provider}:${track && track.id}:`, err.message);
            await this._onStreamError(session, err);
            return false;
        }
    }

    /**
     * Start (or continue) playback from the queue head.
     *
     * Walks past unplayable tracks in a single pass so ONE bad stream can never
     * stall the queue: each candidate is attempted, and on failure it is added
     * to `failedTracks` and skipped. The `_advancing` guard prevents the async
     * player 'error'/'idle' paths from re-entering mid-walk.
     */
    async _playNext(session, { fromHistory = false } = {}) {
        if (session._advancing) return;
        session._advancing = true;
        try {
            if (session.manualPause) { session.state = PLAYBACK_STATES.PAUSED; return; }

            // Repeat-track: replay the current track.
            if (session.repeat === REPEAT_MODES.TRACK && session.current && !fromHistory) {
                return void await this._playTrack(session, session.current);
            }

            if (!session.queue.length) {
                // Autoplay: the queue ran dry — expand from the last track
                // (if enabled) BEFORE going idle. Never overrides repeat-queue.
                if (session.autoplay && session.repeat === REPEAT_MODES.OFF && session.current) {
                    const added = await this._expandAutoplay(session).catch(() => 0);
                    if (added > 0) {
                        // fall through to the play loop below with the new queue
                    }
                }
            }

            if (!session.queue.length) {
                // Empty queue → keep the connection, go idle (never disconnect).
                if (session.repeat === REPEAT_MODES.QUEUE && session.current) {
                    session.queue.push(session.current);
                } else {
                    session.current = null;
                    session.state = PLAYBACK_STATES.IDLE;
                    session.startedAt = null;
                    this._stopPlayerSoft(session);
                    return;
                }
            }

            if (session.current && !fromHistory) {
                session.history.push(stripTrackForPersist(session.current));
                if (session.history.length > HISTORY_LIMIT) session.history.shift();
            }

            let played = null;
            let guard = 0;
            while (session.queue.length && guard++ <= session.maxQueue) {
                const candidate = session.queue.shift();
                const key = candidate._key || `${candidate.provider}:${candidate.id}`;
                if (session.failedTracks.has(key)) continue; // already known-bad this pass
                const ok = await this._playTrack(session, candidate);
                if (ok) { played = candidate; break; }
                // _playTrack failed and already added it to failedTracks; continue.
            }

            if (!played) {
                session.current = null;
                session.state = PLAYBACK_STATES.IDLE;
                this._stopPlayerSoft(session);
                return;
            }

            // Repeat-queue: push the just-played track to the back.
            if (session.repeat === REPEAT_MODES.QUEUE && session.current) {
                const key = session.current._key || `${session.current.provider}:${session.current.id}`;
                if (!session.queue.some(t => (t._key || `${t.provider}:${t.id}`) === key)) {
                    session.queue.push(session.current);
                }
            }
        } finally {
            session._advancing = false;
        }
    }

    _stopPlayerSoft(session) {
        // Stop the audio but KEEP the voice connection alive (24/7 requirement).
        if (session.player) { try { this.voice.stopPlayer(session); } catch (_) {} }
    }

    async _onStreamError(session, err) {
        const track = session.current;
        // Called from inside the _playNext walk — the walk handles the retry/skip,
        // so never re-enter (that re-entrancy was stalling the queue).
        if (session._advancing) {
            if (track) session.failedTracks.add(track._key || `${track.provider}:${track.id}`);
            return;
        }
        session.retries = (session.retries || 0) + 1;
        if (track && session.retries <= MAX_TRACK_RETRIES) {
            // A stale stream URL is the common cause — re-resolving fixes it.
            const again = await this._playTrack(session, track);
            if (again) return;
        }
        if (track) session.failedTracks.add(track._key || `${track.provider}:${track.id}`);
        session.retries = 0;
        session.current = null;
        // Advance to the next playable track (bounded — failed set shrinks).
        await this._playNext(session);
    }

    _onPlayerIdle(session) {
        // The track finished (or the stream ended). Route through the single
        // advance path so a duplicate idle cannot double-advance.
        if (session.trackEndHandled) return;
        session.trackEndHandled = true;
        this._playNext(session).catch(err => console.error('[MUSIC] advance failed:', err.message));
    }

    _onPlayerStateChange(session, oldState, newState) {
        if (newState === 'playing') {
            session.state = PLAYBACK_STATES.PLAYING;
            if (!session.startedAt) session.startedAt = Date.now();
        }
    }

    /**
     * Expand autoplay: search for a track related to the current one and queue
     * it. Returns the number of tracks added (0 when nothing suitable was found
     * or the provider failed). Bounded and deduped so it can never loop.
     */
    async _expandAutoplay(session) {
        const seed = session.current || session.autoplaySeed;
        if (!seed) return 0;
        const query = autoplayQuery(seed);
        if (!query) return 0;
        let candidates = [];
        try {
            if (typeof this.providers.searchQuery === 'function') {
                candidates = await this.providers.searchQuery(query, AUTOPLAY_CANDIDATES);
            } else {
                const one = await this.providers.resolveQuery(query, { searchLimit: AUTOPLAY_CANDIDATES });
                candidates = one ? [one] : [];
            }
        } catch (_) { return 0; }

        const seedKey = seed._key || `${seed.provider}:${seed.id}`;
        const next = (candidates || []).find(c => {
            if (!c || c.id == null) return false;
            const key = `${c.provider}:${c.id}`;
            if (key === seedKey) return false;
            if (session.autoplaySeen.has(key)) return false;
            if (session.failedTracks.has(key)) return false;
            // Reject the same song / an obvious re-upload.
            if (titleSimilarity(c.title, seed.title) >= AUTOPLAY_MAX_SIMILARITY) return false;
            return true;
        });
        if (!next) return 0;
        session.autoplaySeen.add(`${next.provider}:${next.id}`);
        const added = this.enqueue(session, [{ ...next, requesterId: null }], { requesterId: null });
        return added;
    }

    _onConnectionLost(session) {
        // Only auto-recover a 24/7 connection, and never after an intentional
        // disable or /leave (disabledIntentionally guards that).
        if (!session.twentyFourSeven || session.disabledIntentionally) return;
        if (session.reconnecting) return;
        session.reconnecting = true;
        setTimeout(async () => {
            try {
                if (!session.twentyFourSeven || session.disabledIntentionally) { session.reconnecting = false; return; }
                // The player is gone (voice closed / node died). Drop the stale
                // handles so _connect re-creates them, then resume the current
                // track. Queue + track metadata are untouched — only the audio
                // stream restarts.
                session.connection = null;
                session.player = null;
                if (this.engineName === 'lavalink' && this.engine.manager) {
                    try { await this.engine.manager.destroyPlayer(session.guildId); } catch (_) {}
                }
                await this._connect(session);
                session.reconnecting = false;
                if (session.current && !session.manualPause) await this._playTrack(session, session.current);
            } catch (err) {
                session.reconnecting = false;
                console.error('[MUSIC] Reconnect failed:', err.message);
            }
        }, RECONNECT_DELAY_MS).unref?.();
    }

    /**
     * Bridge Lavalink node/player lifecycle into the manager.
     *
     * Node death is treated as a transport failure, never as a queue loss:
     *   • the queue + current track are preserved in the session,
     *   • the player is re-created on a healthy node,
     *   • the current track restarts (a Lavalink node cannot hand a live stream
     *     to another node — we never claim otherwise),
     *   • `playerException` / `playerStuck` / `playerClosed` are routed through
     *     the SAME bounded-retry path the direct engine uses.
     */
    _wireEngineRecovery() {
        const mgr = this.engine.manager;
        if (!mgr || typeof mgr.onPlayer !== 'function') return;

        mgr.onNode('ready', () => {
            console.log(`[MUSIC] Lavalink node ready — ${mgr.health.healthyNames().length} healthy node(s).`);
        });
        mgr.onNode('close', (name) => {
            console.warn(`[MUSIC] Lavalink node "${name}" closed — queues are preserved; playback will resume on a healthy node.`);
        });
        // A node died and took its players with it. The manager only knows voice
        // / text ids; WE hold the queue + current track, so recovery is ours:
        // re-create the player on a healthy node and restart the current track
        // from its last position. Audio always restarts (a Lavalink node cannot
        // hand a live stream to another node) — the queue is never lost.
        mgr.onNode('playersLost', (name, guildIds) => {
            for (const guildId of guildIds || []) {
                const session = this.sessions.get(String(guildId));
                if (!session) continue;
                this._recoverLavalinkSession(session, name).catch(err =>
                    console.error(`[MUSIC] Lavalink recovery for ${guildId} failed:`, err.message));
            }
        });

        mgr.onPlayer('exception', (player, data) => {
            const session = this.sessions.get(String(player.guildId));
            if (!session) return;
            const msg = data && data.exception ? data.exception.message : 'unknown';
            this._onStreamError(session, new Error(`Lavalink exception: ${msg}`));
        });
        mgr.onPlayer('stuck', (player, data) => {
            const session = this.sessions.get(String(player.guildId));
            if (!session) return;
            this._onStreamError(session, new Error(`Lavalink track stuck (${data && data.thresholdMs}ms)`));
        });
        mgr.onPlayer('closed', (player, data) => {
            const session = this.sessions.get(String(player.guildId));
            if (!session) return;
            // The voice websocket closed — reconnect and resume (24/7 aware).
            this._onConnectionLost(session);
        });
        mgr.onPlayer('end', (player) => {
            const session = this.sessions.get(String(player.guildId));
            if (!session) return;
            if (session.trackEndHandled) return;
            session.trackEndHandled = true;
            this._playNext(session).catch(err => console.error('[MUSIC] advance after Lavalink end failed:', err.message));
        });
        mgr.onPlayer('empty', (player) => {
            const session = this.sessions.get(String(player.guildId));
            if (!session) return;
            // Kazagumo emits `empty` synchronously right after `end`, before our
            // async advance has re-filled the player. Only go idle when OUR queue
            // is also empty and nothing is in flight — otherwise the advance we
            // just kicked off would be reported as idle.
            if (session._advancing) return;
            if (session.queue.length && !session.manualPause) return;
            if (session.current && session.state === PLAYBACK_STATES.PLAYING) return;
            session.state = PLAYBACK_STATES.IDLE;
        });
        mgr.onPlayer('resolveError', (player, track, message) => {
            const session = this.sessions.get(String(player.guildId));
            if (!session) return;
            console.warn(`[MUSIC] Lavalink resolve error in ${player.guildId}: ${message}`);
        });
    }

    /**
     * Recover a session whose Lavalink node died.
     *
     * The queue, history and current track live on the SESSION, so they survive
     * the node loss untouched. Only the transport is rebuilt: the dead player is
     * dropped, a fresh player is created on a healthy node (the manager's
     * `_recoverPlayer` picks one), and the current track restarts from the last
     * known position. Audio always restarts — a Lavalink node cannot migrate a
     * live stream — and the position is approximated from the engine's last
     * reading, so we never claim a seamless migration.
     */
    async _recoverLavalinkSession(session, nodeName) {
        if (session.disabledIntentionally) return;
        if (session.reconnecting) return;
        session.reconnecting = true;
        const resumeAt = this.positionMs(session) / 1000;
        try {
            // Drop the dead transport handles; the queue is NOT touched.
            session.connection = null;
            session.player = null;
            if (session.twentyFourSeven || session.current) {
                console.warn(`[MUSIC] Recovering guild ${session.guildId} after Lavalink node "${nodeName}" died — restarting “${session.current ? session.current.title : 'idle session'}”${session.twentyFourSeven ? ' (24/7)' : ''}.`);
            }
            await this.engine.manager._recoverPlayer(session.guildId, {
                voiceId: session.channelId,
                textId: session.textChannelId,
            });
            session.player = this.engine.manager.getPlayer(session.guildId) || null;
            session.connection = session.player;
            if (session.current && !session.manualPause) {
                session._seekSeconds = Math.max(0, Math.floor(resumeAt));
                await this._playTrack(session, session.current);
            } else if (session.twentyFourSeven) {
                session.state = PLAYBACK_STATES.IDLE;
            }
        } finally {
            session.reconnecting = false;
        }
    }

    /** Credential-free engine/node status for the dashboard + logs. */
    engineStatus() {
        const status = {
            engine: this.engineName,
            fallbackReason: this.engineFallbackReason,
            capabilities: this.engine.capabilities || {},
        };
        try {
            if (typeof this.engine.nodeStatus === 'function') status.nodes = this.engine.nodeStatus();
        } catch (_) {}
        return status;
    }

    // ── public playback API ─────────────────────────────────────────────────

    /** Resolve a query and start playing it (immediately, if idle). */
    async play(guildId, query, { channelId = null, textChannelId = null, requesterId = null, settings = {} } = {}) {
        const session = this._ensureSession(guildId, channelId, settings);
        if (!session) throw Object.assign(new Error('This node does not own that guild.'), { status: 409 });
        if (channelId) session.channelId = channelId;
        // Lavalink players carry a text channel id; the direct engine ignores it.
        if (textChannelId) session.textChannelId = textChannelId;
        await this._ensureConnected(session);

        const track = await this.providers.resolveQuery(query, { searchLimit: 1 });
        track.requesterId = requesterId || null;

        if (session.state === PLAYBACK_STATES.PLAYING && session.current) {
            this.enqueue(session, [track], { requesterId });
            return { queued: true, track, session: this.describe(guildId) };
        }
        session.queue.push({ ...track, _key: `${track.provider}:${track.id}` });
        await this._playNext(session);
        return { queued: false, track, session: this.describe(guildId) };
    }

    /** Queue a track without interrupting current playback. */
    async addToQueue(guildId, query, { channelId = null, requesterId = null, settings = {}, collectionLimit = 50 } = {}) {
        const session = this._ensureSession(guildId, channelId, settings);
        if (!session) throw Object.assign(new Error('This node does not own that guild.'), { status: 409 });
        if (channelId) session.channelId = channelId;
        await this._ensureConnected(session);

        let tracks;
        if (/^https?:\/\//i.test(query) && (/[?&]list=/.test(query) || /\/sets\//.test(query) || /spotify\.com/.test(query))) {
            const col = await this.providers.resolveCollection(query, collectionLimit);
            tracks = col.tracks;
            if (!tracks.length) throw new Error(col.limitation || 'That collection has no playable tracks.');
        } else {
            tracks = [await this.providers.resolveQuery(query, { searchLimit: 1 })];
        }
        const added = this.enqueue(session, tracks, { requesterId });
        if (session.state === PLAYBACK_STATES.IDLE && session.queue.length) await this._playNext(session);
        return { added, tracks, session: this.describe(guildId) };
    }

    async pause(guildId, { actor = null } = {}) {
        const s = this.getSession(guildId);
        if (!s || !s.current) throw new Error('Nothing is playing.');
        // Freeze the progress baseline so the bar stops advancing while paused.
        s.positionMs = this.positionMs(s);
        s.startedAt = null;
        s.manualPause = true;
        this._pausePlayer(s);
        s.state = PLAYBACK_STATES.PAUSED;
        return this.describe(guildId);
    }

    async resume(guildId) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('Nothing is playing.');
        s.manualPause = false;
        if (s.current) {
            this.voice.resumePlayer(s);
            s.startedAt = Date.now();
            s.state = PLAYBACK_STATES.PLAYING;
        } else await this._playNext(s);
        return this.describe(guildId);
    }

    async skip(guildId, { actor = null, count = 1 } = {}) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('Nothing is playing.');
        for (let i = 0; i < Math.max(1, count); i++) {
            if (s.queue.length) s.queue.shift();
        }
        if (s.current) { s.history.push(stripTrackForPersist(s.current)); if (s.history.length > HISTORY_LIMIT) s.history.shift(); }
        s.current = null;
        this._stopPlayerSoft(s);
        await this._playNext(s);
        return this.describe(guildId);
    }

    async previous(guildId) {
        const s = this.getSession(guildId);
        if (!s || !s.history.length) throw new Error('There is no previous track.');
        const prev = s.history.pop();
        if (s.current) s.queue.unshift({ ...stripTrackForPersist(s.current), _key: `${s.current.provider}:${s.current.id}` });
        s.current = null;
        this._stopPlayerSoft(s);
        await this._playNext(s);
        return { track: prev, session: this.describe(guildId) };
    }

    async stop(guildId, { actor = null, clearQueue = true } = {}) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('Nothing is playing.');
        this._stopPlayerSoft(s);
        s.current = null;
        s.manualPause = false;
        s.startedAt = null;
        s.positionMs = 0;
        if (clearQueue) { s.queue = []; s.history = []; s.autoplaySeen = new Set(); }
        s.state = PLAYBACK_STATES.STOPPED;
        // Stop playback but KEEP the connection (24/7). The connection is only
        // destroyed by /247 disable or /leave.
        return this.describe(guildId);
    }

    async clear(guildId) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('There is no queue.');
        const removed = s.queue.length;
        s.queue = [];
        return { removed, session: this.describe(guildId) };
    }

    async remove(guildId, position) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('There is no queue.');
        const idx = Number(position) - 1;
        if (!Number.isInteger(idx) || idx < 0 || idx >= s.queue.length) throw new Error(`Position ${position} is out of range (queue has ${s.queue.length}).`);
        const [removed] = s.queue.splice(idx, 1);
        return { removed, session: this.describe(guildId) };
    }

    async shuffle(guildId) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('There is no queue.');
        for (let i = s.queue.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [s.queue[i], s.queue[j]] = [s.queue[j], s.queue[i]];
        }
        s.shuffle = true;
        return this.describe(guildId);
    }

    async setRepeat(guildId, mode) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('There is no active session.');
        const normalized = String(mode || '').toLowerCase();
        if (!Object.values(REPEAT_MODES).includes(normalized)) throw new Error('Repeat mode must be off, track or queue.');
        s.repeat = normalized;
        return this.describe(guildId);
    }

    async setVolume(guildId, volume) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('There is no active session.');
        const v = Math.max(1, Math.min(100, Math.round(Number(volume))));
        if (!Number.isFinite(v)) throw new Error('Volume must be a number between 1 and 100.');
        s.volume = v;
        this.voice.setVolume(s, v);
        return this.describe(guildId);
    }

    async seek(guildId, seconds) {
        const s = this.getSession(guildId);
        if (!s || !s.current) throw new Error('Nothing is playing to seek.');
        const sec = Math.max(0, Math.floor(Number(seconds)));
        if (!Number.isFinite(sec)) throw new Error('Provide a valid timestamp.');
        if (s.current.durationMs && sec * 1000 > s.current.durationMs) throw new Error('That timestamp is past the end of the track.');
        s._seekSeconds = sec;
        await this._playTrack(s, s.current);
        return this.describe(guildId);
    }

    /** Rewind by `seconds` from the current position (never below 0). */
    async rewind(guildId, seconds = 10) {
        const s = this.getSession(guildId);
        if (!s || !s.current) throw new Error('Nothing is playing to rewind.');
        const back = Math.max(1, Math.floor(Number(seconds) || 10));
        const target = Math.max(0, Math.floor(this.positionMs(s) / 1000) - back);
        return this.seek(guildId, target);
    }

    /**
     * Skip directly to the queue position `position` (1-based, 1 = the next
     * track). Everything before it is discarded. Returns the new snapshot.
     */
    async skipTo(guildId, position) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('Nothing is playing.');
        const pos = Math.floor(Number(position));
        if (!Number.isFinite(pos) || pos < 1 || pos > s.queue.length) {
            throw new Error(`Position must be between 1 and ${s.queue.length}.`);
        }
        // Drop every track before the requested one.
        s.queue.splice(0, pos - 1);
        if (s.current) { s.history.push(stripTrackForPersist(s.current)); if (s.history.length > HISTORY_LIMIT) s.history.shift(); }
        s.current = null;
        s.startedAt = null;
        s.positionMs = 0;
        this._stopPlayerSoft(s);
        await this._playNext(s);
        return this.describe(guildId);
    }

    /** Apply an audio filter preset (or clear it with null/'clear'). */
    async setFilter(guildId, filter) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('There is no active session.');
        const id = filter == null ? '' : String(filter).toLowerCase().trim();
        if (id === '' || id === 'clear' || id === 'none' || id === 'off') {
            s.filter = null;
        } else if (musicFilters.isFilter(id)) {
            s.filter = id;
        } else {
            throw new Error(`Unknown filter "${filter}".`);
        }
        // Re-apply to the live track so the change is audible immediately.
        if (s.current && s.state !== PLAYBACK_STATES.IDLE) {
            s._seekSeconds = Math.floor(this.positionMs(s) / 1000);
            await this._playTrack(s, s.current);
        }
        return this.describe(guildId);
    }

    /** Enable/disable autoplay (continues music when the queue empties). */
    async setAutoplay(guildId, enabled) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('There is no active session.');
        s.autoplay = !!enabled;
        if (s.autoplay && s.current) s.autoplaySeed = s.current;
        if (!s.autoplay) s.autoplaySeen = new Set();
        return this.describe(guildId);
    }

    // ── 24/7 persistent connection ──────────────────────────────────────────

    /** Enable 24/7 and connect to `channelId` (admin action). */
    async enable247(guildId, channelId, { settings = {} } = {}) {
        if (!channelId) throw new Error('A voice channel is required.');
        const guild = this.client.guilds.cache.get(guildId);
        const channel = guild && guild.channels.cache.get(channelId);
        if (!channel || !this.voice.isVoiceChannel(channel)) throw new Error('That is not a valid voice channel in this server.');

        const session = this._ensureSession(guildId, channelId, settings);
        if (!session) throw Object.assign(new Error('This node does not own that guild.'), { status: 409 });

        // Idempotent: a repeated `247 enable` for the channel we are already
        // connected to (or connecting to) must NOT rejoin. Re-joining would
        // destroy the in-flight/healthy connection and is the exact race that
        // produced "The operation was aborted" when enable was issued twice.
        const sameChannel = session.channelId === channelId;
        const alreadyLive = this.voice.isConnectionActive(session)
            || this._connectGate.isPending(session.guildId);
        session.channelId = channelId;
        session.twentyFourSeven = true;
        session.disabledIntentionally = false;
        session.ownerNode = this._nodeId;
        if (!(sameChannel && alreadyLive)) await this._ensureConnected(session);
        await this._persist(session, { twentyFourSevenEnabled: true, channelId, disabledIntentionally: false });
        return this.describe(guildId);
    }

    /** Disable 24/7 and intentionally disconnect (admin action). */
    async disable247(guildId) {
        const session = this.getSession(guildId);
        if (session) {
            session.twentyFourSeven = false;
            session.disabledIntentionally = true;
            await this._persist(session, { twentyFourSevenEnabled: false, disabledIntentionally: true });
            this._destroyPlayer(session);
            // session.connection may still be null if a connect was in flight —
            // sweep the registry so a half-open handshake is destroyed too.
            try { this.voice.leave(session); } catch (_) {}
            this.sessions.delete(String(guildId));
        } else {
            // Persist the disable even if this node never held the session.
            await this._persistSettings(guildId, { twentyFourSevenEnabled: false, disabledIntentionally: true });
        }
        return { guildId: String(guildId), enabled: false };
    }

    /** Change the configured 24/7 voice channel, moving the live connection. */
    async set247Channel(guildId, channelId, { settings = {} } = {}) {
        const guild = this.client.guilds.cache.get(guildId);
        const channel = guild && guild.channels.cache.get(channelId);
        if (!channel || !this.voice.isVoiceChannel(channel)) throw new Error('That is not a valid voice channel in this server.');
        const session = this.getSession(guildId);
        if (session && session.twentyFourSeven) {
            try { this.voice.leave(session); } catch (_) {}
            session.connection = null;
            session.channelId = channelId;
            await this._ensureConnected(session);
            await this._persist(session, { channelId });
            return this.describe(guildId);
        }
        await this._persistSettings(guildId, { twentyFourSevenChannelId: channelId });
        return { guildId: String(guildId), channelId };
    }

    /** Explicit /leave — disconnect but remember it was intentional. */
    async leave(guildId) {
        const session = this.getSession(guildId);
        if (!session) return { guildId: String(guildId), left: false };
        this._destroyPlayer(session);
        try { this.voice.leave(session); } catch (_) {}
        session.connection = null;
        session.state = PLAYBACK_STATES.IDLE;
        if (session.twentyFourSeven) {
            // Keep 24/7 config but do not reconnect until /247 enable again.
            session.disabledIntentionally = true;
            await this._persist(session, { disabledIntentionally: true });
        }
        return { guildId: String(guildId), left: true };
    }

    async join(guildId, channelId, { settings = {} } = {}) {
        const session = this._ensureSession(guildId, channelId, settings);
        if (!session) throw Object.assign(new Error('This node does not own that guild.'), { status: 409 });
        session.channelId = channelId;
        await this._ensureConnected(session);
        return this.describe(guildId);
    }

    // ── persistence ─────────────────────────────────────────────────────────

    async _persist(session, extra = {}) {
        if (!this.store) return;
        try {
            await this.store.saveSettings(session.guildId, {
                enabled: true,
                djRoleId: session.djRoleId,
                defaultVolume: session.volume,
                maxQueue: session.maxQueue,
                twentyFourSevenEnabled: session.twentyFourSeven,
                twentyFourSevenChannelId: session.channelId,
                disabledIntentionally: session.disabledIntentionally,
                lastState: session.state,
                ownerNode: session.ownerNode,
                ...extra,
            });
        } catch (err) {
            console.error('[MUSIC] persist failed:', err.message);
        }
    }

    async _persistSettings(guildId, patch) {
        if (!this.store) return;
        try { await this.store.saveSettings(guildId, patch); }
        catch (err) { console.error('[MUSIC] persistSettings failed:', err.message); }
    }

    async _recordHistory(session, track) {
        if (!this.store || typeof this.store.addHistory !== 'function') return;
        try {
            await this.store.addHistory(session.guildId, stripTrackForPersist(track), { requesterId: track.requesterId });
        } catch (_) { /* history is best-effort */ }
    }

    // ── voice-state handling ────────────────────────────────────────────────

    /**
     * The 24/7 rule: an empty channel does NOT pause or disconnect the music.
     * This handler exists so a listener arriving can (re)start playback when the
     * queue has something waiting and the bot is idle — nothing else.
     */
    async handleVoiceStateUpdate(oldState, newState) {
        const guildId = newState.guild ? newState.guild.id : (oldState.guild && oldState.guild.id);
        if (!guildId) return;
        const session = this.sessions.get(String(guildId));
        if (!session) return;
        if (session.ownerNode && session.ownerNode !== this._nodeId) return;
        if (!this.ownsGuild(guildId)) return;

        const joinedRadio = newState.channelId === session.channelId && oldState.channelId !== session.channelId;
        if (!joinedRadio) return;
        // Someone joined the music channel. If we are idle with a queue waiting
        // (e.g. the bot restarted), start playing — but never override a manual
        // pause or an intentional disconnect.
        if (!session.manualPause && !session.disabledIntentionally && session.state === PLAYBACK_STATES.IDLE && session.queue.length) {
            await this._playNext(session);
        }
    }

    // ── recovery ────────────────────────────────────────────────────────────

    /** Restore a single 24/7 session from persisted settings. */
    async restoreOne(row) {
        if (!row || !row.twentyFourSevenEnabled || !row.twentyFourSevenChannelId) return;
        if (row.disabledIntentionally) return;
        if (!this.ownsGuild(row.guildId)) return;
        const guild = this.client.guilds.cache.get(row.guildId);
        const channel = guild && guild.channels.cache.get(row.twentyFourSevenChannelId);
        if (!channel || !this.voice.isVoiceChannel(channel)) {
            console.warn(`[MUSIC] 24/7 channel ${row.twentyFourSevenChannelId} for guild ${row.guildId} is missing — not reconnecting.`);
            return;
        }
        const session = this._ensureSession(row.guildId, row.twentyFourSevenChannelId, row);
        if (!session) return;
        session.channelId = row.twentyFourSevenChannelId;
        session.twentyFourSeven = true;
        session.disabledIntentionally = false;
        // Idempotent: the reload loop calls restoreOne repeatedly. If we are
        // already connected (or connecting) to the right channel, leave it be —
        // reconnecting here would destroy a healthy connection every tick.
        const alreadyLive = this.voice.isConnectionActive(session)
            && session.channelId === row.twentyFourSevenChannelId;
        if (alreadyLive || this._connectGate.isPending(session.guildId)) return;
        // The voice connection did NOT survive the restart — recreate it.
        session.connection = null;
        session.player = null;
        await this._ensureConnected(session);
        // Stay connected silently with an empty queue.
        session.state = PLAYBACK_STATES.IDLE;
        await this._persist(session);
    }

    /** Restore every enabled 24/7 session this node owns (after a restart). */
    async restore() {
        if (!this.store) return;
        let rows = [];
        try { rows = await this.store.list247Settings(); }
        catch (err) { console.error('[MUSIC] restore: could not read settings:', err.message); return; }
        for (const row of rows) {
            try { await this.restoreOne(row); }
            catch (err) { console.error(`[MUSIC] restore failed for ${row.guildId}:`, err.message); }
        }
    }

    async shutdown() {
        try { this._reloadHandle && this._reloadHandle.stop(); } catch (_) {}
        for (const session of this.sessions.values()) {
            try { await this._persist(session); } catch (_) {}
            this._destroyPlayer(session);
            try { this.voice.leave(session); } catch (_) {}
        }
        // Tear the engine down last so every player is released before the
        // Shoukaku socket closes (Lavalink is a no-op on the direct path).
        try { if (this.engine && typeof this.engine.shutdown === 'function') await this.engine.shutdown(); } catch (_) {}
        this.sessions.clear();
    }
}

module.exports = { MusicManager, dedupeTracks, stripTrackForPersist, titleSimilarity, MAX_TRACK_RETRIES, DEFAULT_MAX_QUEUE, HISTORY_LIMIT, formatDuration };
