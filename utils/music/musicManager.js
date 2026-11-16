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

const { REPEAT_MODES, PLAYBACK_STATES, formatDuration } = require('../../shared/musicConstants');

const MAX_TRACK_RETRIES = Math.max(0, parseInt(process.env.MUSIC_MAX_TRACK_RETRIES, 10) || 2);
const RECONNECT_DELAY_MS = Math.max(1000, parseInt(process.env.MUSIC_RECONNECT_DELAY_MS, 10) || 5000);
const DEFAULT_MAX_QUEUE = Math.max(10, parseInt(process.env.MUSIC_MAX_QUEUE, 10) || 500);
const RELOAD_INTERVAL_MS = Math.max(5000, parseInt(process.env.MUSIC_RELOAD_INTERVAL_MS, 10) || 30000);
const HISTORY_LIMIT = 50;

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

class MusicManager {
    constructor(client, deps = {}) {
        this.client = client;
        this.voice = deps.voice || require('./musicVoice');
        this.providers = deps.providers || require('./providers/registry');
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

    // ── lifecycle ───────────────────────────────────────────────────────────

    async start() {
        if (this._started) return;
        this._started = true;
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
    describe(guildId) {
        const s = this.sessions.get(String(guildId));
        if (!s) return null;
        const voiceState = this.voice.getConnectionState(s.connection);
        return {
            guildId: s.guildId,
            channelId: s.channelId,
            connected: voiceState.connected,
            connectionStatus: voiceState.status,
            state: s.state,
            current: s.current,
            queueLength: s.queue.length,
            queue: s.queue.slice(0, 25),
            repeat: s.repeat,
            shuffle: s.shuffle,
            volume: s.volume,
            manualPause: s.manualPause,
            twentyFourSeven: s.twentyFourSeven,
            listeners: this.countListeners(s),
            ownerNode: s.ownerNode,
            ownsHere: s.ownerNode === this._nodeId,
            djRoleId: s.djRoleId,
        };
    }

    // ── connection ──────────────────────────────────────────────────────────

    async _connect(session) {
        if (this.voice.isConnectionActive(session.connection)) return session.connection;
        // Single-flight: two commands arriving close together (/join then
        // /247 enable, a repeated 247 enable, or /play mid-handshake) must share
        // ONE handshake. A second join() destroys the first in-flight
        // connection, and the first handshake's entersState(Ready) then rejects
        // with "The operation was aborted" even though nothing was wrong.
        return this._connectGate.run(session.guildId, async ({ id, reused }) => {
            // Re-check inside the gate — an attempt may have just completed.
            if (this.voice.isConnectionActive(session.connection)) return session.connection;
            const before = this.voice.getConnectionState(session.connection);
            const connection = await this.voice.join({
                client: this.client,
                guildId: session.guildId,
                channelId: session.channelId,
                onDisconnect: () => this._onConnectionLost(session),
            });
            // Stale-operation guard: if 24/7 was disabled (or the session torn
            // down) while the handshake was in flight, do NOT adopt the new
            // connection — otherwise /247 disable during a slow connect leaves
            // the bot connected to a session it just deleted.
            if (session.disabledIntentionally) {
                try { this.voice.leave(connection, session.guildId); } catch (_) {}
                throw new Error('24/7 was disabled while the connection was being established.');
            }
            session.connection = connection;
            console.log(`[MUSIC] voice connect ${reused ? '(shared attempt)' : `#${id}`} node=${this._nodeId} guild=${session.guildId} channel=${session.channelId} ${before.status} -> ${this.voice.getConnectionState(connection).status}`);
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
        session.player = this.voice.createPlayer({
            onError: (err) => this._onStreamError(session, err),
            onIdle: () => this._onPlayerIdle(session),
            onStateChange: (oldState, newState) => this._onPlayerStateChange(session, oldState, newState),
        });
        try { this.voice.subscribe(session.connection, session.player); } catch (_) {}
        return session.player;
    }

    _destroyPlayer(session) {
        if (!session.player) return;
        try { this.voice.stopPlayer(session.player); } catch (_) {}
        try { this.voice.destroyPlayer(session.player); } catch (_) {}
        session.player = null;
    }

    _pausePlayer(session) {
        if (session.player) { try { this.voice.pausePlayer(session.player); } catch (_) {} }
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
     * Play the given track immediately (or the queue head if omitted). Always
     * resolves a FRESH stream URL and applies bounded retries.
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
            const { streamUrl, durationMs } = await this.providers.resolveStream(track);
            if (token !== session._playToken) return false; // superseded by a newer play
            if (durationMs && !track.durationMs) track.durationMs = durationMs;
            const resource = this.voice.createResource(streamUrl, { track, seekSeconds });
            await this._ensureConnected(session);
            this._ensurePlayer(session);
            this.voice.playResource(session.player, resource);
            this.voice.setVolume(session.player, session.volume);
            session.state = PLAYBACK_STATES.PLAYING;
            session.manualPause = false;
            session.retries = 0;
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
                // Empty queue → keep the connection, go idle (never disconnect).
                if (session.repeat === REPEAT_MODES.QUEUE && session.current) {
                    session.queue.push(session.current);
                } else {
                    session.current = null;
                    session.state = PLAYBACK_STATES.IDLE;
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
        if (session.player) { try { this.voice.stopPlayer(session.player); } catch (_) {} }
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
        if (newState === 'playing') session.state = PLAYBACK_STATES.PLAYING;
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
                session.connection = null;
                await this._connect(session);
                session.reconnecting = false;
                if (session.current && !session.manualPause) await this._playTrack(session, session.current);
            } catch (err) {
                session.reconnecting = false;
                console.error('[MUSIC] Reconnect failed:', err.message);
            }
        }, RECONNECT_DELAY_MS).unref?.();
    }

    // ── public playback API ─────────────────────────────────────────────────

    /** Resolve a query and start playing it (immediately, if idle). */
    async play(guildId, query, { channelId = null, requesterId = null, settings = {} } = {}) {
        const session = this._ensureSession(guildId, channelId, settings);
        if (!session) throw Object.assign(new Error('This node does not own that guild.'), { status: 409 });
        if (channelId) session.channelId = channelId;
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
        s.manualPause = true;
        this._pausePlayer(s);
        s.state = PLAYBACK_STATES.PAUSED;
        return this.describe(guildId);
    }

    async resume(guildId) {
        const s = this.getSession(guildId);
        if (!s) throw new Error('Nothing is playing.');
        s.manualPause = false;
        if (s.current) { this.voice.resumePlayer(s.player); s.state = PLAYBACK_STATES.PLAYING; }
        else await this._playNext(s);
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
        if (clearQueue) { s.queue = []; s.history = []; }
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
        this.voice.setVolume(s.player, v);
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
        const alreadyLive = this.voice.isConnectionActive(session.connection)
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
            try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
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
            try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
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
        try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
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
        const alreadyLive = this.voice.isConnectionActive(session.connection)
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
            try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
        }
    }
}

module.exports = { MusicManager, dedupeTracks, stripTrackForPersist, MAX_TRACK_RETRIES, DEFAULT_MAX_QUEUE, HISTORY_LIMIT, formatDuration };
