/**
 * 24/7 Radio manager — the continuous SoundCloud radio state machine.
 *
 * DESIGN
 * ------
 * The bot stays CONNECTED to a configured Discord voice channel continuously,
 * but audio only plays while at least one human listener is in that channel.
 * When the channel empties the player is PAUSED (not stopped, not disconnected);
 * when a listener returns it RESUMES. An administrator's explicit pause is
 * tracked separately (`manualPause`) so a listener joining never overrides it.
 *
 * Ownership / sharding
 * --------------------
 * Each guild's session is owned by exactly one shard node. The owner is the
 * node that currently holds the guild (i.e. has it cached). A session row
 * records `owner_node`; a node only drives a session it owns, and claims it by
 * writing its own node id. A node that does NOT have the guild cached will not
 * create a voice connection, so two nodes can never stream the same guild.
 *
 * Persistence
 * -----------
 * The session (channel, station, enabled, manualPause, current track metadata,
 * position index, queue, state) lives in `radio_sessions` on the RADIO pool.
 * Stream URLs are NEVER persisted — they are short-lived and re-resolved at play
 * time. On restart the bot reloads enabled sessions, reconnects and restores.
 *
 * The voice layer (@discordjs/voice) is injected (`deps.voice`) so the whole
 * state machine is unit-testable with a mock — no real Discord/ffmpeg needed.
 */

const { RADIO_STATES, STATION_SOURCES } = require('../shared/radioConstants');
const { radioPool, ensureRadioTables } = require('../server/radioDb');
const sc = require('./soundcloudSource');
const { StationManager } = require('./radioStations');

// Default bounded retry budget for a failing stream before the track is
// skipped. Prevents an infinite retry loop on a genuinely unplayable track.
const MAX_TRACK_RETRIES = Math.max(1, parseInt(process.env.RADIO_MAX_TRACK_RETRIES, 10) || 2);
// How long to wait before an automatic reconnect of a dropped voice connection.
const RECONNECT_DELAY_MS = Math.max(1000, parseInt(process.env.RADIO_RECONNECT_DELAY_MS, 10) || 5000);
// Cap the in-memory queue so it can never grow unbounded.
const MAX_QUEUE = Math.max(10, parseInt(process.env.RADIO_MAX_QUEUE, 10) || 500);

class RadioManager {
    /**
     * @param {import('discord.js').Client} client
     * @param {object} [deps]  injectable collaborators (tests pass mocks)
     */
    constructor(client, deps = {}) {
        this.client = client;
        this.stations = deps.stations || new StationManager();
        this.voice = deps.voice || require('./radioVoice');
        this.source = deps.source || sc;

        // guildId -> session { guildId, channelId, stationId, enabled, manualPause,
        //   currentTrack, positionIndex, queue, state, ownerNode, player, connection,
        //   retries, trackEndHandled, reconnecting }
        this.sessions = new Map();
        this._ready = false;
        this._nodeId = deps.nodeId || this._resolveNodeId();
        this._connectGate = deps.connectGate || new (require('./voiceConnectGate').VoiceConnectGate)();
        // Per-guild playback mode + transition lock, shared with MusicManager by
        // default so radio and on-demand music can never own the same guild's
        // single voice connection at the same time.
        this.playbackModes = deps.playbackModes || require('./playbackMode').getPlaybackModeRegistry();
        this.musicManager = deps.musicManager || null; // set by index.js once music exists
        this._initPromise = this.load().catch(err => {
            console.error('[RADIO] Failed to load sessions:', err.message);
        });
        this._reloadHandle = null;
        if (deps.autoReload !== false) this._startReload();
    }

    waitForReady() { return this._initPromise; }

    /**
     * Re-read `radio_sessions` on the shared cache scheduler so a dashboard
     * enable/disable/channel change takes effect without a bot restart. The
     * scheduler backs off while the table is quiet (Neon compute) and snaps
     * back to the fast interval when a write calls `notifyActivity()`.
     */
    _startReload() {
        try {
            const { getCacheScheduler } = require('./cacheScheduler');
            this._reloadHandle = getCacheScheduler().register('RADIO', () => this._refreshFromDatabase());
        } catch (err) {
            console.error('[RADIO] Failed to start reload task:', err.message);
        }
    }

    /**
     * Diff the DB against the in-memory sessions:
     *   • enabled row we do not own yet  → claim + connect + play
     *   • disabled/removed row we hold    → stop + disconnect
     *   • enabled row we hold             → sync channel/station changes
     * Returns true when anything changed (so the poller resets its cadence).
     */
    async _refreshFromDatabase() {
        await this.waitForReady();
        let changed = false;
        try {
            await ensureRadioTables();
            const res = await radioPool.query('SELECT * FROM radio_sessions');
            const rows = new Map((res.rows || []).map(r => [r.guild_id, r]));

            for (const row of rows.values()) {
                const existing = this.sessions.get(row.guild_id);
                if (row.enabled === true) {
                    if (!this.ownsGuild(row.guild_id)) continue; // another node drives it
                    if (!existing) {
                        const session = this._rowToSession(row);
                        this.sessions.set(row.guild_id, session);
                        this.playbackModes.setMode(row.guild_id, 'radio');
                        changed = true;
                        this._bringUp(session).catch(err =>
                            console.error(`[RADIO] Auto-start failed for guild ${row.guild_id}:`, err.message));
                    } else if (existing.channelId !== row.channel_id || existing.stationId !== row.station_id) {
                        // Channel or station changed from the dashboard.
                        const channelChanged = existing.channelId !== row.channel_id;
                        existing.channelId = row.channel_id;
                        existing.stationId = row.station_id;
                        existing.manualPause = row.manual_pause === true;
                        changed = true;
                        this._bringUp(existing, { forceReconnect: channelChanged }).catch(err =>
                            console.error(`[RADIO] Reconfigure failed for guild ${row.guild_id}:`, err.message));
                    }
                } else if (existing && existing.enabled) {
                    // Disabled from the dashboard → tear down our session.
                    changed = true;
                    this._teardown(existing).catch(() => {});
                    this.sessions.delete(row.guild_id);
                }
            }
        } catch (err) {
            console.error('[RADIO] Reload failed:', err.message);
        }
        return changed;
    }

    /** Connect + load + play (or hold paused if empty / manually paused). */
    async _bringUp(session, { forceReconnect = false } = {}) {
        if (forceReconnect) {
            this._destroyPlayer(session);
            try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
            session.connection = null;
        }
        await this._connect(session);
        if (!session.queue || session.queue.length === 0) await this._loadStation(session);
        if (this.countListeners(session) > 0 && !session.manualPause) {
            await this._playCurrent(session);
        } else {
            session.state = session.manualPause ? RADIO_STATES.PAUSED_MANUAL : RADIO_STATES.PAUSED_EMPTY;
            await this._persist(session);
        }
    }

    /** Stop the player + connection and persist the stopped state. */
    async _teardown(session) {
        session.enabled = false;
        session.state = RADIO_STATES.STOPPED;
        if (this.playbackModes.getMode(session.guildId) === 'radio') {
            this.playbackModes.setMode(session.guildId, 'idle');
        }
        this._destroyPlayer(session);
        try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
        session.connection = null;
        try { await this._persist(session); } catch (_) {}
    }

    _resolveNodeId() {
        try {
            return require('./nodeIdentity').resolveNodeIdentity(process.env).nodeId;
        } catch (_) {
            return process.env.NODE_ID || process.env.NODE_NAME || 'local';
        }
    }

    // ── persistence ────────────────────────────────────────────────────────

    async load() {
        try {
            await ensureRadioTables();
            const res = await radioPool.query('SELECT * FROM radio_sessions WHERE enabled = true');
            for (const row of res.rows || []) {
                this.sessions.set(row.guild_id, this._rowToSession(row));
                // An enabled radio session owns the guild's voice connection, so
                // claim RADIO mode immediately — otherwise a $play before the
                // first reload could start music alongside it.
                this.playbackModes.setMode(row.guild_id, 'radio');
            }
            this._ready = true;
        } catch (err) {
            console.error('[RADIO] Session load failed:', err.message);
            this._ready = false;
        }
        return this.sessions;
    }

    _rowToSession(row) {
        return {
            guildId: row.guild_id,
            channelId: row.channel_id,
            stationId: row.station_id || null,
            enabled: row.enabled === true,
            manualPause: row.manual_pause === true,
            currentTrack: row.current_track || null,
            positionIndex: Number(row.position_index) || 0,
            queue: Array.isArray(row.queue) ? row.queue.slice(0, MAX_QUEUE) : [],
            state: row.state || RADIO_STATES.STOPPED,
            volume: row.volume != null ? Number(row.volume) : 100,
            ownerNode: row.owner_node || null,
            // runtime-only fields (never persisted)
            player: null, connection: null, retries: 0,
            trackEndHandled: false, reconnecting: false, _playToken: 0, _advancing: false,
            failedTracks: new Set(), emptyStationCycles: 0,
        };
    }

    async _persist(session) {
        try {
            await ensureRadioTables();
            await radioPool.query(
                `INSERT INTO radio_sessions
                   (guild_id, channel_id, station_id, enabled, manual_pause, current_track_id,
                    current_track, position_index, queue, state, volume, owner_node, updated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, NOW())
                 ON CONFLICT (guild_id) DO UPDATE SET
                   channel_id = EXCLUDED.channel_id, station_id = EXCLUDED.station_id,
                   enabled = EXCLUDED.enabled, manual_pause = EXCLUDED.manual_pause,
                   current_track_id = EXCLUDED.current_track_id, current_track = EXCLUDED.current_track,
                   position_index = EXCLUDED.position_index, queue = EXCLUDED.queue,
                   state = EXCLUDED.state, volume = EXCLUDED.volume,
                   owner_node = EXCLUDED.owner_node, updated_at = NOW()`,
                [
                    session.guildId, session.channelId, session.stationId, session.enabled,
                    session.manualPause,
                    session.currentTrack ? String(session.currentTrack.id) : null,
                    session.currentTrack ? JSON.stringify(session.currentTrack) : null,
                    session.positionIndex || 0,
                    JSON.stringify((session.queue || []).slice(0, MAX_QUEUE)),
                    session.state, session.volume != null ? session.volume : 100,
                    session.ownerNode || null,
                ]
            );
        } catch (err) {
            // Persistence must never break playback.
            console.error('[RADIO] Session persist failed:', err.message);
        }
    }

    // ── ownership ──────────────────────────────────────────────────────────

    /** True when THIS node currently owns (has cached) the guild's shard. */
    ownsGuild(guildId) {
        try {
            return !!(this.client.guilds && this.client.guilds.cache && this.client.guilds.cache.has(guildId));
        } catch (_) {
            return false;
        }
    }

    /**
     * Claim a session for this node. A session already owned by ANOTHER node is
     * never stolen while that node is live; instead the caller is told it does
     * not own it. (Only a node that actually has the guild cached may own it.)
     */
    _claim(session) {
        if (session.ownerNode && session.ownerNode !== this._nodeId && this.ownsGuild(session.guildId) === false) {
            return false;
        }
        session.ownerNode = this._nodeId;
        return true;
    }

    // ── public API ─────────────────────────────────────────────────────────

    getSession(guildId) { return this.sessions.get(guildId) || null; }

    /** Live snapshot for the dashboard / status command. */
    describe(guildId) {
        const s = this.sessions.get(guildId);
        if (!s) return null;
        const listeners = this.countListeners(s);
        const voiceState = this.voice.getConnectionState(s.connection);
        return {
            guildId: s.guildId,
            channelId: s.channelId,
            stationId: s.stationId,
            stationName: s.stationId && this.stations.get(s.stationId) ? this.stations.get(s.stationId).name : null,
            enabled: s.enabled,
            manualPause: s.manualPause,
            state: s.state,
            currentTrack: s.currentTrack,
            positionIndex: s.positionIndex,
            queueLength: (s.queue || []).length,
            listeners,
            connected: voiceState.connected,
            playing: s.state === RADIO_STATES.PLAYING,
            ownerNode: s.ownerNode,
            ownsHere: s.ownerNode === this._nodeId,
        };
    }

    countListeners(session) {
        try {
            const guild = this.client.guilds.cache.get(session.guildId);
            if (!guild) return 0;
            // Prefer the voice-state cache: it is not size-limited, whereas the
            // member cache is capped (200 in this bot), so `channel.members`
            // would under-count on a large server and pause while people listen.
            if (guild.voiceStates && guild.voiceStates.cache) {
                let humans = 0;
                for (const state of guild.voiceStates.cache.values()) {
                    if (state.channelId !== session.channelId) continue;
                    const member = state.member;
                    // An uncached member is counted as a listener (safer: keep
                    // playing rather than pause on incomplete data).
                    if (member && member.user && member.user.bot) continue;
                    humans++;
                }
                return humans;
            }
            // Fallback: channel members collection.
            const channel = guild.channels.cache.get(session.channelId);
            if (!channel || !channel.members) return 0;
            return channel.members.filter(m => !m.user.bot).size;
        } catch (_) {
            return 0;
        }
    }

    /**
     * Start (or restart) radio in a voice channel.
     * Validates the channel, claims ownership, connects, loads the station and
     * begins playback if listeners are present.
     */
    async start(guildId, channelId, { stationId = null, actor = null } = {}) {
        // Serialize the mode transition per guild with music (shared lock) so a
        // simultaneous $play + $radio start cannot both win the voice channel.
        return this.playbackModes.runExclusive(guildId, () => this._startLocked(guildId, channelId, { stationId, actor }));
    }

    /**
     * Ensure RADIO may take over the guild's single voice connection. If
     * on-demand MUSIC owns it, music is stopped FIRST (player destroyed, timer
     * cleared, queue preserved in the session) so the radio stream never
     * competes with a Lavalink player. Returns true when radio may proceed.
     */
    async _takeOverForRadio(guildId) {
        const key = String(guildId);
        if (this.playbackModes.getMode(key) !== 'music') {
            this.playbackModes.setMode(key, 'radio');
            return true;
        }
        const music = this.musicManager;
        if (!music || typeof music.stop !== 'function') {
            console.warn(`[RADIO] Guild ${key} is in MUSIC mode but MusicManager is unavailable — cannot switch.`);
            return false;
        }
        try {
            await music.stop(key, { actor: 'radio-switch' });
            this.playbackModes.setMode(key, 'radio');
            console.log(`[RADIO] Guild ${key}: switched MUSIC → RADIO (music stopped).`);
            return true;
        } catch (err) {
            console.error(`[RADIO] Guild ${key}: failed to stop music for the radio switch:`, err.message);
            return false;
        }
    }

    async _startLocked(guildId, channelId, { stationId = null, actor = null } = {}) {
        if (!this.ownsGuild(guildId)) {
            throw Object.assign(new Error('This node does not own that guild.'), { status: 409 });
        }
        const guild = this.client.guilds.cache.get(guildId);
        const channel = guild && guild.channels.cache.get(channelId);
        if (!channel || !this.voice.isVoiceChannel(channel)) {
            throw Object.assign(new Error('That is not a valid voice channel in this server.'), { status: 400 });
        }

        // Mutual exclusion: stop on-demand music first if it owns the guild.
        const ok = await this._takeOverForRadio(guildId);
        if (!ok) {
            throw Object.assign(new Error('Could not stop music to start the radio — try again in a moment.'), { status: 409 });
        }

        let session = this.sessions.get(guildId);
        if (!session) {
            session = this._rowToSession({
                guild_id: guildId, channel_id: channelId, station_id: stationId,
                enabled: true, manual_pause: false, position_index: 0, queue: [], state: RADIO_STATES.CONNECTING,
            });
            this.sessions.set(guildId, session);
        }
        // A live session owned by another node cannot be taken over here.
        if (session.ownerNode && session.ownerNode !== this._nodeId && this.voice.isConnectionActive(session.connection)) {
            throw Object.assign(new Error('Radio for this server is running on another node.'), { status: 409 });
        }
        session.channelId = channelId;
        session.enabled = true;
        session.manualPause = false;
        if (stationId) session.stationId = stationId;
        if (!session.stationId) session.stationId = this.stations.listForGuild(guildId).find(s => s.enabled)?.id || null;
        session.ownerNode = this._nodeId;
        session.state = RADIO_STATES.CONNECTING;

        await this._persist(session);
        await this._connect(session);

        // Load the station queue (only if we don't already have one).
        if ((!session.queue || session.queue.length === 0)) {
            await this._loadStation(session);
        }

        // Begin playback only when listeners are present; otherwise stay
        // connected and paused.
        if (this.countListeners(session) > 0 && session.queue.length > 0) {
            await this._playCurrent(session);
        } else {
            session.state = RADIO_STATES.PAUSED_EMPTY;
            await this._persist(session);
        }
        return this.describe(guildId);
    }

    /** Stop radio and disconnect, cleaning up all resources. */
    async stop(guildId, { actor = null } = {}) {
        const session = this.sessions.get(guildId);
        // Release the guild's playback mode even if there is no live session row
        // (a partially-torn-down radio must never wedge the guild in RADIO mode).
        if (this.playbackModes.getMode(guildId) === 'radio') {
            this.playbackModes.setMode(guildId, 'idle');
        }
        if (!session) return false;
        session.enabled = false;
        session.state = RADIO_STATES.STOPPED;
        session.manualPause = false;
        this._destroyPlayer(session);
        try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
        session.connection = null;
        session.currentTrack = null;
        session.queue = [];
        session.positionIndex = 0;
        session.ownerNode = this._nodeId;
        await this._persist(session);
        this.sessions.delete(guildId);
        return true;
    }

    /** Manual pause — a listener joining must NOT override this. */
    async pause(guildId, { actor = null } = {}) {
        const session = this.sessions.get(guildId);
        if (!session) throw Object.assign(new Error('Radio is not active in this server.'), { status: 404 });
        session.manualPause = true;
        session.state = RADIO_STATES.PAUSED_MANUAL;
        this._pausePlayer(session);
        await this._persist(session);
        return this.describe(guildId);
    }

    /** Manual resume — clears the manual pause and plays if listeners exist. */
    async resume(guildId, { actor = null } = {}) {
        const session = this.sessions.get(guildId);
        if (!session) throw Object.assign(new Error('Radio is not active in this server.'), { status: 404 });
        session.manualPause = false;
        await this._persist(session);
        if (this.countListeners(session) > 0) {
            await this._playCurrent(session);
        } else {
            session.state = RADIO_STATES.PAUSED_EMPTY;
        }
        return this.describe(guildId);
    }

    /** Skip the current track (starts the next one). */
    async skip(guildId, { actor = null } = {}) {
        const session = this.sessions.get(guildId);
        if (!session) throw Object.assign(new Error('Radio is not active in this server.'), { status: 404 });
        await this._advance(session, { reason: 'skip', force: true });
        return this.describe(guildId);
    }

    /** Select a station and rebuild the queue. */
    async setStation(guildId, stationId, { actor = null } = {}) {
        const session = this.sessions.get(guildId);
        if (!session) throw Object.assign(new Error('Radio is not active in this server.'), { status: 404 });
        const station = this.stations.get(stationId);
        if (!station || (station.guildId && station.guildId !== guildId) || !station.enabled) {
            throw Object.assign(new Error('Unknown or disabled station.'), { status: 400 });
        }
        session.stationId = stationId;
        session.queue = [];
        session.positionIndex = 0;
        await this._loadStation(session);
        await this._persist(session);
        if (this.countListeners(session) > 0 && !session.manualPause) {
            await this._playCurrent(session);
        }
        return this.describe(guildId);
    }

    /** Set the permanent radio voice channel (config only, no session needed). */
    async setChannel(guildId, channelId, { actor = null } = {}) {
        if (!this.ownsGuild(guildId)) {
            throw Object.assign(new Error('This node does not own that guild.'), { status: 409 });
        }
        const guild = this.client.guilds.cache.get(guildId);
        const channel = guild && guild.channels.cache.get(channelId);
        if (!channel || !this.voice.isVoiceChannel(channel)) {
            throw Object.assign(new Error('That is not a valid voice channel in this server.'), { status: 400 });
        }
        let session = this.sessions.get(guildId);
        if (!session) {
            session = this._rowToSession({
                guild_id: guildId, channel_id: channelId, station_id: null,
                enabled: false, manual_pause: false, position_index: 0, queue: [], state: RADIO_STATES.STOPPED,
            });
            this.sessions.set(guildId, session);
        } else {
            session.channelId = channelId;
        }
        session.ownerNode = this._nodeId;
        await this._persist(session);
        return this.describe(guildId);
    }

    /** Set the volume (0-100 → player volume 0-1 when the voice layer supports it). */
    async setVolume(guildId, volume, { actor = null } = {}) {
        const session = this.sessions.get(guildId);
        if (!session) throw Object.assign(new Error('Radio is not active in this server.'), { status: 404 });
        const v = Math.max(0, Math.min(100, Number(volume)));
        session.volume = v;
        this.voice.setVolume(session.player, v / 100);
        await this._persist(session);
        return this.describe(guildId);
    }

    // ── voice lifecycle ────────────────────────────────────────────────────

    async _connect(session) {
        if (this.voice.isConnectionActive(session.connection)) return session.connection;
        // Single-flight: concurrent start/voice-state/recovery calls must share
        // ONE handshake. A second join() destroys the first in-flight connection
        // and the first entersState(Ready) then rejects with "The operation was
        // aborted" even though nothing was actually wrong.
        return this._connectGate.run(session.guildId, async ({ id, reused }) => {
            if (this.voice.isConnectionActive(session.connection)) return session.connection;
            const before = this.voice.getConnectionState(session.connection);
            const connection = await this.voice.join({
                client: this.client,
                guildId: session.guildId,
                channelId: session.channelId,
                onDisconnect: () => this._onConnectionLost(session),
            });
            // Stale-operation guard: if the radio was stopped while the
            // handshake was in flight, do not adopt the new connection.
            if (session.enabled === false) {
                try { this.voice.leave(connection, session.guildId); } catch (_) {}
                throw new Error('Radio was stopped while the connection was being established.');
            }
            session.connection = connection;
            console.log(`[RADIO] voice connect ${reused ? '(shared attempt)' : `#${id}`} node=${this._nodeId} guild=${session.guildId} channel=${session.channelId} ${before.status} -> ${this.voice.getConnectionState(connection).status}`);
            return connection;
        });
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

    // ── queue + playback ───────────────────────────────────────────────────

    async _loadStation(session) {
        const station = session.stationId ? this.stations.get(session.stationId) : null;
        if (!station) { session.queue = []; return; }
        const tracks = await this.stations.resolveTracks(station);
        session.queue = dedupeTracks(tracks).slice(0, MAX_QUEUE);
        session.positionIndex = 0;
        // A fresh load clears the failure marks so a track that failed on a
        // previous pass (e.g. a stale stream URL) gets another chance.
        session.failedTracks = new Set();
    }

    /**
     * Play the track at `positionIndex`. Resolves a FRESH stream URL (never the
     * persisted one), creates a resource and starts the player. Bounded retries
     * skip an unplayable track safely.
     */
    async _playCurrent(session) {
        if (!session.enabled || session.manualPause) return;
        if (this.countListeners(session) === 0) {
            session.state = RADIO_STATES.PAUSED_EMPTY;
            this._pausePlayer(session);
            await this._persist(session);
            return;
        }
        if (!session.queue || session.queue.length === 0) {
            // Empty queue → reload the station so playback continues.
            await this._loadStation(session);
            if (!session.queue.length) { session.state = RADIO_STATES.IDLE; return; }
        }
        if (session.positionIndex >= session.queue.length) session.positionIndex = 0;

        // If every track has already failed in this pass, pause and wait rather
        // than spinning. A fresh station load (or a listener join later) resets
        // the failure set, so the radio recovers instead of looping forever.
        const healthyCount = session.queue.filter(t => !session.failedTracks.has(String(t.id))).length;
        if (healthyCount === 0) {
            session.state = RADIO_STATES.IDLE;
            await this._persist(session);
            return;
        }
        // Walk forward to the next track that has not already failed.
        let guard = 0;
        while (guard++ < session.queue.length && session.failedTracks.has(String(session.queue[session.positionIndex].id))) {
            session.positionIndex = (session.positionIndex + 1) % session.queue.length;
        }

        const track = session.queue[session.positionIndex];
        // Guard against a duplicate play of the same track.
        const token = ++session._playToken;
        session.trackEndHandled = false;
        try {
            const { streamUrl } = await this.source.resolveStreamUrl(track);
            if (token !== session._playToken) return; // superseded
            const resource = this.voice.createResource(streamUrl, { track });
            this._ensurePlayer(session);
            this.voice.playResource(session.player, resource);
            session.currentTrack = stripTrackForPersist(track);
            session.state = RADIO_STATES.PLAYING;
            session.retries = 0;
            session.failedTracks.delete(String(track.id)); // it plays now
            await this._persist(session);
        } catch (err) {
            console.error(`[RADIO] Failed to play track ${track && track.id}:`, err.message);
            await this._onStreamError(session, err);
        }
    }

    /**
     * Advance to the next track. `_advance` is the single place a track-end is
     * handled, so a duplicate `Idle` event cannot double-advance.
     */
    async _advance(session, { reason = 'ended', force = false } = {}) {
        // Dedupe track-end handling: `_advancing` is set synchronously so two
        // end events in the same tick (or an Idle racing a manual skip) can
        // never double-advance. Explicit recovery paths (skip / stream error)
        // pass force:true so they still advance while a prior advance is in
        // flight.
        if (session._advancing && !force) return;
        session._advancing = true;
        session.retries = 0;
        try {
        if (!session.enabled) return;
        session.positionIndex = (session.positionIndex + 1);
        if (session.positionIndex >= (session.queue || []).length) session.positionIndex = 0;
        if (this.countListeners(session) === 0) {
            session.state = RADIO_STATES.PAUSED_EMPTY;
            this._pausePlayer(session);
            await this._persist(session);
            return;
        }
        if (session.manualPause) { session.state = RADIO_STATES.PAUSED_MANUAL; await this._persist(session); return; }
        await this._playCurrent(session);
        } finally {
            session._advancing = false;
        }
    }

    async _onStreamError(session, err) {
        // A stream failure must NOT stop the radio. Retry the SAME track a
        // bounded number of times (a stale stream URL is the common cause and a
        // fresh resolve usually fixes it), then mark it failed and skip it.
        const track = session.queue && session.queue[session.positionIndex];
        session.retries = (session.retries || 0) + 1;
        if (session.retries <= MAX_TRACK_RETRIES) {
            try {
                this.source.resetClient && this.source.resetClient();
            } catch (_) {}
            await this._playCurrent(session);
            return;
        }
        console.error(`[RADIO] Skipping unplayable track after ${session.retries} attempts:`, err && err.message);
        // Record the failure so _playCurrent never re-picks it in this pass.
        if (track) session.failedTracks.add(String(track.id));
        session.retries = 0;
        await this._advance(session, { reason: 'stream_error', force: true });
    }

    _onPlayerIdle(session) {
        // The player went idle = the track finished (or the stream ended).
        // Route through _advance so a duplicate idle cannot double-advance.
        this._advance(session, { reason: 'ended' }).catch(err =>
            console.error('[RADIO] advance failed:', err.message));
    }

    _onPlayerStateChange(session, oldState, newState) {
        // Track our own state so the dashboard is honest about what is happening.
        if (newState === 'playing') session.state = RADIO_STATES.PLAYING;
    }

    _onConnectionLost(session) {
        if (!session.enabled) return;
        if (session.reconnecting) return; // never stack reconnect loops
        session.reconnecting = true;
        session.state = RADIO_STATES.CONNECTING;
        setTimeout(async () => {
            try {
                if (!session.enabled) return;
                session.connection = null;
                await this._connect(session);
                session.reconnecting = false;
                if (this.countListeners(session) > 0 && !session.manualPause) await this._playCurrent(session);
            } catch (err) {
                session.reconnecting = false;
                console.error('[RADIO] Reconnect failed:', err.message);
            }
        }, RECONNECT_DELAY_MS).unref?.();
    }

    // ── voice-state handling ───────────────────────────────────────────────

    /**
     * Called from the guildVoiceStateUpdate event. Only reacts to the CONFIGURED
     * radio channel. When the last human leaves, pause (keep the connection);
     * when a human returns, resume unless an admin paused manually.
     */
    async handleVoiceStateUpdate(oldState, newState) {
        const guildId = newState.guild ? newState.guild.id : (oldState.guild && oldState.guild.id);
        if (!guildId) return;
        const session = this.sessions.get(guildId);
        if (!session || !session.enabled) return;
        // Only the owning node reacts, so two nodes never fight over the same
        // guild's playback state.
        if (session.ownerNode && session.ownerNode !== this._nodeId) return;
        if (!this.ownsGuild(guildId)) return;

        const channelId = session.channelId;
        const leftRadio = oldState.channelId === channelId && newState.channelId !== channelId;
        const joinedRadio = newState.channelId === channelId && oldState.channelId !== channelId;
        if (!leftRadio && !joinedRadio) return;

        const listeners = this.countListeners(session);
        if (listeners === 0) {
            // Everyone left → pause immediately, keep the connection alive.
            if (session.state !== RADIO_STATES.PAUSED_MANUAL) {
                session.state = RADIO_STATES.PAUSED_EMPTY;
                this._pausePlayer(session);
                await this._persist(session);
            }
            return;
        }
        // A listener is present → resume, unless an admin paused manually.
        if (session.manualPause) {
            session.state = RADIO_STATES.PAUSED_MANUAL;
            return;
        }
        if (session.state !== RADIO_STATES.PLAYING) {
            await this._playCurrent(session);
        }
    }

    /**
     * Restore enabled sessions after a restart. The voice connection did NOT
     * survive the restart, so it is recreated. A session whose channel is empty
     * stays connected-but-paused; playback resumes when a listener appears.
     */
    async restore() {
        await this.waitForReady();
        for (const session of this.sessions.values()) {
            if (!session.enabled) continue;
            if (!this.ownsGuild(session.guildId)) continue; // another node owns it
            try {
                // Idempotent: the reload loop calls restore() repeatedly. If the
                // session is already connected (or connecting), leave it alone —
                // reconnecting every tick would destroy a healthy connection.
                if (this.voice.isConnectionActive(session.connection) || this._connectGate.isPending(session.guildId)) {
                    continue;
                }
                // Recreate the voice connection (never assume it survived).
                session.connection = null;
                session.player = null;
                await this._connect(session);
                if ((!session.queue || session.queue.length === 0)) {
                    await this._loadStation(session);
                }
                if (this.countListeners(session) > 0 && !session.manualPause) {
                    await this._playCurrent(session);
                } else {
                    session.state = session.manualPause ? RADIO_STATES.PAUSED_MANUAL : RADIO_STATES.PAUSED_EMPTY;
                    await this._persist(session);
                }
            } catch (err) {
                console.error(`[RADIO] Restore failed for guild ${session.guildId}:`, err.message);
            }
        }
    }

    /** Clean shutdown: stop players + connections (persist first). */
    async shutdown() {
        try { this._reloadHandle && this._reloadHandle.stop(); } catch (_) {}
        for (const session of this.sessions.values()) {
            try { await this._persist(session); } catch (_) {}
            this._destroyPlayer(session);
            try { this.voice.leave(session.connection, session.guildId); } catch (_) {}
        }
    }
}

// Keep the queue free of duplicates (same track id) while preserving order.
function dedupeTracks(tracks) {
    const seen = new Set();
    const out = [];
    for (const t of tracks) {
        if (!t || t.id == null) continue;
        if (seen.has(t.id)) continue;
        seen.add(t.id);
        out.push(t);
    }
    return out;
}

// Persist only stable metadata — never the short-lived stream URL.
function stripTrackForPersist(track) {
    if (!track) return null;
    return {
        id: String(track.id),
        title: track.title || null,
        url: track.url || null,
        durationMs: track.durationMs != null ? track.durationMs : null,
        genre: track.genre || null,
        artworkUrl: track.artworkUrl || null,
        artist: track.artist ? { id: track.artist.id, username: track.artist.username, profileUrl: track.artist.profileUrl || null } : null,
    };
}

module.exports = { RadioManager, dedupeTracks, stripTrackForPersist, MAX_TRACK_RETRIES, MAX_QUEUE };
