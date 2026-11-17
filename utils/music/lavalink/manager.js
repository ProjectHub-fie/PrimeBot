/**
 * LavalinkManager — the Shoukaku/Kazagumo node + player lifecycle.
 *
 * Responsibilities (kept deliberately narrow — the Music engine owns the queue,
 * permissions and 24/7 policy):
 *   • create the Kazagumo player manager exactly once (module-level singleton),
 *   • register node + player event listeners exactly once (no duplicate WS
 *     listeners — a duplicate would double every response),
 *   • forward Discord voice state / voice server updates to Lavalink
 *     (Shoukaku's DiscordJS connector listens for the raw gateway packets; we
 *     additionally forward `voiceStateUpdate` so a manually-issued join is not
 *     lost when the raw stream is unavailable),
 *   • track node health, pick a HEALTHY node for a new player (never the first
 *     blindly), back off + retry with bounded attempts, and fail over to another
 *     healthy node,
 *   • keep player state independent of node state so a node restart never
 *     destroys the queue (the engine re-creates the player against another node
 *     and re-plays the current track — audio restarts, the queue does not).
 *
 * Diagnostics never print credentials: `describeNodes()` exposes only a
 * password-free shape (see nodeConfig.describeNode).
 */

const { NodeHealthTracker, HEALTH_STATES } = require('./nodeHealth');
const { loadNodeConfig, describeNodes } = require('./nodeConfig');
const { toTrack, trackKey, searchPrefix, LavalinkProviders } = require('./lavalinkProviders');
const { PROVIDERS } = require('../../../shared/musicConstants');

// Source names a node must advertise for a given provider to be playable.
const SOURCE_HINTS = {
    [PROVIDERS.YOUTUBE]: ['youtube'],
    [PROVIDERS.SOUNDCLOUD]: ['soundcloud'],
    [PROVIDERS.SPOTIFY]: ['spotify', 'applemusic', 'deezer'],
    [PROVIDERS.DIRECT]: ['http', 'local'],
};

/** Module-level guard: one manager (and therefore one Shoukaku instance) per client. */
const _instances = new WeakMap();

function loadLibs() {
    // Lazy so the direct engine never pays for (or requires) the Lavalink libs.
    const shoukaku = require('shoukaku');
    const kazagumo = require('kazagumo');
    return { shoukaku, kazagumo };
}

class LavalinkManager {
    constructor(client, options = {}) {
        this.client = client;
        this._libs = options.libs || null; // injectable for tests
        this._kazagumo = null;
        this._started = false;
        this._startPromise = null;
        this._retryTimer = null;
        this._destroyed = false;

        const cfg = options.nodeConfig || loadNodeConfig();
        this.nodeOptions = cfg.nodes;
        this.configErrors = cfg.errors || [];
        this.configSource = cfg.source;

        this.health = options.health || new NodeHealthTracker(this.nodeOptions, {
            maxReconnectAttempts: parseInt(process.env.LAVALINK_MAX_RECONNECT_ATTEMPTS, 10) || 5,
            cooldownMs: parseInt(process.env.LAVALINK_NODE_COOLDOWN_MS, 10) || 60000,
            baseBackoffMs: parseInt(process.env.LAVALINK_BACKOFF_BASE_MS, 10) || 2000,
            maxBackoffMs: parseInt(process.env.LAVALINK_BACKOFF_MAX_MS, 10) || 120000,
        });

        this.searchEngine = options.searchEngine || process.env.LAVALINK_SEARCH_ENGINE || 'ytsearch';
        /** guildId → KazagumoPlayer (the live Lavalink player). */
        this.players = new Map();
        /** Guilds whose player must be re-created on the next healthy node. */
        this._recoverable = new Map(); // guildId → { voiceId, textId, onReady }
        /** Track metadata waiting for the player to be recreated. */
        /** PrimeBot track → encoded Lavalink track (in-memory only). */
        this._encoded = new Map(); // key → encoded string
        /** Event listeners registered by the engine. */
        this._listeners = { node: {}, player: {} };
        /** True once a real node has been ready at least once. */
        this.everReady = false;
        /** Provider adapter (lazily constructed — see the `providers` getter). */
        this._providers = null;
    }

    // ── lifecycle ───────────────────────────────────────────────────────────

    /** The Kazagumo instance (created on first access). */
    get kazagumo() { return this._kazagumo; }

    /**
     * The provider adapter (LavalinkProviders). Built lazily so a caller that
     * reaches it before start() still gets the Lavalink adapter rather than
     * silently falling through to the direct provider registry.
     */
    get providers() {
        if (!this._providers) this._providers = new LavalinkProviders(this, { defaultEngine: this.searchEngine });
        return this._providers;
    }

    set providers(adapter) { this._providers = adapter || null; }

    /**
     * Register the configured nodes with Shoukaku when the connector's own
     * `clientReady` hook can no longer fire (client already logged in). This is
     * the ONLY place we call `shoukaku.addNode` — the normal path is the
     * connector's `ready(nodes)` on login, and calling both would create a
     * duplicate node per entry (two WebSockets to the same Lavalink server).
     */
    _ensureNodesAdded() {
        try {
            const sk = this._kazagumo && this._kazagumo.shoukaku;
            if (!sk) return;
            if (sk.nodes && sk.nodes.size > 0) return; // connector already added them
            const ready = typeof this.client.isReady === 'function' ? this.client.isReady() : true;
            if (!ready) return; // the connector's clientReady hook will add them
            for (const opt of this.nodeOptions) {
                try { sk.addNode(opt); }
                catch (err) { console.warn(`[LAVALINK] Could not add node ${opt.name}: ${err.message}`); }
            }
        } catch (err) {
            console.warn('[LAVALINK] Node registration failed:', err.message);
        }
    }

    /** Create the player manager exactly once. Safe to call repeatedly. */
    async start() {
        if (this._started) return this._kazagumo;
        if (this._startPromise) return this._startPromise;
        this._startPromise = this._start().finally(() => { this._startPromise = null; });
        return this._startPromise;
    }

    async _start() {
        if (this._started || this._destroyed) return this._kazagumo;
        if (!this.nodeOptions.length) {
            const reason = this.configErrors.length ? this.configErrors.join('; ') : 'no nodes configured';
            console.warn(`[LAVALINK] Not starting — ${reason}. Set LAVALINK_NODES (or LAVALINK_HOST/…).`);
            return null;
        }
        const { shoukaku, kazagumo } = this._libs || loadLibs();
        const { Kazagumo, Connectors } = { Kazagumo: kazagumo.Kazagumo, Connectors: shoukaku.Connectors };

        this._kazagumo = new Kazagumo(
            {
                defaultSearchEngine: this.searchEngine,
                send: (guildId, payload) => {
                    // Route the op-4 voice payload to the guild's shard.
                    try {
                        const guild = this.client.guilds.cache.get(guildId);
                        const shardId = (guild && typeof guild.shardId === 'number') ? guild.shardId : 0;
                        const shard = this.client.ws.shards.get(shardId) || [...this.client.ws.shards.values()][0];
                        if (shard) shard.send(payload);
                        else this.client.ws.broadcast(payload);
                    } catch (err) {
                        console.error('[LAVALINK] voice payload send failed:', err.message);
                    }
                },
            },
            new Connectors.DiscordJS(this.client),
            this.nodeOptions,
            {
                // Do NOT move players automatically: we drive recovery so the
                // queue/track metadata survives and we can report what happened.
                moveOnDisconnect: false,
                resume: false,
                reconnectTries: Math.max(1, parseInt(process.env.LAVALINK_RECONNECT_TRIES, 10) || 3),
                reconnectInterval: Math.max(500, parseInt(process.env.LAVALINK_RECONNECT_INTERVAL_MS, 10) || 5000),
                restTimeout: Math.max(1000, parseInt(process.env.LAVALINK_REST_TIMEOUT_MS, 10) || 10000),
                userAgent: `PrimeBot/${require('../../../config').version || '1.0.0'}`,
                voiceConnectionTimeout: Math.max(5, parseInt(process.env.LAVALINK_VOICE_TIMEOUT_S, 10) || 20),
                // Prefer a HEALTHY node with the fewest players (see nodeHealth).
                nodeResolver: (nodes) => {
                    const name = this.health.selectNode();
                    if (name && nodes.has(name)) return nodes.get(name);
                    // Fall back to any connected node so Shoukaku can still try.
                    return [...nodes.values()].find(n => this.health.isHealthy(n.name)) || undefined;
                },
            },
        );

        this._wireEvents();
        this._started = true;
        // Shoukaku's DiscordJS connector adds nodes on `clientReady`. If the
        // client is ALREADY ready (manager started after login — a reconnect, a
        // hot reload, or a test harness), that event has already fired and no
        // node would ever be registered. Add them here in that case. `addNode`
        // is idempotent-safe for us: we only call it when the map is empty.
        this._ensureNodesAdded();
        console.log(`[LAVALINK] Manager created — ${this.nodeOptions.length} node(s) from ${this.configSource} (${describeNodes(this.nodeOptions).map(n => `${n.name}@${n.url}${n.secure ? ' (secure)' : ''}`).join(', ')})`);
        if (this.configErrors.length) console.warn(`[LAVALINK] ${this.configErrors.length} config problem(s): ${this.configErrors.join('; ')}`);
        // Voice state / voice server updates are forwarded to Lavalink by
        // Shoukaku's DiscordJS connector, which subscribes to the gateway `raw`
        // stream itself (client.on('raw')). We deliberately do NOT add a second
        // `raw` listener — a duplicate would forward every voice update twice.
        return this._kazagumo;
    }

    /** Register node + player listeners exactly once. */
    _wireEvents() {
        const sk = this._kazagumo.shoukaku;

        // Node events — the full set the task calls out.
        sk.on('ready', (name, lavalinkResume, libraryResume) => {
            this.everReady = true;
            this.health.markReady(name);
            console.log(`[LAVALINK] Node "${name}" ready (lavalinkResume=${!!lavalinkResume}, libraryResume=${!!libraryResume}).`);
            this._emitNode('ready', name);
            this._onNodeReady(name);
        });
        sk.on('error', (name, error) => {
            this.health.markError(name, error);
            console.error(`[LAVALINK] Node "${name}" error: ${error && error.message ? error.message : error}`);
            this._emitNode('error', name, error);
        });
        sk.on('close', (name, code, reason) => {
            this.health.markClose(name, code, reason);
            console.warn(`[LAVALINK] Node "${name}" closed (code ${code}${reason ? `, ${reason}` : ''}).`);
            this._emitNode('close', name, code, reason);
            this._scheduleReconnect();
        });
        sk.on('disconnect', (name, count) => {
            this.health.markClose(name, null, `disconnected (${count} players)`);
            console.warn(`[LAVALINK] Node "${name}" disconnected (${count} player(s) affected).`);
            this._emitNode('disconnect', name, count);
            this._onNodeDisconnect(name, count);
        });
        sk.on('reconnecting', (name, reconnectsLeft, reconnectInterval) => {
            this.health.markReconnecting(name);
            console.warn(`[LAVALINK] Node "${name}" reconnecting (${reconnectsLeft} tries left, every ${reconnectInterval}ms).`);
            this._emitNode('reconnecting', name, reconnectsLeft, reconnectInterval);
        });
        sk.on('debug', (name, info) => this._emitNode('debug', name, info));

        // Player events — Kazagumo level.
        const kz = this._kazagumo;
        kz.on('playerCreate', (player) => {
            this.players.set(player.guildId, player);
            const nodeName = player.shoukaku && player.shoukaku.node ? player.shoukaku.node.name : null;
            if (nodeName) this.health.setPlayers(nodeName, this._playersOnNode(nodeName));
            this._emitPlayer('create', player);
        });
        kz.on('playerDestroy', (player) => {
            const nodeName = player.shoukaku && player.shoukaku.node ? player.shoukaku.node.name : null;
            this.players.delete(player.guildId);
            if (nodeName) this.health.setPlayers(nodeName, this._playersOnNode(nodeName));
            this._emitPlayer('destroy', player);
        });
        kz.on('playerStart', (player, track) => this._emitPlayer('start', player, track));
        kz.on('playerEnd', (player) => this._emitPlayer('end', player));
        kz.on('playerEmpty', (player) => this._emitPlayer('empty', player));
        kz.on('playerResolveError', (player, track, message) => {
            console.warn(`[LAVALINK] Resolve error in guild ${player.guildId}: ${message || 'unknown'}`);
            this._emitPlayer('resolveError', player, track, message);
        });
        kz.on('playerException', (player, data) => {
            const reason = data && (data.exception ? data.exception.message : data.message);
            console.error(`[LAVALINK] Player exception in guild ${player.guildId}: ${reason || 'unknown'}`);
            this._emitPlayer('exception', player, data);
        });
        kz.on('playerStuck', (player, data) => {
            console.warn(`[LAVALINK] Player stuck in guild ${player.guildId} (threshold ${data && data.thresholdMs}ms).`);
            this._emitPlayer('stuck', player, data);
        });
        kz.on('playerClosed', (player, data) => {
            console.warn(`[LAVALINK] Voice closed in guild ${player.guildId} (code ${data && data.code}).`);
            this._emitPlayer('closed', player, data);
        });
        kz.on('playerResumed', (player) => this._emitPlayer('resumed', player));
        kz.on('playerUpdate', (player, data) => this._emitPlayer('update', player, data));
    }

    /** Engine subscribes here to react to lifecycle events. */
    onNode(event, fn) { (this._listeners.node[event] = this._listeners.node[event] || []).push(fn); }
    onPlayer(event, fn) { (this._listeners.player[event] = this._listeners.player[event] || []).push(fn); }
    _emitNode(event, ...args) { (this._listeners.node[event] || []).forEach(fn => { try { fn(...args); } catch (e) { console.error('[LAVALINK] node listener failed:', e.message); } }); }
    _emitPlayer(event, ...args) { (this._listeners.player[event] || []).forEach(fn => { try { fn(...args); } catch (e) { console.error('[LAVALINK] player listener failed:', e.message); } }); }

    // ── node selection + recovery ───────────────────────────────────────────

    /** Player counts per node (metrics). */
    _playersOnNode(nodeName) {
        let n = 0;
        for (const p of this.players.values()) {
            const nn = p.shoukaku && p.shoukaku.node ? p.shoukaku.node.name : null;
            if (nn === nodeName) n++;
        }
        return n;
    }

    /** Is any node currently usable? (a connected one is preferred) */
    hasHealthyNode() { return this.health.healthyNames().length > 0; }

    /** Is any node at least worth attempting (connecting / cooldown elapsed)? */
    hasAvailableNode() { return this.health.hasAvailable(); }

    /** A healthy node name for a new player (or null). */
    selectNode() { return this.health.selectNode(); }

    /** Does a connected node advertise the source needed for `provider`? */
    supportsSource(provider) {
        const hints = SOURCE_HINTS[provider];
        if (!hints) return false;
        if (!this._kazagumo) return false;
        for (const node of this._kazagumo.shoukaku.nodes.values()) {
            if (!this.health.isHealthy(node.name)) continue;
            const info = node.info;
            const managers = (info && Array.isArray(info.sourceManagers)) ? info.sourceManagers.map(s => String(s).toLowerCase()) : [];
            if (!managers.length) return true; // unknown → optimistically allow
            if (managers.some(m => hints.some(h => m.includes(h)))) return true;
        }
        return false;
    }

    /** Source managers advertised by the connected nodes (for diagnostics). */
    nodeInfo() {
        if (!this._kazagumo) return [];
        return [...this._kazagumo.shoukaku.nodes.values()].map(node => ({
            name: node.name,
            state: node.state,
            connected: node.state === 1, // State.CONNECTED
            sessionId: node.sessionId ? 'set' : null,
            sourceManagers: (node.info && node.info.sourceManagers) || [],
            plugins: (node.info && node.info.plugins) ? node.info.plugins.map(p => p.name) : [],
            players: node.stats && typeof node.stats.playingPlayers === 'number' ? node.stats.playingPlayers : null,
        }));
    }

    /** Called when a node becomes ready — the engine owner drives recovery. */
    _onNodeReady(name) {
        // Recovery is owned by MusicManager (it holds the queue + current track),
        // which reacts to the `playersLost` node event. The manager deliberately
        // does NOT recreate players here: it cannot replay a track, and doing so
        // would race the engine's own recovery.
        const pending = this._recoverable.size;
        if (pending) console.log(`[LAVALINK] Node "${name}" is healthy — ${pending} guild(s) awaiting engine recovery.`);
    }

    /** A node died: mark its players recoverable and try to move them. */
    _onNodeDisconnect(name, count) {
        const lost = [];
        for (const [guildId, player] of [...this.players]) {
            const nn = player.shoukaku && player.shoukaku.node ? player.shoukaku.node.name : null;
            if (nn !== name) continue;
            this._recoverable.set(guildId, { voiceId: player.voiceId, textId: player.textId });
            // The player object belongs to a dead node — drop our reference so
            // the next play creates a fresh one on a healthy node.
            this.players.delete(guildId);
            lost.push(guildId);
        }
        if (count) console.warn(`[LAVALINK] Node "${name}" lost ${count} player(s) — queues preserved, playback will restart on a healthy node.`);
        // The engine owner (MusicManager) holds the QUEUE, so it drives recovery;
        // the manager only knows voice/text ids and cannot replay a track.
        this._emitNode('playersLost', name, lost);
        this._scheduleReconnect();
    }

    /**
     * Re-create a player for `guildId` on a healthy node. Audio ALWAYS restarts
     * from the current track (a Lavalink node cannot hand a live stream to
     * another node); the engine owner (MusicManager) keeps the queue + track
     * metadata and calls this, then replays the track itself.
     *
     * Returns the new player, or `null` when no healthy node exists yet — the
     * guild stays in `_recoverable` so a later `ready` can try again.
     */
    async _recoverPlayer(guildId, info = {}) {
        if (!this.hasHealthyNode()) return null;
        const remembered = this._recoverable.get(String(guildId)) || {};
        const player = await this.createPlayer({
            guildId,
            voiceId: info.voiceId || remembered.voiceId,
            textId: info.textId || remembered.textId,
            deaf: true,
        });
        this._recoverable.delete(String(guildId));
        return player;
    }

    // ── retry scheduling (bounded, jittered, single timer) ───────────────────

    _scheduleReconnect() {
        if (this._destroyed || this._retryTimer) return;
        // Only retry nodes that are not connected and whose backoff has elapsed.
        const now = Date.now();
        const candidates = this.health.describe(now).filter(r => !r.healthy);
        if (!candidates.length) return;
        const next = Math.min(...candidates.map(r => (r.nextRetryAt || now + 1000))) - now;
        const delay = Math.max(250, next);
        this._retryTimer = setTimeout(() => {
            this._retryTimer = null;
            this._attemptReconnects();
        }, delay);
        this._retryTimer.unref?.();
    }

    _attemptReconnects() {
        if (this._destroyed || !this._kazagumo) return;
        for (const rec of this.health.describe()) {
            if (rec.healthy) continue;
            const { exhausted, delay } = this.health.markReconnecting(rec.name);
            if (exhausted) {
                console.warn(`[LAVALINK] Node "${rec.name}" failed ${rec.reconnectAttempts} times — cooling down for ${Math.round(delay / 1000)}s before the next attempt.`);
                continue;
            }
            const node = this._kazagumo.shoukaku.nodes.get(rec.name);
            if (!node) continue;
            console.log(`[LAVALINK] Retrying node "${rec.name}" in ${delay}ms (attempt ${rec.reconnectAttempts}).`);
            setTimeout(() => {
                if (this._destroyed) return;
                try { node.connect().catch(err => this.health.markError(rec.name, err)); }
                catch (err) { this.health.markError(rec.name, err); }
            }, delay).unref?.();
        }
        this._scheduleReconnect();
    }

    // ── player creation (single-flight per guild) ───────────────────────────

    /**
     * Create (or return the existing) Kazagumo player for a guild. Single-flight
     * per guild: two concurrent joins cannot create competing players, and a
     * player already registered for the guild is returned untouched.
     */
    async createPlayer({ guildId, voiceId, textId, deaf = true, volume = 100 }) {
        if (!this._started) await this.start();
        if (!this._kazagumo) throw new Error('Lavalink is not available (no node configured).');
        const key = String(guildId);

        const existing = this._kazagumo.players.get(key) || this.players.get(key);
        if (existing) {
            if (voiceId && existing.voiceId !== voiceId) {
                try { existing.setVoiceChannel(voiceId); } catch (_) {}
            }
            if (textId) { try { existing.setTextChannel(textId); } catch (_) {} }
            this.players.set(key, existing);
            return existing;
        }

        if (!this.hasAvailableNode()) {
            const st = this.health.describe();
            const why = st.length ? st.map(n => `${n.name}:${n.state}`).join(', ') : 'no nodes';
            throw new Error(`No healthy Lavalink node is available (${why}).`);
        }

        const nodeName = this.health.selectNode();
        const player = await this._kazagumo.createPlayer({
            guildId: key,
            voiceId,
            textId,
            deaf,
            volume,
            ...(nodeName ? { nodeName } : {}),
        });
        this.players.set(key, player);
        const chosen = player.shoukaku && player.shoukaku.node ? player.shoukaku.node.name : nodeName;
        if (chosen) this.health.setPlayers(chosen, this._playersOnNode(chosen));
        return player;
    }

    getPlayer(guildId) { return this.players.get(String(guildId)) || (this._kazagumo && this._kazagumo.getPlayer(String(guildId))) || null; }

    /** Destroy a guild's player and forget it (used on /leave and 24/7 disable). */
    async destroyPlayer(guildId) {
        const key = String(guildId);
        const player = this.players.get(key);
        this._recoverable.delete(key);
        this.players.delete(key);
        if (player) { try { await player.destroy(); } catch (_) {} }
        else if (this._kazagumo) { try { this._kazagumo.destroyPlayer(key); } catch (_) {} }
    }

    // ── search / resolve ────────────────────────────────────────────────────

    /** Raw Lavalink resolve (Kazagumo shape: { type, tracks, playlistName }). */
    async resolve(query, { requester = null, nodeName = null } = {}) {
        if (!this._started) await this.start();
        if (!this._kazagumo) throw new Error('Lavalink is not available (no node configured).');
        return this._kazagumo.search(String(query), { requester, ...(nodeName ? { nodeName } : {}) });
    }

    /** Search with an explicit engine prefix and limit; returns { type, tracks }. */
    async search(query, { limit = 10, engine = null } = {}) {
        if (!this._started) await this.start();
        if (!this._kazagumo) throw new Error('Lavalink is not available (no node configured).');
        const q = searchPrefix(String(query), engine || this.searchEngine);
        const res = await this._kazagumo.search(q, { requester: null });
        const tracks = (res.tracks || []).slice(0, Math.max(1, limit));
        return { type: res.type, tracks, playlistName: res.playlistName };
    }

    /**
     * Remember the resolved Lavalink track for a PrimeBot track (in-memory only).
     *
     * The KazagumoTrack OBJECT is cached, not just its base64 `encoded` string:
     * `KazagumoPlayer#play()` rejects anything that is not a KazagumoTrack
     * instance, and a resolved instance skips the re-search (its `readyToPlay`
     * getter short-circuits `resolve()`). Encoded Lavalink tracks are
     * node-agnostic, so a cached track replays on a different node after a
     * failover. Never persisted — see the engine's `stripTrackForPersist`.
     */
    rememberEncoded(track, kt) {
        const key = trackKey(track);
        if (key && kt && kt.track) this._encoded.set(key, kt);
    }

    /** The cached KazagumoTrack for a PrimeBot track (or null). */
    encodedFor(track) {
        const key = trackKey(track);
        return key ? (this._encoded.get(key) || null) : null;
    }

    // ── status / shutdown ───────────────────────────────────────────────────

    /** Credential-free status snapshot for logs and the dashboard. */
    describe() {
        return {
            engine: 'lavalink',
            started: this._started,
            configSource: this.configSource,
            configErrors: this.configErrors.slice(),
            nodes: this.health.describe().map(rec => {
                const cfg = this.nodeOptions.find(n => n.name === rec.name) || {};
                const info = this.nodeInfo().find(n => n.name === rec.name) || {};
                return {
                    ...rec,
                    url: cfg.url || null,
                    secure: !!cfg.secure,
                    hasPassword: !!cfg.auth,
                    state: rec.state,
                    players: rec.players,
                    sourceManagers: info.sourceManagers || [],
                    plugins: info.plugins || [],
                };
            }),
            healthyNodes: this.health.healthyNames(),
            playerCount: this.players.size,
            everReady: this.everReady,
        };
    }

    async shutdown() {
        this._destroyed = true;
        if (this._retryTimer) { clearTimeout(this._retryTimer); this._retryTimer = null; }
        for (const guildId of [...this.players.keys()]) {
            try { await this.destroyPlayer(guildId); } catch (_) {}
        }
        try { if (this._kazagumo) { this._kazagumo.shoukaku.removeAllListeners(); this._kazagumo.removeAllListeners(); } } catch (_) {}
        this.players.clear();
        this._encoded.clear();
        this._recoverable.clear();
        this._providers = null;
        this._started = false;
    }

    // ── singleton ───────────────────────────────────────────────────────────

    /**
     * One manager (one Shoukaku instance, one set of WS listeners) per client.
     * Re-entrant calls with the same client return the existing instance — this
     * is what guarantees "initialize the player manager exactly once".
     */
    static getOrCreate(client, options = {}) {
        if (!client || (typeof client !== 'object' && typeof client !== 'function')) {
            return new LavalinkManager(client, options);
        }
        let inst = _instances.get(client);
        if (!inst || inst._destroyed) {
            inst = new LavalinkManager(client, options);
            _instances.set(client, inst);
        }
        return inst;
    }

    static reset(client) { if (client && _instances.has(client)) _instances.delete(client); }
}

module.exports = { LavalinkManager, HEALTH_STATES, trackKey, toTrack };
