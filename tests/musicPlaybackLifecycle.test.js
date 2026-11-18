/**
 * Regression tests for the Lavalink playback lifecycle bugs.
 *
 * These cover the THREE defects behind "the embed says Playing but nothing is
 * heard and the timer is frozen":
 *
 *   1. Shoukaku's DiscordJS connector only learns the bot's id inside its
 *      `clientReady` once-hook; when the manager starts after the client is
 *      already ready the id stays null and every VOICE_STATE_UPDATE is dropped
 *      (`sessionId` never captured → no audio). `_ensureNodesAdded()` must
 *      restore the identity.
 *   2. `KazagumoPlayer.state` never leaves CONNECTING (Kazagumo never calls
 *      `player.connect()`), so "connected" must be read from the Shoukaku
 *      Connection — and a track must never be reported PLAYING unless the
 *      transport is really up.
 *   3. Nothing refreshed the Now Playing embed, and the position fell back to a
 *      fake wall-clock counter. There is now a bounded per-session refresh
 *      timer driven by the REAL position, with stalled-playback detection.
 *
 * Plus the radio ↔ music mutual exclusion (one voice connection per guild).
 *
 * All doubles are in-process — no Lavalink node, no Discord gateway, no ffmpeg.
 */

const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');

const { LavalinkManager } = require('../utils/music/lavalink/manager');
const { LavalinkEngine } = require('../utils/music/engines/lavalink');
const { MusicManager } = require('../utils/music/musicManager');
const { PlaybackModeRegistry } = require('../utils/playbackMode');
const { PLAYBACK_STATES, PLAYBACK_MODES } = require('../shared/musicConstants');

// ── doubles ─────────────────────────────────────────────────────────────────

function makeClient({ ready = true, userId = 'BOTID' } = {}) {
    const channels = new Map();
    return {
        user: { id: userId },
        isReady: () => ready,
        guilds: { cache: new Map([['g1', { id: 'g1', shardId: 0, channels: { cache: new Map() } }]]) },
        ws: { shards: new Map(), broadcast: () => {} },
        channels: { cache: channels },
    };
}

/** A minimal but faithful Shoukaku/Kazagumo double. */
function makeFakeLibs() {
    class FakeConnector {
        constructor(client) { this.client = client; this.manager = null; }
        set(m) { this.manager = m; return this; }
        getId() { return (this.client && this.client.user && this.client.user.id) || null; }
        ready() {}
        raw() {}
    }

    class FakeNode extends EventEmitter {
        constructor(def) {
            super();
            this.name = def.name;
            this.url = def.url;
            this.auth = def.auth;
            this.secure = def.secure;
            this.state = 0;
            this.sessionId = null;
            this.info = { sourceManagers: ['youtube', 'soundcloud'] };
            this.stats = { players: 0, playingPlayers: 0, frameStats: { sent: 100, nulled: 0, deficit: 0 } };
        }
        connect() { return Promise.resolve(); }
        destroy() { return Promise.resolve(); }
    }

    class FakeShoukaku extends EventEmitter {
        constructor(connector, nodes, options) {
            super();
            this.connector = connector;
            this.options = options || {};
            this.nodes = new Map();
            this.connections = new Map();
            this.id = null; // the connector identity — set on clientReady normally
            this._defs = nodes;
            for (const n of nodes) this.nodes.set(n.name, new FakeNode(n));
        }
        addNode(def) { const node = new FakeNode(def); this.nodes.set(def.name, node); return node; }
        leaveVoiceChannel() { return Promise.resolve(); }
    }

    class FakePlayer extends EventEmitter {
        constructor(opts) {
            super();
            this.guildId = opts.guildId;
            this.voiceId = opts.voiceId;
            this.textId = opts.textId;
            this.state = 1;
            this.position = 0;
            this.paused = false;
            this.volume = opts.volume || 100;
            this.queue = { current: null };
            this.shoukaku = { node: { name: opts.nodeName || 'n1' }, position: 0, ping: 12 };
        }
        setPaused(p) { this.paused = p; return Promise.resolve(); }
        setVolume(v) { this.volume = v; return Promise.resolve(); }
        playTrack() { return Promise.resolve(); }
        stopTrack() { return Promise.resolve(); }
        seekTo() { return Promise.resolve(); }
        destroy() { return Promise.resolve(); }
        setVoiceChannel() {}
        setTextChannel() {}
    }

    class FakeKazagumo extends EventEmitter {
        constructor(options, connector, nodes, kzOptions) {
            super();
            this.options = options;
            this.shoukaku = new FakeShoukaku(connector, nodes, kzOptions);
            this.players = new Map();
        }
        createPlayer(opts) {
            const player = new FakePlayer(opts);
            this.players.set(opts.guildId, player);
            this.emit('playerCreate', player);
            return player;
        }
        getPlayer(guildId) { return this.players.get(guildId) || null; }
        destroyPlayer(guildId) {
            const p = this.players.get(guildId);
            this.players.delete(guildId);
            if (p) this.emit('playerDestroy', p);
            return Promise.resolve();
        }
        search() { return Promise.resolve({ tracks: [] }); }
    }

    return { shoukaku: { Connectors: { DiscordJS: FakeConnector }, Shoukaku: FakeShoukaku }, kazagumo: { Kazagumo: FakeKazagumo } };
}

/** A voice layer double that reports a REAL connected/disconnected state. */
function makeVoice({ connected = true } = {}) {
    let pos = 0;
    const calls = { play: 0 };
    return {
        calls,
        setPosition(p) { pos = p; },
        isVoiceChannel: () => true,
        isConnectionActive: () => connected,
        getConnectionState: () => ({ connected, status: connected ? 'ready' : 'buffering' }),
        join: async () => ({ _v: true, destroy() {} }),
        leave: () => {}, abortConnection: () => {},
        ensurePlayer: (session) => (session.player = session.player || { _p: true }),
        createPlayer: () => ({ _p: true, on() {}, emit() {} }),
        subscribe: () => {},
        pausePlayer: () => {}, resumePlayer: () => {}, stopPlayer: () => {}, destroyPlayer: () => {},
        setVolume: () => {},
        getPlaybackPosition: () => pos,
        createResource: () => ({}),
        playResource: () => { calls.play++; },
        setFilter: async () => true,
        diagnostics: () => ({ connected, connectionStatus: connected ? 'ready' : 'buffering', ping: 10, node: 'n1', frameStats: { sent: 1, nulled: 0, deficit: 0 } }),
    };
}

function makeProviders(tracks = {}) {
    return {
        streamable: ['youtube', 'soundcloud', 'direct'],
        resolveQuery: async (q) => tracks[q] || { provider: 'youtube', id: q, title: q, durationMs: 1000 },
        searchQuery: async () => [],
        resolveCollection: async () => ({ tracks: [] }),
        resolveStream: async () => ({ streamUrl: 'https://x/y' }),
        matchToStreamable: async (t) => t,
        normalizeTitle: (s) => s,
    };
}

// ── 1. connector identity (root cause of "no audio") ────────────────────────

test('manager restores the Shoukaku connector identity when the client is already ready', async () => {
    const libs = makeFakeLibs();
    const manager = new LavalinkManager(makeClient({ ready: true, userId: 'BOTID' }), {
        libs,
        nodeConfig: { nodes: [{ name: 'n1', url: 'localhost:2333', auth: 'pw' }], errors: [], source: 'test' },
    });
    await manager.start();
    const sk = manager._kazagumo.shoukaku;
    assert.equal(sk.id, 'BOTID', 'connector identity is restored so VOICE_STATE_UPDATE is not dropped');
    assert.ok(sk.nodes.size >= 1, 'the node is still registered');
});

test('manager does NOT touch the connector identity when the client is not ready', async () => {
    const libs = makeFakeLibs();
    const manager = new LavalinkManager(makeClient({ ready: false }), {
        libs,
        nodeConfig: { nodes: [{ name: 'n1', url: 'localhost:2333', auth: 'pw' }], errors: [], source: 'test' },
    });
    await manager.start();
    // The connector's own clientReady hook will add nodes + set the id.
    assert.equal(manager._kazagumo.shoukaku.id, null, 'identity is left for the connector clientReady hook');
});

// ── 2. real connection state (never KazagumoPlayer.state) ────────────────────

test('connectionState requires a live connection + sessionId + endpoint', () => {
    const libs = makeFakeLibs();
    const manager = new LavalinkManager(makeClient(), { libs, nodeConfig: { nodes: [{ name: 'n1', url: 'localhost:2333', auth: 'pw' }], errors: [], source: 'test' } });
    // Manually wire a kazagumo without a full start() so we can inspect state.
    manager._kazagumo = new libs.kazagumo.Kazagumo({}, new libs.shoukaku.Connectors.DiscordJS(makeClient()), [{ name: 'n1', url: 'localhost:2333', auth: 'pw' }], {});
    const conn = { state: 1, sessionId: 'sess', serverUpdate: { endpoint: 'eu' }, channelId: 'vc1' };
    manager._kazagumo.shoukaku.connections.set('g1', conn);

    const ready = manager.connectionState('g1');
    assert.equal(ready.connected, true);
    assert.equal(ready.status, 'ready');
    assert.equal(ready.sessionId, 'set', 'the session id is reported as "set", never its value');

    // Missing the voice session id → NOT connected (the reported bug state).
    conn.sessionId = null;
    const noSession = manager.connectionState('g1');
    assert.equal(noSession.connected, false);
    assert.equal(noSession.status, 'awaiting_session');
    assert.equal(noSession.sessionId, null);

    // No connection at all.
    manager._kazagumo.shoukaku.connections.delete('g1');
    assert.equal(manager.connectionState('g1').connected, false);
});

test('the lavalink engine reports connected from the real connection, not player.state', () => {
    const libs = makeFakeLibs();
    const manager = new LavalinkManager(makeClient(), { libs, nodeConfig: { nodes: [{ name: 'n1', url: 'localhost:2333', auth: 'pw' }], errors: [], source: 'test' } });
    manager._kazagumo = new libs.kazagumo.Kazagumo({}, new libs.shoukaku.Connectors.DiscordJS(makeClient()), [{ name: 'n1', url: 'localhost:2333', auth: 'pw' }], {});
    // A Kazagumo player whose state is CONNECTING (0) but whose connection is up.
    manager._kazagumo.players.set('g1', { guildId: 'g1', state: 0, shoukaku: { position: 0, ping: 5 } });
    manager._kazagumo.shoukaku.connections.set('g1', { state: 1, sessionId: 's', serverUpdate: { endpoint: 'eu' }, channelId: 'vc1' });

    const engine = new LavalinkEngine(makeClient(), { manager });
    const session = { guildId: 'g1', player: manager.getPlayer('g1') };
    assert.equal(engine.isConnectionActive(session), true, 'connected comes from the Shoukaku Connection, not player.state');
    assert.equal(engine.getConnectionState(session).connected, true);

    // Now the connection loses its session id → not connected, even though the
    // player object still exists (this is the "no audio" state).
    manager._kazagumo.shoukaku.connections.get('g1').sessionId = null;
    assert.equal(engine.isConnectionActive(session), false);
});

// ── 3. derived state + real position + refresh timer ─────────────────────────

test('a resolved track on a dead transport is Buffering, never Playing', async () => {
    const voice = makeVoice({ connected: false });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ song: { provider: 'youtube', id: 'a', title: 'A', durationMs: 1000 } }), store: null });
    await mgr.play('g1', 'song', { channelId: 'c1' });
    const snap = mgr.describe('g1');
    assert.equal(snap.state, PLAYBACK_STATES.BUFFERING, 'no audio transport → Buffering, not a false Playing');
    assert.equal(snap.connected, false);
});

test('a resolved track on a live transport reports Playing', async () => {
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ song: { provider: 'youtube', id: 'a', title: 'A', durationMs: 1000 } }), store: null });
    await mgr.play('g1', 'song', { channelId: 'c1' });
    assert.equal(mgr.describe('g1').state, PLAYBACK_STATES.PLAYING);
});

test('positionMs uses the REAL position and never fabricates progress when disconnected', async () => {
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 10000 } }), store: null });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    const s = mgr.getSession('g1');
    voice.setPosition(4200);
    assert.equal(mgr.positionMs(s), 4200, 'the real transport position wins');

    // Transport down → no fabricated advancement (the frozen-timer fix).
    const dead = makeVoice({ connected: false });
    const mgr2 = new MusicManager(makeClient(), { voice: dead, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 10000 } }), store: null });
    await mgr2.play('g1', 'a', { channelId: 'c1' });
    const s2 = mgr2.getSession('g1');
    const first = mgr2.positionMs(s2);
    await new Promise(r => setTimeout(r, 20));
    assert.equal(mgr2.positionMs(s2), first, 'a disconnected player never advances the timer');
});

test('the now-playing refresh timer edits the tracked message and stops on idle', async () => {
    const edits = [];
    const client = makeClient();
    client.channels.cache.set('tc1', {
        id: 'tc1',
        messages: { fetch: async (id) => ({ id, edit: async (payload) => { edits.push(payload); return true; } }) },
    });
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(client, { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 10000 } }), store: null });
    await mgr.play('g1', 'a', { channelId: 'c1', textChannelId: 'tc1' });
    mgr.trackNowPlaying('g1', { channelId: 'tc1', messageId: 'm1' });
    const s = mgr.getSession('g1');
    assert.ok(s._refreshTimer, 'a refresh timer was started');

    // One tick renders the embed from the real position.
    voice.setPosition(1500);
    await mgr._refreshTick(s);
    assert.ok(edits.length >= 1, 'the tracked message was edited');
    const payload = edits[edits.length - 1];
    assert.ok(JSON.stringify(payload).includes('0:01'), 'the progress reflects the real position (1.5s → 0:01)');

    // Going idle stops the timer.
    s.current = null;
    s.state = PLAYBACK_STATES.IDLE;
    await mgr._refreshTick(s);
    assert.equal(s._refreshTimer, null, 'the timer stops once playback ends');
});

test('only ONE refresh timer exists per session (no duplicate timers)', async () => {
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 10000 } }), store: null });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    const s = mgr.getSession('g1');
    const first = s._refreshTimer;
    mgr._startRefreshTimer(s);
    mgr._startRefreshTimer(s);
    assert.equal(s._refreshTimer, first, 'a second start is a no-op');
    mgr._stopRefreshTimer(s);
    assert.equal(s._refreshTimer, null);
});

test('a stalled PLAYING session is downgraded to Buffering (frozen-timer detection)', async () => {
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 10000 } }), store: null });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    const s = mgr.getSession('g1');
    assert.equal(s.state, PLAYBACK_STATES.PLAYING);
    voice.setPosition(0); // position never advances
    for (let i = 0; i < 5; i++) mgr._checkStalled(s);
    assert.equal(s.state, PLAYBACK_STATES.BUFFERING, 'a frozen position is reported as Buffering, not a false Playing');
});

test('describe() reports Buffering for a stalled session and Playing again once it recovers', async () => {
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 10000 } }), store: null });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    const s = mgr.getSession('g1');
    assert.equal(mgr.describe('g1').state, PLAYBACK_STATES.PLAYING);

    voice.setPosition(0);
    for (let i = 0; i < 4; i++) mgr._checkStalled(s);
    assert.equal(mgr.describe('g1').state, PLAYBACK_STATES.BUFFERING, 'describe reflects the stall');

    // The position moves again → healthy, PLAYING once more.
    voice.setPosition(2000);
    mgr._checkStalled(s);
    assert.equal(mgr.describe('g1').state, PLAYBACK_STATES.PLAYING, 'recovery clears the stall');
});

// ── 4. playback modes: radio ↔ music mutual exclusion ────────────────────────

function makeFakeRadio(registry) {
    return {
        stopCalls: 0,
        async stop(guildId) { this.stopCalls++; registry.setMode(guildId, PLAYBACK_MODES.IDLE); return true; },
    };
}

test('playing music while the radio owns the guild stops the radio FIRST', async () => {
    const registry = new PlaybackModeRegistry();
    const radio = makeFakeRadio(registry);
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 1000 } }), store: null, playbackModes: registry, radioManager: radio });

    registry.setMode('g1', PLAYBACK_MODES.RADIO);
    await mgr.play('g1', 'a', { channelId: 'c1' });
    assert.equal(radio.stopCalls, 1, 'radio was stopped before music started');
    assert.equal(registry.getMode('g1'), PLAYBACK_MODES.MUSIC);
});

test('music refuses to start if the radio cannot be stopped (no double source)', async () => {
    const registry = new PlaybackModeRegistry();
    const radio = { stop: async () => { throw new Error('nope'); } };
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 1000 } }), store: null, playbackModes: registry, radioManager: radio });
    registry.setMode('g1', PLAYBACK_MODES.RADIO);
    await assert.rejects(() => mgr.play('g1', 'a', { channelId: 'c1' }), /radio/i);
});

test('two simultaneous play commands are serialized by the per-guild lock', async () => {
    const registry = new PlaybackModeRegistry();
    const voice = makeVoice({ connected: true });
    let order = [];
    const providers = makeProviders();
    const orig = providers.resolveQuery;
    providers.resolveQuery = async (q) => { order.push(`resolve:${q}`); await new Promise(r => setTimeout(r, 10)); return orig(q); };
    const mgr = new MusicManager(makeClient(), { voice, providers, store: null, playbackModes: registry });
    await Promise.all([
        mgr.play('g1', 'a', { channelId: 'c1' }),
        mgr.play('g1', 'b', { channelId: 'c1' }),
    ]);
    // The two transitions never overlap: the second resolve starts only after
    // the first fully committed.
    assert.deepEqual(order, ['resolve:a', 'resolve:b'], 'transitions run one after the other');
});

test('the mode registry releases a guild back to idle on leave', async () => {
    const registry = new PlaybackModeRegistry();
    const voice = makeVoice({ connected: true });
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: { provider: 'youtube', id: 'a', title: 'A', durationMs: 1000 } }), store: null, playbackModes: registry });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    assert.equal(registry.getMode('g1'), PLAYBACK_MODES.MUSIC);
    await mgr.leave('g1');
    assert.equal(registry.getMode('g1'), PLAYBACK_MODES.IDLE);
});

// ── 5. state labels ──────────────────────────────────────────────────────────

test('the embed renders the new buffering/reconnecting states honestly', () => {
    const ui = require('../utils/music/musicEmbed');
    assert.match(ui.stateLabel(PLAYBACK_STATES.BUFFERING), /buffering/i);
    assert.match(ui.stateLabel(PLAYBACK_STATES.RECONNECTING), /reconnecting/i);
    assert.match(ui.stateLabel(PLAYBACK_STATES.PLAYING), /playing/i);
});

// ── 6. radio manager mode gating (shared registry) ───────────────────────────

test('RadioManager claims RADIO mode on an enabled session load', async () => {
    const { RadioManager } = require('../utils/radioManager');
    const registry = new PlaybackModeRegistry();
    const db = require('../server/radioDb');
    const orig = db.radioPool.query;
    db.radioPool.query = async (sql) => {
        if (/SELECT \* FROM radio_sessions WHERE enabled = true/i.test(sql)) {
            return { rows: [{ guild_id: 'g9', channel_id: 'vc9', station_id: 's1', enabled: true, manual_pause: false, position_index: 0, queue: [], state: 'playing' }] };
        }
        return { rows: [] };
    };
    try {
        const client = {
            guilds: { cache: new Map([['g9', { id: 'g9', channels: { cache: new Map() } }]]) },
            user: { id: 'bot' },
        };
        const mgr = new RadioManager(client, {
            playbackModes: registry, nodeId: 'n', autoReload: false,
            voice: { isVoiceChannel: () => true, isConnectionActive: () => false, getConnectionState: () => ({ connected: false }) },
            source: {}, stations: { get: () => null, listForGuild: () => [] },
        });
        await mgr.waitForReady();
        assert.equal(registry.getMode('g9'), PLAYBACK_MODES.RADIO, 'an enabled radio session claims RADIO mode');
    } finally {
        db.radioPool.query = orig;
    }
});

test('RadioManager.start stops music FIRST when music owns the guild', async () => {
    const { RadioManager } = require('../utils/radioManager');
    const registry = new PlaybackModeRegistry();
    const db = require('../server/radioDb');
    const orig = db.radioPool.query;
    db.radioPool.query = async (sql) => {
        if (/SELECT \* FROM radio_sessions WHERE enabled = true/i.test(sql)) return { rows: [] };
        return { rows: [] };
    };
    try {
        const music = { stopCalls: 0, async stop(guildId) { this.stopCalls++; registry.setMode(guildId, PLAYBACK_MODES.IDLE); } };
        const channel = { id: 'vc1', type: 2 };
        const client = {
            guilds: { cache: new Map([['g1', { id: 'g1', channels: { cache: new Map([['vc1', channel]]) } }]]) },
            user: { id: 'bot' },
        };
        const mgr = new RadioManager(client, {
            playbackModes: registry, musicManager: music, nodeId: 'n', autoReload: false,
            voice: {
                isVoiceChannel: () => true, isConnectionActive: () => false,
                getConnectionState: () => ({ connected: false }),
                join: async () => ({ destroy() {} }), leave: () => {}, destroyPlayer: () => {},
                ensurePlayer: (s) => (s.player = { on() {}, emit() {} }), subscribe: () => {},
                createPlayer: () => ({ on() {}, emit() {} }), createResource: () => ({}),
                playResource: () => {}, pausePlayer: () => {}, stopPlayer: () => {}, setVolume: () => {},
                abortConnection: () => {},
            },
            source: { resolveStreamUrl: async () => ({ streamUrl: 'https://x' }) },
            stations: { get: () => null, listForGuild: () => [] },
        });
        registry.setMode('g1', PLAYBACK_MODES.MUSIC);
        // start() will connect and (with no listeners) hold paused — that is fine;
        // the assertion is that music was stopped first.
        await mgr.start('g1', 'vc1').catch(() => {});
        assert.equal(music.stopCalls, 1, 'music was stopped before the radio started');
        assert.equal(registry.getMode('g1'), PLAYBACK_MODES.RADIO);
    } finally {
        db.radioPool.query = orig;
    }
});

