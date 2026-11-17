/**
 * Lavalink integration tests.
 *
 * The real Shoukaku/Kazagumo packages are replaced by faithful in-process
 * doubles (injected via `libs` / `manager`), so these tests exercise the REAL
 * node-config parser, health tracker, manager lifecycle, engine and the
 * MusicManager's engine routing — no network, no Lavalink node required.
 *
 * Anything that genuinely needs a live Lavalink node + Discord voice gateway
 * (a real audio handshake, a real YouTube/SoundCloud stream) is labelled
 * UNVERIFIED in the migration report rather than faked here.
 */

const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');

const nodeConfig = require('../utils/music/lavalink/nodeConfig');
const { NodeHealthTracker, computeBackoff, HEALTH_STATES } = require('../utils/music/lavalink/nodeHealth');
const { LavalinkManager } = require('../utils/music/lavalink/manager');
const lavalinkFilters = require('../utils/music/lavalink/lavalinkFilters');
const { LavalinkEngine } = require('../utils/music/engines/lavalink');
const { createEngine, resolveEngineName } = require('../utils/music/engines');
const { MusicManager } = require('../utils/music/musicManager');

// ── doubles ─────────────────────────────────────────────────────────────────

function makeFakeLibs() {
    class FakeConnector {
        constructor(client) { this.client = client; this.manager = null; this.rawCalls = 0; }
        set(m) { this.manager = m; return this; }
        getId() { return (this.client && this.client.user && this.client.user.id) || 'bot'; }
        ready() {}
        raw() { this.rawCalls++; }
    }

    class FakeShoukaku extends EventEmitter {
        constructor(connector, nodes, options) {
            super();
            this.connector = connector;
            this.options = options || {};
            this.nodes = new Map();
            this._defs = nodes;
            for (const n of nodes) {
                this.nodes.set(n.name, {
                    name: n.name, url: n.url, auth: n.auth, secure: n.secure,
                    state: 0, sessionId: null, info: null, stats: null,
                    connect: async () => { this.emit('ready', n.name, false, false); },
                    destroy: async () => {},
                });
            }
        }
    }

    class FakePlayer {
        constructor(opts, node) {
            this.guildId = opts.guildId;
            this.voiceId = opts.voiceId;
            this.textId = opts.textId;
            this.state = 1; // CONNECTED
            this.volume = opts.volume || 100;
            this.played = [];
            this.seeks = [];
            this.filterCalls = [];
            this.paused = false;
            this.shoukaku = {
                node,
                position: 0,
                stopTrack: async () => {},
                setFilters: async (f) => { this.filterCalls.push(f); },
            };
        }
        async play(track) { this.played.push(track); }
        async seek(pos) { this.seeks.push(pos); }
        pause(v) { this.paused = v; }
        setVolume(v) { this.volume = v; }
        disconnect() { this.state = 3; }
        destroy() { this.state = 5; }
        setVoiceChannel(id) { this.voiceId = id; }
        setTextChannel(id) { this.textId = id; }
    }

    class FakeKazagumo extends EventEmitter {
        constructor(options, connector, nodes, shoukakuOptions) {
            super();
            this.KazagumoOptions = options;
            this.connector = connector;
            this.shoukaku = new FakeShoukaku(connector, nodes, shoukakuOptions);
            this.players = new Map();
            this._defs = nodes;
            this.searchResult = { type: 'TRACK_LOADED', tracks: [] };
            this.createCalls = 0;
            this.searchCount = 0;
        }
        async createPlayer(opts) {
            this.createCalls++;
            const existing = this.players.get(opts.guildId);
            if (existing) return existing;
            const nodeName = opts.nodeName || (this._defs[0] && this._defs[0].name);
            const node = this.shoukaku.nodes.get(nodeName) || { name: nodeName };
            const p = new FakePlayer(opts, node);
            this.players.set(opts.guildId, p);
            this.emit('playerCreate', p);
            return p;
        }
        getPlayer(id) { return this.players.get(id); }
        async destroyPlayer(id) {
            const p = this.players.get(id);
            if (!p) return;
            await p.destroy();
            this.players.delete(id);
            this.emit('playerDestroy', p);
        }
        async search(query, opts) { this.searchCount++; this.lastSearch = { query, opts }; return this.searchResult; }
    }

    return { shoukaku: { Connectors: { DiscordJS: FakeConnector } }, kazagumo: { Kazagumo: FakeKazagumo } };
}

const NODES = [
    { name: 'n1', url: 'lav1.example.com:2333', auth: 'secret-1', secure: false },
    { name: 'n2', url: 'lav2.example.com:443', auth: 'secret-2', secure: true },
];

function makeClient() {
    const shards = new Map([[0, { id: 0, send() {} }]]);
    return {
        user: { id: 'bot1' },
        guilds: { cache: new Map([['g1', { id: 'g1', shardId: 0 }]]) },
        ws: { shards, broadcast() {} },
        on() {}, removeListener() {},
    };
}

function makeManager(overrides = {}) {
    const libs = overrides.libs || makeFakeLibs();
    const client = overrides.client || makeClient();
    const mgr = new LavalinkManager(client, {
        libs,
        nodeConfig: { nodes: overrides.nodes || NODES, errors: [], source: 'test' },
        ...overrides,
    });
    return { mgr, libs, client };
}

/** A real LavalinkEngine over a fake manager, for the engine-level tests. */
function makeEngine(overrides = {}) {
    const { mgr } = makeManager(overrides);
    const engine = new LavalinkEngine(makeClient(), { manager: mgr });
    return { engine, mgr };
}

const TRACK = { provider: 'youtube', id: 'yt1', title: 'Song', artist: 'Artist', durationMs: 1000, url: 'https://youtu.be/yt1' };

/** A KazagumoTrack-shaped object returned by the fake search. */
function makeKT(id, title = 'Song', sourceName = 'youtube') {
    return { track: `ENC:${id}`, identifier: id, title, author: 'Artist', length: 1000, sourceName, uri: `https://x/${id}`, isStream: false, isSeekable: true };
}

// ── 1. node configuration ───────────────────────────────────────────────────

test('LAVALINK_NODES JSON is parsed into Shoukaku NodeOption objects', () => {
    const env = { LAVALINK_NODES: JSON.stringify([
        { name: 'main', host: 'lav.example.com', port: 443, password: 'pw', secure: true },
    ]) };
    const { nodes, errors, source } = nodeConfig.loadNodeConfig(env);
    assert.equal(source, 'LAVALINK_NODES');
    assert.equal(errors.length, 0);
    assert.equal(nodes.length, 1);
    assert.deepEqual({ name: nodes[0].name, url: nodes[0].url, auth: nodes[0].auth, secure: nodes[0].secure },
        { name: 'main', url: 'lav.example.com:443', auth: 'pw', secure: true });
});

test('individual LAVALINK_HOST variables describe a single node', () => {
    const env = { LAVALINK_HOST: 'lav.local', LAVALINK_PORT: '2333', LAVALINK_PASSWORD: 'pw' };
    const { nodes, source } = nodeConfig.loadNodeConfig(env);
    assert.equal(source, 'LAVALINK_HOST');
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].url, 'lav.local:2333');
    assert.equal(nodes[0].secure, false);
});

test('secure nodes default to port 443 and plain nodes to 2333', () => {
    const s = nodeConfig.normalizeNode({ host: 'a.example.com', password: 'p', secure: true }, 0);
    assert.equal(s.node.url, 'a.example.com:443');
    const p = nodeConfig.normalizeNode({ host: 'b.example.com', password: 'p' }, 1);
    assert.equal(p.node.url, 'b.example.com:2333');
});

test('an entry missing a host or password is dropped with a reason (never silently accepted)', () => {
    const env = { LAVALINK_NODES: JSON.stringify([
        { name: 'good', host: 'a.example.com', password: 'p' },
        { name: 'no-host', password: 'p' },
        { name: 'no-password', host: 'b.example.com' },
    ]) };
    const { nodes, errors } = nodeConfig.loadNodeConfig(env);
    assert.equal(nodes.length, 1, 'only the valid node survives');
    assert.equal(nodes[0].name, 'good');
    assert.equal(errors.length, 2);
    assert.ok(errors.some(e => /missing a host/.test(e)));
    assert.ok(errors.some(e => /missing a password/.test(e)));
});

test('invalid LAVALINK_NODES JSON is reported, not thrown', () => {
    const { nodes, errors } = nodeConfig.loadNodeConfig({ LAVALINK_NODES: '{not json' });
    assert.equal(nodes.length, 0);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /not valid JSON/);
});

test('describeNodes never exposes a password', () => {
    const { nodes } = nodeConfig.loadNodeConfig({ LAVALINK_NODES: JSON.stringify(NODES) });
    const described = nodeConfig.describeNodes(nodes);
    const json = JSON.stringify(described);
    assert.ok(!json.includes('secret-1') && !json.includes('secret-2'), 'passwords must never be described');
    assert.ok(!/auth/i.test(json), 'the auth field must not leak');
    assert.equal(described[0].hasPassword, true);
});

test('duplicate node names are made unique so they cannot collide in a Map', () => {
    const env = { LAVALINK_NODES: JSON.stringify([
        { name: 'dup', host: 'a.example.com', password: 'p' },
        { name: 'dup', host: 'b.example.com', password: 'p' },
    ]) };
    const { nodes } = nodeConfig.loadNodeConfig(env);
    assert.equal(new Set(nodes.map(n => n.name)).size, 2);
});

test('a URL-form entry derives host/port/secure', () => {
    const { node } = nodeConfig.normalizeNode({ name: 'u', url: 'wss://lav.example.com:8443', password: 'p' }, 0);
    assert.equal(node.host, 'lav.example.com');
    assert.equal(node.port, 8443);
    assert.equal(node.secure, true);
});

// ── 2. node health ──────────────────────────────────────────────────────────

test('computeBackoff grows exponentially and is bounded + jittered', () => {
    const a = computeBackoff(0, { baseMs: 1000, maxMs: 60000, jitter: 0 });
    const b = computeBackoff(1, { baseMs: 1000, maxMs: 60000, jitter: 0 });
    const c = computeBackoff(2, { baseMs: 1000, maxMs: 60000, jitter: 0 });
    assert.equal(a, 1000);
    assert.equal(b, 2000);
    assert.equal(c, 4000);
    assert.ok(computeBackoff(99, { baseMs: 1000, maxMs: 60000, jitter: 0 }) <= 60000, 'must be capped');
    // Jitter keeps the value within ±20% of the raw delay.
    for (let i = 0; i < 50; i++) {
        const v = computeBackoff(3, { baseMs: 1000, maxMs: 60000, jitter: 0.2 });
        assert.ok(v >= 8000 * 0.8 - 1 && v <= 8000 * 1.2 + 1, `jittered value ${v} out of range`);
    }
});

test('markReady resets the backoff and marks the node healthy', () => {
    const t = new NodeHealthTracker(NODES);
    t.markClose('n1', 4000, 'gone');
    t.markReconnecting('n1');
    assert.equal(t.isHealthy('n1'), false);
    t.markReady('n1');
    const rec = t.get('n1');
    assert.equal(rec.state, HEALTH_STATES.CONNECTED);
    assert.equal(rec.reconnectAttempts, 0);
    assert.equal(t.isHealthy('n1'), true);
});

test('a failed node is parked for a cooldown then becomes eligible again', () => {
    const t = new NodeHealthTracker(NODES, { maxReconnectAttempts: 1, cooldownMs: 5000 });
    t.markClose('n1', 4000, 'gone');
    const first = t.markReconnecting('n1'); // attempt 1
    assert.equal(first.exhausted, false);
    const second = t.markReconnecting('n1'); // attempt 2 > max 1
    assert.equal(second.exhausted, true);
    assert.equal(t.get('n1').state, HEALTH_STATES.FAILED);
    assert.equal(t.isHealthy('n1', Date.now()), false, 'within cooldown → unhealthy');
    assert.equal(t.isHealthy('n1', Date.now() + 6000), true, 'after cooldown → eligible again');
});

test('selectNode picks a healthy node with the fewest players (never blindly the first)', () => {
    const t = new NodeHealthTracker(NODES);
    t.markReady('n1');
    t.markReady('n2');
    t.setPlayers('n1', 5);
    t.setPlayers('n2', 1);
    assert.equal(t.selectNode(), 'n2', 'the least-loaded healthy node wins');

    // n2 goes down → n1 is chosen even though it is first in config order.
    t.markClose('n2', 4000, 'gone');
    assert.equal(t.selectNode(), 'n1');
});

test('selectNode returns null when every node is parked (caller must fail fast)', () => {
    const t = new NodeHealthTracker(NODES, { maxReconnectAttempts: 1, cooldownMs: 60000 });
    for (const name of ['n1', 'n2']) {
        t.markClose(name, 4000, 'gone');
        t.markReconnecting(name); // attempt 1 (allowed)
        t.markReconnecting(name); // attempt 2 > max 1 → parked FAILED + cooldown
    }
    assert.equal(t.isAvailable('n1'), false);
    assert.equal(t.selectNode(), null, 'a parked node must not be selected');
    // Once the cooldown lapses the node is eligible again.
    assert.ok(t.selectNode(Date.now() + 61000), 'a cooled-down node becomes eligible');
});

test('describe() reports diagnostics without credentials', () => {
    const t = new NodeHealthTracker(NODES);
    t.markError('n1', new Error('boom'));
    const json = JSON.stringify(t.describe());
    assert.ok(!json.includes('secret-1'), 'no password in the health snapshot');
    assert.match(json, /boom/);
});

// ── 3. manager lifecycle ────────────────────────────────────────────────────

test('the player manager is created exactly once (repeated start() is a no-op)', async () => {
    const { mgr } = makeManager();
    const a = await mgr.start();
    const b = await mgr.start();
    assert.ok(a, 'the manager must be created');
    assert.equal(a, b, 'start() must return the same instance');
    // A second start on the same instance must not build another Kazagumo.
    const before = mgr.kazagumo;
    await mgr.start();
    assert.equal(mgr.kazagumo, before);
});

test('LavalinkManager.getOrCreate is a singleton per client', () => {
    const client = makeClient();
    const a = LavalinkManager.getOrCreate(client, { libs: makeFakeLibs(), nodeConfig: { nodes: NODES, errors: [], source: 'test' } });
    const b = LavalinkManager.getOrCreate(client, { libs: makeFakeLibs(), nodeConfig: { nodes: NODES, errors: [], source: 'test' } });
    assert.equal(a, b, 'one manager per client');
    LavalinkManager.reset(client);
});

test('start() with no configured nodes warns and returns null instead of throwing', async () => {
    const { mgr } = makeManager({ nodes: [] });
    const out = await mgr.start();
    assert.equal(out, null);
    assert.equal(mgr.everReady, false);
});

test('node ready/error/close/disconnect events update health and are surfaced', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    const seen = [];
    mgr.onNode('ready', (name) => seen.push(`ready:${name}`));
    mgr.onNode('error', (name) => seen.push(`error:${name}`));
    mgr.onNode('close', (name) => seen.push(`close:${name}`));
    mgr.onNode('disconnect', (name) => seen.push(`disconnect:${name}`));

    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    assert.equal(mgr.everReady, true);
    assert.equal(mgr.health.isHealthy('n1'), true);
    mgr.kazagumo.shoukaku.emit('error', 'n1', new Error('auth failed'));
    assert.match(mgr.health.get('n1').lastError, /auth failed/);
    mgr.kazagumo.shoukaku.emit('close', 'n2', 4001, 'unknown opcode');
    assert.equal(mgr.health.get('n2').closeCode, 4001);
    mgr.kazagumo.shoukaku.emit('disconnect', 'n2', 3);
    assert.deepEqual(seen, ['ready:n1', 'error:n1', 'close:n2', 'disconnect:n2']);
});

test('player lifecycle events are forwarded to engine subscribers', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    const seen = [];
    for (const ev of ['start', 'end', 'exception', 'stuck', 'closed', 'update', 'empty']) {
        mgr.onPlayer(ev, () => seen.push(ev));
    }
    const player = await mgr.createPlayer({ guildId: 'g1', voiceId: 'vc1', textId: 'tc1' });
    mgr.kazagumo.emit('playerStart', player, makeKT('yt1'));
    mgr.kazagumo.emit('playerEnd', player);
    mgr.kazagumo.emit('playerException', player, { exception: { message: 'oops' } });
    mgr.kazagumo.emit('playerStuck', player, { thresholdMs: 10000 });
    mgr.kazagumo.emit('playerClosed', player, { code: 4014 });
    mgr.kazagumo.emit('playerUpdate', player, { position: 500 });
    mgr.kazagumo.emit('playerEmpty', player);
    assert.deepEqual(seen, ['start', 'end', 'exception', 'stuck', 'closed', 'update', 'empty']);
});

test('createPlayer returns the existing player for a guild (no duplicate players)', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    const a = await mgr.createPlayer({ guildId: 'g1', voiceId: 'vc1' });
    const b = await mgr.createPlayer({ guildId: 'g1', voiceId: 'vc2' });
    assert.equal(a, b, 'the same player object must be reused');
    assert.equal(mgr.kazagumo.createCalls, 1, 'only one player was ever created');
    assert.equal(b.voiceId, 'vc2', 'a channel change is applied to the existing player');
});

test('createPlayer throws a clear error when no node is healthy', async () => {
    const { mgr } = makeManager({ nodes: [] });
    await mgr.start();
    await assert.rejects(
        () => mgr.createPlayer({ guildId: 'g1', voiceId: 'vc1' }),
        /Lavalink is not available|No healthy Lavalink node/,
    );
});

test('createPlayer selects a HEALTHY node, skipping a dead one', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    mgr.kazagumo.shoukaku.emit('ready', 'n2', false, false);
    // n1 dies; n2 must be selected even though n1 is first in config order.
    mgr.kazagumo.shoukaku.emit('close', 'n1', 4000, 'gone');
    mgr.kazagumo.shoukaku.emit('disconnect', 'n1', 0);
    const player = await mgr.createPlayer({ guildId: 'g1', voiceId: 'vc1' });
    assert.equal(player.shoukaku.node.name, 'n2');
});

test('a node disconnect marks its players recoverable and preserves their queue metadata', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    mgr.kazagumo.shoukaku.emit('ready', 'n2', false, false);
    const player = await mgr.createPlayer({ guildId: 'g1', voiceId: 'vc1', textId: 'tc1' });
    assert.equal(player.shoukaku.node.name, 'n1');
    mgr.kazagumo.shoukaku.emit('disconnect', 'n1', 1);
    assert.equal(mgr.players.has('g1'), false, 'the dead player is dropped');
    assert.ok(mgr._recoverable.has('g1'), 'the guild is queued for recovery');
    assert.equal(mgr._recoverable.get('g1').voiceId, 'vc1');
});

test('supportsSource reads the node source managers (no fake Spotify support)', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    const node = mgr.kazagumo.shoukaku.nodes.get('n1');
    node.info = { sourceManagers: ['http', 'youtube'] };
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    assert.equal(mgr.supportsSource('youtube'), true);
    assert.equal(mgr.supportsSource('soundcloud'), false, 'soundcloud is not advertised');
    assert.equal(mgr.supportsSource('spotify'), false, 'spotify is NOT claimed without a plugin');
    node.info = { sourceManagers: ['http', 'youtube', 'soundcloud', 'spotify'] };
    assert.equal(mgr.supportsSource('spotify'), true);
});

test('the manager never adds its own raw gateway listener (the connector owns it)', async () => {
    const client = makeClient();
    const added = [];
    client.on = (ev) => { added.push(ev); };
    const { mgr } = makeManager({ client });
    await mgr.start();
    assert.ok(!added.includes('raw'), 'a second raw listener would double every voice update');
});

test('describe() is credential-free and reports healthy nodes + player count', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    await mgr.createPlayer({ guildId: 'g1', voiceId: 'vc1' });
    const desc = mgr.describe();
    assert.equal(desc.engine, 'lavalink');
    assert.equal(desc.playerCount, 1);
    assert.ok(desc.healthyNodes.includes('n1'));
    const json = JSON.stringify(desc);
    assert.ok(!json.includes('secret-1'), 'no password in the status snapshot');
});

test('shutdown destroys players and clears state', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    const player = await mgr.createPlayer({ guildId: 'g1', voiceId: 'vc1' });
    await mgr.shutdown();
    assert.equal(player.state, 5, 'the player is destroyed');
    assert.equal(mgr.players.size, 0);
    assert.equal(mgr._started, false);
});

// ── 4. filters ──────────────────────────────────────────────────────────────

test('every PrimeBot filter preset maps to a real Lavalink filter (or is rejected)', () => {
    const { FILTER_LIST } = require('../utils/music/musicFilters');
    for (const f of FILTER_LIST) {
        const mapped = lavalinkFilters.lavalinkFilterFor(f.id);
        assert.ok(mapped, `filter "${f.id}" must have a Lavalink mapping`);
        const keys = Object.keys(mapped);
        assert.ok(keys.length > 0, `filter "${f.id}" must map to at least one real Lavalink filter`);
        // No mapping may be an empty object (an embed-only decoration).
        assert.ok(keys.every(k => mapped[k] != null), `filter "${f.id}" must set real values`);
    }
    assert.equal(lavalinkFilters.lavalinkFilterFor('not-a-filter'), null);
    assert.equal(lavalinkFilters.supportsFilter('bassboost'), true);
    assert.equal(lavalinkFilters.supportsFilter('nope'), false);
});

// ── 5. engine ───────────────────────────────────────────────────────────────

test('the Lavalink engine plays a track by resolving the encoded track on the node', async () => {
    const { engine, mgr } = makeEngine();
    await engine.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    mgr.kazagumo.searchResult = { type: 'TRACK_LOADED', tracks: [makeKT('yt1')] };
    const session = { guildId: 'g1', channelId: 'vc1', volume: 80 };
    await engine.join({ session });
    await engine.playTrack(session, TRACK);
    const player = mgr.getPlayer('g1');
    assert.equal(player.played.length, 1, 'the track was handed to Lavalink');
    assert.equal(player.played[0].track, 'ENC:yt1');
    assert.equal(player.volume, 80, 'the session volume was applied');
});

test('the engine caches the resolved track in memory (never persisted)', async () => {
    const { engine, mgr } = makeEngine();
    await engine.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    mgr.kazagumo.searchResult = { type: 'TRACK_LOADED', tracks: [makeKT('yt1')] };
    const session = { guildId: 'g1', channelId: 'vc1' };
    await engine.join({ session });
    await engine.playTrack(session, TRACK);
    // The cached value is the resolved KazagumoTrack OBJECT (not a bare encoded
    // string): KazagumoPlayer#play() rejects anything that is not an instance.
    const cached = mgr.encodedFor(TRACK);
    assert.ok(cached && cached.track === 'ENC:yt1', 'the resolved track is cached by object');
    const searches = mgr.kazagumo.lastSearch;
    assert.ok(searches, 'the node was searched');

    // A second play must NOT re-search — it reuses the cached track.
    const searchesBefore = mgr.kazagumo.searchCount;
    await engine.playTrack(session, TRACK);
    assert.equal(mgr.kazagumo.searchCount, searchesBefore, 'a cached track is not re-searched');
});

test('the engine applies a filter before playback and clears on request', async () => {
    const { engine, mgr } = makeEngine();
    await engine.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    mgr.kazagumo.searchResult = { type: 'TRACK_LOADED', tracks: [makeKT('yt1')] };
    const session = { guildId: 'g1', channelId: 'vc1' };
    await engine.join({ session });
    await engine.playTrack(session, TRACK, { filter: 'bassboost' });
    const player = mgr.getPlayer('g1');
    assert.ok(player.filterCalls.length >= 1, 'setFilters was called');
    const applied = player.filterCalls[player.filterCalls.length - 1];
    assert.ok(Array.isArray(applied.equalizer), 'bassboost maps to an equalizer curve');
    await engine.setFilter(session, null);
    const cleared = player.filterCalls[player.filterCalls.length - 1];
    assert.ok(cleared.equalizer.every(b => b.gain === 0), 'clearing resets the equalizer');
});

test('the engine rejects an unsupported filter instead of applying a wrong one', async () => {
    const { engine, mgr } = makeEngine();
    await engine.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    const session = { guildId: 'g1', channelId: 'vc1' };
    await engine.join({ session });
    await assert.rejects(() => engine.setFilter(session, 'no-such-filter'), /not supported/);
});

test('the engine seeks the Lavalink player', async () => {
    const { engine, mgr } = makeEngine();
    await engine.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    mgr.kazagumo.searchResult = { type: 'TRACK_LOADED', tracks: [makeKT('yt1')] };
    const session = { guildId: 'g1', channelId: 'vc1' };
    await engine.join({ session });
    await engine.playTrack(session, TRACK, { seekSeconds: 30 });
    const player = mgr.getPlayer('g1');
    assert.deepEqual(player.seeks, [30], 'playTrack applied the seek');
    await engine.seek(session, 45);
    assert.deepEqual(player.seeks, [30, 45]);
});

test('the engine fails clearly when Lavalink cannot resolve a track', async () => {
    const { engine, mgr } = makeEngine();
    await engine.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    mgr.kazagumo.searchResult = { type: 'LOAD_FAILED', tracks: [] };
    const session = { guildId: 'g1', channelId: 'vc1' };
    await engine.join({ session });
    await assert.rejects(() => engine.playTrack(session, TRACK), /could not resolve/);
});

test('engine.isVoiceChannel accepts voice + stage channels only', () => {
    const { engine } = makeEngine();
    assert.equal(engine.isVoiceChannel({ type: 2 }), true);
    assert.equal(engine.isVoiceChannel({ type: 13 }), true);
    assert.equal(engine.isVoiceChannel({ type: 0 }), false);
    assert.equal(engine.isVoiceChannel(null), false);
});

// ── 6. engine selection + MusicManager integration ──────────────────────────

test('MUSIC_ENGINE defaults to direct; unknown values fall back to direct', () => {
    assert.equal(resolveEngineName({}), 'direct');
    assert.equal(resolveEngineName({ MUSIC_ENGINE: 'direct' }), 'direct');
    assert.equal(resolveEngineName({ MUSIC_ENGINE: 'lavalink' }), 'lavalink');
    assert.equal(resolveEngineName({ MUSIC_ENGINE: 'LAVALINK' }), 'lavalink');
    assert.equal(resolveEngineName({ MUSIC_ENGINE: 'bogus' }), 'direct');
});

test('an injected voice layer always selects the direct engine (tests + rollback)', () => {
    const r = createEngine(makeClient(), { voice: {}, providers: {} });
    assert.equal(r.name, 'direct');
    assert.equal(r.fallbackReason, null);
});

test('the default MusicManager runs the direct engine', () => {
    const mgr = new MusicManager(makeClient(), { voice: {}, providers: {}, store: null });
    assert.equal(mgr.engineName, 'direct');
    assert.equal(mgr.engineFallbackReason, null);
});

test('a Lavalink-configured MusicManager routes _playTrack through the engine', async () => {
    // A fake engine that records playTrack calls, standing in for a live node.
    const calls = [];
    const fakeEngine = {
        name: 'lavalink',
        capabilities: { filters: true, seek: true, nativeSpotify: false, serverSideAudio: true },
        isVoiceChannel: () => true,
        isConnectionActive: () => true,
        getConnectionState: () => ({ connected: true, status: 'ready' }),
        join: async () => ({}),
        leave: () => {},
        abortConnection: () => {},
        ensurePlayer: () => ({}),
        pausePlayer: () => {}, resumePlayer: () => {}, stopPlayer: () => {}, destroyPlayer: () => {},
        setVolume: () => {}, getPlaybackPosition: () => 0,
        createResource: () => null, playResource: async () => true,
        playTrack: async (session, track) => { calls.push(track.id); return true; },
        resolveStream: async () => ({ streamUrl: null }),
        setFilter: async () => true, seek: async () => ({ seeked: true }), skip: async () => {},
        supportsFilter: () => true, supportsSource: () => false,
        nodeStatus: () => ({ engine: 'lavalink', nodes: [] }),
        start: async () => {},
        shutdown: async () => {},
    };
    const providers = {
        streamable: ['youtube'],
        resolveQuery: async () => ({ provider: 'youtube', id: 'yt1', title: 'S', artist: 'A' }),
        searchQuery: async () => [],
        resolveCollection: async () => ({ tracks: [] }),
        resolveStream: async () => ({ streamUrl: 'stream://x' }),
        matchToStreamable: async (t) => t,
        normalizeTitle: (s) => String(s).toLowerCase(),
    };
    const mgr = new MusicManager(makeClient(), { engine: fakeEngine, providers, store: null });
    assert.equal(mgr.engineName, 'lavalink');
    await mgr.start();
    const res = await mgr.play('g1', 'song', { channelId: 'vc1' });
    assert.equal(res.track.id, 'yt1');
    assert.deepEqual(calls, ['yt1'], 'the Lavalink engine played the track, not the direct pipeline');
});

test('engineStatus() exposes a credential-free status object', () => {
    const mgr = new MusicManager(makeClient(), { voice: {}, providers: {}, store: null });
    const st = mgr.engineStatus();
    assert.equal(st.engine, 'direct');
    assert.equal(st.fallbackReason, null);
    assert.ok(st.capabilities);
    assert.ok(!JSON.stringify(st).includes('password'));
});

// ── 7. node-loss recovery preserves the queue ───────────────────────────────

/** A Lavalink engine double that can simulate a node dying. */
function makeRecoverableEngine() {
    const played = [];
    let player = { guildId: 'g1' };
    const manager = {
        _recoverable: new Map(),
        _player: player,
        getPlayer: () => player,
        _recoverPlayer: async (guildId) => { player = { guildId, recovered: true }; return player; },
        destroyPlayer: async () => {},
        hasHealthyNode: () => true,
        onNode: () => {},
        onPlayer: () => {},
        health: { healthyNames: () => ['n1'] },
        describe: () => ({ engine: 'lavalink', nodes: [] }),
    };
    const engine = {
        name: 'lavalink',
        manager,
        capabilities: { filters: true, seek: true, nativeSpotify: false, serverSideAudio: true },
        isVoiceChannel: () => true,
        isConnectionActive: () => true,
        getConnectionState: () => ({ connected: true, status: 'ready' }),
        join: async ({ session }) => { session.connection = player; return player; },
        leave: () => {}, abortConnection: () => {},
        ensurePlayer: (session) => (session.player = player),
        pausePlayer: () => {}, resumePlayer: () => {}, stopPlayer: () => {}, destroyPlayer: () => {},
        setVolume: () => {}, getPlaybackPosition: () => 0,
        createResource: () => null, playResource: async () => true,
        playTrack: async (session, track) => { played.push(track.id); session.current = track; return true; },
        resolveStream: async () => ({ streamUrl: null }),
        setFilter: async () => true, seek: async () => ({ seeked: true }), skip: async () => {},
        supportsFilter: () => true, supportsSource: () => false,
        nodeStatus: () => manager.describe(),
        start: async () => {}, shutdown: async () => {},
    };
    return { engine, manager, played };
}

test('a node death preserves the queue and restarts the current track (never claims seamless migration)', async () => {
    const { engine, manager, played } = makeRecoverableEngine();
    const providers = {
        streamable: ['youtube'],
        resolveQuery: async () => ({ provider: 'youtube', id: 'yt1', title: 'A', artist: 'X' }),
        searchQuery: async () => [], resolveCollection: async () => ({ tracks: [] }),
        resolveStream: async () => ({ streamUrl: 'x' }),
        matchToStreamable: async (t) => t, normalizeTitle: (s) => String(s).toLowerCase(),
    };
    const mgr = new MusicManager(makeClient(), { engine, providers, store: null });
    await mgr.start();

    // Play a track, then queue a second one.
    await mgr.play('g1', 'first', { channelId: 'vc1' });
    const session = mgr.getSession('g1');
    mgr.enqueue(session, [{ provider: 'youtube', id: 'yt2', title: 'B' }], { requesterId: 'u1' });
    const queuedBefore = session.queue.length;
    const currentBefore = session.current.id;
    assert.equal(queuedBefore, 1);
    assert.equal(currentBefore, 'yt1');

    // The node dies and takes its player with it.
    await mgr._recoverLavalinkSession(session, 'n1');

    assert.equal(session.queue.length, queuedBefore, 'the queue must survive a node death');
    assert.equal(session.current.id, currentBefore, 'the current track is retained');
    assert.deepEqual(played, ['yt1', 'yt1'], 'the current track restarts from the top of a new player');
    assert.ok(session.player.recovered, 'the player was re-created on a healthy node');
    assert.equal(session.reconnecting, false, 'the recovery flag is cleared');
});

test('a node death does NOT disturb a 24/7 session with an empty queue', async () => {
    const { engine } = makeRecoverableEngine();
    const mgr = new MusicManager(makeClient(), {
        engine,
        providers: { streamable: ['youtube'], resolveQuery: async () => ({ provider: 'youtube', id: 'z', title: 'Z' }), searchQuery: async () => [], resolveCollection: async () => ({ tracks: [] }), resolveStream: async () => ({}), matchToStreamable: async (t) => t, normalizeTitle: (s) => s },
        store: null,
    });
    await mgr.start();
    const session = mgr._ensureSession('g1', 'vc1', {});
    session.twentyFourSeven = true;
    session.state = 'idle';
    await mgr._recoverLavalinkSession(session, 'n1');
    assert.equal(session.current, null, 'an idle 24/7 session stays idle');
    assert.equal(session.state, 'idle');
    assert.ok(session.player, 'a player is still created so the connection is re-established');
});

test('an intentional 24/7 disable is never overridden by node recovery', async () => {
    const { engine, played } = makeRecoverableEngine();
    const mgr = new MusicManager(makeClient(), {
        engine,
        providers: { streamable: ['youtube'], resolveQuery: async () => ({ provider: 'youtube', id: 'z', title: 'Z' }), searchQuery: async () => [], resolveCollection: async () => ({ tracks: [] }), resolveStream: async () => ({}), matchToStreamable: async (t) => t, normalizeTitle: (s) => s },
        store: null,
    });
    await mgr.start();
    const session = mgr._ensureSession('g1', 'vc1', {});
    session.disabledIntentionally = true;
    session.current = { provider: 'youtube', id: 'yt1', title: 'A' };
    await mgr._recoverLavalinkSession(session, 'n1');
    assert.deepEqual(played, [], 'a disabled session must not resume playback');
});

// ── 8. provider adapter + lifecycle edge cases ──────────────────────────────

test('the provider adapter is resolved lazily (available even before start())', () => {
    const { engine, mgr } = makeEngine();
    const manager = new MusicManager(makeClient(), { engine, store: null });
    // The engine's adapter only exists after start(); the getter must still
    // return the Lavalink adapter rather than silently falling back to direct.
    assert.equal(typeof manager.providers.resolveQuery, 'function');
    assert.equal(manager.providers.manager, mgr, 'the Lavalink provider adapter is used, not the direct registry');
});

test('start() refreshes the provider adapter from the engine', async () => {
    const { engine, mgr } = makeEngine();
    const manager = new MusicManager(makeClient(), { engine, store: null });
    await manager.start();
    assert.equal(manager.providers.manager, mgr, 'the adapter is refreshed once the engine is up');
});

test('a stale playerEmpty does not clobber a session whose queue still has tracks', async () => {
    const { engine } = makeRecoverableEngine();
    const manager = new MusicManager(makeClient(), {
        engine,
        providers: { streamable: ['youtube'], resolveQuery: async () => ({ provider: 'youtube', id: 'yt1', title: 'A' }), searchQuery: async () => [], resolveCollection: async () => ({ tracks: [] }), resolveStream: async () => ({}), matchToStreamable: async (t) => t, normalizeTitle: (s) => s },
        store: null,
    });
    await manager.start();
    await manager.play('g1', 'first', { channelId: 'vc1' });
    const session = manager.getSession('g1');
    manager.enqueue(session, [{ provider: 'youtube', id: 'yt2', title: 'B' }], { requesterId: 'u1' });

    // Capture the real player-event listeners the manager registers.
    const listeners = {};
    const fakeMgr = {
        onNode() {},
        onPlayer(event, fn) { listeners[event] = fn; },
        health: { healthyNames: () => ['n1'] },
    };
    const manager2 = new MusicManager(makeClient(), { engine: { ...engine, manager: fakeMgr }, providers: manager.providers, store: null });
    manager2._wireEngineRecovery();
    manager2.sessions.set('g1', session);

    session.state = 'playing';
    listeners.empty({ guildId: 'g1' });
    assert.equal(session.state, 'playing', 'an empty event with a non-empty queue must not force idle');

    // With an actually-empty queue it DOES go idle.
    session.queue.length = 0;
    session.current = null;
    listeners.empty({ guildId: 'g1' });
    assert.equal(session.state, 'idle', 'a genuinely empty queue goes idle');
});

test('destroying a player goes through the manager so its registry is updated', async () => {
    const { engine, mgr } = makeEngine();
    await engine.start();
    mgr.kazagumo.shoukaku.emit('ready', 'n1', false, false);
    const session = { guildId: 'g1', channelId: 'vc1' };
    await engine.join({ session });
    assert.ok(mgr.players.has('g1'), 'the manager tracks the player after join');
    engine.destroyPlayer(session);
    await new Promise(r => setImmediate(r));
    assert.equal(mgr.players.has('g1'), false, 'the manager dropped the destroyed player from its registry');
    assert.equal(session.player, null);
    assert.equal(session.connection, null);
});

// ── 9. node config redaction ────────────────────────────────────────────────

test('nodes are registered when the client is already ready (connector hook cannot fire)', async () => {
    const { shoukaku, kazagumo } = makeFakeLibs();
    // An EMPTY node map = the connector never ran its ready() hook.
    const added = [];
    const libs = {
        shoukaku: { Connectors: { DiscordJS: shoukaku.Connectors.DiscordJS } },
        kazagumo: {
            Kazagumo: class extends kazagumo.Kazagumo {
                constructor(options, connector, nodes, sk) {
                    super(options, connector, nodes, sk);
                    this.shoukaku.nodes.clear();
                    this.shoukaku.addNode = (opt) => { added.push(opt.name); };
                }
            },
        },
    };
    const client = makeClient();
    client.isReady = () => true;
    const mgr = new LavalinkManager(client, {
        libs, nodeConfig: { nodes: NODES, errors: [], source: 'test' },
    });
    await mgr.start();
    assert.deepEqual(added, ['n1', 'n2'], 'both configured nodes are registered when the client is already ready');
});

test('nodes are NOT re-added when the connector already registered them', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    const before = mgr.kazagumo.shoukaku.nodes.size;
    // The fake pre-populates nodes, so _ensureNodesAdded must be a no-op.
    assert.ok(before >= 1, 'the fake connector registered nodes');
    mgr._ensureNodesAdded();
    assert.equal(mgr.kazagumo.shoukaku.nodes.size, before, 'no duplicate nodes are created');
});

test('node status never exposes the password', async () => {
    const { mgr } = makeManager();
    await mgr.start();
    const described = mgr.describe();
    const json = JSON.stringify(described);
    assert.ok(!json.includes('secret-1') && !json.includes('secret-2'), 'passwords must never appear in status');
    assert.equal(described.nodes[0].hasPassword, true, 'presence of a password is reported without its value');
});

test('concurrent node-loss recoveries for one guild do not double-replay', async () => {
    const { engine, played } = makeRecoverableEngine();
    const mgr = new MusicManager(makeClient(), {
        engine,
        providers: { streamable: ['youtube'], resolveQuery: async () => ({ provider: 'youtube', id: 'yt1', title: 'A' }), searchQuery: async () => [], resolveCollection: async () => ({ tracks: [] }), resolveStream: async () => ({}), matchToStreamable: async (t) => t, normalizeTitle: (s) => s },
        store: null,
    });
    await mgr.start();
    await mgr.play('g1', 'first', { channelId: 'vc1' });
    const session = mgr.getSession('g1');
    // Two simultaneous notifications for the same guild (audit retry / reconnect).
    await Promise.all([
        mgr._recoverLavalinkSession(session, 'n1'),
        mgr._recoverLavalinkSession(session, 'n1'),
    ]);
    assert.equal(played.filter(id => id === 'yt1').length, 2, 'exactly one replay beyond the initial play');
});

