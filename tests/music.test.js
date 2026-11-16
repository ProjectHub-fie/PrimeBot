/**
 * Music system regression tests.
 *
 * Drives the REAL MusicManager with a mocked voice layer and mocked providers
 * (the sandbox has no Discord/voice/network), then exercises the parts of the
 * state machine the task calls out:
 *   1. play connects + starts playback,
 *   2. a track ending advances to the next track,
 *   3. an empty queue keeps the connection (never disconnects),
 *   4. a failing stream is skipped (one bad track never stops the queue),
 *   5. bounded retries — no infinite loop,
 *   6. manual pause is not overridden,
 *   7. 24/7 enable/disable/reconnect semantics,
 *   8. shard ownership (only the owning node drives a guild),
 *   9. persistence strips stream URLs,
 *  10. the dashboard page renders (server-side, no DB/network).
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

const { MusicManager, dedupeTracks, stripTrackForPersist } = require('../utils/music/musicManager');
const { PLAYBACK_STATES, REPEAT_MODES } = require('../shared/musicConstants');
const guildPages = require('../dashboard/render/guild-pages');

// ── mocks ───────────────────────────────────────────────────────────────────

function makeTrack(id, provider = 'soundcloud') {
    return { provider, id, title: `Track ${id}`, artist: 'Artist', durationMs: 180000, url: `https://example.com/${id}` };
}

/** A voice layer that records calls and can simulate a live player. */
function makeVoice() {
    const calls = { join: 0, leave: 0, pause: 0, resume: 0, stop: 0, play: 0, destroy: 0 };
    let active = false;
    const listeners = {};
    const player = {
        on: (ev, cb) => { listeners[ev] = listeners[ev] || []; listeners[ev].push(cb); },
        emit: (ev, ...args) => { (listeners[ev] || []).forEach(cb => cb(...args)); },
        play: () => { calls.play++; },
        pause: () => { calls.pause++; },
        unpause: () => { calls.resume++; },
        stop: () => { calls.stop++; },
    };
    return {
        calls,
        player,
        emit: (ev, ...args) => player.emit(ev, ...args),
        isVoiceChannel: (ch) => !!ch && (ch.type === 2 || ch.type === 13),
        isConnectionActive: () => active,
        getConnectionState: () => ({ connected: active, status: active ? 'ready' : 'destroyed' }),
        join: async () => { calls.join++; active = true; return { _mock: true, destroy: () => { calls.destroy++; active = false; } }; },
        leave: async () => { calls.leave++; active = false; },
        createPlayer: () => player,
        createResource: async () => ({ volume: { setVolume: () => {} } }),
        playResource: () => { calls.play++; },
        pausePlayer: () => { calls.pause++; },
        resumePlayer: () => { calls.resume++; },
        stopPlayer: () => { calls.stop++; },
        subscribe: () => {},
        setVolume: () => {},
        seekStream: () => ({}),
    };
}

/** A provider registry where each query resolves to a controllable track. */
function makeProviders(trackMap) {
    return {
        streamable: ['youtube', 'soundcloud', 'direct'],
        resolveQuery: async (query) => {
            const t = trackMap[query];
            if (!t) throw new Error(`No results for ${query}`);
            return { ...t };
        },
        searchQuery: async () => Object.values(trackMap),
        resolveCollection: async (query) => [trackMap[query]].filter(Boolean),
        resolveStream: async (track) => ({ streamUrl: `stream://${track.id}`, kind: 'url' }),
        matchToStreamable: async (track) => track,
        normalizeTitle: (s) => String(s).toLowerCase(),
    };
}

function makeClient(guildIds = ['g1'], channels = {}) {
    const cache = new Map(guildIds.map(id => [id, {
        id,
        channels: { cache: new Map(Object.entries(channels).map(([cid, name]) => [cid, { id: cid, name, type: 2 }])) },
        voiceStates: { cache: new Map() },
    }]));
    return { guilds: { cache } };
}

function makeStore(rows = []) {
    const saved = [];
    return {
        saved,
        getSettings: async () => ({}),
        listEnabledSettings: async () => rows,
        list247Settings: async () => rows,
        saveSettings: async (guildId, patch) => { saved.push({ guildId, patch }); },
        addHistory: async () => {},
    };
}

// ── prefix command routing (the "music commands not working" regression) ─────

/**
 * Drive the REAL messageCreate handler so the prefix switch is exercised end to
 * end. Regression for: only `$music` was wired, so `$play` / `$join` / `$247` /
 * bare `play` (no-prefix mode) silently hit the switch default and did nothing.
 */
function makeHandlerClient({ noPrefix = false } = {}) {
    const calls = [];
    const manager = new Proxy({}, {
        get(_t, prop) {
            if (prop === 'getSession') return () => ({ channelId: 'vc1', twentyFourSeven: false, queue: [], djRoleId: null });
            if (prop === 'describe') return () => ({ state: 'idle', queue: [], queueLength: 0, current: null, connected: false, volume: 100, repeat: 'off', twentyFourSeven: false, listeners: 0 });
            return (...a) => {
                calls.push(prop);
                return Promise.resolve({
                    track: { title: 'T', provider: 'youtube', id: '1' }, queued: false,
                    queueLength: 0, current: { title: 'T' }, volume: 100, repeat: 'off',
                    channelId: 'vc1', twentyFourSeven: true, connected: true, state: 'playing',
                    listeners: 1, added: 1, removed: 1, tracks: [],
                });
            };
        },
    });
    const client = {
        user: { id: 'bot' },
        musicManager: manager,
        radioManager: null,
        countingManager: { isCountingChannel: () => false, processCountingMessage: async () => false },
        levelingManager: { processMessage: async () => {} },
        serverSettingsManager: {
            hasNoPrefixMode: () => noPrefix,
            getGuildPrefix: () => '$',
            getTriggeredReactions: () => [],
            getTriggeredResponses: () => [],
        },
        commands: new Map(),
    };
    return { client, calls };
}

function makeHandlerMessage(content) {
    const replies = [];
    return {
        content,
        author: { id: 'u1', tag: 'u#1', bot: false },
        member: { id: 'u1', permissions: { has: () => true }, voice: { channelId: 'vc1', channel: { id: 'vc1', type: 2 } }, roles: { cache: new Map() } },
        guild: { id: 'g1', name: 'G' },
        channel: { id: 'ch1', type: 0, send: async () => ({}) },
        mentions: { channels: { first: () => null }, users: { first: () => null } },
        reply: async (payload) => { replies.push(payload); return { edit: async () => ({}) }; },
        _replies: replies,
    };
}

test('prefix music commands work as $music <sub> AND as top-level aliases', async () => {
    global.botActive = true;
    const handler = require('../events/messageCreate.js');
    const cases = [
        ['$music play song', 'play'],
        ['$play song', 'play'],
        ['$join', 'join'],
        ['$leave', 'leave'],
        ['$skip', 'skip'],
        ['$247 enable', 'enable247'],
        ['$playlist list', null], // store-backed; just must reply, not be ignored
    ];
    for (const [content, expected] of cases) {
        const { client, calls } = makeHandlerClient();
        const msg = makeHandlerMessage(content);
        await handler.execute(msg, client);
        assert.ok(msg._replies.length >= 1, `${content} must reply (was silently ignored)`);
        if (expected) assert.ok(calls.includes(expected), `${content} should call ${expected} (got ${calls.join(',') || 'none'})`);
    }
});

test('no-prefix mode routes bare music words through the same handler', async () => {
    global.botActive = true;
    const handler = require('../events/messageCreate.js');
    for (const [content, expected] of [['play song', 'play'], ['join', 'join']]) {
        const { client, calls } = makeHandlerClient({ noPrefix: true });
        const msg = makeHandlerMessage(content);
        await handler.execute(msg, client);
        assert.ok(calls.includes(expected), `bare "${content}" should call ${expected}`);
    }
});

// ── pure helpers ────────────────────────────────────────────────────────────

test('stripTrackForPersist removes the volatile stream URL', () => {
    const t = { ...makeTrack('a'), streamUrl: 'https://cdn/expiring' };
    const s = stripTrackForPersist(t);
    assert.equal(s.streamUrl, undefined);
    assert.equal(s.id, 'a');
});

test('dedupeTracks preserves order and drops duplicate provider:id', () => {
    const out = dedupeTracks([makeTrack('a'), makeTrack('b'), makeTrack('a')]);
    assert.deepEqual(out.map(t => t.id), ['a', 'b']);
});

// ── playback ────────────────────────────────────────────────────────────────

test('play() connects and starts playback', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ song: makeTrack('a') }), store: makeStore() });
    const res = await mgr.play('g1', 'song', { channelId: 'c1', requesterId: 'u1' });
    assert.equal(res.queued, false);
    assert.equal(voice.calls.join, 1);
    assert.equal(voice.calls.play, 1);
    const snap = mgr.describe('g1');
    assert.equal(snap.state, PLAYBACK_STATES.PLAYING);
    assert.equal(snap.current.id, 'a');
    assert.equal(snap.connected, true);
});

test('a finished track advances to the next queued track', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a'), b: makeTrack('b') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    await mgr.addToQueue('g1', 'b', { channelId: 'c1' });
    assert.equal(mgr.getSession('g1').queue.length, 1);

    // Simulate the player reporting the track ended.
    await mgr._playNext(mgr.getSession('g1'));
    const snap = mgr.describe('g1');
    assert.equal(snap.current.id, 'b');
    assert.equal(snap.connected, true);
});

test('an empty queue keeps the connection (never disconnects)', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    const session = mgr.getSession('g1');
    session.queue.length = 0;
    await mgr._playNext(session);
    const snap = mgr.describe('g1');
    assert.equal(snap.state, PLAYBACK_STATES.IDLE);
    assert.equal(snap.connected, true, 'connection must survive an empty queue');
    assert.equal(voice.calls.destroy, 0);
    assert.equal(voice.calls.leave, 0);
});

test('a failing stream is skipped and the queue continues (bounded retries)', async () => {
    const voice = makeVoice();
    let fails = 0;
    const providers = makeProviders({ bad: makeTrack('bad'), good: makeTrack('good') });
    const origStream = providers.resolveStream;
    providers.resolveStream = async (track) => {
        if (track.id === 'bad') { fails++; throw new Error('stream expired'); }
        return origStream(track);
    };
    const mgr = new MusicManager(makeClient(), { voice, providers, store: makeStore() });
    const session = mgr._ensureSession('g1', 'c1', {});
    session.queue.push({ ...makeTrack('bad'), _key: 'soundcloud:bad' });
    session.queue.push({ ...makeTrack('good'), _key: 'soundcloud:good' });
    await mgr._playNext(session);
    // The bad track failed (bounded), the good track played.
    assert.ok(fails >= 1);
    assert.ok(fails <= 4, 'retries must be bounded, not infinite');
    assert.equal(mgr.describe('g1').current.id, 'good');
    assert.equal(mgr.describe('g1').connected, true);
});

test('manual pause is not overridden by resume-on-join', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    await mgr.pause('g1', { actor: 'admin' });
    assert.equal(mgr.getSession('g1').manualPause, true);
    // A listener joining the channel must NOT resume a manual pause.
    await mgr.handleVoiceStateUpdate(
        { guild: { id: 'g1' }, channelId: null, id: 'u2', client: mgr.client },
        { guild: { id: 'g1' }, channelId: 'c1', id: 'u2', client: mgr.client },
    );
    assert.equal(mgr.getSession('g1').manualPause, true);
    assert.equal(mgr.getSession('g1').state, PLAYBACK_STATES.PAUSED);
});

test('an empty channel does NOT pause, stop or disconnect', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    const before = voice.calls.stop;
    // Everyone (the bot's own subscriber excluded) leaves the channel.
    await mgr.handleVoiceStateUpdate(
        { guild: { id: 'g1' }, channelId: 'c1', id: 'u2', client: mgr.client },
        { guild: { id: 'g1' }, channelId: null, id: 'u2', client: mgr.client },
    );
    const snap = mgr.describe('g1');
    assert.equal(snap.connected, true);
    assert.equal(voice.calls.destroy, 0);
    assert.equal(voice.calls.stop, before, 'leaving must not stop the player');
});

// ── 24/7 ────────────────────────────────────────────────────────────────────

test('enable247 connects and stays connected with nobody listening', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(['g1'], { c1: 'Radio' }), { voice, providers: makeProviders({}), store: makeStore() });
    const view = await mgr.enable247('g1', 'c1', { settings: {} });
    assert.equal(view.twentyFourSeven, true);
    assert.equal(voice.calls.join, 1);
    assert.equal(mgr.describe('g1').connected, true);
    assert.equal(mgr.getSession('g1').queue.length, 0);
});

test('disable247 disconnects and marks the session intentionally disabled', async () => {
    const voice = makeVoice();
    const store = makeStore();
    const mgr = new MusicManager(makeClient(['g1'], { c1: 'Radio' }), { voice, providers: makeProviders({}), store });
    await mgr.enable247('g1', 'c1', { settings: {} });
    await mgr.disable247('g1');
    assert.equal(mgr.getSession('g1'), null);
    assert.ok(voice.calls.leave >= 1, 'disable247 must disconnect the voice connection');
    assert.ok(store.saved.some(s => s.patch && s.patch.disabledIntentionally === true));
});

test('a genuinely lost connection is NOT recreated after an intentional 24/7 disable', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(['g1'], { c1: 'Radio' }), { voice, providers: makeProviders({}), store: makeStore() });
    await mgr.enable247('g1', 'c1', { settings: {} });
    await mgr.disable247('g1');
    const joins = voice.calls.join;
    // Simulate a late connection-lost callback.
    await mgr._reload();
    assert.equal(voice.calls.join, joins, 'must not reconnect after an intentional disable');
});

// ── shard ownership ─────────────────────────────────────────────────────────

test('only the node that owns a guild drives its session', () => {
    const mgr = new MusicManager(makeClient(['g1']), { voice: makeVoice(), providers: makeProviders({}), store: makeStore() });
    assert.equal(mgr.ownsGuild('g1'), true);
    assert.equal(mgr.ownsGuild('g2'), false);
});

test('restore skips guilds this node does not own', async () => {
    const voice = makeVoice();
    const rows = [
        { guildId: 'g1', twentyFourSevenEnabled: true, twentyFourSevenChannelId: 'c1', disabledIntentionally: false },
        { guildId: 'g2', twentyFourSevenEnabled: true, twentyFourSevenChannelId: 'c2', disabledIntentionally: false },
    ];
    const mgr = new MusicManager(makeClient(['g1'], { c1: 'Radio' }), { voice, providers: makeProviders({}), store: makeStore(rows) });
    await mgr.restore();
    assert.ok(mgr.getSession('g1'), 'owned guild restored');
    assert.equal(mgr.getSession('g2'), null, 'unowned guild not restored');
});

// ── persistence ─────────────────────────────────────────────────────────────

test('_persist stores the track without the stream URL', async () => {
    const voice = makeVoice();
    const queries = [];
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    // Stub the DB pool used by _persist.
    const musicDb = require('../server/musicDb');
    const origPool = musicDb.musicPool;
    musicDb.musicPool = { query: async (sql, params) => { queries.push(params); return { rows: [], rowCount: 1 }; } };
    try {
        await mgr.play('g1', 'a', { channelId: 'c1' });
        const session = mgr.getSession('g1');
        await mgr._persist(session, {});
        const persisted = JSON.stringify(queries);
        assert.ok(!/stream:\/\//.test(persisted), 'stream URLs must never be persisted');
    } finally {
        musicDb.musicPool = origPool;
    }
});

// ── dashboard page ──────────────────────────────────────────────────────────

test('the Music dashboard page renders with SVG icons and the radio sections', () => {
    const guild = {
        id: '1', name: 'Test', icon: null,
        _config: {
            musicSettings: { twentyFourSevenEnabled: true, twentyFourSevenChannelId: 'c1', djRoleId: 'r1', defaultVolume: 80, maxQueue: 100 },
            musicPlaylists: [{ id: 1, name: 'Chill', isPublic: true, trackCount: 3 }],
            musicHistory: [{ id: 1, title: 'Song', artist: 'Artist', provider: 'soundcloud', requesterId: 'u1', playedAt: new Date() }],
            radioSession: { enabled: true, state: 'playing', channelId: 'c1' },
            radioStations: [{ id: 'global-1', name: 'House', source: 'genre', reference: 'house', enabled: true }],
        },
        _channels: [{ id: 'c1', name: 'Radio', type: 2 }],
        _roles: [{ id: 'r1', name: 'DJ' }],
    };
    const html = guildPages.musicPage({ guild, user: { username: 'u' } });
    assert.match(html, /<svg class="ico"/);
    assert.match(html, /id="mu-247-enabled"/);
    assert.match(html, /id="mu-dj-role"/);
    // Radio sections are embedded (radio lives inside Music).
    assert.match(html, /data-section="stations"/);
    assert.match(html, /data-section="radio"/);
    assert.match(html, /id="rd-enabled"/);
    assert.doesNotMatch(html, /class="icon">[^$<]/);
});

// ── voice-state cache (the "cannot find me in a voice channel" regression) ───

test('the client caches voice states, so member.voice.channel resolves', () => {
    // GuildVoiceStates delivers the voiceStateUpdate EVENT, but the cache is
    // what `member.voice.channel`, `channel.members` and `guild.voiceStates.cache`
    // read. `VoiceStateManager: { maxSize: 0 }` made discord.js drop every voice
    // state on arrival, so the bot could never see anyone in a voice channel —
    // `$join`/`$music play` replied "Join a voice channel first" while the user
    // was sitting in one, and the radio/music listener counts were always 0.
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const block = src.slice(src.indexOf('makeCache: Options.cacheWithLimits('));
    const line = block.match(/VoiceStateManager:\s*\{[^}]*maxSize:\s*([^,}]+)/);
    assert.ok(line, 'VoiceStateManager must be configured explicitly');
    assert.notEqual(line[1].trim(), '0', 'maxSize 0 discards every voice state');
    assert.match(line[1], /Infinity|^\d{3,}$/, 'voice states must actually be retained');

    // Prove the behaviour against the real discord.js cache factory.
    const { Options } = require('discord.js');
    const make = Options.cacheWithLimits({ VoiceStateManager: { maxSize: Infinity } });
    const cache = make('VoiceStateManager', null, { name: 'VoiceStateManager' });
    cache.set('u1', { channelId: 'vc1' });
    assert.equal(cache.get('u1').channelId, 'vc1', 'a cached voice state must be readable');
});

test('listener counting reads the voice-state cache and counts humans only', () => {
    const { MusicManager } = require('../utils/music/musicManager');
    const voiceStates = new Map([
        ['u1', { channelId: 'vc1', member: { user: { bot: false } } }],
        ['u2', { channelId: 'vc1', member: { user: { bot: true } } }],   // bot: ignored
        ['u3', { channelId: 'vc2', member: { user: { bot: false } } }],  // other channel
        ['u4', { channelId: 'vc1', member: null }],                       // uncached: counted
    ]);
    const client = { guilds: { cache: new Map([['g1', {
        voiceStates: { cache: { values: () => voiceStates.values() } },
        channels: { cache: new Map() },
    }]]) } };
    const mgr = new MusicManager(client, { voice: {}, providers: {}, store: null });
    mgr._nodeId = 'n1';
    assert.equal(mgr.countListeners({ guildId: 'g1', channelId: 'vc1' }), 2);
});

// ── zombie voice connection (the "leave succeeds but stays connected" bug) ───

test('a join that never becomes ready destroys its connection and frees the guild', async () => {
    const { getVoiceConnection, joinVoiceChannel } = require('@discordjs/voice');
    const musicVoice = require('../utils/music/musicVoice');
    const adapter = () => ({ sendPayload: () => true, destroy: () => {} });
    const client = { guilds: { cache: new Map([['zg1', {
        id: 'zg1',
        channels: { cache: new Map([['vc1', { id: 'vc1', type: 2 }]]) },
        voiceAdapterCreator: adapter,
    }]]) } };

    const prev = process.env.VOICE_READY_TIMEOUT_MS;
    process.env.VOICE_READY_TIMEOUT_MS = '1000';
    try {
        await assert.rejects(
            () => musicVoice.join({ client, guildId: 'zg1', channelId: 'vc1' }),
            /did not become ready/,
        );
        // The half-open connection must NOT be left tracked — otherwise every
        // later join returns this same wedged object and /leave cannot destroy it.
        assert.equal(getVoiceConnection('zg1'), undefined, 'failed join must free the guild');
    } finally {
        if (prev === undefined) delete process.env.VOICE_READY_TIMEOUT_MS;
        else process.env.VOICE_READY_TIMEOUT_MS = prev;
    }
    // A fresh join after the failure creates a new connection (proves the guild
    // is not wedged to a dead one).
    const fresh = joinVoiceChannel({ guildId: 'zg1', channelId: 'vc1', adapterCreator: adapter, selfDeaf: true });
    assert.equal(fresh.state.status, 'signalling');
    fresh.destroy();
});

test('leave(guildId) disconnects a connection we hold no reference to', () => {
    const { getVoiceConnection, joinVoiceChannel } = require('@discordjs/voice');
    const musicVoice = require('../utils/music/musicVoice');
    const adapter = () => ({ sendPayload: () => true, destroy: () => {} });
    const conn = joinVoiceChannel({ guildId: 'zg2', channelId: 'vc1', adapterCreator: adapter, selfDeaf: true });
    assert.equal(getVoiceConnection('zg2'), conn);
    // This is the /leave + /247 disable path when join() threw and the manager
    // never stored the connection: no reference, so only the registry sweep can
    // disconnect. Before the fix the bot replied success while still connected.
    musicVoice.leave(null, 'zg2');
    assert.equal(getVoiceConnection('zg2'), undefined, 'leave must clear the registry');
});
