/**
 * Linix music integration — regression tests.
 *
 * Covers the features added on top of PrimeBot's existing music engine:
 *   1. real ffmpeg audio filters (not embed-only),
 *   2. autoplay (continues when the queue empties, deduped, never loops),
 *   3. skipto / rewind,
 *   4. filter + autoplay on the manager session,
 *   5. premium embed presentation (progress bar, requester, artwork, filter),
 *   6. queue pagination + filter select menu component limits,
 *   7. lyrics service (no new dependency, bounded),
 *   8. the prefix command routing for the new aliases.
 *
 * The voice layer + providers are mocked (the sandbox has no Discord/voice);
 * the REAL MusicManager and REAL embed/render modules are exercised.
 */

const test = require('node:test');
const assert = require('node:assert');

const { MusicManager, titleSimilarity } = require('../utils/music/musicManager');
const musicFilters = require('../utils/music/musicFilters');
const musicVoice = require('../utils/music/musicVoice');
const ui = require('../utils/music/musicEmbed');
const { progressBar, PLAYBACK_STATES } = require('../shared/musicConstants');
const { fetchLyrics, splitQuery } = require('../utils/music/lyricsService');

// ── mocks ───────────────────────────────────────────────────────────────────

function makeTrack(id, provider = 'soundcloud', extra = {}) {
    return {
        provider, id, title: `Track ${id}`, artist: 'Artist',
        durationMs: 180000, url: `https://example.com/${id}`,
        artworkUrl: `https://img.example/${id}.jpg`, source: 'SoundCloud', ...extra,
    };
}

function makeVoice() {
    const calls = { join: 0, leave: 0, pause: 0, resume: 0, stop: 0, play: 0, destroy: 0, resourceFilters: [] };
    let active = false;
    const listeners = {};
    const player = {
        on: (ev, cb) => { listeners[ev] = listeners[ev] || []; listeners[ev].push(cb); },
        emit: (ev, ...args) => { (listeners[ev] || []).forEach(cb => cb(...args)); },
        play: () => { calls.play++; },
        pause: () => { calls.pause++; },
        unpause: () => { calls.resume++; },
        stop: () => { calls.stop++; },
        state: { status: 'playing', playbackDuration: 0, resource: { volume: { setVolume: () => {} } } },
    };
    return {
        calls, player,
        emit: (ev, ...args) => player.emit(ev, ...args),
        isVoiceChannel: (ch) => !!ch && (ch.type === 2 || ch.type === 13),
        isConnectionActive: () => active,
        getConnectionState: () => ({ connected: active, status: active ? 'ready' : 'destroyed' }),
        join: async () => { calls.join++; active = true; return { _mock: true, destroy: () => { calls.destroy++; active = false; } }; },
        leave: async () => { calls.leave++; active = false; },
        createPlayer: () => player,
        createResource: async (url, opts = {}) => { calls.resourceFilters.push(opts.filter || null); return { volume: { setVolume: () => {} } }; },
        playResource: () => { calls.play++; },
        pausePlayer: () => { calls.pause++; },
        resumePlayer: () => { calls.resume++; },
        stopPlayer: () => { calls.stop++; },
        subscribe: () => {},
        setVolume: () => {},
        getPlaybackPosition: (p) => (p && p.state && p.state.playbackDuration) || 0,
        seekStream: () => ({}),
    };
}

function makeProviders(trackMap, { searchPool = [] } = {}) {
    return {
        streamable: ['youtube', 'soundcloud', 'direct'],
        resolveQuery: async (query) => {
            const t = trackMap[query];
            if (!t) throw new Error(`No results for ${query}`);
            return { ...t };
        },
        searchQuery: async () => searchPool.map(t => ({ ...t })),
        resolveCollection: async (q) => [trackMap[q]].filter(Boolean),
        resolveStream: async (track) => ({ streamUrl: `stream://${track.id}`, kind: 'url' }),
        matchToStreamable: async (t) => t,
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

function makeStore() {
    return {
        getSettings: async () => ({}),
        listEnabledSettings: async () => [],
        list247Settings: async () => [],
        saveSettings: async () => {},
        addHistory: async () => {},
    };
}

// ── 1. real audio filters ───────────────────────────────────────────────────

test('every filter preset maps to a real ffmpeg -af chain (never embed-only)', () => {
    assert.ok(musicFilters.FILTER_LIST.length >= 6, 'a useful filter set exists');
    for (const f of musicFilters.FILTER_LIST) {
        assert.ok(f.id && f.label, 'filter has an id + label');
        assert.ok(Array.isArray(f.args) && f.args.length >= 2, `${f.id} has ffmpeg args`);
        assert.equal(f.args[0], '-af', `${f.id} applies via -af`);
        assert.ok(typeof f.args[1] === 'string' && f.args[1].length > 0, `${f.id} has a filter chain`);
    }
    // The Linix set is represented.
    for (const id of ['bassboost', 'nightcore', 'vaporwave', '8d', 'karaoke', 'equalizer', 'treble']) {
        assert.ok(musicFilters.isFilter(id), `expected filter preset "${id}"`);
    }
});

test('filterArgs rejects unknown ids (never silently applies a wrong chain)', () => {
    assert.deepEqual(musicFilters.filterArgs('definitely-not-a-filter'), []);
    assert.deepEqual(musicFilters.filterArgs(null), []);
    assert.deepEqual(musicFilters.filterArgs('clear'), []);
    assert.deepEqual(musicFilters.filterArgs('bassboost'), musicFilters.FILTERS.bassboost.args);
});

test('buildTranscodeArgs injects the filter chain into the ffmpeg command', () => {
    const args = musicVoice.buildTranscodeArgs('http://src', { seekSeconds: 30, filterArgs: musicFilters.FILTERS.nightcore.args });
    assert.deepEqual(args.slice(0, 2), ['-ss', '30']);
    assert.ok(args.includes('-i') && args.includes('http://src'));
    assert.ok(args.includes('-af'), 'the -af flag is present');
    assert.ok(args.includes(musicFilters.FILTERS.nightcore.args[1]), 'the nightcore chain is present');
    // No filter → no -af.
    const plain = musicVoice.buildTranscodeArgs('http://src', {});
    assert.ok(!plain.includes('-af'));
    // Always ends with the PCM output format.
    assert.deepEqual(args.slice(-7), ['-f', 's16le', '-ar', '48000', '-ac', '2', 'pipe:1']);
});

test('the manager applies the session filter when building the resource', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    await mgr.setFilter('g1', 'bassboost');
    assert.equal(mgr.getSession('g1').filter, 'bassboost');
    assert.ok(voice.calls.resourceFilters.includes('bassboost'), 'the filter reached createResource');
});

test('setFilter rejects an unknown preset and clears on null', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    await assert.rejects(() => mgr.setFilter('g1', 'nope'), /Unknown filter/);
    await mgr.setFilter('g1', '8d');
    assert.equal(mgr.getSession('g1').filter, '8d');
    await mgr.setFilter('g1', null);
    assert.equal(mgr.getSession('g1').filter, null);
});

// ── 2. autoplay ─────────────────────────────────────────────────────────────

test('autoplay queues a related track when the queue empties', async () => {
    const voice = makeVoice();
    const seed = makeTrack('seed', 'youtube', { title: 'Song One', artist: 'Band' });
    const related = makeTrack('related', 'youtube', { title: 'Another Song', artist: 'Band' });
    const providers = makeProviders({ seed }, { searchPool: [related] });
    const mgr = new MusicManager(makeClient(), { voice, providers, store: makeStore() });
    await mgr.play('g1', 'seed', { channelId: 'c1' });
    await mgr.setAutoplay('g1', true);
    const session = mgr.getSession('g1');
    // The queue is empty and the current track ends → autoplay must refill it.
    await mgr._playNext(session);
    const snap = mgr.describe('g1');
    assert.equal(snap.autoplay, true);
    assert.ok(snap.current, 'a related track is now playing');
    assert.notEqual(snap.current.id, 'seed', 'autoplay did not replay the seed');
});

test('autoplay never replays a too-similar title and never loops', async () => {
    const voice = makeVoice();
    const seed = makeTrack('seed', 'youtube', { title: 'Exact Song', artist: 'Band' });
    const clone = makeTrack('clone', 'youtube', { title: 'Exact Song (Official Audio)', artist: 'Band' });
    const providers = makeProviders({ seed }, { searchPool: [clone] });
    const mgr = new MusicManager(makeClient(), { voice, providers, store: makeStore() });
    await mgr.play('g1', 'seed', { channelId: 'c1' });
    await mgr.setAutoplay('g1', true);
    const session = mgr.getSession('g1');
    const added = await mgr._expandAutoplay(session);
    assert.equal(added, 0, 'a re-upload of the same song is rejected');
    assert.ok(titleSimilarity(clone.title, seed.title) >= 0.75, 'the similarity guard is what rejected it');
});

test('autoplay is off by default and can be toggled', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    assert.equal(mgr.getSession('g1').autoplay, false);
    const on = await mgr.setAutoplay('g1', true);
    assert.equal(on.autoplay, true);
    const off = await mgr.setAutoplay('g1', false);
    assert.equal(off.autoplay, false);
});

// ── 3. skipto / rewind ──────────────────────────────────────────────────────

test('skipTo jumps to a queue position and discards everything before it', async () => {
    const voice = makeVoice();
    const providers = makeProviders({ a: makeTrack('a'), b: makeTrack('b'), c: makeTrack('c'), d: makeTrack('d') });
    const mgr = new MusicManager(makeClient(), { voice, providers, store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    await mgr.addToQueue('g1', 'b', { channelId: 'c1' });
    await mgr.addToQueue('g1', 'c', { channelId: 'c1' });
    await mgr.addToQueue('g1', 'd', { channelId: 'c1' });
    assert.equal(mgr.getSession('g1').queue.length, 3);
    const snap = await mgr.skipTo('g1', 2); // skip b, play c
    assert.equal(snap.current.id, 'c');
});

test('skipTo rejects an out-of-range position', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    await assert.rejects(() => mgr.skipTo('g1', 5), /Position must be/);
    await assert.rejects(() => mgr.skipTo('g1', 0), /Position must be/);
});

test('rewind seeks backwards from the current position and clamps at 0', async () => {
    const voice = makeVoice();
    const mgr = new MusicManager(makeClient(), { voice, providers: makeProviders({ a: makeTrack('a') }), store: makeStore() });
    await mgr.play('g1', 'a', { channelId: 'c1' });
    const session = mgr.getSession('g1');
    // Pretend we are 40s in (wall-clock fallback drives positionMs).
    session.startedAt = Date.now() - 40000;
    const before = mgr.positionMs(session);
    const playsBefore = voice.calls.play;
    await mgr.rewind('g1', 10);
    assert.ok(voice.calls.play > playsBefore, 'rewind re-issued playback');
    const after = mgr.positionMs(mgr.getSession('g1'));
    assert.ok(after < before, `rewind moved playback back (${before} -> ${after})`);
    // Near the start, rewinding clamps to 0 instead of going negative.
    session.startedAt = Date.now() - 3000;
    await mgr.rewind('g1', 30);
    assert.ok(mgr.positionMs(mgr.getSession('g1')) >= 0, 'rewind never goes negative');
});

// ── 4. premium embed presentation ───────────────────────────────────────────

test('the Now Playing embed shows artwork, progress, requester, filter and controls', () => {
    const snap = {
        current: { title: 'Song', artist: 'Artist', durationMs: 200000, url: 'https://x', artworkUrl: 'https://img/x.jpg', requesterId: 'u1' },
        positionMs: 60000, durationMs: 200000, volume: 80, repeat: 'track', shuffle: false,
        autoplay: true, filter: 'bassboost', queueLength: 3, state: PLAYBACK_STATES.PLAYING,
        twentyFourSeven: false, listeners: 2, channelId: 'c1',
    };
    const { embed, components } = ui.nowPlaying(snap);
    const json = embed.toJSON();
    assert.ok(json.thumbnail && json.thumbnail.url === 'https://img/x.jpg', 'artwork thumbnail');
    assert.ok(json.description.includes('▬'), 'a progress bar is rendered');
    assert.ok(json.description.includes('1:00 / 3:20'), 'current / total time');
    const fieldNames = json.fields.map(f => f.name);
    for (const name of ['Duration', 'Requester', 'Source', 'Volume', 'Repeat', 'Autoplay', 'Filter', 'Queue']) {
        assert.ok(fieldNames.includes(name), `Now Playing has a "${name}" field`);
    }
    assert.equal(json.fields.find(f => f.name === 'Requester').value, '<@u1>');
    assert.ok(json.fields.find(f => f.name === 'Filter').value.includes('Bass Boost'));
    assert.ok(components[0].components.length <= 5, '≤5 buttons in the control row');
});

test('the control row + second row respect the Discord 5-button limit', () => {
    const first = ui.controlRow({ state: PLAYBACK_STATES.PLAYING }).toJSON();
    const second = ui.secondControlRow({ autoplay: true }).toJSON();
    assert.ok(first.components.length <= 5);
    assert.ok(second.components.length <= 5);
    const ids = second.components.map(c => c.custom_id);
    assert.ok(ids.includes('music_autoplay') && ids.includes('music_lyrics'));
});

test('the queue embed paginates 10 per page with numbers and a total', () => {
    const queue = Array.from({ length: 25 }, (_, i) => makeTrack(`t${i}`));
    const { embed, components } = ui.queueEmbed({ current: makeTrack('now'), queue, queueLength: 25 }, 1);
    const json = embed.toJSON();
    assert.ok(json.footer.text.includes('Page 2/3'), 'page 2 of 3');
    assert.ok(json.description.includes('`11.`'), 'absolute track numbers continue across pages');
    assert.ok(json.footer.text.includes('track(s)'));
    assert.ok(json.footer.text.includes('total'));
    const row = components[0].toJSON();
    assert.equal(row.components.length, 3, 'prev / close / next');
});

test('the search embed lists results and the select menu stays within 25 options', () => {
    const tracks = Array.from({ length: 30 }, (_, i) => makeTrack(`t${i}`, 'youtube', { title: `Song ${i}` }));
    const embed = ui.searchEmbed('query', tracks).toJSON();
    assert.ok(embed.author.name.includes('query'));
    const row = ui.searchSelect(tracks, 'tok').toJSON();
    assert.ok(row.components[0].options.length <= 25, 'select menu ≤25 options');
});

test('the filter picker exposes every preset (≤25 options) and the active one', () => {
    const { embed, components } = ui.filterEmbed('nightcore');
    const json = embed.toJSON();
    assert.ok(json.description.includes('Nightcore'));
    const opts = components[0].toJSON().components[0].options;
    assert.ok(opts.length <= 25);
    assert.ok(opts.some(o => o.value === 'clear'), 'a reset option exists');
    assert.ok(opts.some(o => o.value === 'nightcore' && o.default), 'the active filter is marked');
});

test('the track-info embed carries the detailed fields', () => {
    const json = ui.trackInfoEmbed(makeTrack('x', 'youtube', { requesterId: 'u9' })).toJSON();
    const names = json.fields.map(f => f.name);
    for (const n of ['Artist', 'Duration', 'Source', 'Provider ID', 'Requester', 'URL']) {
        assert.ok(names.includes(n), `track info has "${n}"`);
    }
});

// ── 5. progress bar + lyrics helpers ────────────────────────────────────────

test('progressBar renders proportionally and never fabricates progress', () => {
    const half = progressBar(50000, 100000);
    assert.ok(half.includes('🔘'));
    assert.ok(half.includes('▬'));
    // No duration → a head-only bar, never a fake filled position.
    const unknown = progressBar(1000, 0);
    assert.ok(unknown.startsWith('🔘'));
    assert.equal(progressBar(0, 100000).indexOf('🔘'), 0, 'position 0 puts the head at the start');
});

test('splitQuery separates "Artist - Title"', () => {
    assert.deepEqual(splitQuery('Band - Song'), { artist: 'Band', title: 'Song' });
    assert.deepEqual(splitQuery('Just A Song'), { artist: '', title: 'Just A Song' });
});

test('fetchLyrics returns a structured result and never throws', async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => ({ ok: true, json: async () => ({ lyrics: 'la la la' }) });
    try {
        const res = await fetchLyrics({ track: { title: 'Song', artist: 'Band' } });
        assert.equal(res.lyrics, 'la la la');
    } finally { globalThis.fetch = original; }

    globalThis.fetch = async () => ({ ok: false, status: 404, json: async () => ({}) });
    try {
        const res = await fetchLyrics({ query: 'Band - Missing' });
        assert.equal(res.lyrics, null);
        assert.ok(res.reason, 'a reason is provided instead of throwing');
    } finally { globalThis.fetch = original; }
});

test('fetchLyrics degrades safely when the network fails', async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => { throw new Error('offline'); };
    try {
        const res = await fetchLyrics({ query: 'Whatever' });
        assert.equal(res.lyrics, null);
        assert.match(res.reason, /Could not reach/);
    } finally { globalThis.fetch = original; }
});

// ── 6. prefix command routing for the new aliases ───────────────────────────

function makeHandlerClient() {
    const calls = [];
    const manager = new Proxy({}, {
        get(_t, prop) {
            if (prop === 'getSession') return () => ({ channelId: 'vc1', twentyFourSeven: false, queue: [], djRoleId: null, autoplay: false, filter: null });
            if (prop === 'describe') return () => ({ state: 'playing', queue: [], queueLength: 0, current: { title: 'T', durationMs: 1000, requesterId: 'u1' }, connected: true, volume: 100, repeat: 'off', twentyFourSeven: false, listeners: 1, autoplay: false, filter: null, positionMs: 0 });
            return (...a) => { calls.push(prop); return Promise.resolve({ track: { title: 'T', provider: 'youtube', id: '1' }, queued: false, queueLength: 0, current: { title: 'T' }, volume: 100, repeat: 'off', autoplay: true, filter: 'bassboost', channelId: 'vc1', twentyFourSeven: true, connected: true, state: 'playing', listeners: 1, added: 1, removed: 1, tracks: [] }); };
        },
    });
    const client = {
        user: { id: 'bot' },
        musicManager: manager,
        radioManager: null,
        countingManager: { isCountingChannel: () => false, processCountingMessage: async () => false },
        levelingManager: { processMessage: async () => {} },
        serverSettingsManager: { hasNoPrefixMode: () => false, getGuildPrefix: () => '$', getTriggeredReactions: () => [], getTriggeredResponses: () => [] },
        commands: new Map(),
    };
    return { client, calls };
}

function makeHandlerMessage(content) {
    const replies = [];
    return {
        content,
        author: { id: 'u1', tag: 'u#1', bot: false, send: async () => ({}) },
        member: { id: 'u1', permissions: { has: () => true }, voice: { channelId: 'vc1', channel: { id: 'vc1', type: 2 } }, roles: { cache: new Map() } },
        guild: { id: 'g1', name: 'G' },
        channel: { id: 'ch1', type: 0, send: async () => ({}) },
        mentions: { channels: { first: () => null }, users: { first: () => null } },
        reply: async (payload) => { replies.push(payload); return { edit: async () => ({}), delete: async () => {} }; },
        _replies: replies,
    };
}

test('prefix aliases for the new music features route to the manager', async () => {
    global.botActive = true;
    const handler = require('../events/messageCreate.js');
    const cases = [
        ['$autoplay', 'setAutoplay'],
        ['$ap on', 'setAutoplay'],
        ['$filter', null], // renders the picker (no manager call)
        ['$filter bassboost', 'setFilter'],
        ['$eq clear', 'setFilter'],
        ['$skipto 2', 'skipTo'],
        ['$jump 3', 'skipTo'],
        ['$rewind 15', 'rewind'],
        ['$track', null], // describe-only
    ];
    for (const [content, expected] of cases) {
        const { client, calls } = makeHandlerClient();
        const msg = makeHandlerMessage(content);
        await handler.execute(msg, client);
        assert.ok(msg._replies.length >= 1, `${content} must reply (was silently ignored)`);
        if (expected) assert.ok(calls.includes(expected), `${content} should call ${expected} (got ${calls.join(',') || 'none'})`);
    }
});

test('an unknown filter name is rejected without touching the manager', async () => {
    global.botActive = true;
    const handler = require('../events/messageCreate.js');
    const { client, calls } = makeHandlerClient();
    const msg = makeHandlerMessage('$filter not-a-real-filter');
    await handler.execute(msg, client);
    assert.ok(!calls.includes('setFilter'), 'an unknown filter must not reach setFilter');
    const body = JSON.stringify(msg._replies[0]);
    assert.ok(/Unknown filter/.test(body), 'a helpful error is shown');
});
