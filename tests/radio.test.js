/**
 * 24/7 Radio regression tests.
 *
 * Drives the REAL RadioManager state machine with a mocked voice layer and a
 * mocked SoundCloud source, so the critical behaviour — pause on empty channel,
 * STAY CONNECTED, resume on join, manual pause not overridden — is asserted
 * without a real Discord gateway or ffmpeg process.
 *
 * The eleven scenarios map onto the task's numbered test list.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const { RadioManager, dedupeTracks, stripTrackForPersist } = require('../utils/radioManager');
const { STATION_SOURCES, RADIO_STATES, normalizeStation } = require('../shared/radioConstants');
const { BUILTIN_STATIONS } = require('../utils/radioStations');

// ── fake collaborators ───────────────────────────────────────────────────────

function fakeVoice() {
    const created = { players: [], joins: 0, leaves: 0, resources: [] };
    return {
        created,
        isVoiceChannel: (c) => !!c && (c.type === 2 || c.type === 13),
        isConnectionActive: (conn) => !!conn && conn.active === true,
        getConnectionState: (conn) => ({ connected: !!conn && conn.active === true, status: conn && conn.active ? 'ready' : 'destroyed' }),
        async join({ channelId }) {
            created.joins++;
            return { active: true, channelId, destroyed: false, destroy() { this.active = false; this.destroyed = true; } };
        },
        leave(conn) { if (conn) { created.leaves++; conn.active = false; conn.destroyed = true; } },
        createPlayer({ onIdle, onError }) {
            const p = {
                state: { status: 'idle', resource: null }, _onIdle: onIdle, _onError: onError,
                play(r) { this.state.resource = r; this.state.status = 'playing'; },
                pause() { this.state.status = 'paused'; },
                stop() { this.state.status = 'idle'; },
            };
            created.players.push(p);
            return p;
        },
        createResource(url, { track } = {}) { created.resources.push({ url, track }); return { url, track, volume: { setVolume() {} } }; },
        playResource(player, resource) { player.play(resource); },
        pausePlayer(player) { if (player) player.pause(); },
        stopPlayer(player) { if (player) player.stop(); },
        destroyPlayer(player) { if (player) player.stop(); },
        subscribe() { return {}; },
        setVolume() {},
        // Test helper: simulate the track finishing (fires the Idle handler).
        finish(player) { player.state.status = 'idle'; player._onIdle && player._onIdle(); },
        fail(player, err) { player._onError && player._onError(err || new Error('stream failed')); },
    };
}

function fakeSource() {
    let counter = 0;
    const calls = { resolveStreamUrl: 0 };
    return {
        calls,
        resetClient() {},
        async resolveStreamUrl(track) {
            calls.resolveStreamUrl++;
            // Emulate a short-lived URL — the value is different each resolve.
            return { streamUrl: `https://cdn.example/stream-${++counter}.m3u8`, trackAuthorization: 'tok', durationMs: track.durationMs };
        },
    };
}

function fakeClient({ guildId = 'g1', listeners = 2 } = {}) {
    const members = { size: listeners, filter: (fn) => ({ size: listeners }) };
    // A channel whose members collection reports `size` and honours filter().
    const channel = { id: 'vc1', type: 2, get members() { return { size: listeners, filter: () => ({ size: listeners }) }; } };
    const guild = { id: guildId, channels: { cache: new Map([['vc1', channel]]) }, voiceAdapterCreator: () => {} };
    return {
        guilds: { cache: new Map([[guildId, guild]]) },
        _setListeners(n) { listeners = n; },
        _channel: channel,
    };
}

function fakeStations(tracks) {
    const station = { id: 'test-station', name: 'Test', source: STATION_SOURCES.GENRE, reference: 'test', enabled: true, guildId: null };
    return {
        get: (id) => (id === 'test-station' ? station : null),
        listForGuild: () => [station],
        async resolveTracks() { return tracks; },
    };
}

function makeTracks(n) {
    return Array.from({ length: n }, (_, i) => ({
        id: String(1000 + i), title: `Track ${i}`, url: `https://soundcloud.com/x/track-${i}`,
        durationMs: 180000, genre: 'Test', artworkUrl: null, artist: { id: 1, username: 'artist', profileUrl: null },
    }));
}

// The manager holds the SAME `radioPool` object reference captured at require
// time, so we mutate that object in place (no cache juggling) — both
// ensureRadioTables and _persist go through `radioPool.query`.
function stubDb(sessionRows = []) {
    const mod = require('../server/radioDb');
    const original = mod.radioPool.query;
    const rows = [];
    mod.radioPool.query = async (sql, params) => {
        if (/SELECT \* FROM radio_sessions WHERE enabled = true/i.test(sql)) return { rows: sessionRows };
        if (/INSERT INTO radio_sessions/i.test(sql)) { rows.push({ sql, params }); return { rowCount: 1, rows: [] }; }
        if (/SELECT \* FROM radio_stations/i.test(sql)) return { rows: [] };
        return { rows: [] };
    };
    return { rows, restore: () => { mod.radioPool.query = original; } };
}

function makeManager(overrides = {}) {
    const client = overrides.client || fakeClient();
    const voice = overrides.voice || fakeVoice();
    const source = overrides.source || fakeSource();
    const stations = overrides.stations || fakeStations(makeTracks(3));
    const mgr = new RadioManager(client, { voice, source, stations, nodeId: 'node-test', autoReload: false });
    return { mgr, client, voice, source, stations };
}

// ── 1 & 2: start → connect → play ────────────────────────────────────────────

test('1-2: start connects, loads the station and plays when listeners are present', async () => {
    const db = stubDb();
    try {
        const { mgr, voice } = makeManager();
        const status = await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        assert.equal(voice.created.joins, 1, 'one voice connection created');
        assert.equal(voice.created.players.length, 1, 'exactly one player (no duplicates)');
        assert.equal(status.connected, true);
        assert.equal(status.playing, true);
        assert.equal(status.state, RADIO_STATES.PLAYING);
        assert.ok(status.currentTrack && status.currentTrack.id, 'a real resolved track is playing');
    } finally { db.restore(); }
});

test('start rejects a non-voice channel and a guild this node does not own', async () => {
    const db = stubDb();
    try {
        const { mgr } = makeManager();
        await assert.rejects(() => mgr.start('g1', 'nope'), /valid voice channel/);
        // A guild not in the client cache is not owned by this node.
        await assert.rejects(() => mgr.start('g-other', 'vc1'), /does not own/);
    } finally { db.restore(); }
});

// ── 3, 4, 5: everyone leaves → pause, stay connected ─────────────────────────

test('3-5: when everyone leaves, playback PAUSES and the connection STAYS alive', async () => {
    const db = stubDb();
    try {
        const { mgr, client, voice } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        const connectionBefore = session.connection;
        assert.equal(voice.created.joins, 1);

        client._setListeners(0);
        await mgr.handleVoiceStateUpdate(
            { guild: { id: 'g1' }, channelId: 'vc1' },
            { guild: { id: 'g1' }, channelId: null }
        );

        assert.equal(session.state, RADIO_STATES.PAUSED_EMPTY, 'paused because the channel is empty');
        assert.equal(session.player.state.status, 'paused', 'the audio player is paused');
        assert.equal(session.connection, connectionBefore, 'the SAME connection is kept');
        assert.equal(voice.created.leaves, 0, 'the bot did NOT disconnect');
        assert.equal(voice.created.joins, 1, 'the connection was NOT recreated');
        assert.ok(session.currentTrack, 'the current track is preserved');
        assert.ok(session.queue.length > 0, 'the queue is preserved');
        assert.equal(session.stationId, 'test-station', 'the station is preserved');
    } finally { db.restore(); }
});

// ── 6, 7: a listener joins → resume ──────────────────────────────────────────

test('6-7: a listener joining RESUMES playback on the existing connection', async () => {
    const db = stubDb();
    try {
        const { mgr, client, voice } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        client._setListeners(0);
        await mgr.handleVoiceStateUpdate({ guild: { id: 'g1' }, channelId: 'vc1' }, { guild: { id: 'g1' }, channelId: null });
        assert.equal(session.state, RADIO_STATES.PAUSED_EMPTY);

        client._setListeners(1);
        await mgr.handleVoiceStateUpdate({ guild: { id: 'g1' }, channelId: null }, { guild: { id: 'g1' }, channelId: 'vc1' });

        assert.equal(session.state, RADIO_STATES.PLAYING, 'playback resumed');
        assert.equal(voice.created.joins, 1, 'no duplicate connection');
        assert.equal(voice.created.players.length, 1, 'no duplicate player');
    } finally { db.restore(); }
});

test('a voice-state update for a DIFFERENT channel is ignored', async () => {
    const db = stubDb();
    try {
        const { mgr, client } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        client._setListeners(0);
        // Someone joins a different voice channel — must not affect radio.
        await mgr.handleVoiceStateUpdate({ guild: { id: 'g1' }, channelId: null }, { guild: { id: 'g1' }, channelId: 'other-vc' });
        assert.equal(session.state, RADIO_STATES.PLAYING, 'unrelated channel activity is ignored');
    } finally { db.restore(); }
});

// ── 8, 9: leave again → pause, no disconnect ─────────────────────────────────

test('8-9: emptying again pauses without ever disconnecting', async () => {
    const db = stubDb();
    try {
        const { mgr, client, voice } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        client._setListeners(1);
        await mgr.handleVoiceStateUpdate({ guild: { id: 'g1' }, channelId: null }, { guild: { id: 'g1' }, channelId: 'vc1' });
        client._setListeners(0);
        await mgr.handleVoiceStateUpdate({ guild: { id: 'g1' }, channelId: 'vc1' }, { guild: { id: 'g1' }, channelId: null });
        assert.equal(session.state, RADIO_STATES.PAUSED_EMPTY);
        assert.equal(voice.created.leaves, 0, 'still connected');
        assert.equal(voice.created.joins, 1, 'connection never recreated');
    } finally { db.restore(); }
});

// ── 10, 11, 12: manual pause is not overridden by a join ─────────────────────

test('10-12: a manual pause survives a listener joining; resume clears it', async () => {
    const db = stubDb();
    try {
        const { mgr, client } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');

        await mgr.pause('g1');
        assert.equal(session.manualPause, true);
        assert.equal(session.state, RADIO_STATES.PAUSED_MANUAL);

        // A listener joins — playback must STAY paused (admin intent wins).
        client._setListeners(2);
        await mgr.handleVoiceStateUpdate({ guild: { id: 'g1' }, channelId: null }, { guild: { id: 'g1' }, channelId: 'vc1' });
        assert.equal(session.state, RADIO_STATES.PAUSED_MANUAL, 'a join does not override a manual pause');
        assert.equal(session.player.state.status, 'paused');

        // An explicit resume clears it and plays.
        await mgr.resume('g1');
        assert.equal(session.manualPause, false);
        assert.equal(session.state, RADIO_STATES.PLAYING);
    } finally { db.restore(); }
});

test('manual pause while empty keeps PAUSED_MANUAL through an empty-channel event', async () => {
    const db = stubDb();
    try {
        const { mgr, client } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        await mgr.pause('g1');
        client._setListeners(0);
        await mgr.handleVoiceStateUpdate({ guild: { id: 'g1' }, channelId: 'vc1' }, { guild: { id: 'g1' }, channelId: null });
        assert.equal(session.state, RADIO_STATES.PAUSED_MANUAL, 'manual pause is preserved, not downgraded');
    } finally { db.restore(); }
});

// ── 13: track finishes → next track starts ───────────────────────────────────

test('13: a finished track advances to the next track', async () => {
    const db = stubDb();
    try {
        const { mgr, voice } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        const first = session.currentTrack.id;
        voice.finish(session.player);
        // _advance is async; let the microtask queue drain.
        await new Promise(r => setImmediate(r));
        await new Promise(r => setImmediate(r));
        assert.notEqual(session.currentTrack.id, first, 'advanced to a different track');
        assert.equal(session.state, RADIO_STATES.PLAYING);
    } finally { db.restore(); }
});

test('13b: a duplicate track-end event does not double-advance', async () => {
    const db = stubDb();
    try {
        const { mgr, voice } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        const startIdx = session.positionIndex;
        // Fire the Idle handler TWICE in the same tick (the classic duplicate
        // event) — the synchronous `_advancing` guard must let only one through.
        voice.finish(session.player);
        voice.finish(session.player);
        await new Promise(r => setImmediate(r));
        await new Promise(r => setImmediate(r));
        const advancedBy = (session.positionIndex - startIdx + session.queue.length) % session.queue.length;
        assert.equal(advancedBy, 1, 'only advanced ONE track despite two end events');
    } finally { db.restore(); }
});

test('an empty queue reloads the station so playback continues', async () => {
    const db = stubDb();
    try {
        const { mgr } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        session.queue = [];
        await mgr.skip('g1');
        assert.ok(session.queue.length > 0, 'queue refilled from the station');
        assert.equal(session.state, RADIO_STATES.PLAYING);
    } finally { db.restore(); }
});

// ── 14: a track fails → skip safely, radio keeps going ───────────────────────

test('14: an unplayable track is skipped after bounded retries; radio keeps playing', async () => {
    const db = stubDb();
    try {
        let failCount = 0;
        const source = fakeSource();
        const realResolve = source.resolveStreamUrl.bind(source);
        source.resolveStreamUrl = async (track) => {
            // Fail the FIRST track every time it is resolved.
            if (String(track.id) === '1000') { failCount++; throw new Error('410 Gone'); }
            return realResolve(track);
        };
        const { mgr, voice } = makeManager({ source });
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        // The first track failed on start; the manager should have skipped it.
        assert.ok(failCount >= 1, 'the bad track was attempted');
        assert.notEqual(String(session.currentTrack.id), '1000', 'the bad track was skipped');
        assert.equal(session.state, RADIO_STATES.PLAYING, 'radio did not stop because one stream failed');
    } finally { db.restore(); }
});

test('14b: bounded retries — a permanently failing track does not loop forever', async () => {
    const db = stubDb();
    try {
        let attempts = 0;
        const source = { resetClient() {}, async resolveStreamUrl() { attempts++; throw new Error('expired'); } };
        // Single-track station so every resolve fails.
        const stations = fakeStations([{ id: '9999', title: 'Broken', url: 'https://soundcloud.com/x/broken', durationMs: 1000 }]);
        const { mgr } = makeManager({ source, stations });
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        // MAX_TRACK_RETRIES (2) retries of the same track, then a skip that also
        // fails and retries — bounded, not infinite.
        assert.ok(attempts <= 6, `attempts must be bounded, got ${attempts}`);
        assert.ok(attempts >= 1);
    } finally { db.restore(); }
});

// ── 15: expired stream URL is re-resolved ────────────────────────────────────

test('15: an expired stream URL is re-resolved on every play (never reused)', async () => {
    const db = stubDb();
    try {
        const { mgr, voice, source } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        const firstUrl = voice.created.resources[voice.created.resources.length - 1].url;
        voice.finish(session.player);
        await new Promise(r => setImmediate(r));
        await new Promise(r => setImmediate(r));
        const secondUrl = voice.created.resources[voice.created.resources.length - 1].url;
        assert.notEqual(firstUrl, secondUrl, 'a fresh stream URL was resolved for the next track');
        assert.ok(source.calls.resolveStreamUrl >= 2, 'resolveStreamUrl called again');
    } finally { db.restore(); }
});

test('15b: the persisted current track never contains a stream URL', async () => {
    const db = stubDb();
    try {
        const { mgr } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        assert.equal(session.currentTrack.streamUrl, undefined, 'no stream URL persisted');
        const inserts = db.rows.filter(r => /INSERT INTO radio_sessions/i.test(r.sql));
        assert.ok(inserts.length > 0);
        for (const ins of inserts) {
            const serialized = JSON.stringify(ins.params);
            assert.ok(!/m3u8/.test(serialized), 'no HLS URL in persisted params');
            assert.ok(!/track_authorization/i.test(serialized), 'no track authorization in persisted params');
        }
    } finally { db.restore(); }
});

// ── 16, 17: voice connection genuinely drops → recover ───────────────────────

test('16-17: a real voice disconnect triggers a bounded reconnect', async () => {
    const db = stubDb();
    try {
        const { mgr, voice } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const session = mgr.getSession('g1');
        // Simulate the connection dropping (our fake calls onDisconnect).
        session.reconnecting = false;
        mgr._onConnectionLost(session);
        assert.equal(session.reconnecting, true, 'reconnect scheduled');
        // Two overlapping drops must not stack reconnect loops.
        mgr._onConnectionLost(session);
        assert.equal(session.reconnecting, true);
    } finally { db.restore(); }
});

// ── 18, 19: restart → restore ────────────────────────────────────────────────

test('18-19: after a restart the session is restored (connection recreated, resumes with listeners)', async () => {
    const db = stubDb([{
        guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: true,
        manual_pause: false, current_track: { id: '1001', title: 'Track 1' },
        position_index: 1, queue: [{ id: '1001', title: 'Track 1', url: 'https://soundcloud.com/x/1' }],
        state: 'playing', owner_node: 'node-test',
    }]);
    try {
        const { mgr, voice } = makeManager();
        await mgr.waitForReady();
        assert.ok(mgr.getSession('g1'), 'session loaded from the database');
        await mgr.restore();
        assert.equal(voice.created.joins, 1, 'voice connection was RECREATED after restart');
        const session = mgr.getSession('g1');
        assert.equal(session.connection !== null, true);
        assert.equal(session.state, RADIO_STATES.PLAYING, 'playback restored because listeners are present');
    } finally { db.restore(); }
});

test('19b: after a restart an empty channel stays connected-but-paused', async () => {
    const db = stubDb([{
        guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: true,
        manual_pause: false, current_track: null, position_index: 0, queue: [], state: 'paused_empty', owner_node: 'node-test',
    }]);
    try {
        const client = fakeClient({ listeners: 0 });
        const { mgr, voice } = makeManager({ client });
        await mgr.waitForReady();
        await mgr.restore();
        const session = mgr.getSession('g1');
        assert.equal(voice.created.joins, 1, 'connected even with nobody listening');
        assert.equal(session.state, RADIO_STATES.PAUSED_EMPTY, 'waiting for listeners, not playing');
        assert.equal(voice.created.leaves, 0, 'did not disconnect');
    } finally { db.restore(); }
});

// ── 20: multiple guilds are independent ──────────────────────────────────────

test('20: multiple guilds run independent radio sessions', async () => {
    const db = stubDb();
    try {
        const client = fakeClient({ guildId: 'g1' });
        // Add a second guild + channel.
        const ch2 = { id: 'vc2', type: 2, members: { size: 2, filter: () => ({ size: 2 }) } };
        client.guilds.cache.set('g2', { id: 'g2', channels: { cache: new Map([['vc2', ch2]]) }, voiceAdapterCreator: () => {} });
        const { mgr, voice } = makeManager({ client });
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        await mgr.start('g2', 'vc2', { stationId: 'test-station' });
        assert.equal(mgr.sessions.size, 2);
        assert.equal(voice.created.joins, 2, 'two independent connections');
        assert.notEqual(mgr.getSession('g1').connection, mgr.getSession('g2').connection);
        // Stopping one guild leaves the other alone.
        await mgr.stop('g1');
        assert.equal(mgr.getSession('g1'), null);
        assert.ok(mgr.getSession('g2'), 'the other guild is untouched');
    } finally { db.restore(); }
});

// ── 21: shard safety — only the owning node drives a session ─────────────────

test('21: a node without the guild cached does not start playback (no duplicate sessions)', async () => {
    const db = stubDb();
    try {
        // This node's client has NO guilds cached → owns nothing.
        const emptyClient = { guilds: { cache: new Map() } };
        const { mgr, voice } = makeManager({ client: emptyClient });
        await assert.rejects(() => mgr.start('g1', 'vc1'), /does not own/);
        assert.equal(voice.created.joins, 0, 'no voice connection on a non-owner node');
    } finally { db.restore(); }
});

test('21b: a session owned by another live node is not taken over', async () => {
    const db = stubDb([{
        guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: true,
        manual_pause: false, current_track: null, position_index: 0, queue: [], state: 'playing', owner_node: 'node-other',
    }]);
    try {
        const { mgr } = makeManager();
        await mgr.waitForReady();
        const session = mgr.getSession('g1');
        // Pretend the other node's connection is live.
        session.connection = { active: true };
        await assert.rejects(() => mgr.start('g1', 'vc1'), /another node/);
    } finally { db.restore(); }
});

test('21c: the owning node claims the session (owner_node is written)', async () => {
    const db = stubDb();
    try {
        const { mgr } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        assert.equal(mgr.getSession('g1').ownerNode, 'node-test');
    } finally { db.restore(); }
});

// ── stop: cleanup ────────────────────────────────────────────────────────────

test('stop destroys the player, disconnects and clears the session', async () => {
    const db = stubDb();
    try {
        const { mgr, voice } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const ok = await mgr.stop('g1');
        assert.equal(ok, true);
        assert.equal(voice.created.leaves, 1, 'disconnected');
        assert.equal(mgr.getSession('g1'), null, 'session cleared');
    } finally { db.restore(); }
});

test('skip and setStation work through the public API', async () => {
    const db = stubDb();
    try {
        const { mgr } = makeManager();
        await mgr.start('g1', 'vc1', { stationId: 'test-station' });
        const before = mgr.getSession('g1').currentTrack.id;
        const after = await mgr.skip('g1');
        assert.notEqual(after.currentTrack.id, before);
        const res = await mgr.setStation('g1', 'test-station');
        assert.equal(res.stationId, 'test-station');
        await assert.rejects(() => mgr.setStation('g1', 'does-not-exist'), /Unknown or disabled/);
    } finally { db.restore(); }
});

// ── unit helpers + catalog ───────────────────────────────────────────────────

test('dedupeTracks removes duplicate ids while preserving order', () => {
    const out = dedupeTracks([{ id: '1' }, { id: '2' }, { id: '1' }, { id: '3' }]);
    assert.deepEqual(out.map(t => t.id), ['1', '2', '3']);
});

test('stripTrackForPersist keeps metadata but drops nothing stable', () => {
    const s = stripTrackForPersist({ id: 5, title: 'T', url: 'u', durationMs: 1, genre: 'g', artworkUrl: 'a', artist: { id: 9, username: 'x' }, streamUrl: 'secret' });
    assert.equal(s.streamUrl, undefined);
    assert.equal(s.id, '5');
    assert.equal(s.artist.username, 'x');
});

test('built-in stations are real SoundCloud sources, never fake tracks', () => {
    assert.ok(BUILTIN_STATIONS.length >= 3);
    for (const s of BUILTIN_STATIONS) {
        const n = normalizeStation(s);
        assert.equal(n.ok, true, `station ${s.id} must be valid: ${n.error}`);
        assert.ok(s.reference && s.reference.length > 0);
    }
});

// ── static: the radio must never disconnect on empty ─────────────────────────

test('the radio manager never calls leave() from the empty-channel path', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils', 'radioManager.js'), 'utf8');
    // handleVoiceStateUpdate must not contain a leave/destroy call.
    const fn = src.match(/async handleVoiceStateUpdate\([\s\S]*?\n    \}/)[0];
    assert.ok(!/\.leave\(|destroy\(/.test(fn), 'the empty-channel handler must not disconnect');
    assert.match(fn, /_pausePlayer/, 'it must pause instead');
});

test('the manager re-resolves the stream URL (never plays a persisted one)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils', 'radioManager.js'), 'utf8');
    assert.match(src, /resolveStreamUrl/, 'playback resolves a fresh stream URL');
});

// ── dashboard-driven reload (enable / disable / channel change) ──────────────

// A stub that lets the test control the FULL radio_sessions table (the reload
// path reads every row, not just enabled ones).
function stubReloadDb() {
    const mod = require('../server/radioDb');
    const original = mod.radioPool.query;
    const state = { rows: [] };
    mod.radioPool.query = async (sql) => {
        if (/SELECT \* FROM radio_sessions/i.test(sql)) return { rows: state.rows };
        if (/SELECT \* FROM radio_stations/i.test(sql)) return { rows: [] };
        return { rows: [], rowCount: 1 };
    };
    return { state, restore: () => { mod.radioPool.query = original; } };
}

test('reload: an enabled row added from the dashboard is claimed and started', async () => {
    const db = stubReloadDb();
    try {
        const { mgr, voice } = makeManager();
        await mgr.waitForReady();
        assert.equal(mgr.getSession('g1'), null);
        db.state.rows = [{ guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: true, manual_pause: false, state: 'connecting', volume: 100, queue: [] }];
        const changed = await mgr._refreshFromDatabase();
        assert.equal(changed, true);
        // The connect/play is kicked off asynchronously; give it a tick.
        await new Promise(r => setImmediate(r));
        assert.ok(mgr.getSession('g1'), 'session created');
        assert.ok(voice.created.joins >= 1, 'connected to the channel');
    } finally { db.restore(); }
});

test('reload: disabling the row tears the session down and disconnects', async () => {
    const db = stubReloadDb();
    try {
        const { mgr, voice } = makeManager();
        await mgr.waitForReady();
        db.state.rows = [{ guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: true, manual_pause: false, state: 'playing', volume: 100, queue: [] }];
        await mgr._refreshFromDatabase();
        await new Promise(r => setImmediate(r));
        assert.ok(mgr.getSession('g1'));

        db.state.rows = [{ guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: false, manual_pause: false, state: 'stopped', volume: 100, queue: [] }];
        const changed = await mgr._refreshFromDatabase();
        assert.equal(changed, true);
        await new Promise(r => setImmediate(r));
        assert.equal(mgr.getSession('g1'), null, 'session cleared');
        assert.ok(voice.created.leaves >= 1, 'disconnected');
    } finally { db.restore(); }
});

test('reload: a channel change reconnects the session', async () => {
    const db = stubReloadDb();
    try {
        const { mgr, voice } = makeManager();
        await mgr.waitForReady();
        db.state.rows = [{ guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: true, manual_pause: false, state: 'playing', volume: 100, queue: [] }];
        await mgr._refreshFromDatabase();
        await new Promise(r => setImmediate(r));
        const joinsBefore = voice.created.joins;
        db.state.rows = [{ guild_id: 'g1', channel_id: 'vc2', station_id: 'test-station', enabled: true, manual_pause: false, state: 'playing', volume: 100, queue: [] }];
        const changed = await mgr._refreshFromDatabase();
        assert.equal(changed, true);
        await new Promise(r => setImmediate(r));
        assert.ok(voice.created.joins > joinsBefore, 'reconnected on the new channel');
        assert.equal(mgr.getSession('g1').channelId, 'vc2');
    } finally { db.restore(); }
});

test('reload: a quiet table reports no change (so the poller backs off)', async () => {
    const db = stubReloadDb();
    try {
        const { mgr } = makeManager();
        await mgr.waitForReady();
        db.state.rows = [{ guild_id: 'g1', channel_id: 'vc1', station_id: 'test-station', enabled: true, manual_pause: false, state: 'playing', volume: 100, queue: [] }];
        await mgr._refreshFromDatabase();
        await new Promise(r => setImmediate(r));
        const again = await mgr._refreshFromDatabase();
        assert.equal(again, false, 'no change on the second pass');
    } finally { db.restore(); }
});
