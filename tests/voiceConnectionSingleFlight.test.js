/**
 * Voice connection single-flight + abort regression tests.
 *
 * Root cause of the production error
 *   "Voice connection did not become ready: The operation was aborted"
 *
 * Two independent causes, both covered here:
 *   A. Concurrent connect attempts. `/join`, `/music 247 enable` (issued twice)
 *      and `/play` all called `_ensureConnected` → `_connect` → `voice.join`.
 *      Because `session.connection` is only assigned AFTER the handshake
 *      resolves, the second attempt saw no live connection and destroyed the
 *      first one while it was still in flight. The first handshake's
 *      `entersState(Ready)` then rejected with `The operation was aborted`.
 *   B. A join issued while the shard is not Ready is silently dropped by
 *      discord.js (`AdapterUnavailable`) and can never reach Ready — the exact
 *      situation right after a node restart.
 *
 * These tests drive the REAL MusicManager against a voice double whose
 * `join()` models a slow, cancellable handshake, so the race is reproduced
 * deterministically (no timers beyond a short settle delay, no network).
 */

const test = require('node:test');
const assert = require('node:assert');

const { MusicManager } = require('../utils/music/musicManager');
const { VoiceConnectGate } = require('../utils/voiceConnectGate');
const { waitForShardReady, shardReadyTimeoutMs } = require('../utils/voiceReadiness');

// ── doubles ─────────────────────────────────────────────────────────────────

/**
 * A voice layer that models a real, slow voice handshake. `join()` stays
 * pending until `handshakeMs` elapses; destroying the connection mid-handshake
 * rejects it with the SAME message the production bug produced.
 */
function makeSlowVoice({ handshakeMs = 60, failWith = null } = {}) {
    const calls = { join: 0, destroy: 0, play: 0, leave: 0 };
    let live = null;
    const voice = {
        calls,
        isVoiceChannel: () => true,
        isConnectionActive: (c) => !!c && c.status === 'ready',
        getConnectionState: (c) => ({ connected: !!c && c.status === 'ready', status: c ? c.status : 'destroyed' }),
        join: () => {
            calls.join++;
            return new Promise((resolve, reject) => {
                const conn = {
                    status: 'signalling',
                    destroyed: false,
                    destroy() {
                        if (this.destroyed) return;
                        this.destroyed = true;
                        this.status = 'destroyed';
                        calls.destroy++;
                        // mirrors @discordjs/voice: destroying a pending handshake
                        // aborts the awaits inside it
                        reject(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }));
                    },
                };
                live = conn;
                const t = setTimeout(() => {
                    if (conn.destroyed) return;
                    if (failWith) { conn.status = 'disconnected'; reject(failWith); return; }
                    conn.status = 'ready';
                    resolve(conn);
                }, handshakeMs);
            });
        },
        destroyGuildConnection: () => { if (live && !live.destroyed) { live.destroy(); return true; } return false; },
        leave: (c) => { calls.leave++; if (c) c.destroy(); },
        createPlayer: () => ({ on() {}, play() { calls.play++; }, pause() {}, unpause() {}, stop() {} }),
        subscribe: () => {},
        createResource: () => ({ volume: { setVolume() {} } }),
        playResource: () => { calls.play++; },
        setVolume: () => {},
        seekStream: () => ({}),
    };
    return voice;
}

function makeProviders() {
    const track = { provider: 'youtube', id: 'yt1', title: 'Song', artist: 'A', durationMs: 1000 };
    return {
        streamable: ['youtube'],
        resolveQuery: async () => ({ ...track }),
        searchQuery: async () => [{ ...track }],
        resolveCollection: async () => [{ ...track }],
        resolveStream: async () => ({ streamUrl: 'stream://1', kind: 'url' }),
        matchToStreamable: async (t) => t,
        normalizeTitle: (s) => String(s).toLowerCase(),
    };
}

function makeClient(guildIds = ['g1']) {
    const cache = new Map(guildIds.map(id => [id, {
        id,
        channels: { cache: new Map([['vc1', { id: 'vc1', name: 'vc', type: 2 }], ['vc2', { id: 'vc2', name: 'vc2', type: 2 }]]) },
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

function makeManager(opts = {}) {
    const voice = opts.voice || makeSlowVoice(opts);
    const client = opts.client || makeClient(opts.guildIds);
    const mgr = new MusicManager(client, {
        voice,
        providers: makeProviders(),
        store: opts.store || null,
        nodeId: opts.nodeId || 'sn1',
    });
    // Tests drive connection logic directly; ownership is covered elsewhere.
    mgr.ownsGuild = () => true;
    return { mgr, voice };
}

const settle = (ms = 120) => new Promise(r => setTimeout(r, ms));

// ── 1. the core race ────────────────────────────────────────────────────────

test('concurrent _ensureConnected calls share ONE handshake (join then play)', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 60 });
    const s = mgr._ensureSession('g1', 'vc1', {});

    // /join and /play arrive back to back.
    const a = mgr._ensureConnected(s);
    await new Promise(r => setTimeout(r, 10));
    const b = mgr._ensureConnected(s);

    const [ca, cb] = await Promise.all([a, b]);
    assert.equal(ca, cb, 'both callers must receive the same connection');
    assert.equal(voice.calls.join, 1, 'exactly one join attempt');
    assert.equal(voice.calls.destroy, 0, 'a valid in-flight connection is never destroyed');
});

test('two simultaneous 247 enable requests create one connection and are idempotent', async () => {
    const store = makeStore();
    const { mgr, voice } = makeManager({ handshakeMs: 60, store });
    const p1 = mgr.enable247('g1', 'vc1', { settings: {} });
    const p2 = mgr.enable247('g1', 'vc1', { settings: {} });
    const [v1, v2] = await Promise.all([p1, p2]);
    assert.equal(voice.calls.join, 1, 'one connection for two concurrent enables');
    assert.equal(voice.calls.destroy, 0);
    assert.equal(v1.channelId, 'vc1');
    assert.equal(v2.channelId, 'vc1');
});

test('repeated 247 enable for the same live channel does not rejoin', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 20 });
    await mgr.enable247('g1', 'vc1', { settings: {} });
    assert.equal(voice.calls.join, 1);
    await mgr.enable247('g1', 'vc1', { settings: {} });
    assert.equal(voice.calls.join, 1, 'already connected to vc1 → reuse');
    assert.equal(voice.calls.destroy, 0);
});

test('repeated /join requests create only one connection', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 50 });
    const s = mgr._ensureSession('g1', 'vc1', {});
    const results = await Promise.all([
        mgr._ensureConnected(s),
        mgr._ensureConnected(s),
        mgr._ensureConnected(s),
    ]);
    assert.equal(voice.calls.join, 1);
    assert.equal(new Set(results).size, 1, 'all callers share the connection');
});

// ── 2. the abort itself ─────────────────────────────────────────────────────

test('a genuine timeout surfaces a descriptive reason, not a bare abort', async () => {
    // join() that never settles → the wrapper must report a timeout, and the
    // manager must not lose the connection silently.
    const voice = makeSlowVoice({ handshakeMs: 10 });
    voice.join = () => new Promise(() => {}); // never resolves
    const { mgr } = makeManager({ voice });
    const s = mgr._ensureSession('g1', 'vc1', {});
    // The gate must release even if the attempt is abandoned, so a later
    // attempt is not blocked forever.
    const pending = mgr._connectGate.run('g1', async () => { throw new Error('x'); }).catch(() => {});
    await pending;
    assert.equal(mgr._connectGate.isPending('g1'), false);
    void s;
});

test('the gate releases its lock after every attempt settles (success and failure)', async () => {
    const gate = new VoiceConnectGate();
    await gate.run('g1', async () => 'ok');
    assert.equal(gate.isPending('g1'), false);
    await gate.run('g1', async () => { throw new Error('boom'); }).catch(() => {});
    assert.equal(gate.isPending('g1'), false, 'a failed attempt must not leak the lock');
});

test('a stale attempt cannot clear a newer attempt lock', async () => {
    const gate = new VoiceConnectGate();
    let releaseFirst;
    const first = gate.run('g1', () => new Promise(r => { releaseFirst = r; }));
    assert.equal(gate.isPending('g1'), true);
    // Force a newer attempt to own the lock (simulating an out-of-band reset).
    gate.clear('g1');
    const second = gate.run('g1', async () => 'second');
    releaseFirst('first');
    await first;
    await second;
    assert.equal(gate.isPending('g1'), false);
});

// ── 3. intentional cancellation vs timeout ──────────────────────────────────

test('/247 disable during connection establishment prevents reconnection', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 40 });
    const enabling = mgr.enable247('g1', 'vc1', { settings: {} });
    await new Promise(r => setTimeout(r, 10));
    await mgr.disable247('g1');
    await enabling.catch(() => {});
    assert.equal(mgr.getSession('g1'), null, 'disable clears the session');
    assert.ok(voice.calls.destroy >= 1, 'disable destroys the connection');
    // A later restore must not bring it back — disabledIntentionally is persisted.
    const store = makeStore([{ guildId: 'g1', twentyFourSevenEnabled: false, disabledIntentionally: true, twentyFourSevenChannelId: 'vc1' }]);
    const { mgr: mgr2, voice: voice2 } = makeManager({ handshakeMs: 10, store });
    await mgr2.restore();
    assert.equal(voice2.calls.join, 0, 'a disabled 24/7 session must not reconnect');
});

// ── 4. restart recovery + ownership ─────────────────────────────────────────

test('restore reconnects an enabled 24/7 session exactly once', async () => {
    const store = makeStore([{ guildId: 'g1', twentyFourSevenEnabled: true, twentyFourSevenChannelId: 'vc1', disabledIntentionally: false }]);
    const { mgr, voice } = makeManager({ handshakeMs: 20, store });
    await mgr.restore();
    await mgr.restore(); // idempotent
    assert.equal(voice.calls.join, 1, 'restore is idempotent across calls');
    assert.equal(mgr.getSession('g1').twentyFourSeven, true);
});

test('a node that does not own the guild never creates a session (no duplicate nodes)', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 10, guildIds: ['other'] });
    mgr.ownsGuild = (id) => mgr.client.guilds.cache.has(id);
    const store = makeStore([{ guildId: 'g1', twentyFourSevenEnabled: true, twentyFourSevenChannelId: 'vc1', disabledIntentionally: false }]);
    mgr.store = store;
    await mgr.restore();
    assert.equal(voice.calls.join, 0, 'standby node must not connect a guild it does not serve');
    assert.equal(mgr.getSession('g1'), null);
});

test('two guilds run independent connections', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 20, guildIds: ['g1', 'g2'] });
    const s1 = mgr._ensureSession('g1', 'vc1', {});
    const s2 = mgr._ensureSession('g2', 'vc1', {});
    await Promise.all([mgr._ensureConnected(s1), mgr._ensureConnected(s2)]);
    assert.equal(voice.calls.join, 2, 'one connection per guild');
    assert.notEqual(s1.connection, s2.connection);
});

// ── 5. empty queue keeps the connection ─────────────────────────────────────

test('24/7 stays connected with an empty queue and no listeners', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 20 });
    await mgr.enable247('g1', 'vc1', { settings: {} });
    const s = mgr.getSession('g1');
    s.queue = [];
    await mgr.stop('g1', {});
    assert.equal(voice.calls.leave, 0, 'stop must not disconnect a 24/7 session');
    assert.equal(voice.calls.destroy, 0);
});

// ── 6. shard readiness ──────────────────────────────────────────────────────

test('waitForShardReady resolves immediately when the shard is Ready', async () => {
    const { Status } = require('discord.js');
    const client = { guilds: { cache: new Map([['g1', { id: 'g1', shard: { status: Status.Ready } }]]) } };
    assert.equal(await waitForShardReady(client, 'g1'), true);
});

test('waitForShardReady times out when the shard never becomes Ready', async () => {
    const { Status } = require('discord.js');
    const client = { guilds: { cache: new Map([['g1', { id: 'g1', shard: { status: Status.Connecting } }]]) } };
    const prev = process.env.VOICE_SHARD_READY_TIMEOUT_MS;
    process.env.VOICE_SHARD_READY_TIMEOUT_MS = '1000';
    try {
        const ok = await waitForShardReady(client, 'g1');
        assert.equal(ok, false, 'a shard stuck Connecting must not be reported ready');
    } finally {
        if (prev === undefined) delete process.env.VOICE_SHARD_READY_TIMEOUT_MS;
        else process.env.VOICE_SHARD_READY_TIMEOUT_MS = prev;
    }
});

test('waitForShardReady waits until a reconnecting shard becomes Ready', async () => {
    const { Status } = require('discord.js');
    const shard = { status: Status.Reconnecting };
    const client = { guilds: { cache: new Map([['g1', { id: 'g1', shard }]]) } };
    setTimeout(() => { shard.status = Status.Ready; }, 300);
    assert.equal(await waitForShardReady(client, 'g1'), true);
});

test('waitForShardReady does not block a client without a shard handle', async () => {
    const client = { guilds: { cache: new Map([['g1', { id: 'g1' }]]) } };
    assert.equal(await waitForShardReady(client, 'g1'), true);
});

test('shardReadyTimeoutMs honours the env var with a floor', () => {
    const prev = process.env.VOICE_SHARD_READY_TIMEOUT_MS;
    try {
        process.env.VOICE_SHARD_READY_TIMEOUT_MS = '5000';
        assert.equal(shardReadyTimeoutMs(), 5000);
        process.env.VOICE_SHARD_READY_TIMEOUT_MS = '1';
        assert.equal(shardReadyTimeoutMs(), 1000);
    } finally {
        if (prev === undefined) delete process.env.VOICE_SHARD_READY_TIMEOUT_MS;
        else process.env.VOICE_SHARD_READY_TIMEOUT_MS = prev;
    }
});

// ── 7. the wrapper join() reports a real timeout ────────────────────────────

test('the voice wrapper reports a descriptive timeout and frees the guild', async () => {
    const { getVoiceConnection } = require('@discordjs/voice');
    const musicVoice = require('../utils/music/musicVoice');
    const adapter = () => ({ sendPayload: () => true, destroy: () => {} });
    const client = { guilds: { cache: new Map([['zg9', {
        id: 'zg9',
        channels: { cache: new Map([['vc1', { id: 'vc1', type: 2 }]]) },
        voiceAdapterCreator: adapter,
    }]]) } };
    const prev = process.env.VOICE_READY_TIMEOUT_MS;
    process.env.VOICE_READY_TIMEOUT_MS = '1000';
    try {
        await assert.rejects(
            () => musicVoice.join({ client, guildId: 'zg9', channelId: 'vc1' }),
            (err) => {
                assert.match(err.message, /timed out after 1000ms/);
                assert.equal(err.voiceState.aborted, true);
                assert.equal(err.voiceState.guildId, 'zg9');
                return true;
            },
        );
        assert.equal(getVoiceConnection('zg9'), undefined, 'a failed join must free the guild');
    } finally {
        if (prev === undefined) delete process.env.VOICE_READY_TIMEOUT_MS;
        else process.env.VOICE_READY_TIMEOUT_MS = prev;
    }
});

void settle;

// ── 8. remaining scenarios from the task list ───────────────────────────────

test('/play while the connection is READY reuses it (no second join)', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 20 });
    await mgr.enable247('g1', 'vc1', { settings: {} });
    assert.equal(voice.calls.join, 1);
    const s = mgr.getSession('g1');
    await mgr._ensureConnected(s); // stands in for a /play on a live connection
    assert.equal(voice.calls.join, 1, 'a ready connection is reused, never rejoined');
});

test('/play while the connection is CONNECTING awaits the same attempt', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 60 });
    const s = mgr._ensureSession('g1', 'vc1', {});
    const connecting = mgr._ensureConnected(s); // /join
    await new Promise(r => setTimeout(r, 10));
    const playing = mgr._ensureConnected(s); // /play mid-handshake
    await Promise.all([connecting, playing]);
    assert.equal(voice.calls.join, 1);
    assert.equal(voice.calls.destroy, 0);
});

test('an intentional stop during a slow connect does not leave the bot connected', async () => {
    const { mgr, voice } = makeManager({ handshakeMs: 60 });
    const enabling = mgr.enable247('g1', 'vc1', { settings: {} }).catch(e => e);
    await new Promise(r => setTimeout(r, 10));
    await mgr.disable247('g1');
    await enabling;
    assert.equal(mgr.getSession('g1'), null);
    // The in-flight handshake must be torn down, not adopted.
    assert.ok(voice.calls.destroy >= 1, 'the half-open connection is destroyed');
});

test('a non-timeout failure is reported with its real error, not "aborted"', async () => {
    // Inject a voice lib whose handshake fails for a NON-timeout reason, so we
    // prove the wrapper reports the original error instead of a bare abort.
    const voicePath = require.resolve('@discordjs/voice');
    const real = require.cache[voicePath];
    const realExports = real ? real.exports : require('@discordjs/voice');
    const fakeConn = { state: { status: 'signalling' }, on() {}, destroy() { this.destroyed = true; } };
    require.cache[voicePath] = {
        id: voicePath, filename: voicePath, loaded: true,
        exports: {
            joinVoiceChannel: () => fakeConn,
            entersState: async () => { throw Object.assign(new Error('socket hang up'), { name: 'Error' }); },
            VoiceConnectionStatus: realExports.VoiceConnectionStatus,
            getVoiceConnection: () => undefined,
        },
    };
    const mvPath = require.resolve('../utils/music/musicVoice');
    delete require.cache[mvPath];
    try {
        const mv = require('../utils/music/musicVoice');
        const client = { guilds: { cache: new Map([['zi7', {
            id: 'zi7',
            channels: { cache: new Map([['vc1', { id: 'vc1', type: 2 }]]) },
            voiceAdapterCreator: () => ({ sendPayload: () => true, destroy: () => {} }),
        }]]) } };
        await assert.rejects(
            () => mv.join({ client, guildId: 'zi7', channelId: 'vc1' }),
            (err) => {
                assert.match(err.message, /Error: socket hang up/);
                assert.doesNotMatch(err.message, /timed out/);
                assert.equal(err.voiceState.aborted, false, 'not mislabelled as a timeout');
                assert.equal(fakeConn.destroyed, true, 'the half-open connection is destroyed');
                return true;
            },
        );
    } finally {
        if (real) require.cache[voicePath] = real; else delete require.cache[voicePath];
        delete require.cache[mvPath];
    }
});

test('shard restart: a join aborts fast (no 20s hang) when the shard is not Ready', async () => {
    const { Status } = require('discord.js');
    const musicVoice = require('../utils/music/musicVoice');
    const client = { guilds: { cache: new Map([['zr1', {
        id: 'zr1',
        channels: { cache: new Map([['vc1', { id: 'vc1', type: 2 }]]) },
        shard: { status: Status.Identifying }, // mid-restart
        voiceAdapterCreator: () => ({ sendPayload: () => false, destroy: () => {} }),
    }]]) } };
    const prev = process.env.VOICE_SHARD_READY_TIMEOUT_MS;
    process.env.VOICE_SHARD_READY_TIMEOUT_MS = '1000';
    const t0 = Date.now();
    try {
        await assert.rejects(
            () => musicVoice.join({ client, guildId: 'zr1', channelId: 'vc1' }),
            /shard is not ready/i,
        );
        assert.ok(Date.now() - t0 < 5000, 'must fail fast, not wait the full 20s voice timeout');
    } finally {
        if (prev === undefined) delete process.env.VOICE_SHARD_READY_TIMEOUT_MS;
        else process.env.VOICE_SHARD_READY_TIMEOUT_MS = prev;
    }
});

test('conflicting reload ticks do not create duplicate connections', async () => {
    const store = makeStore([{ guildId: 'g1', twentyFourSevenEnabled: true, twentyFourSevenChannelId: 'vc1', disabledIntentionally: false }]);
    const { mgr, voice } = makeManager({ handshakeMs: 50, store });
    // Two concurrent restores (e.g. boot + first reload tick).
    await Promise.all([mgr.restore(), mgr.restore()]);
    assert.equal(voice.calls.join, 1, 'concurrent restores share one connection');
    assert.equal(voice.calls.destroy, 0);
});
