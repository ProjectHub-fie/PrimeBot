/**
 * radioVoice.join() — real-module regression tests.
 *
 * The radio suite (tests/radio.test.js) drives RadioManager with a MOCK voice
 * layer, so `utils/radioVoice.js` `join()` never actually executes in tests.
 * That gap let a broken sibling require ship:
 *
 *   [RADIO] Restore failed for guild … : Cannot find module '../voiceReadiness'
 *   Require stack: /home/container/utils/radioVoice.js
 *
 * `utils/radioVoice.js` lives in `utils/`, so its sibling is `./voiceReadiness`
 * (not `../voiceReadiness`, which resolves to the repo root). This file loads the
 * REAL module and drives its REAL `join()` so the same class of bug cannot return
 * silently. `@discordjs/voice` is stubbed via the module cache (the same
 * technique the other voice tests use) — no real gateway, no ffmpeg.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

const REPO = path.join(__dirname, '..');
const VOICE_PATH = require.resolve('@discordjs/voice');

/** Install a fake @discordjs/voice into the module cache for the duration of fn. */
function withFakeVoice(fake, fn) {
    const original = require.cache[VOICE_PATH];
    require.cache[VOICE_PATH] = new Module(VOICE_PATH, null);
    require.cache[VOICE_PATH].filename = VOICE_PATH;
    require.cache[VOICE_PATH].exports = fake;
    require.cache[VOICE_PATH].loaded = true;
    try {
        return fn();
    } finally {
        if (original) require.cache[VOICE_PATH] = original;
        else delete require.cache[VOICE_PATH];
    }
}

/** A client whose guild has a voice channel and a Ready shard. */
function makeClient({ shardStatus } = {}) {
    const { Status } = require('discord.js');
    const channel = { id: 'vc1', type: 2 };
    const guild = {
        id: 'g1',
        channels: { cache: new Map([['vc1', channel]]) },
        shard: { status: shardStatus === undefined ? Status.Ready : shardStatus },
        voiceAdapterCreator: () => {},
    };
    return { guilds: { cache: new Map([['g1', guild]]) } };
}

function makeConnection({ reachReady = true } = {}) {
    const listeners = {};
    const conn = {
        state: { status: 'signalling' },
        destroyed: false,
        on(evt, cb) { (listeners[evt] = listeners[evt] || []).push(cb); return this; },
        emit(evt, ...a) { (listeners[evt] || []).forEach(cb => cb(...a)); },
        destroy() { this.destroyed = true; this.state = { status: 'destroyed' }; },
    };
    return { conn, reachReady };
}

// ── the regression ──────────────────────────────────────────────────────────

test('radioVoice.join() loads and connects (the "../voiceReadiness" require is resolved)', async () => {
    const calls = { joins: 0, entersState: 0 };
    let conn;
    const fake = {
        VoiceConnectionStatus: { Ready: 'ready', Disconnected: 'disconnected', Signalling: 'signalling' },
        joinVoiceChannel() { calls.joins++; conn = makeConnection().conn; return conn; },
        async entersState(connection, status) {
            calls.entersState++;
            assert.equal(status, 'ready');
            connection.state = { status: 'ready' };
            return connection;
        },
    };

    await withFakeVoice(fake, async () => {
        // require AFTER the stub is installed so the module binds to the fake.
        delete require.cache[require.resolve(path.join(REPO, 'utils/radioVoice.js'))];
        const radioVoice = require(path.join(REPO, 'utils/radioVoice.js'));
        const client = makeClient();
        const connection = await radioVoice.join({ client, guildId: 'g1', channelId: 'vc1' });
        assert.ok(connection, 'join resolves a connection');
        assert.equal(calls.joins, 1, 'exactly one joinVoiceChannel call');
        assert.equal(calls.entersState, 1, 'entersState was awaited');
    });
});

test('radioVoice.join() aborts fast (no joinVoiceChannel) when the shard is not Ready', async () => {
    const calls = { joins: 0 };
    const fake = {
        VoiceConnectionStatus: { Ready: 'ready', Disconnected: 'disconnected' },
        joinVoiceChannel() { calls.joins++; throw new Error('should not join'); },
        async entersState() { throw new Error('should not enter state'); },
    };

    await withFakeVoice(fake, async () => {
        delete require.cache[require.resolve(path.join(REPO, 'utils/radioVoice.js'))];
        const radioVoice = require(path.join(REPO, 'utils/radioVoice.js'));
        const { Status } = require('discord.js');
        const client = makeClient({ shardStatus: Status.Resuming });
        const prev = process.env.VOICE_SHARD_READY_TIMEOUT_MS;
        process.env.VOICE_SHARD_READY_TIMEOUT_MS = '1000'; // don't wait the 15s default
        try {
            await assert.rejects(
                () => radioVoice.join({ client, guildId: 'g1', channelId: 'vc1', }),
                /shard is not ready/i,
            );
        } finally {
            if (prev === undefined) delete process.env.VOICE_SHARD_READY_TIMEOUT_MS;
            else process.env.VOICE_SHARD_READY_TIMEOUT_MS = prev;
        }
        assert.equal(calls.joins, 0, 'the join was never attempted');
    });
});

test('every sibling require in radioVoice.js resolves on disk (guards the path bug)', () => {
    const fs = require('node:fs');
    const src = fs.readFileSync(path.join(REPO, 'utils/radioVoice.js'), 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')   // strip block comments
        .replace(/^\s*\/\/.*$/gm, '');      // strip line comments
    const re = /require\(\s*['"](\.[^'"]+)['"]\s*\)/g;
    const missing = [];
    let m;
    while ((m = re.exec(src))) {
        const base = path.resolve(path.join(REPO, 'utils'), m[1]);
        const ok = [base, `${base}.js`, `${base}.json`, path.join(base, 'index.js')]
            .some(p => { try { return fs.statSync(p).isFile(); } catch { return false; } });
        if (!ok) missing.push(m[1]);
    }
    assert.deepEqual(missing, [], `unresolvable relative requires in utils/radioVoice.js: ${missing.join(', ')}`);
});
