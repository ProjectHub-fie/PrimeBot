/**
 * Voice defense — the bot is always self-deafened ("defended") by default.
 *
 * Verifies the module itself, the join-option defaults, and the wiring in
 * events/voiceStateUpdate.js. No network / no real voice connection.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const vd = require('../utils/voiceDefense');

const ROOT = path.join(__dirname, '..');

test.beforeEach(() => {
    vd.resetCooldowns();
    delete process.env.VOICE_DEFEND_ENABLED;
    delete process.env.VOICE_DEFEND_COOLDOWN_MS;
});

test('JOIN_OPTIONS defend the bot: self-deafened, never self-muted', () => {
    assert.deepStrictEqual({ ...vd.JOIN_OPTIONS }, { selfDeaf: true, selfMute: false });
});

test('both voice layers build their join from JOIN_OPTIONS (no hardcoded drift)', () => {
    for (const rel of ['utils/music/musicVoice.js', 'utils/radioVoice.js']) {
        const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
        assert.match(src, /\.\.\.require\(['"][^'"]*voiceDefense['"]\)\.JOIN_OPTIONS/,
            `${rel} must spread voiceDefense.JOIN_OPTIONS into joinVoiceChannel`);
        assert.doesNotMatch(src, /selfDeaf:\s*false/, `${rel} must never self-deafen:false`);
    }
});

test('both voice layers re-assert the defense after a successful join', () => {
    for (const rel of ['utils/music/musicVoice.js', 'utils/radioVoice.js']) {
        const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
        assert.match(src, /voiceDefense'\)\.defendGuild\(client, guildId\)/,
            `${rel} must call defendGuild(client, guildId) after a successful join`);
    }
});

test('isDefended accepts either flag Discord deafens on', () => {
    assert.strictEqual(vd.isDefended({ selfDeaf: true }), true);
    assert.strictEqual(vd.isDefended({ deaf: true }), true);
    assert.strictEqual(vd.isDefended({ selfDeaf: false, deaf: false }), false);
    assert.strictEqual(vd.isDefended({}), false);
    assert.strictEqual(vd.isDefended(null), false);
});

test('defendVoiceState re-asserts the deafen when it was lost', async () => {
    const calls = [];
    const state = { id: 'bot', guild: { id: 'g1' }, selfDeaf: false, setDeaf: async (v, r) => calls.push([v, r]) };
    const changed = await vd.defendVoiceState(state, { force: true });
    assert.strictEqual(changed, true);
    assert.deepStrictEqual(calls, [[true, vd.REASON]]);
});

test('defendVoiceState is a no-op when already defended', async () => {
    const calls = [];
    const state = { id: 'bot', guild: { id: 'g2' }, selfDeaf: true, setDeaf: async () => calls.push(1) };
    assert.strictEqual(await vd.defendVoiceState(state, { force: true }), false);
    assert.strictEqual(calls.length, 0);
});

test('defendVoiceState throttles repeated re-asserts per guild', async () => {
    let n = 0;
    const make = () => ({ id: 'bot', guild: { id: 'g3' }, selfDeaf: false, setDeaf: async () => { n++; } });
    assert.strictEqual(await vd.defendVoiceState(make()), true);
    assert.strictEqual(await vd.defendVoiceState(make()), false, 'second call within the cooldown is skipped');
    assert.strictEqual(await vd.defendVoiceState(make(), { force: true }), true, 'force bypasses the throttle');
    assert.strictEqual(n, 2);
});

test('defendVoiceState never throws when setDeaf rejects', async () => {
    const state = { id: 'bot', guild: { id: 'g4' }, selfDeaf: false, setDeaf: async () => { throw new Error('Missing Permissions'); } };
    assert.strictEqual(await vd.defendVoiceState(state, { force: true }), false);
});

test('handleVoiceStateUpdate only polices the bot, and only while connected', async () => {
    const client = { user: { id: 'bot' } };
    // another member → ignored
    let touched = 0;
    const other = { id: 'human', client, guild: { id: 'g5' }, channelId: 'vc', selfDeaf: false, setDeaf: async () => { touched++; } };
    vd.handleVoiceStateUpdate(null, other);
    // bot but disconnected → ignored
    const gone = { id: 'bot', client, guild: { id: 'g6' }, channelId: null, selfDeaf: false, setDeaf: async () => { touched++; } };
    vd.handleVoiceStateUpdate(null, gone);
    await new Promise((r) => setTimeout(r, 5));
    assert.strictEqual(touched, 0);

    // bot, connected, undeafened → re-asserted (fire-and-forget)
    let asserted = null;
    const bot = { id: 'bot', client, guild: { id: 'g7' }, channelId: 'vc', selfDeaf: false, setDeaf: async (v) => { asserted = v; } };
    vd.handleVoiceStateUpdate(null, bot);
    await new Promise((r) => setTimeout(r, 5));
    assert.strictEqual(asserted, true);
});

test('defense can be disabled with VOICE_DEFEND_ENABLED=false', async () => {
    process.env.VOICE_DEFEND_ENABLED = 'false';
    assert.strictEqual(vd.isEnabled(), false);
    let n = 0;
    const state = { id: 'bot', guild: { id: 'g8' }, selfDeaf: false, setDeaf: async () => { n++; } };
    assert.strictEqual(await vd.defendVoiceState(state, { force: true }), false);
    assert.strictEqual(n, 0);
    process.env.VOICE_DEFEND_ENABLED = 'true';
    assert.strictEqual(vd.isEnabled(), true);
});

test('the voiceStateUpdate event wires the defense in, before radio/music', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events/voiceStateUpdate.js'), 'utf8');
    const defIdx = src.indexOf("voiceDefense').handleVoiceStateUpdate");
    const radioIdx = src.indexOf('radioManager');
    assert.ok(defIdx > -1, 'the defense must be wired into the event');
    assert.ok(defIdx < radioIdx, 'the defense must run before the radio forwarder');
});

test('defendGuild resolves the bot member and defends it', async () => {
    let asserted = null;
    const state = { selfDeaf: false, setDeaf: async (v) => { asserted = v; } };
    const client = {
        user: { id: 'bot' },
        guilds: { cache: { get: (id) => (id === 'g9' ? { members: { me: { voice: state } } } : null) } },
    };
    assert.strictEqual(await vd.defendGuild(client, 'g9', { force: true }), true);
    assert.strictEqual(asserted, true);
    assert.strictEqual(await vd.defendGuild(client, 'missing', { force: true }), false);
    assert.strictEqual(await vd.defendGuild(null, 'g9'), false);
});
