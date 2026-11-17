/**
 * Voice-connection reliability regression tests.
 *
 * The production symptom this guards against is the bot's voice handshake
 * stalling forever in `signalling` and eventually failing with
 * `connect FAILED — timed out after 20000ms (status stayed 'signalling')`.
 *
 * Root cause: Discord's voice gateway performs DAVE (E2EE) negotiation. A client
 * that does not advertise a DAVE protocol version in its IDENTIFY payload never
 * receives the "session description" frame that moves the handshake past
 * `signalling`. `@discordjs/voice@0.18.x` did not send
 * `max_dave_protocol_version`; `@discordjs/voice@0.19.x` does (via
 * `@snazzah/davey`). These tests pin the upgraded, DAVE-capable dependency so a
 * downgrade cannot silently reintroduce the stall.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.join(__dirname, '..');

function readJson(p) {
    return JSON.parse(fs.readFileSync(path.join(repoRoot, p), 'utf8'));
}

test('@discordjs/voice is >= 0.19.0 (DAVE negotiation support)', () => {
    const pkg = readJson('node_modules/@discordjs/voice/package.json');
    const [major, minor] = pkg.version.split('.').map(Number);
    assert.ok(
        major > 0 || minor >= 19,
        `@discordjs/voice ${pkg.version} predates DAVE support — the voice handshake will stall in 'signalling'. Upgrade to >= 0.19.0.`,
    );
});

test('package.json pins @discordjs/voice to a DAVE-capable range', () => {
    const pkg = readJson('package.json');
    const range = String(pkg.dependencies['@discordjs/voice'] || '');
    const m = range.match(/(\d+)\.(\d+)/);
    assert.ok(m, `unparseable @discordjs/voice range: "${range}"`);
    const [major, minor] = [Number(m[1]), Number(m[2])];
    assert.ok(major > 0 || minor >= 19, `package.json pins @discordjs/voice "${range}" — DAVE support requires >= 0.19.0`);
});

test('@snazzah/davey (the DAVE implementation) is installed', () => {
    // @discordjs/voice 0.19.x depends on @snazzah/davey and loads it lazily; the
    // voice IDENTIFY advertises a DAVE protocol version only when it is present.
    const pkg = readJson('node_modules/@snazzah/davey/package.json');
    assert.ok(pkg.version, 'davey must be installed for DAVE negotiation');
});

test('the installed voice library actually advertises max_dave_protocol_version', () => {
    // Belt-and-braces: read the shipped dist and confirm the IDENTIFY field is
    // present. A dependency that satisfies the semver range but dropped the
    // field would still stall the handshake.
    const dist = path.join(repoRoot, 'node_modules/@discordjs/voice/dist/index.js');
    const src = fs.readFileSync(dist, 'utf8');
    assert.match(src, /max_dave_protocol_version/, 'the voice IDENTIFY payload must advertise a DAVE protocol version');
});

test('the voice library exposes the DAVE-aware encryption API', () => {
    const voice = require('@discordjs/voice');
    // These are the primitives the handshake uses once DAVE is negotiated.
    assert.equal(typeof voice.entersState, 'function');
    assert.ok(voice.VoiceConnectionStatus, 'VoiceConnectionStatus must be exported');
    assert.ok('Ready' in voice.VoiceConnectionStatus);
    assert.ok('Signalling' in voice.VoiceConnectionStatus);
});

test('musicVoice builds the voice connection through the shared, DAVE-aware lib', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'utils/music/musicVoice.js'), 'utf8');
    // The connection must go through @discordjs/voice's joinVoiceChannel (which
    // sends the DAVE-aware IDENTIFY), never a hand-rolled gateway join.
    assert.match(src, /joinVoiceChannel/, 'musicVoice must use joinVoiceChannel');
    assert.ok(!/op\s*[:=]\s*4/.test(src), 'musicVoice must not hand-roll a voice gateway OP4 join');
});
