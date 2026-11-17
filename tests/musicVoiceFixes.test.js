/**
 * Regression tests for three production bugs reported after the Linix/Lavalink
 * music work landed (all pre-existing, none introduced by the Lavalink PR):
 *
 *   1. `Cannot find module '../voiceReadiness'` — utils/radioVoice.js resolved
 *      its sibling one directory too high. (tests/radioVoiceJoin.test.js)
 *   2. `Invalid video url` on a VALID YouTube URL — youtube.resolve() handed a
 *      bare video id to youtube-sr's getVideo(), which validates its argument as
 *      a VIDEO URL. This file pins the fix.
 *   3. "song plays but no sound" — ffmpeg-static returns a path string even when
 *      the binary was never downloaded, so the old try/catch fell through to a
 *      non-existent path and every play failed. This file pins the existence
 *      check + system-ffmpeg fallback.
 *
 * A follow-up round of bugs (after the control-button fix) is pinned at the
 * bottom of this file:
 *
 *   4. "the music control buttons are not working" — every control button calls
 *      `refreshNowPlaying()` -> `nowPlaying()`, which called
 *      `embed.setImage(artworkUrl)`. discord.js validates that argument and
 *      THROWS on a non-URL value (a bare id, an empty string, a relative path),
 *      so a single bad artwork value made EVERY button fail ("This interaction
 *      failed"). Artwork is now applied through a guarded `applyArtwork()`.
 *   5. "no thumbnail is showing in the image field" — the play replies built the
 *      Now Playing payload (artwork + controls) and then REPLACED `payload.embeds`
 *      with a bare `successEmbed`, which has no image. They now override only the
 *      headline so the artwork survives.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const REPO = path.join(__dirname, '..');

// ── 2. YouTube URL resolution ────────────────────────────────────────────────

test('youtube.resolve() sends getVideo a canonical watch URL, never a bare id', () => {
    const src = fs.readFileSync(path.join(REPO, 'utils/music/providers/youtube.js'), 'utf8');
    // The bare-id call is the bug: `YT.getVideo(id)` → "Invalid video url".
    assert.doesNotMatch(src, /getVideo\(\s*id\s*\)/, 'getVideo must not be called with the bare id');
    assert.match(src, /getVideo\(`https:\/\/www\.youtube\.com\/watch\?v=\$\{id\}`\)/, 'getVideo must receive the watch URL');
});

test('youtube.resolve() actually resolves the reported youtu.be URL (or fails on the network, never on the URL)', async () => {
    const youtube = require(path.join(REPO, 'utils/music/providers/youtube'));
    const url = 'https://youtu.be/-SgP0Im6u6I?si=zb8tfiCIWPsoAS4Y';
    try {
        const track = await youtube.resolve(url);
        assert.equal(track.provider, 'youtube');
        assert.equal(track.id, '-SgP0Im6u6I');
    } catch (err) {
        // Offline CI: a fetch/network failure is acceptable. "Invalid video url"
        // — the bug — is not: that proves the URL was rejected before any fetch.
        assert.doesNotMatch(String(err.message), /Invalid video url/i,
            'a valid YouTube URL must never be rejected as "Invalid video url"');
    }
});

// ── 3. ffmpeg resolution ─────────────────────────────────────────────────────

test('musicVoice.ffmpeg() never returns a non-existent ffmpeg-static path', () => {
    const musicVoice = require(path.join(REPO, 'utils/music/musicVoice'));
    const resolved = musicVoice.ffmpeg();
    assert.ok(resolved && typeof resolved === 'string', 'returns a path string');
    if (resolved !== 'ffmpeg') {
        assert.ok(fs.existsSync(resolved), `resolved ffmpeg path exists on disk: ${resolved}`);
    }
});

test('musicVoice source verifies the ffmpeg-static binary exists before using it', () => {
    const src = fs.readFileSync(path.join(REPO, 'utils/music/musicVoice.js'), 'utf8');
    assert.match(src, /existsSync\(candidate\)/, 'must existence-check the ffmpeg-static path');
    assert.match(src, /ffmpegPath = 'ffmpeg'/, 'must fall back to the system ffmpeg');
});

// ── 1. radioVoice sibling require (see also tests/radioVoiceJoin.test.js) ─────

test('radioVoice.js resolves its voiceReadiness sibling (utils/, not the repo root)', () => {
    const src = fs.readFileSync(path.join(REPO, 'utils/radioVoice.js'), 'utf8');
    assert.match(src, /require\('\.\/voiceReadiness'\)/, 'must require ./voiceReadiness');
    assert.doesNotMatch(src, /require\('\.\.\/voiceReadiness'\)/, 'must not require ../voiceReadiness');
});

// ── 4. control buttons on the play reply ─────────────────────────────────────

test('nowPlayingPayload() returns the embed plus BOTH control rows', () => {
    const ui = require(path.join(REPO, 'utils/music/musicEmbed'));
    const payload = ui.nowPlayingPayload({ state: 'playing', current: null, queue: [], queueLength: 0, volume: 100, repeat: 'off' });
    assert.equal(payload.components.length, 2, 'two action rows (control + second control)');
    const ids = payload.components.flatMap(r => r.toJSON().components.map(c => c.custom_id));
    for (const id of ['music_prev', 'music_pauseresume', 'music_skip', 'music_stop', 'music_shuffle',
        'music_repeat', 'music_autoplay', 'music_queue', 'music_lyrics', 'music_247status']) {
        assert.ok(ids.includes(id), `control row exposes ${id}`);
    }
});

test('the real $play handler replies WITH the control buttons (regression: buttons were missing)', async () => {
    global.botActive = true;
    const handler = require(path.join(REPO, 'events/messageCreate.js'));

    const manager = new Proxy({}, {
        get(_t, prop) {
            if (prop === 'getSession') return () => ({ channelId: 'vc1', twentyFourSeven: false, queue: [], djRoleId: null });
            if (prop === 'describe') return () => ({ state: 'playing', queue: [], queueLength: 0, current: { title: 'T', provider: 'youtube', id: '1' }, connected: true, volume: 100, repeat: 'off', twentyFourSeven: false, listeners: 1 });
            return () => Promise.resolve({ track: { title: 'T', provider: 'youtube', id: '1' }, queued: false });
        },
    });
    const client = {
        user: { id: 'bot' }, musicManager: manager, radioManager: null,
        countingManager: { isCountingChannel: () => false, processCountingMessage: async () => false },
        levelingManager: { processMessage: async () => {} },
        serverSettingsManager: { hasNoPrefixMode: () => false, getGuildPrefix: () => '$', getTriggeredReactions: () => [], getTriggeredResponses: () => [] },
        commands: new Map(),
    };

    let edited = null;
    const message = {
        content: '$play some song',
        author: { id: 'u1', tag: 'u#1', bot: false },
        member: { id: 'u1', permissions: { has: () => true }, voice: { channelId: 'vc1', channel: { id: 'vc1', type: 2 } }, roles: { cache: new Map() } },
        guild: { id: 'g1', name: 'G' },
        channel: { id: 'ch1', type: 0, send: async () => ({}) },
        mentions: { channels: { first: () => null }, users: { first: () => null } },
        reply: async () => ({ edit: async (p) => { edited = p; return {}; } }),
    };

    await handler.execute(message, client);
    assert.ok(edited, 'the play reply was edited');
    assert.ok(Array.isArray(edited.components) && edited.components.length === 2,
        'the play reply carries both control rows (was a bare embed with no buttons)');
});

// ── 5. artwork in the large image field, and never able to break a button ────

test('nowPlaying()/trackInfoEmbed() put the artwork in the IMAGE field', () => {
    const ui = require(path.join(REPO, 'utils/music/musicEmbed'));
    const track = { provider: 'youtube', id: '1', title: 'T', durationMs: 1000, artworkUrl: 'https://i.ytimg.com/vi/1/hqdefault.jpg' };
    const np = ui.nowPlaying({ state: 'playing', current: track, queue: [], queueLength: 0, volume: 100, repeat: 'off' }).embed.toJSON();
    assert.equal(np.image && np.image.url, track.artworkUrl, 'nowPlaying shows the artwork as the large image');
    assert.ok(!np.thumbnail, 'nowPlaying no longer uses the corner thumbnail');
    const ti = ui.trackInfoEmbed(track).toJSON();
    assert.equal(ti.image && ti.image.url, track.artworkUrl, 'trackInfoEmbed shows the artwork as the large image');
});

test('a NON-URL artwork value never throws (regression: it broke every control button)', () => {
    const ui = require(path.join(REPO, 'utils/music/musicEmbed'));
    // These are the shapes a misbehaving provider can return. `setImage()` throws
    // on each of them; `applyArtwork()` must swallow that.
    for (const bad of ['', 'not-a-url', 'vid123', '/relative/path.jpg', null, undefined, 42]) {
        const track = { provider: 'youtube', id: '1', title: 'T', durationMs: 1000, artworkUrl: bad };
        assert.doesNotThrow(() => ui.nowPlaying({ state: 'playing', current: track, queue: [], queueLength: 0, volume: 100, repeat: 'off' }),
            `nowPlaying must not throw for artworkUrl=${JSON.stringify(bad)}`);
        assert.doesNotThrow(() => ui.trackInfoEmbed(track),
            `trackInfoEmbed must not throw for artworkUrl=${JSON.stringify(bad)}`);
        // And the embed simply carries no image rather than a broken one.
        const json = ui.nowPlaying({ state: 'playing', current: track, queue: [], queueLength: 0, volume: 100, repeat: 'off' }).embed.toJSON();
        assert.equal(json.image, undefined, `no image is set for artworkUrl=${JSON.stringify(bad)}`);
    }
});

test('nowPlayingPayload keeps the artwork on a play announcement (regression: bare successEmbed dropped it)', async () => {
    global.botActive = true;
    const handler = require(path.join(REPO, 'events/messageCreate.js'));

    const artwork = 'https://i.ytimg.com/vi/vid1/hqdefault.jpg';
    const track = { title: 'Song', artist: 'A', provider: 'youtube', id: 'vid1', durationMs: 1000, artworkUrl: artwork };
    const manager = new Proxy({}, {
        get(_t, prop) {
            if (prop === 'getSession') return () => ({ channelId: 'vc1', twentyFourSeven: false, queue: [], djRoleId: null });
            if (prop === 'describe') return () => ({ state: 'playing', queue: [], queueLength: 0, current: track, connected: true, volume: 100, repeat: 'off', twentyFourSeven: false, listeners: 1 });
            return () => Promise.resolve({ track, queued: false });
        },
    });
    const client = {
        user: { id: 'bot' }, musicManager: manager, radioManager: null,
        countingManager: { isCountingChannel: () => false, processCountingMessage: async () => false },
        levelingManager: { processMessage: async () => {} },
        serverSettingsManager: { hasNoPrefixMode: () => false, getGuildPrefix: () => '$', getTriggeredReactions: () => [], getTriggeredResponses: () => [] },
        commands: new Map(),
    };

    let edited = null;
    const message = {
        content: '$play some song',
        author: { id: 'u1', tag: 'u#1', bot: false },
        member: { id: 'u1', permissions: { has: () => true }, voice: { channelId: 'vc1', channel: { id: 'vc1', type: 2 } }, roles: { cache: new Map() } },
        guild: { id: 'g1', name: 'G' },
        channel: { id: 'ch1', type: 0, send: async () => ({}) },
        mentions: { channels: { first: () => null }, users: { first: () => null } },
        reply: async () => ({ edit: async (p) => { edited = p; return {}; } }),
    };

    await handler.execute(message, client);
    assert.ok(edited, 'the play reply was edited');
    const json = edited.embeds[0].toJSON();
    assert.equal(json.image && json.image.url, artwork, 'the play reply shows the artwork in the image field');
    assert.ok(Array.isArray(edited.components) && edited.components.length === 2, 'and still carries both control rows');
});
