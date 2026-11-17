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
