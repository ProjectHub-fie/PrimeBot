/**
 * SoundCloud provider adapter.
 *
 * Wraps the existing `utils/soundcloudSource.js` (which itself wraps the
 * verified `soundcloud-core` API) so the music engine gets the same stable
 * surface the radio uses. This is the ONLY music module that touches
 * `soundcloud-core` transitively.
 *
 * Verified `soundcloud-core` facts (see utils/soundcloudSource.js):
 *   • getPlaylist returns a SINGLE object at runtime (the .d.ts lies).
 *   • getMetaData().streamUrl is a SHORT-LIVED signed URL (usually HLS) and is
 *     re-resolved on every play.
 */

const { PROVIDERS, isSoundCloudUrl } = require('../../../shared/musicConstants');
const sc = require('../../soundcloudSource');

function toTrack(raw, extra = {}) {
    if (!raw || raw.id == null) return null;
    return {
        provider: PROVIDERS.SOUNDCLOUD,
        id: String(raw.id),
        title: raw.title || 'Unknown title',
        artist: raw.artist && raw.artist.username ? raw.artist.username : (raw.artist || null),
        durationMs: raw.durationMs != null ? Number(raw.durationMs) : (raw.duration != null ? Number(raw.duration) : null),
        url: raw.url || null,
        artworkUrl: raw.artworkUrl || null,
        source: 'SoundCloud',
        ...extra,
    };
}

function canHandle(input) {
    return typeof input === 'string' && isSoundCloudUrl(input);
}

async function search(query, limit = 10) {
    const results = await sc.search(query, limit);
    return results.map(r => toTrack(r)).filter(Boolean);
}

async function resolve(url) {
    const raw = await sc.resolveTrack(url);
    const track = toTrack(raw);
    if (!track) throw new Error('SoundCloud track could not be resolved.');
    return track;
}

async function resolveStream(track) {
    const { streamUrl, durationMs } = await sc.resolveStreamUrl(track);
    if (!streamUrl) throw new Error('SoundCloud did not return a playable stream.');
    return { streamUrl, durationMs: durationMs != null ? durationMs : track.durationMs };
}

async function resolveCollection(url, limit = 50) {
    const playlist = await sc.resolvePlaylist(url, limit);
    const tracks = (playlist.tracks || []).map(t => toTrack(t)).filter(Boolean);
    return { title: playlist.title || 'SoundCloud playlist', tracks };
}

module.exports = { id: PROVIDERS.SOUNDCLOUD, canHandle, search, resolve, resolveStream, resolveCollection, _toTrack: toTrack };
