/**
 * YouTube provider adapter.
 *
 * Verified APIs (from the installed typings/source, not assumed):
 *
 *   youtube-sr (4.x)  — default export `YouTube`:
 *     YouTube.search(query, { limit })      → Promise<Video[]>
 *     YouTube.getVideo(urlOrVideo)          → Promise<Video>
 *     YouTube.getPlaylist(url, { limit })   → Promise<Playlist>
 *     Video: { id, title, duration (ms), channel: { name }, thumbnail: { url },
 *              url, durationFormatted }
 *
 *   @distube/ytdl-core — maintained ytdl-core fork:
 *     ytdl.getInfo(url)                     → Promise<Info>
 *     ytdl.chooseFormat(info.formats, { quality:'highestaudio', filter:'audioonly' })
 *
 * ytdl stream URLs are short-lived and are therefore re-resolved on every play
 * (resolveStream), never persisted.
 */

const { PROVIDERS, isYouTubeUrl, youTubeId } = require('../../../shared/musicConstants');

let YouTube = null;
let ytdl = null;
function libs() {
    if (!YouTube) YouTube = require('youtube-sr').default || require('youtube-sr');
    if (!ytdl) ytdl = require('@distube/ytdl-core');
    return { YouTube, ytdl };
}

function toTrack(v, extra = {}) {
    if (!v || !v.id) return null;
    return {
        provider: PROVIDERS.YOUTUBE,
        id: String(v.id),
        title: v.title || 'Unknown title',
        artist: v.channel && v.channel.name ? v.channel.name : null,
        durationMs: v.duration != null ? Number(v.duration) : null,
        url: v.url || `https://www.youtube.com/watch?v=${v.id}`,
        artworkUrl: (v.thumbnail && (v.thumbnail.url || v.thumbnail)) || null,
        source: 'YouTube',
        ...extra,
    };
}

function canHandle(input) {
    return typeof input === 'string' && isYouTubeUrl(input);
}

async function search(query, limit = 10) {
    const { YouTube: YT } = libs();
    const results = await YT.search(query, { limit: Math.min(Math.max(1, limit), 25) });
    return (results || []).map(v => toTrack(v)).filter(Boolean);
}

async function resolve(url) {
    const { YouTube: YT } = libs();
    const id = youTubeId(url) || url;
    // youtube-sr's getVideo() validates its argument as a VIDEO URL — a bare
    // id fails `YT.validate(id, 'VIDEO')` and throws "Invalid video url". Always
    // hand it the canonical watch URL.
    const video = await YT.getVideo(`https://www.youtube.com/watch?v=${id}`);
    const track = toTrack(video);
    if (!track) throw new Error('YouTube video could not be resolved.');
    return track;
}

async function resolveStream(track) {
    const { ytdl } = libs();
    const url = track.url || `https://www.youtube.com/watch?v=${track.id}`;
    const info = await ytdl.getInfo(url);
    if (!info || !Array.isArray(info.formats) || info.formats.length === 0) {
        throw new Error('No playable YouTube formats available.');
    }
    let format = null;
    try {
        format = ytdl.chooseFormat(info.formats, { quality: 'highestaudio', filter: 'audioonly' });
    } catch (_) {
        format = null;
    }
    if (!format) format = ytdl.chooseFormat(info.formats, { quality: 'highestaudio' });
    if (!format || !format.url) throw new Error('No playable YouTube audio format available.');
    const durationMs = info.videoDetails && info.videoDetails.lengthSeconds
        ? Number(info.videoDetails.lengthSeconds) * 1000
        : track.durationMs;
    return { streamUrl: format.url, durationMs };
}

async function resolveCollection(url, limit = 50) {
    const { YouTube: YT } = libs();
    const playlist = await YT.getPlaylist(url, { limit: Math.min(Math.max(1, limit), 100) });
    const tracks = ((playlist && playlist.videos) || []).map(v => toTrack(v)).filter(Boolean);
    return { title: (playlist && playlist.title) || 'YouTube playlist', tracks };
}

module.exports = { id: PROVIDERS.YOUTUBE, canHandle, search, resolve, resolveStream, resolveCollection, _toTrack: toTrack };
