/**
 * SoundCloud source adapter for the 24/7 Radio feature.
 *
 * Wraps the `soundcloud-core` package (verified API — see the notes below) and
 * exposes a small, stable surface the radio manager can rely on:
 *
 *   • search(query, limit)             → lightweight track candidates
 *   • resolveTrack(url)                → full track metadata (incl. a stream URL)
 *   • resolvePlaylist(url, limit)      → a playlist + its tracks
 *   • resolveProfile(username)         → artist metadata
 *   • resolveStreamUrl(track)          → a FRESH, playable stream URL
 *
 * VERIFIED `soundcloud-core` API (v2.0.0) — do not invent methods:
 *   new SoundCloudClient({ userAgent?, clientId? })
 *     .getClientId({ xForwardedFor? })            → Promise<string>
 *     .getMetaData({ url })                       → Promise<MetaData>
 *     .getPlaylist({ url, limit })                → Promise<Playlist>  (NOT an array)
 *     .getProfile({ username })                   → Promise<Profile>
 *     .search({ query, limit })                   → Promise<Search[]>
 *
 * IMPORTANT STREAMING LIMITATION (verified live, not assumed):
 *   `getMetaData().streamUrl` is a SHORT-LIVED URL. The package prefers an HLS
 *   transcoding, so the value is usually a `.m3u8` playlist URL that carries a
 *   signed `expires=` / `Signature=` query string; progressive MP3 is only used
 *   when no HLS rendition exists. Therefore:
 *     - the stream URL is NEVER persisted as a track identity (only the numeric
 *       track id + metadata are), and
 *     - `resolveStreamUrl()` re-resolves on every play so an expired URL is
 *       always replaced with a fresh one.
 *   ffmpeg (via @discordjs/voice) reads the URL directly, so HLS is fine.
 *
 * The package does not expose a raw stream/byte API and does not offer a
 * "genre station" primitive — genre stations are built by searching and
 * collecting tracks (see utils/radioStations.js). It also cannot stream a whole
 * playlist in one go; playlists are expanded into individual tracks.
 */

const { SoundCloudClient } = require('soundcloud-core');

const DEFAULT_USER_AGENT = 'PrimeBot/1.0 (+https://github.com/ProjectHub-fie/PrimeBot)';

// The package reuses one client_id for the life of the client. Reusing a single
// client across calls keeps SoundCloud resolution cheap and avoids re-fetching
// the client id (which the package otherwise does lazily per client).
let _client = null;
function getClient() {
    if (!_client) {
        _client = new SoundCloudClient({
            userAgent: process.env.SOUNDCLOUD_USER_AGENT || DEFAULT_USER_AGENT,
            clientId: process.env.SOUNDCLOUD_CLIENT_ID || undefined,
        });
    }
    return _client;
}

// Reset the cached client (test-only, and used when a stream resolution keeps
// failing because the client id went stale).
function resetClient() {
    _client = null;
}

/**
 * Bound concurrent SoundCloud resolutions so a burst (e.g. restoring many guilds
 * at once) cannot open dozens of simultaneous HTTP requests. Simple FIFO gate.
 */
const MAX_CONCURRENT = Math.max(1, parseInt(process.env.RADIO_RESOLVE_CONCURRENCY, 10) || 3);
let active = 0;
const waiters = [];
async function withSlot(fn) {
    if (active >= MAX_CONCURRENT) {
        await new Promise(resolve => waiters.push(resolve));
    }
    active++;
    try {
        return await fn();
    } finally {
        active--;
        const next = waiters.shift();
        if (next) next();
    }
}

/** Normalize a raw SoundCloud track (MetaData or a playlist track) to our shape. */
function normalizeTrack(raw, fallbackId) {
    if (!raw) return null;
    const id = raw.id != null ? raw.id : fallbackId;
    if (id == null) return null;
    const artist = raw.artist && raw.artist.username
        ? { id: raw.artist.id, username: raw.artist.username, profileUrl: raw.artist.profileUrl || null }
        : null;
    return {
        id: String(id),
        title: raw.title || null,
        url: raw.permalinkUrl || raw.url || null,
        durationMs: raw.duration != null ? Number(raw.duration) : null,
        genre: raw.genre || null,
        artworkUrl: raw.artworkUrl || null,
        artist,
    };
}

/** Normalize a playlist to our shape. `soundcloud-core` returns ONE object. */
function normalizePlaylist(raw) {
    if (!raw) return null;
    const tracks = Array.isArray(raw.tracks)
        ? raw.tracks.map(t => normalizeTrack(t, t && t.id)).filter(Boolean)
        : [];
    return {
        id: raw.id != null ? String(raw.id) : null,
        title: raw.title || null,
        url: raw.permalinkUrl || null,
        trackCount: raw.trackCount != null ? Number(raw.trackCount) : tracks.length,
        durationMs: raw.duration != null ? Number(raw.duration) : null,
        genre: raw.genre || null,
        artworkUrl: raw.artworkUrl || null,
        curator: raw.curator ? { id: raw.curator.id, username: raw.curator.username } : null,
        tracks,
    };
}

/**
 * Search SoundCloud for tracks. Returns normalized candidates (no stream URL —
 * a search hit is a candidate, not a resolved track).
 */
async function search(query, limit = 10) {
    if (!query || typeof query !== 'string') throw new Error('search: a query is required');
    const capped = Math.min(Math.max(1, Number(limit) || 10), 50);
    const results = await withSlot(() => getClient().search({ query, limit: capped }));
    return (Array.isArray(results) ? results : []).map(r => normalizeTrack(r, r && r.id)).filter(Boolean);
}

/**
 * Resolve a single track URL to full metadata. The returned `streamUrl` is
 * short-lived and must NOT be persisted — call `resolveStreamUrl()` at play
 * time instead.
 */
async function resolveTrack(url) {
    if (!url || typeof url !== 'string') throw new Error('resolveTrack: a URL is required');
    const meta = await withSlot(() => getClient().getMetaData({ url }));
    const track = normalizeTrack(meta, meta && meta.id);
    if (!track) throw new Error('resolveTrack: no track metadata returned');
    return { ...track, streamUrl: meta.streamUrl || null, trackAuthorization: meta.trackAuthorization || null };
}

/** Resolve a playlist URL. Expands up to `limit` tracks (default all we ask for). */
async function resolvePlaylist(url, limit = 50) {
    if (!url || typeof url !== 'string') throw new Error('resolvePlaylist: a URL is required');
    const raw = await withSlot(() => getClient().getPlaylist({ url, limit: Number(limit) || 50 }));
    const playlist = normalizePlaylist(raw);
    if (!playlist) throw new Error('resolvePlaylist: no playlist returned');
    return playlist;
}

/** Resolve an artist profile (username or profile URL). */
async function resolveProfile(username) {
    if (!username || typeof username !== 'string') throw new Error('resolveProfile: a username is required');
    const profile = await withSlot(() => getClient().getProfile({ username }));
    if (!profile) throw new Error('resolveProfile: no profile returned');
    return {
        id: profile.id != null ? String(profile.id) : null,
        username: profile.username || null,
        permalinkUrl: profile.permalinkUrl || null,
        avatarUrl: profile.avatarUrl || null,
        description: profile.description || null,
        trackCount: profile.stats && profile.stats.tracks != null ? Number(profile.stats.tracks) : null,
    };
}

/**
 * Re-resolve a FRESH playable stream URL for a track. `track` may be a resolved
 * track (with `url`) or a raw URL string. This is the only supported way to get
 * a stream URL — it always re-resolves so an expired URL is never reused.
 */
async function resolveStreamUrl(track) {
    const url = typeof track === 'string' ? track : (track && track.url);
    if (!url) throw new Error('resolveStreamUrl: track has no SoundCloud URL to resolve');
    const meta = await withSlot(() => getClient().getMetaData({ url }));
    if (!meta || !meta.streamUrl) throw new Error(`resolveStreamUrl: no streamable URL for ${url}`);
    return {
        streamUrl: meta.streamUrl,
        trackAuthorization: meta.trackAuthorization || null,
        durationMs: meta.duration != null ? Number(meta.duration) : null,
    };
}

module.exports = {
    search,
    resolveTrack,
    resolvePlaylist,
    resolveProfile,
    resolveStreamUrl,
    normalizeTrack,
    normalizePlaylist,
    resetClient,
    getClient,
    MAX_CONCURRENT,
};
