/**
 * Provider registry + resolution pipeline.
 *
 * `resolveQuery(query, opts)` turns a free-text query or a URL into a playable
 * Track (or a collection of tracks), applying provider fallback:
 *
 *   1. A URL is routed to the provider that owns it.
 *   2. A Spotify URL resolves to Spotify METADATA, then is matched on a
 *      streamable provider (YouTube first, then SoundCloud). The resulting track
 *      keeps the Spotify title/artist/artwork but carries `source` = the actual
 *      playback provider, so the UI is honest about where audio comes from.
 *   3. A free-text query is searched on YouTube, then SoundCloud.
 *
 * Every candidate that is not directly streamable is matched to a streamable
 * one before it is returned — the engine never plays a non-streamable track.
 * The actual playback source is always reported; an unrelated track is never
 * silently substituted (the match is validated against the requested title).
 */

const { PROVIDERS } = require('../../../shared/musicConstants');
const youtube = require('./youtube');
const soundcloud = require('./soundcloud');
const spotify = require('./spotify');
const direct = require('./direct');

const STREAMABLE = [youtube, soundcloud, direct];

function normalizeTitle(s) {
    return String(s || '').toLowerCase().replace(/\([^)]*\)|\[[^\]]*\]/g, ' ').replace(/[^a-z0-9]+/g, ' ').trim();
}

/** Confidence that `candidate` matches the requested title (token overlap). */
function matchScore(requested, candidate) {
    const want = normalizeTitle(requested);
    const got = normalizeTitle(candidate);
    if (!want || !got) return 0;
    const wantTokens = new Set(want.split(' ').filter(Boolean));
    const gotTokens = new Set(got.split(' ').filter(Boolean));
    let overlap = 0;
    for (const t of wantTokens) if (gotTokens.has(t)) overlap++;
    const denom = Math.max(wantTokens.size, 1);
    return overlap / denom;
}

/**
 * Match a non-streamable track (e.g. Spotify) to a streamable one.
 * Returns a track whose metadata is the ORIGINAL (Spotify) but whose stream
 * fields come from the matched provider. Throws when no confident match exists.
 */
async function matchToStreamable(track, { minScore = 0.4 } = {}) {
    const query = track.matchQuery || [track.artist, track.title].filter(Boolean).join(' ');
    if (!query) throw new Error('No search query available to match this track.');
    const errors = [];
    for (const provider of [youtube, soundcloud]) {
        try {
            const candidates = await provider.search(query, 5);
            let best = null;
            let bestScore = 0;
            for (const c of candidates) {
                const score = matchScore(track.title, c.title);
                if (score > bestScore) { bestScore = score; best = c; }
            }
            if (best && bestScore >= minScore) {
                return {
                    ...best,
                    // Keep the original (Spotify) presentation metadata …
                    title: track.title || best.title,
                    artist: track.artist || best.artist,
                    artworkUrl: track.artworkUrl || best.artworkUrl,
                    durationMs: track.durationMs || best.durationMs,
                    requestedUrl: track.url || null,
                    // … but be explicit about where the audio actually comes from.
                    source: best.source,
                    matchedFrom: track.provider,
                    matchScore: bestScore,
                };
            }
            errors.push(`${provider.id}: no confident match (best ${bestScore.toFixed(2)})`);
        } catch (err) {
            errors.push(`${provider.id}: ${err.message}`);
        }
    }
    throw new Error(`Could not find a playable match for “${track.title}”. ${errors.join('; ')}`);
}

/**
 * Resolve a single query (URL or free text) to ONE streamable track.
 */
async function resolveQuery(query, { searchLimit = 1 } = {}) {
    const raw = String(query || '').trim();
    if (!raw) throw new Error('Nothing to play — provide a search term or a URL.');

    // URL routing.
    if (/^https?:\/\//i.test(raw)) {
        if (spotify.canHandle(raw)) {
            const meta = await spotify.resolve(raw);
            return await matchToStreamable(meta);
        }
        if (youtube.canHandle(raw)) return await youtube.resolve(raw);
        if (soundcloud.canHandle(raw)) return await soundcloud.resolve(raw);
        // Fall through: a generic URL (direct audio).
        return await direct.resolve(raw);
    }

    // Free-text search: YouTube first, then SoundCloud.
    const errors = [];
    for (const provider of [youtube, soundcloud]) {
        try {
            const results = await provider.search(raw, Math.max(1, searchLimit));
            if (results.length) return results[0];
        } catch (err) {
            errors.push(`${provider.id}: ${err.message}`);
        }
    }
    throw new Error(`No results found for “${raw}”.${errors.length ? ' ' + errors.join('; ') : ''}`);
}

/**
 * Resolve a query to a LIST of candidates (for /search).
 */
async function searchQuery(query, limit = 10) {
    const raw = String(query || '').trim();
    if (!raw) throw new Error('Provide a search term.');
    const errors = [];
    // A Spotify URL → match each is expensive; search its metadata title instead.
    let term = raw;
    if (/^https?:\/\//i.test(raw) && spotify.canHandle(raw)) {
        const meta = await spotify.resolve(raw).catch(() => null);
        term = meta ? (meta.matchQuery || meta.title) : raw;
    }
    for (const provider of [youtube, soundcloud]) {
        try {
            const results = await provider.search(term, limit);
            if (results.length) return results;
        } catch (err) {
            errors.push(`${provider.id}: ${err.message}`);
        }
    }
    throw new Error(`No results found for “${term}”.${errors.length ? ' ' + errors.join('; ') : ''}`);
}

/**
 * Resolve a collection (playlist/album) URL into { title, tracks, limitation? }.
 * Non-streamable collections (Spotify without credentials) are matched
 * track-by-track when their tracks are known.
 */
async function resolveCollection(url, limit = 50) {
    if (spotify.canHandle(url)) {
        const col = await spotify.resolveCollection(url, limit);
        if (!col.tracks.length) return col; // no tracks → caller reports the limitation
        const matched = [];
        for (const t of col.tracks) {
            try { matched.push(await matchToStreamable(t)); }
            catch (_) { /* skip an unmatchable Spotify track */ }
        }
        return { ...col, tracks: matched };
    }
    if (youtube.canHandle(url) && /[?&]list=/.test(url)) return await youtube.resolveCollection(url, limit);
    if (soundcloud.canHandle(url) && /\/sets\//.test(url)) return await soundcloud.resolveCollection(url, limit);
    // Single track URL.
    const track = await resolveQuery(url);
    return { title: track.title, tracks: [track] };
}

/** Resolve a FRESH stream URL for any streamable track. */
async function resolveStream(track) {
    const provider = STREAMABLE.find(p => p.id === track.provider);
    if (!provider) throw new Error(`Provider "${track.provider}" cannot be streamed.`);
    return provider.resolveStream(track);
}

module.exports = {
    providers: { youtube, soundcloud, spotify, direct },
    streamable: STREAMABLE,
    resolveQuery,
    searchQuery,
    resolveCollection,
    resolveStream,
    matchToStreamable,
    matchScore,
    normalizeTitle,
};
