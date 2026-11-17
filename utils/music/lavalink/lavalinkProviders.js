/**
 * Lavalink-backed provider adapter.
 *
 * Presents the SAME surface as utils/music/providers/registry so the Music
 * engine does not need to know where audio comes from:
 *
 *   resolveQuery(query, { searchLimit })  → one track
 *   searchQuery(query, limit)             → candidate list (for /search)
 *   resolveCollection(url, limit)         → { title, tracks, limitation? }
 *   resolveStream(track)                  → { streamUrl, durationMs }
 *   matchToStreamable(track)              → streamable match for metadata tracks
 *
 * Track shape is PrimeBot's, not Lavalink's (`provider/id/title/artist/
 * durationMs/url/artworkUrl/source`), so persistence, embeds, permissions and
 * the dashboard keep working unchanged. The Lavalink-only bits (the encoded
 * track) live in the manager's in-memory cache — never in a persisted row.
 *
 * Source honesty: a Spotify URL is only played natively when the node has a
 * Spotify source plugin (LavaSrc/Lavalink v4 `spotify` source) AND returns a
 * playable track. Otherwise the existing oEmbed metadata + match-to-streamable
 * path is used, and the reported `source` is the provider that actually
 * streams the audio — we never claim native Spotify audio we do not have.
 */

const { PROVIDERS, PROVIDER_LABELS, isSpotifyUrl } = require('../../../shared/musicConstants');

/** Map a Lavalink sourceName onto a PrimeBot provider id. */
function providerFor(sourceName) {
    const s = String(sourceName || '').toLowerCase();
    if (s.includes('youtube') || s === 'ytsearch' || s === 'ytmsearch') return PROVIDERS.YOUTUBE;
    if (s.includes('soundcloud') || s === 'scsearch') return PROVIDERS.SOUNDCLOUD;
    if (s.includes('spotify') || s.includes('spsearch') || s.includes('dzsearch')) return PROVIDERS.SPOTIFY;
    if (s === 'http' || s === 'local' || s === 'https') return PROVIDERS.DIRECT;
    return s || PROVIDERS.DIRECT;
}

function labelFor(provider) {
    return PROVIDER_LABELS[provider] || (provider ? String(provider) : 'Unknown');
}

/** Convert a KazagumoTrack into PrimeBot's persisted track shape. */
function toTrack(kt) {
    if (!kt) return null;
    const provider = providerFor(kt.sourceName);
    const id = String(kt.identifier || kt.uri || kt.title || '');
    if (!id) return null;
    return {
        provider,
        id,
        title: kt.title || 'Unknown title',
        artist: kt.author || null,
        durationMs: kt.length != null && Number.isFinite(Number(kt.length)) ? Number(kt.length) : null,
        url: kt.uri || kt.realUri || null,
        artworkUrl: kt.thumbnail || null,
        source: labelFor(provider),
        isStream: !!kt.isStream,
    };
}

/** Track key used by the manager's encoded-track cache and the engine's dedupe. */
function trackKey(track) {
    if (!track) return null;
    return `${track.provider}:${track.id}`;
}

/**
 * Search-engine prefix for a free-text query. Lavalink resolves a bare query
 * with the node's default; we prefix explicitly so the configured engine always
 * wins and the behaviour is predictable.
 */
function searchPrefix(query, defaultEngine) {
    const engine = String(defaultEngine || 'ytsearch').trim();
    if (/^https?:\/\//i.test(query)) return query;
    // A query already carrying an engine prefix is passed through untouched.
    if (/^[a-z]{2,10}search:/i.test(query)) return query;
    return `${engine}:${query}`;
}

class LavalinkProviders {
    /**
     * @param {import('./manager').LavalinkManager} manager
     * @param {object} [deps] injectable for tests
     * @param {object} [deps.spotify] metadata fallback (utils/music/providers/spotify)
     */
    constructor(manager, deps = {}) {
        this.manager = manager;
        this.defaultEngine = deps.defaultEngine || process.env.LAVALINK_SEARCH_ENGINE || 'ytsearch';
        this.spotify = deps.spotify !== undefined ? deps.spotify : require('../providers/spotify');
    }

    get streamable() {
        return this.manager.streamableProviders();
    }

    /** Resolve a single query (URL or free text) to ONE playable track. */
    async resolveQuery(query, { searchLimit = 1 } = {}) {
        const raw = String(query || '').trim();
        if (!raw) throw new Error('Nothing to play — provide a search term or a URL.');

        // A Spotify URL: only stream it when the node actually resolves audio
        // for it. Otherwise fall back to metadata + match (honest labelling).
        if (isSpotifyUrl(raw)) {
            const native = await this._searchOnce(raw, 1).catch(() => []);
            if (native.length && native[0].provider !== PROVIDERS.SPOTIFY) return native[0];
            if (native.length && this.manager.supportsSource('spotify')) return native[0];
            const meta = await this.spotify.resolve(raw);
            return await this.matchToStreamable(meta);
        }

        const results = await this._search(raw, Math.max(1, searchLimit));
        if (!results.length) throw new Error(`No results found for “${raw}”.`);
        return results[0];
    }

    /** Resolve a query to a LIST of candidates (for /search). */
    async searchQuery(query, limit = 10) {
        const raw = String(query || '').trim();
        if (!raw) throw new Error('Provide a search term.');
        let term = raw;
        // Searching a Spotify URL → search its metadata title instead (the
        // user wants candidates, not a single native resolve).
        if (isSpotifyUrl(raw)) {
            const meta = await this.spotify.resolve(raw).catch(() => null);
            term = meta ? (meta.matchQuery || meta.title) : raw;
        }
        const results = await this._search(term, limit);
        if (!results.length) throw new Error(`No results found for “${term}”.`);
        return results;
    }

    /** Resolve a collection (playlist/album) URL into { title, tracks, limitation? }. */
    async resolveCollection(url, limit = 50) {
        if (isSpotifyUrl(url) && !this.manager.supportsSource('spotify')) {
            // No Spotify source plugin → keep the existing metadata path.
            const col = await this.spotify.resolveCollection(url, limit);
            if (!col.tracks.length) return col;
            const matched = [];
            for (const t of col.tracks) {
                try { matched.push(await this.matchToStreamable(t)); }
                catch (_) { /* skip an unmatchable Spotify track */ }
            }
            return { ...col, tracks: matched };
        }

        const res = await this.manager.resolve(url, { requester: null });
        const tracks = (res.tracks || []).map(kt => toTrack(kt)).filter(Boolean);
        if (!tracks.length) return { title: url, tracks: [], limitation: res.limitation || 'That collection has no playable tracks.' };
        return { title: res.playlistName || url, tracks: tracks.slice(0, Math.max(1, limit)) };
    }

    /**
     * Lavalink streams the track itself, so there is no separate stream URL to
     * resolve. Kept for interface parity with the direct engine; the actual
     * encoded track is resolved (and cached) by the manager at play time.
     */
    async resolveStream(track) {
        if (!track) throw new Error('No track to play.');
        return { streamUrl: null, durationMs: track.durationMs || null, lavalink: true };
    }

    /**
     * Match a metadata-only track (e.g. Spotify) to a streamable one. Uses the
     * node's search so the match plays on the same node as everything else.
     */
    async matchToStreamable(track, { minScore = 0.4 } = {}) {
        const { matchScore } = require('../providers/registry');
        const query = track.matchQuery || [track.artist, track.title].filter(Boolean).join(' ');
        if (!query) throw new Error('No search query available to match this track.');
        const candidates = await this._search(query, 5);
        let best = null;
        let bestScore = 0;
        for (const c of candidates) {
            const score = matchScore(track.title, c.title);
            if (score > bestScore) { bestScore = score; best = c; }
        }
        if (!best || bestScore < minScore) {
            throw new Error(`Could not find a playable match for “${track.title}”.`);
        }
        return {
            ...best,
            title: track.title || best.title,
            artist: track.artist || best.artist,
            artworkUrl: track.artworkUrl || best.artworkUrl,
            durationMs: track.durationMs || best.durationMs,
            requestedUrl: track.url || null,
            source: best.source,
            matchedFrom: track.provider,
            matchScore: bestScore,
        };
    }

    /** Raw single-shot search used by the Spotify path. */
    async _searchOnce(query, limit) {
        const res = await this.manager.search(query, { limit, engine: this.defaultEngine });
        return (res.tracks || []).map(kt => toTrack(kt)).filter(Boolean);
    }

    /** Search + normalize to PrimeBot tracks. */
    async _search(query, limit) {
        const res = await this.manager.search(query, { limit, engine: this.defaultEngine });
        return (res.tracks || []).map(kt => toTrack(kt)).filter(Boolean);
    }
}

module.exports = { LavalinkProviders, toTrack, providerFor, trackKey, searchPrefix, labelFor };
