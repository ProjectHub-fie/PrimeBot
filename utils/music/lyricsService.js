/**
 * Lyrics lookup — no new dependency.
 *
 * Uses the public `lyrics.ovh` API (`GET /v1/{artist}/{title}`), which needs no
 * key. The request is bounded by a timeout so a hung endpoint can never stall a
 * command, and every failure resolves to `{ lyrics: null, reason }` rather than
 * throwing into the command handler.
 *
 * A caller may pass a raw query instead of a track (e.g. `$lyrics <song>`); in
 * that case the whole string is used as the title.
 */

const DEFAULT_TIMEOUT_MS = Math.max(1000, parseInt(process.env.LYRICS_TIMEOUT_MS, 10) || 8000);

// Resolved per call (never cached) so a test/override of globalThis.fetch — or
// a runtime that installs fetch later — is always honoured.
function http() { return globalThis.fetch; }

/** Split "Artist - Title" style strings into artist/title parts. */
function splitQuery(query) {
    const raw = String(query || '').trim();
    if (!raw) return { artist: '', title: '' };
    const m = raw.match(/^(.*?)\s+[-–—]\s+(.*)$/);
    if (m) return { artist: m[1].trim(), title: m[2].trim() };
    return { artist: '', title: raw };
}

/** Look up an artist name for a bare title via Deezer's public search API. */
async function resolveArtist(title, timeoutMs) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
        const url = `https://api.deezer.com/search?q=${encodeURIComponent(title)}&limit=1`;
        const res = await http()(url, { signal: controller ? controller.signal : undefined });
        if (!res.ok) return null;
        const json = await res.json().catch(() => null);
        const hit = json && Array.isArray(json.data) ? json.data[0] : null;
        return hit && hit.artist && hit.artist.name ? hit.artist.name : null;
    } catch (_) {
        return null;
    } finally {
        if (timer) clearTimeout(timer);
    }
}

/**
 * Fetch lyrics for a track or a raw query string.
 * Returns `{ lyrics: string|null, artist, title, reason? }`.
 */
async function fetchLyrics({ track = null, query = null, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    let artist = '';
    let title = '';
    if (track) {
        artist = track.artist || '';
        title = track.title || '';
        // Some providers fold "Artist - Title" into the title.
        if (!artist && title) ({ artist, title } = splitQuery(title));
    } else {
        ({ artist, title } = splitQuery(query));
    }
    title = title.replace(/\s*[\(\[](official|lyrics?|audio|video|hd|mv)[^\)\]]*[\)\]]/gi, '').trim();
    if (!title) return { lyrics: null, artist, title, reason: 'Provide a song name.' };

    // lyrics.ovh needs an artist; resolve one for a bare title so `$lyrics <song>`
    // actually works instead of always 404ing.
    if (!artist) {
        const found = await resolveArtist(title, timeoutMs);
        if (found) artist = found;
    }

    const base = 'https://api.lyrics.ovh/v1';
    const url = artist
        ? `${base}/${encodeURIComponent(artist)}/${encodeURIComponent(title)}`
        : `${base}/${encodeURIComponent(title)}`;
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
        const res = await http()(url, { signal: controller ? controller.signal : undefined });
        if (!res.ok) return { lyrics: null, artist, title, reason: `No lyrics found (HTTP ${res.status}).` };
        const json = await res.json().catch(() => null);
        const lyrics = json && typeof json.lyrics === 'string' ? json.lyrics.trim() : '';
        if (!lyrics) return { lyrics: null, artist, title, reason: 'No lyrics found for that song.' };
        return { lyrics, artist, title };
    } catch (err) {
        const reason = err && err.name === 'AbortError'
            ? 'The lyrics service timed out.'
            : `Could not reach the lyrics service: ${err.message}`;
        return { lyrics: null, artist, title, reason };
    } finally {
        if (timer) clearTimeout(timer);
    }
}

module.exports = { fetchLyrics, splitQuery, DEFAULT_TIMEOUT_MS };
