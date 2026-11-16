/**
 * Spotify provider adapter — METADATA + TRACK MATCHING ONLY.
 *
 * Spotify audio is DRM-protected and cannot (and must not) be streamed directly.
 * This adapter therefore:
 *   1. recognises Spotify track/album/playlist URLs,
 *   2. resolves the ORIGINAL Spotify metadata (title, artist, artwork),
 *   3. hands the MusicManager a search query to match against a streamable
 *      provider (YouTube / SoundCloud),
 *   4. reports the actual playback source separately from the Spotify metadata.
 *
 * Metadata resolution uses Spotify's PUBLIC oEmbed endpoint (no auth, no
 * scraping of protected content):
 *   GET https://open.spotify.com/oembed?url=<trackUrl>
 *     → { title, thumbnail_url, provider_name, ... }
 *
 * Playlist/album EXPANSION (enumerating every track) requires the Spotify Web
 * API with a client-credentials token. That is supported ONLY when
 * SPOTIFY_CLIENT_ID + SPOTIFY_CLIENT_SECRET are configured; otherwise a playlist
 * resolves to its oEmbed title with an empty track list and a clear limitation
 * is reported (we never invent tracks). No credentials are logged.
 */

const { PROVIDERS, isSpotifyUrl, spotifyKind, spotifyId } = require('../../../shared/musicConstants');

const OEMBED = 'https://open.spotify.com/oembed';
const API = 'https://api.spotify.com/v1';
const TOKEN_URL = 'https://accounts.spotify.com/api/token';

let _token = null; // { value, expiresAt }
let _fetch = null;
function http() {
    if (!_fetch) _fetch = globalThis.fetch;
    return _fetch;
}

function credentials() {
    const id = process.env.SPOTIFY_CLIENT_ID;
    const secret = process.env.SPOTIFY_CLIENT_SECRET;
    return id && secret ? { id, secret } : null;
}

async function getToken() {
    const creds = credentials();
    if (!creds) return null;
    if (_token && _token.expiresAt > Date.now() + 5000) return _token.value;
    const basic = Buffer.from(`${creds.id}:${creds.secret}`).toString('base64');
    const res = await http()(TOKEN_URL, {
        method: 'POST',
        headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials',
    });
    if (!res.ok) throw new Error(`Spotify token request failed (${res.status}).`);
    const json = await res.json();
    _token = { value: json.access_token, expiresAt: Date.now() + (Number(json.expires_in) || 3600) * 1000 };
    return _token.value;
}

function canHandle(input) {
    return typeof input === 'string' && isSpotifyUrl(input);
}

/** Metadata-only "track" carrying a search query for provider matching. */
function toTrack(oembed, url) {
    if (!oembed || !oembed.title) return null;
    // oEmbed title is usually "Artist · Track" or just the track title.
    const title = String(oembed.title);
    const splitMatch = title.split(/\s+[·\-–]\s+/);
    const artist = splitMatch.length > 1 ? splitMatch[0].trim() : null;
    const trackTitle = splitMatch.length > 1 ? splitMatch.slice(1).join(' - ').trim() : title;
    return {
        provider: PROVIDERS.SPOTIFY,
        id: spotifyId(url) || title,
        title: trackTitle,
        artist,
        durationMs: null,
        url,
        artworkUrl: oembed.thumbnail_url || null,
        source: 'Spotify',
        // The MusicManager uses this to find a streamable match.
        matchQuery: [artist, trackTitle].filter(Boolean).join(' '),
        streamable: false,
    };
}

async function oembed(url) {
    const res = await http()(`${OEMBED}?url=${encodeURIComponent(url)}`, {
        headers: { Accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`Spotify metadata could not be read (${res.status}).`);
    return res.json();
}

async function resolve(url) {
    const oembedData = await oembed(url);
    const track = toTrack(oembedData, url);
    if (!track) throw new Error('Spotify track metadata could not be resolved.');
    return track;
}

/**
 * Spotify cannot provide an audio stream. This always throws with a clear,
 * honest reason — callers must fall back to a streamable provider.
 */
async function resolveStream() {
    throw Object.assign(
        new Error('Spotify does not provide playable audio (DRM-protected). PrimeBot matches the track on YouTube/SoundCloud instead.'),
        { code: 'SPOTIFY_NOT_STREAMABLE' },
    );
}

/** Enumerate a Spotify playlist/album via the Web API (needs credentials). */
async function resolveCollection(url, limit = 50) {
    const kind = spotifyKind(url);
    const id = spotifyId(url);
    const meta = await oembed(url).catch(() => null);
    const title = (meta && meta.title) || `Spotify ${kind || 'collection'}`;
    if (!credentials() || !id) {
        return { title, tracks: [], limitation: 'Spotify playlist expansion needs SPOTIFY_CLIENT_ID/SPOTIFY_CLIENT_SECRET; only single tracks can be matched without them.' };
    }
    const token = await getToken();
    const endpoint = kind === 'album' ? `albums/${id}/tracks` : `playlists/${id}/tracks`;
    const cap = Math.min(Math.max(1, limit), 100);
    const res = await http()(`${API}/${endpoint}?limit=${cap}`, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`Spotify ${kind} could not be read (${res.status}).`);
    const json = await res.json();
    const tracks = (json.items || []).map(item => {
        const t = item.track || item; // playlist items wrap in .track; album items do not
        if (!t || !t.name) return null;
        const artist = Array.isArray(t.artists) && t.artists[0] ? t.artists[0].name : null;
        const artwork = t.album && Array.isArray(t.album.images) && t.album.images[0] ? t.album.images[0].url : null;
        return {
            provider: PROVIDERS.SPOTIFY,
            id: t.id || t.name,
            title: t.name,
            artist,
            durationMs: t.duration_ms != null ? Number(t.duration_ms) : null,
            url: t.external_urls ? t.external_urls.spotify : null,
            artworkUrl: artwork,
            source: 'Spotify',
            matchQuery: [artist, t.name].filter(Boolean).join(' '),
            streamable: false,
        };
    }).filter(Boolean);
    return { title, tracks };
}

function _resetToken() { _token = null; }

module.exports = { id: PROVIDERS.SPOTIFY, canHandle, resolve, resolveStream, resolveCollection, hasCredentials: () => !!credentials(), _toTrack: toTrack, _resetToken };
