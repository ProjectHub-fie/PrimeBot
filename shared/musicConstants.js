/**
 * Shared music constants — the single source of truth for provider ids,
 * repeat modes, playback states and URL detection, used by the bot, the
 * dashboard and the tests.
 */

const PROVIDERS = {
    YOUTUBE: 'youtube',
    SOUNDCLOUD: 'soundcloud',
    SPOTIFY: 'spotify',
    DIRECT: 'direct',
};

const PROVIDER_LABELS = {
    youtube: 'YouTube',
    soundcloud: 'SoundCloud',
    spotify: 'Spotify',
    direct: 'Direct URL',
};

// Providers that can actually resolve a playable audio stream. Spotify is a
// metadata/matching provider only — it is never streamed directly.
const STREAMABLE_PROVIDERS = [PROVIDERS.YOUTUBE, PROVIDERS.SOUNDCLOUD, PROVIDERS.DIRECT];

const REPEAT_MODES = { OFF: 'off', TRACK: 'track', QUEUE: 'queue' };
const VALID_REPEAT_MODES = Object.values(REPEAT_MODES);

const PLAYBACK_STATES = {
    IDLE: 'idle',
    PLAYING: 'playing',
    PAUSED: 'paused',
    STOPPED: 'stopped',
    // A track was accepted but audio is not flowing yet: the voice connection is
    // still establishing (no session id / endpoint) or Lavalink has not reported
    // a position. Never shown as "Playing".
    BUFFERING: 'buffering',
    // The voice connection was lost (or a node died) and is being re-established.
    RECONNECTING: 'reconnecting',
};

// Playback MODES — one per guild, mutually exclusive. Radio (24/7 station) and
// on-demand Music share the guild's single voice connection, so exactly one may
// own it at a time.
const PLAYBACK_MODES = {
    IDLE: 'idle',
    MUSIC: 'music',
    RADIO: 'radio',
};

// Supported direct-audio container/stream extensions and content types.
const AUDIO_EXTENSIONS = ['.mp3', '.m4a', '.aac', '.ogg', '.oga', '.opus', '.wav', '.flac', '.webm', '.mp4'];
const AUDIO_CONTENT_TYPES = [
    'audio/', 'application/ogg', 'application/octet-stream',
    'video/mp4', 'video/webm', // some CDNs serve audio-only mp4/webm
];

const SPOTIFY_HOSTS = ['open.spotify.com', 'spotify.com', 'play.spotify.com'];
const SOUNDCLOUD_HOSTS = ['soundcloud.com', 'www.soundcloud.com', 'm.soundcloud.com', 'on.soundcloud.com'];
const YOUTUBE_HOSTS = ['youtube.com', 'www.youtube.com', 'm.youtube.com', 'music.youtube.com', 'youtu.be', 'www.youtu.be'];

function hostOf(raw) {
    try {
        return new URL(String(raw)).hostname.toLowerCase();
    } catch (_) {
        return null;
    }
}

function isSpotifyUrl(raw) {
    const h = hostOf(raw);
    return !!h && SPOTIFY_HOSTS.includes(h);
}

function isSoundCloudUrl(raw) {
    const h = hostOf(raw);
    return !!h && SOUNDCLOUD_HOSTS.includes(h);
}

function isYouTubeUrl(raw) {
    const h = hostOf(raw);
    return !!h && YOUTUBE_HOSTS.includes(h);
}

/** Spotify entity kind from a URL: 'track' | 'album' | 'playlist' | null. */
function spotifyKind(raw) {
    try {
        const parts = new URL(String(raw)).pathname.split('/').filter(Boolean);
        // /track/<id>, /playlist/<id>, /album/<id> (optionally /intl-xx/ prefix)
        const idx = parts.findIndex(p => ['track', 'album', 'playlist'].includes(p));
        return idx >= 0 ? parts[idx] : null;
    } catch (_) {
        return null;
    }
}

/** Extract a Spotify id from a URL (track/album/playlist). */
function spotifyId(raw) {
    try {
        const parts = new URL(String(raw)).pathname.split('/').filter(Boolean);
        const idx = parts.findIndex(p => ['track', 'album', 'playlist'].includes(p));
        if (idx < 0) return null;
        return parts[idx + 1] ? parts[idx + 1].split('?')[0] : null;
    } catch (_) {
        return null;
    }
}

/** Extract a YouTube video id from any YouTube URL form. */
function youTubeId(raw) {
    try {
        const u = new URL(String(raw));
        if (u.hostname.toLowerCase().endsWith('youtu.be')) return u.pathname.slice(1).split('/')[0] || null;
        if (u.searchParams.get('v')) return u.searchParams.get('v');
        const parts = u.pathname.split('/').filter(Boolean);
        const idx = parts.findIndex(p => ['shorts', 'embed', 'v', 'live'].includes(p));
        if (idx >= 0 && parts[idx + 1]) return parts[idx + 1];
        return null;
    } catch (_) {
        return null;
    }
}

/**
 * Classify a raw query/URL into a provider hint. Returns
 * { provider, url, kind } or null when the input is a free-text query.
 */
function classifyInput(raw) {
    if (!raw || typeof raw !== 'string') return null;
    const value = raw.trim();
    if (!/^https?:\/\//i.test(value)) return null;
    if (isSpotifyUrl(value)) return { provider: PROVIDERS.SPOTIFY, url: value, kind: spotifyKind(value) };
    if (isSoundCloudUrl(value)) return { provider: PROVIDERS.SOUNDCLOUD, url: value, kind: 'url' };
    if (isYouTubeUrl(value)) return { provider: PROVIDERS.YOUTUBE, url: value, kind: 'url' };
    return { provider: PROVIDERS.DIRECT, url: value, kind: 'direct' };
}

/** Is a URL plausibly a direct audio stream (extension or known host)? */
function looksLikeAudioUrl(raw) {
    try {
        const u = new URL(String(raw));
        if (!/^https?:$/.test(u.protocol)) return false;
        const path = u.pathname.toLowerCase();
        return AUDIO_EXTENSIONS.some(ext => path.endsWith(ext));
    } catch (_) {
        return false;
    }
}

function formatDuration(ms) {
    const n = Number(ms);
    if (!Number.isFinite(n) || n <= 0) return '—';
    const total = Math.floor(n / 1000);
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    const pad = (x) => String(x).padStart(2, '0');
    return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

/** Parse a timestamp ("90", "1:30", "1h2m3s") into seconds, or null. */
function parseTimestamp(input) {
    if (input == null) return null;
    const s = String(input).trim().toLowerCase();
    if (!s) return null;
    if (/^\d+$/.test(s)) return parseInt(s, 10);
    let m = s.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
    if (m && (m[1] || m[2] || m[3])) {
        return (parseInt(m[1] || 0, 10) * 3600) + (parseInt(m[2] || 0, 10) * 60) + parseInt(m[3] || 0, 10);
    }
    m = s.match(/^(\d+):(\d{1,2})(?::(\d{1,2}))?$/);
    if (m) {
        if (m[3] != null) return (parseInt(m[1], 10) * 3600) + (parseInt(m[2], 10) * 60) + parseInt(m[3], 10);
        return (parseInt(m[1], 10) * 60) + parseInt(m[2], 10);
    }
    return null;
}

const PROGRESS_BAR_SIZE = 14;
const PROGRESS_LINE = '▬';
const PROGRESS_SLIDER = '🔘';

/**
 * Render a Discord-style playback progress bar, e.g.
 *   `▬▬▬▬▬🔘▬▬▬▬▬▬▬▬`
 * Returns an empty-position bar when nothing is playing / the duration is
 * unknown (never fabricates progress).
 */
function progressBar(positionMs, durationMs, { size = PROGRESS_BAR_SIZE, line = PROGRESS_LINE, slider = PROGRESS_SLIDER } = {}) {
    const total = Number(durationMs);
    const current = Number(positionMs);
    const width = Math.max(1, size | 0);
    if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(current)) {
        return `${slider}${line.repeat(width)}`;
    }
    const ratio = Math.min(1, Math.max(0, current / total));
    const filled = Math.round(ratio * width);
    const head = Math.min(width, Math.max(0, filled));
    return `${line.repeat(head)}${slider}${line.repeat(Math.max(0, width - head))}`;
}

/**
 * Track a repeating-queue playlist / artist name for autoplay queries.
 * (Kept here so the manager and the tests share one implementation.)
 */
function autoplayQuery(track) {
    if (!track) return null;
    const artist = track.artist || '';
    const title = track.title || '';
    const q = `${artist} ${title}`.trim();
    return q || null;
}

module.exports = {
    PROVIDERS,
    PROVIDER_LABELS,
    PLAYBACK_MODES,
    STREAMABLE_PROVIDERS,
    REPEAT_MODES,
    VALID_REPEAT_MODES,
    PLAYBACK_STATES,
    AUDIO_EXTENSIONS,
    AUDIO_CONTENT_TYPES,
    SPOTIFY_HOSTS,
    SOUNDCLOUD_HOSTS,
    YOUTUBE_HOSTS,
    isSpotifyUrl,
    isSoundCloudUrl,
    isYouTubeUrl,
    spotifyKind,
    spotifyId,
    youTubeId,
    classifyInput,
    looksLikeAudioUrl,
    formatDuration,
    parseTimestamp,
    progressBar,
    autoplayQuery,
    PROGRESS_BAR_SIZE,
};
