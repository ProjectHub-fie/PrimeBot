/**
 * Shared constants for the 24/7 Radio feature (bot + dashboard).
 *
 * Kept dependency-free so the dashboard can require it without pulling in the
 * voice stack. The station SOURCES are deliberately limited to what the
 * `soundcloud-core` package actually supports (see utils/soundcloudSource.js):
 * a single track, a playlist/set, or a search query (used for genre stations).
 */

const RADIO_STATES = {
    STOPPED: 'stopped',
    CONNECTING: 'connecting',
    PLAYING: 'playing',
    PAUSED_EMPTY: 'paused_empty',
    PAUSED_MANUAL: 'paused_manual',
    IDLE: 'idle',
};

const RADIO_STATE_LABELS = {
    [RADIO_STATES.STOPPED]: 'Stopped',
    [RADIO_STATES.CONNECTING]: 'Connecting…',
    [RADIO_STATES.PLAYING]: 'Playing',
    [RADIO_STATES.PAUSED_EMPTY]: 'Paused (channel empty)',
    [RADIO_STATES.PAUSED_MANUAL]: 'Paused (by an admin)',
    [RADIO_STATES.IDLE]: 'Idle',
};

const STATION_SOURCES = {
    PLAYLIST: 'soundcloud_playlist',
    TRACK: 'soundcloud_track',
    GENRE: 'soundcloud_genre',
    PROFILE: 'soundcloud_profile',
};

const VALID_SOURCES = Object.values(STATION_SOURCES);

// Human-readable labels for the dashboard / command output.
const SOURCE_LABELS = {
    [STATION_SOURCES.PLAYLIST]: 'Playlist',
    [STATION_SOURCES.TRACK]: 'Single track',
    [STATION_SOURCES.GENRE]: 'Genre (search)',
    [STATION_SOURCES.PROFILE]: 'Artist profile',
};

// Only SoundCloud URLs are accepted as a station reference (never arbitrary
// hosts). Genre stations use a plain search string instead.
const SOUNDCLOUD_HOST_RE = /^(https?:\/\/)?(www\.|m\.)?soundcloud\.com\//i;

function isSoundCloudUrl(value) {
    return typeof value === 'string' && SOUNDCLOUD_HOST_RE.test(value.trim());
}

/**
 * Validate + normalize a station definition. Returns { ok, error, station } so
 * callers (dashboard API, slash command) can reject bad input uniformly. Never
 * trusts client input: ids are slugged, references are length-capped, and URL
 * sources must point at soundcloud.com.
 */
function normalizeStation(raw = {}) {
    const name = String(raw.name || '').trim().slice(0, 100);
    if (!name) return { ok: false, error: 'A station name is required.' };

    const source = VALID_SOURCES.includes(raw.source) ? raw.source : STATION_SOURCES.PLAYLIST;
    const reference = String(raw.reference || '').trim();
    if (!reference) return { ok: false, error: 'A station reference (URL or search query) is required.' };
    if (reference.length > 500) return { ok: false, error: 'The station reference is too long.' };

    if (source !== STATION_SOURCES.GENRE && !isSoundCloudUrl(reference)) {
        return { ok: false, error: 'The reference must be a soundcloud.com URL for this source type.' };
    }
    if (source === STATION_SOURCES.GENRE && isSoundCloudUrl(reference)) {
        return { ok: false, error: 'A genre station reference is a search term, not a URL.' };
    }

    const id = String(raw.id || slugify(name)).trim().slice(0, 80);
    return {
        ok: true,
        station: {
            id,
            name,
            description: String(raw.description || '').trim().slice(0, 500),
            source,
            reference,
            genre: raw.genre ? String(raw.genre).trim().slice(0, 80) : null,
            enabled: raw.enabled === undefined ? true : raw.enabled !== false,
            guildId: raw.guildId ? String(raw.guildId) : null,
        },
    };
}

function slugify(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 60) || 'station';
}

module.exports = {
    RADIO_STATES,
    RADIO_STATE_LABELS,
    STATION_SOURCES,
    VALID_SOURCES,
    SOURCE_LABELS,
    isSoundCloudUrl,
    normalizeStation,
    slugify,
};
