/**
 * Radio station catalog + resolution.
 *
 * A station is a NAMED source that expands into a list of playable tracks:
 *
 *   soundcloud_playlist  → the tracks of a SoundCloud set
 *   soundcloud_track     → a single track
 *   soundcloud_genre     → a search query (the only "genre station" the
 *                          soundcloud-core package can support — it has no
 *                          genre primitive, so we search and collect)
 *   soundcloud_profile   → an artist's most popular tracks (via search scoped
 *                          to the artist name; the package exposes a profile's
 *                          track COUNT but not its track list)
 *
 * Stations live in the `radio_stations` table (RADIO_DATABASE_URL pool). Global
 * stations have guild_id = NULL; administrator-created stations are scoped to a
 * guild. Nothing is hardcoded or fabricated — every track comes from a real
 * SoundCloud resolution.
 */

const { radioPool, ensureRadioTables } = require('../server/radioDb');
const { STATION_SOURCES, normalizeStation, slugify } = require('../shared/radioConstants');
const sc = require('./soundcloudSource');

// A small set of built-in GLOBAL stations. They are real search queries / well
// known public sets — not fake tracks. Admins can add their own on top.
const BUILTIN_STATIONS = [
    {
        id: 'lofi-hip-hop',
        name: 'Lofi Hip Hop',
        description: 'Chill lofi hip hop beats — 24/7 study & relax.',
        source: STATION_SOURCES.GENRE,
        reference: 'lofi hip hop radio beats',
        genre: 'Lo-fi',
        enabled: true,
        guildId: null,
    },
    {
        id: 'synthwave',
        name: 'Synthwave / Retro',
        description: 'Neon-drenched synthwave and retro electro.',
        source: STATION_SOURCES.GENRE,
        reference: 'synthwave retrowave mix',
        genre: 'Synthwave',
        enabled: true,
        guildId: null,
    },
    {
        id: 'deep-house',
        name: 'Deep House',
        description: 'Deep house grooves for focus and flow.',
        source: STATION_SOURCES.GENRE,
        reference: 'deep house mix',
        genre: 'House',
        enabled: true,
        guildId: null,
    },
    {
        id: 'jazz-cafe',
        name: 'Jazz Café',
        description: 'Smooth jazz for a calm, focused room.',
        source: STATION_SOURCES.GENRE,
        reference: 'smooth jazz cafe mix',
        genre: 'Jazz',
        enabled: true,
        guildId: null,
    },
    {
        id: 'classical',
        name: 'Classical Focus',
        description: 'Classical pieces for deep work.',
        source: STATION_SOURCES.GENRE,
        reference: 'classical music for studying',
        genre: 'Classical',
        enabled: true,
        guildId: null,
    },
];

const GENRE_TRACK_LIMIT = Math.max(5, parseInt(process.env.RADIO_GENRE_TRACK_LIMIT, 10) || 25);
const PLAYLIST_TRACK_LIMIT = Math.max(10, parseInt(process.env.RADIO_PLAYLIST_TRACK_LIMIT, 10) || 100);

class StationManager {
    constructor() {
        this._stations = new Map(); // id -> station
        this._ready = false;
        this._initPromise = this.load().catch(err => {
            console.error('[RADIO] Station catalog load failed:', err.message);
            this._ready = false;
        });
    }

    waitForReady() { return this._initPromise; }

    // Load the DB stations and merge the built-in globals (DB rows win so an
    // admin can override a built-in by reusing its id).
    async load() {
        try {
            await ensureRadioTables();
            const res = await radioPool.query('SELECT * FROM radio_stations');
            const map = new Map();
            for (const b of BUILTIN_STATIONS) map.set(b.id, { ...b });
            for (const row of res.rows || []) {
                map.set(row.id, {
                    id: row.id,
                    guildId: row.guild_id || null,
                    name: row.name,
                    description: row.description || '',
                    source: row.source,
                    reference: row.reference,
                    genre: row.genre || null,
                    enabled: row.enabled !== false,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at,
                });
            }
            this._stations = map;
            this._ready = true;
        } catch (err) {
            console.error('[RADIO] Station catalog load failed:', err.message);
            // Fall back to the built-in globals so the feature still works
            // without a database (read-only).
            const map = new Map();
            for (const b of BUILTIN_STATIONS) map.set(b.id, { ...b });
            this._stations = map;
            this._ready = false;
        }
        return this._stations;
    }

    /** Stations visible to a guild: globals + that guild's own. */
    listForGuild(guildId) {
        return [...this._stations.values()].filter(
            s => !s.guildId || s.guildId === guildId
        );
    }

    get(id) {
        return this._stations.get(id) || null;
    }

    /** Create or update an administrator station (guild-scoped). */
    async upsert(raw, guildId) {
        const normalized = normalizeStation({ ...raw, guildId });
        if (!normalized.ok) throw Object.assign(new Error(normalized.error), { status: 400 });
        const s = normalized.station;
        // Guard against an admin silently overwriting a BUILT-IN global station
        // from one guild (the id is global). Prefix guild ids for collisions.
        let id = s.id;
        const existing = this._stations.get(id);
        if (existing && existing.guildId && existing.guildId !== guildId) {
            id = `${slugify(String(guildId).slice(-6))}-${s.id}`.slice(0, 80);
        }
        await ensureRadioTables();
        await radioPool.query(
            `INSERT INTO radio_stations (id, guild_id, name, description, source, reference, genre, enabled, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8, NOW())
             ON CONFLICT (id) DO UPDATE SET
               guild_id = EXCLUDED.guild_id, name = EXCLUDED.name, description = EXCLUDED.description,
               source = EXCLUDED.source, reference = EXCLUDED.reference, genre = EXCLUDED.genre,
               enabled = EXCLUDED.enabled, updated_at = NOW()`,
            [id, guildId, s.name, s.description, s.source, s.reference, s.genre, s.enabled]
        );
        const station = { ...s, id, guildId };
        this._stations.set(id, station);
        return station;
    }

    /** Remove a guild-scoped station. Built-in globals cannot be deleted. */
    async remove(id, guildId) {
        const station = this._stations.get(id);
        if (!station) return false;
        if (!station.guildId) return false; // built-in global — not deletable
        if (station.guildId !== guildId) return false; // not this guild's station
        await ensureRadioTables();
        await radioPool.query('DELETE FROM radio_stations WHERE id = $1 AND guild_id = $2', [id, guildId]);
        this._stations.delete(id);
        return true;
    }

    /**
     * Expand a station into a bounded list of playable tracks (normalized
     * metadata, never stream URLs). Returns [] when nothing resolves rather
     * than throwing, so the manager can skip an unusable station.
     */
    async resolveTracks(station) {
        if (!station) return [];
        try {
            switch (station.source) {
                case STATION_SOURCES.TRACK: {
                    const track = await sc.resolveTrack(station.reference);
                    return track ? [stripStream(track)] : [];
                }
                case STATION_SOURCES.PLAYLIST: {
                    const playlist = await sc.resolvePlaylist(station.reference, PLAYLIST_TRACK_LIMIT);
                    return (playlist.tracks || []).map(stripStream).filter(Boolean);
                }
                case STATION_SOURCES.GENRE:
                case STATION_SOURCES.PROFILE: {
                    const results = await sc.search(station.reference, GENRE_TRACK_LIMIT);
                    return results.map(stripStream).filter(Boolean);
                }
                default:
                    return [];
            }
        } catch (err) {
            console.error(`[RADIO] Station "${station.id}" failed to resolve:`, err.message);
            return [];
        }
    }
}

// Never carry a stream URL into the queue/cache — it is short-lived.
function stripStream(track) {
    if (!track) return null;
    const { streamUrl, trackAuthorization, ...rest } = track;
    return rest;
}

module.exports = { StationManager, BUILTIN_STATIONS, stripStream };
