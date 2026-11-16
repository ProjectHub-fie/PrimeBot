/**
 * Music persistence store.
 *
 * Bridges MusicManager's storage interface onto the MUSIC_DATABASE_URL pool:
 *
 *   getSettings(guildId)          → normalized guild music settings
 *   saveSettings(guildId, patch)  → upsert (partial patch merged)
 *   listEnabledSettings()         → settings for guilds with music enabled
 *   list247Settings()             → settings for guilds with 24/7 enabled
 *   addHistory(guildId, track)    → append a played track (bounded)
 *
 * Only stable track identities are stored — never a stream URL.
 */

const { musicPool, ensureMusicTables } = require('../../server/musicDb');
const { DEFAULT_MAX_QUEUE } = require('./musicManager');

function rowToSettings(r) {
    if (!r) return null;
    return {
        guildId: String(r.guild_id),
        enabled: !!r.enabled,
        djRoleId: r.dj_role_id || null,
        defaultVolume: r.default_volume != null ? Number(r.default_volume) : 100,
        maxQueue: r.max_queue != null ? Number(r.max_queue) : DEFAULT_MAX_QUEUE,
        twentyFourSevenEnabled: !!r.twentyfourseven_enabled,
        twentyFourSevenChannelId: r.twentyfourseven_channel_id || null,
        disabledIntentionally: !!r.disabled_intentionally,
        lastState: r.last_state || null,
        ownerNode: r.owner_node || null,
    };
}

async function getSettings(guildId) {
    await ensureMusicTables();
    const res = await musicPool.query('SELECT * FROM music_settings WHERE guild_id = $1', [String(guildId)]);
    return rowToSettings(res.rows[0]);
}

async function saveSettings(guildId, patch = {}) {
    await ensureMusicTables();
    const current = await getSettings(guildId) || { guildId: String(guildId) };
    const next = { ...current, ...patch, guildId: String(guildId) };
    const res = await musicPool.query(
        `INSERT INTO music_settings
            (guild_id, enabled, dj_role_id, default_volume, max_queue,
             twentyfourseven_enabled, twentyfourseven_channel_id, disabled_intentionally,
             last_state, owner_node, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
         ON CONFLICT (guild_id) DO UPDATE SET
            enabled = EXCLUDED.enabled,
            dj_role_id = EXCLUDED.dj_role_id,
            default_volume = EXCLUDED.default_volume,
            max_queue = EXCLUDED.max_queue,
            twentyfourseven_enabled = EXCLUDED.twentyfourseven_enabled,
            twentyfourseven_channel_id = EXCLUDED.twentyfourseven_channel_id,
            disabled_intentionally = EXCLUDED.disabled_intentionally,
            last_state = EXCLUDED.last_state,
            owner_node = EXCLUDED.owner_node,
            updated_at = NOW()
         RETURNING *`,
        [
            String(guildId),
            !!next.enabled,
            next.djRoleId || null,
            next.defaultVolume != null ? next.defaultVolume : 100,
            next.maxQueue != null ? next.maxQueue : DEFAULT_MAX_QUEUE,
            !!next.twentyFourSevenEnabled,
            next.twentyFourSevenChannelId || null,
            !!next.disabledIntentionally,
            next.lastState || null,
            next.ownerNode || null,
        ],
    );
    return rowToSettings(res.rows[0]);
}

async function listEnabledSettings() {
    await ensureMusicTables();
    const res = await musicPool.query('SELECT * FROM music_settings WHERE enabled = true OR twentyfourseven_enabled = true');
    return res.rows.map(rowToSettings);
}

async function list247Settings() {
    await ensureMusicTables();
    const res = await musicPool.query(
        'SELECT * FROM music_settings WHERE twentyfourseven_enabled = true AND disabled_intentionally = false',
    );
    return res.rows.map(rowToSettings);
}

async function addHistory(guildId, track, { requesterId = null } = {}) {
    await ensureMusicTables();
    if (!track) return;
    await musicPool.query(
        `INSERT INTO music_history (guild_id, provider, track_id, title, artist, duration_ms, requester_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [String(guildId), track.provider || 'unknown', String(track.id), track.title || null, track.artist || null,
            track.durationMs != null ? Math.round(track.durationMs) : null, requesterId || track.requesterId || null],
    );
    // Bound the history table so it cannot grow without limit.
    await musicPool.query(
        `DELETE FROM music_history WHERE id IN (
            SELECT id FROM music_history WHERE guild_id = $1 ORDER BY played_at DESC OFFSET 200
        )`, [String(guildId)],
    ).catch(() => {});
}

// ── playlists ───────────────────────────────────────────────────────────────

function rowToPlaylist(r) {
    if (!r) return null;
    return {
        id: r.id,
        guildId: String(r.guild_id),
        ownerId: r.owner_id || null,
        name: r.name,
        description: r.description || '',
        isPublic: !!r.is_public,
        createdAt: r.created_at,
        updatedAt: r.updated_at,
    };
}

function rowToPlaylistTrack(r) {
    if (!r) return null;
    return {
        id: r.id,
        playlistId: r.playlist_id,
        position: r.position,
        provider: r.provider,
        trackId: r.track_id,
        title: r.title,
        artist: r.artist,
        durationMs: r.duration_ms != null ? Number(r.duration_ms) : null,
        url: r.url,
        artworkUrl: r.artwork_url,
        addedBy: r.added_by || null,
    };
}

async function listPlaylists(guildId, { ownerId = null, includePublic = true } = {}) {
    await ensureMusicTables();
    let sql = 'SELECT * FROM music_playlists WHERE guild_id = $1';
    const params = [String(guildId)];
    if (ownerId && includePublic) { sql += ' AND (owner_id = $2 OR is_public = true)'; params.push(String(ownerId)); }
    else if (ownerId) { sql += ' AND owner_id = $2'; params.push(String(ownerId)); }
    else if (!includePublic) { sql += ' AND is_public = true'; }
    sql += ' ORDER BY is_public DESC, name ASC';
    const res = await musicPool.query(sql, params);
    return res.rows.map(rowToPlaylist);
}

async function getPlaylist(guildId, id) {
    await ensureMusicTables();
    const res = await musicPool.query('SELECT * FROM music_playlists WHERE id = $1 AND guild_id = $2', [Number(id), String(guildId)]);
    return rowToPlaylist(res.rows[0]);
}

async function createPlaylist(guildId, { name, description = '', isPublic = false, ownerId = null }) {
    await ensureMusicTables();
    const res = await musicPool.query(
        `INSERT INTO music_playlists (guild_id, owner_id, name, description, is_public)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [String(guildId), ownerId || null, String(name).slice(0, 100), String(description || '').slice(0, 500), !!isPublic],
    );
    return rowToPlaylist(res.rows[0]);
}

async function renamePlaylist(guildId, id, name) {
    await ensureMusicTables();
    const res = await musicPool.query(
        'UPDATE music_playlists SET name = $3, updated_at = NOW() WHERE id = $1 AND guild_id = $2 RETURNING *',
        [Number(id), String(guildId), String(name).slice(0, 100)],
    );
    return rowToPlaylist(res.rows[0]);
}

async function deletePlaylist(guildId, id) {
    await ensureMusicTables();
    const res = await musicPool.query('DELETE FROM music_playlists WHERE id = $1 AND guild_id = $2 RETURNING id', [Number(id), String(guildId)]);
    return res.rowCount > 0;
}

async function listPlaylistTracks(playlistId) {
    await ensureMusicTables();
    const res = await musicPool.query('SELECT * FROM music_playlist_tracks WHERE playlist_id = $1 ORDER BY position ASC, id ASC', [Number(playlistId)]);
    return res.rows.map(rowToPlaylistTrack);
}

/** Replace a playlist's tracks in one transaction (transaction-safe save). */
async function replacePlaylistTracks(playlistId, tracks, { addedBy = null } = {}) {
    await ensureMusicTables();
    const client = await musicPool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM music_playlist_tracks WHERE playlist_id = $1', [Number(playlistId)]);
        let pos = 0;
        for (const t of tracks || []) {
            await client.query(
                `INSERT INTO music_playlist_tracks (playlist_id, position, provider, track_id, title, artist, duration_ms, url, artwork_url, added_by)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
                [Number(playlistId), pos++, t.provider || 'unknown', String(t.id), t.title || null, t.artist || null,
                    t.durationMs != null ? Math.round(t.durationMs) : null, t.url || null, t.artworkUrl || null, addedBy],
            );
        }
        await client.query('UPDATE music_playlists SET updated_at = NOW() WHERE id = $1', [Number(playlistId)]);
        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}

async function addPlaylistTrack(playlistId, track, { addedBy = null } = {}) {
    await ensureMusicTables();
    const posRes = await musicPool.query('SELECT COALESCE(MAX(position), -1) + 1 AS pos FROM music_playlist_tracks WHERE playlist_id = $1', [Number(playlistId)]);
    const pos = posRes.rows[0].pos;
    const res = await musicPool.query(
        `INSERT INTO music_playlist_tracks (playlist_id, position, provider, track_id, title, artist, duration_ms, url, artwork_url, added_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [Number(playlistId), pos, track.provider || 'unknown', String(track.id), track.title || null, track.artist || null,
            track.durationMs != null ? Math.round(track.durationMs) : null, track.url || null, track.artworkUrl || null, addedBy],
    );
    return rowToPlaylistTrack(res.rows[0]);
}

async function removePlaylistTrack(playlistId, position) {
    await ensureMusicTables();
    const res = await musicPool.query(
        'DELETE FROM music_playlist_tracks WHERE playlist_id = $1 AND position = $2 RETURNING id',
        [Number(playlistId), Number(position)],
    );
    return res.rowCount > 0;
}

module.exports = {
    getSettings, saveSettings, listEnabledSettings, list247Settings, addHistory,
    listPlaylists, getPlaylist, createPlaylist, renamePlaylist, deletePlaylist,
    listPlaylistTracks, replacePlaylistTracks, addPlaylistTrack, removePlaylistTrack,
    rowToSettings, rowToPlaylist, rowToPlaylistTrack,
};
