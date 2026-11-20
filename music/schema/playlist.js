/**
 * Linix `schema/playlist.js` — user playlists.
 *
 * Field names match the Linix mongoose schema exactly (`Username`, `UserId`,
 * `PlaylistName`, `Playlist`, `CreatedOn`) so the vendored playlist commands
 * run unchanged. `Playlist` is stored as JSONB.
 */

const { createModel } = require('./_pg');

const Playlist = createModel({
    table: 'music_playlists',
    columns: [
        ['id', 'serial PRIMARY KEY'],
        ['Username', 'text'],
        ['UserId', 'varchar(50) NOT NULL'],
        ['PlaylistName', 'text NOT NULL'],
        ['Playlist', "jsonb NOT NULL DEFAULT '[]'::jsonb"],
        ['CreatedOn', 'bigint'],
    ],
    serialize: [
        ['Playlist', (v) => JSON.stringify(Array.isArray(v) ? v : [])],
    ],
    deserialize: [
        ['Playlist', (v) => (typeof v === 'string' ? JSON.parse(v) : (v || []))],
    ],
});

module.exports = Playlist;
