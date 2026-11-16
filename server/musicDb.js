const { resolveDbUrl } = require('./resolveDbUrl');
const { createPool } = require('./createPool');

/**
 * Dedicated PostgreSQL pool for the Music feature.
 *
 * Tables:
 *   music_settings        per-guild music configuration (DJ role, default volume,
 *                         24/7 persistent connection state)
 *   music_playlists       public + personal playlists
 *   music_playlist_tracks  ordered tracks inside a playlist
 *   music_history         recently played tracks (bounded, pruned)
 *
 * Follows the same multi-pool pattern as every other feature:
 * MUSIC_DATABASE_URL, else the shared FALLBACK_DATABASE_URL, else DATABASE_URL —
 * so a single-DB deployment works with zero extra configuration.
 *
 * Same-DB requirement: every shard node must point at the same
 * MUSIC_DATABASE_URL (or the same fallback) so a guild's player is owned by
 * exactly one node and its 24/7 config survives a restart.
 *
 * Stream URLs are NEVER stored here — only stable track identities (provider +
 * provider track id + metadata) so an expired stream URL is always re-resolved.
 */

function resolveConnectionString() {
    return resolveDbUrl('MUSIC_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ MUSIC_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — the music feature will have no database.');
}

const musicPool = createPool(cs, { label: 'MUSIC DB' });

// Self-create the tables so the feature works even when drizzle-kit migrations
// were never applied. Idempotent — the DDL is memoized by
// server/schemaBootstrap.js so it runs at most once per process.
let ensured = false;
async function ensureMusicTables() {
    if (ensured) return;
    await musicPool.query(`
        CREATE TABLE IF NOT EXISTS music_settings (
            guild_id varchar(50) PRIMARY KEY,
            enabled boolean NOT NULL DEFAULT false,
            dj_role_id varchar(50),
            default_volume integer NOT NULL DEFAULT 100,
            max_queue integer NOT NULL DEFAULT 500,
            -- 24/7 persistent voice connection
            twentyfourseven_enabled boolean NOT NULL DEFAULT false,
            twentyfourseven_channel_id varchar(50),
            -- set true on an intentional /247 disable so recovery never re-joins
            disabled_intentionally boolean NOT NULL DEFAULT false,
            last_state varchar(32),
            owner_node varchar(80),
            updated_at timestamptz NOT NULL DEFAULT NOW()
        );
    `);
    await musicPool.query(`
        CREATE TABLE IF NOT EXISTS music_playlists (
            id serial PRIMARY KEY,
            guild_id varchar(50) NOT NULL,
            owner_id varchar(50),
            name text NOT NULL,
            description text DEFAULT '',
            is_public boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT NOW(),
            updated_at timestamptz NOT NULL DEFAULT NOW()
        );
    `);
    await musicPool.query(`
        CREATE TABLE IF NOT EXISTS music_playlist_tracks (
            id serial PRIMARY KEY,
            playlist_id integer NOT NULL REFERENCES music_playlists(id) ON DELETE CASCADE,
            position integer NOT NULL DEFAULT 0,
            provider varchar(32) NOT NULL,
            track_id varchar(160) NOT NULL,
            title text,
            artist text,
            duration_ms bigint,
            url text,
            artwork_url text,
            added_by varchar(50),
            created_at timestamptz NOT NULL DEFAULT NOW()
        );
    `);
    await musicPool.query(`
        CREATE TABLE IF NOT EXISTS music_history (
            id serial PRIMARY KEY,
            guild_id varchar(50) NOT NULL,
            provider varchar(32) NOT NULL,
            track_id varchar(160) NOT NULL,
            title text,
            artist text,
            duration_ms bigint,
            requester_id varchar(50),
            played_at timestamptz NOT NULL DEFAULT NOW()
        );
    `);
    await musicPool.query(`CREATE INDEX IF NOT EXISTS music_playlists_guild_idx ON music_playlists (guild_id);`);
    await musicPool.query(`CREATE INDEX IF NOT EXISTS music_playlists_owner_idx ON music_playlists (owner_id);`);
    await musicPool.query(`CREATE INDEX IF NOT EXISTS music_playlist_tracks_playlist_idx ON music_playlist_tracks (playlist_id, position);`);
    await musicPool.query(`CREATE INDEX IF NOT EXISTS music_history_guild_idx ON music_history (guild_id, played_at DESC);`);
    // Additive migration for tables created before the 24/7 columns existed.
    await musicPool.query(`ALTER TABLE music_settings ADD COLUMN IF NOT EXISTS twentyfourseven_enabled boolean NOT NULL DEFAULT false;`);
    await musicPool.query(`ALTER TABLE music_settings ADD COLUMN IF NOT EXISTS twentyfourseven_channel_id varchar(50);`);
    await musicPool.query(`ALTER TABLE music_settings ADD COLUMN IF NOT EXISTS disabled_intentionally boolean NOT NULL DEFAULT false;`);
    await musicPool.query(`ALTER TABLE music_settings ADD COLUMN IF NOT EXISTS last_state varchar(32);`);
    await musicPool.query(`ALTER TABLE music_settings ADD COLUMN IF NOT EXISTS owner_node varchar(80);`);
    ensured = true;
}

async function testMusicConnection() {
    try {
        const client = await musicPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Music database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Music database connection failed:', err.message);
        return false;
    }
}

module.exports = { musicPool, ensureMusicTables, testMusicConnection, resolveConnectionString };
