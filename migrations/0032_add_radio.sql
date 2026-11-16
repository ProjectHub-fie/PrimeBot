-- 24/7 Radio (SoundCloud) — persistent per-guild radio sessions + the station
-- catalog.
--
-- Tables live on the dedicated RADIO_DATABASE_URL pool (falls back to
-- FALLBACK_DATABASE_URL then DATABASE_URL, so single-DB setups need no extra
-- configuration). They are also self-created by server/radioDb.js
-- (CREATE TABLE IF NOT EXISTS on first use), so this migration is
-- belt-and-suspenders for setups that run drizzle-kit migrations.

CREATE TABLE IF NOT EXISTS radio_sessions (
    guild_id varchar(50) PRIMARY KEY,
    channel_id varchar(50) NOT NULL,
    station_id varchar(80),
    enabled boolean NOT NULL DEFAULT false,
    manual_pause boolean NOT NULL DEFAULT false,
    current_track_id varchar(120),
    current_track jsonb,
    position_index integer NOT NULL DEFAULT 0,
    queue jsonb NOT NULL DEFAULT '[]'::jsonb,
    state varchar(32) NOT NULL DEFAULT 'stopped',
    volume integer NOT NULL DEFAULT 100,
    owner_node varchar(80),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS radio_stations (
    id varchar(80) PRIMARY KEY,
    guild_id varchar(50),
    name text NOT NULL,
    description text DEFAULT '',
    source varchar(32) NOT NULL DEFAULT 'soundcloud_playlist',
    reference text NOT NULL,
    genre varchar(80),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS radio_stations_guild_idx ON radio_stations (guild_id);
