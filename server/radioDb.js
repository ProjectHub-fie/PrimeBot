const { resolveDbUrl } = require('./resolveDbUrl');
const { createPool } = require('./createPool');

/**
 * Dedicated PostgreSQL pool for the 24/7 Radio feature.
 *
 * Tables: `radio_sessions` (persistent per-guild radio state) and
 * `radio_stations` (the station catalog). They follow the same multi-pool
 * pattern as every other feature: RADIO_DATABASE_URL, else the shared
 * FALLBACK_DATABASE_URL, else DATABASE_URL — so a single-DB deployment works
 * with zero extra configuration.
 *
 * Same-DB requirement: for the dashboard to see / control the bot's sessions
 * (and for every shard node to agree on who owns a guild's session) all
 * deployments must point at the same RADIO_DATABASE_URL.
 */

function resolveConnectionString() {
    return resolveDbUrl('RADIO_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ RADIO_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — the radio feature will have no database.');
}

const radioPool = createPool(cs, { label: 'RADIO DB' });

// Self-create the tables so the feature works even when drizzle-kit migrations
// were never applied to this database. Idempotent — the DDL is memoized by
// server/schemaBootstrap.js, so it runs at most once per process.
let ensured = false;
async function ensureRadioTables() {
    if (ensured) return;
    await radioPool.query(`
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
    `);
    await radioPool.query(`
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
    `);
    await radioPool.query(`CREATE INDEX IF NOT EXISTS radio_stations_guild_idx ON radio_stations (guild_id);`);
    // Additive migration for existing tables created before `volume` existed.
    await radioPool.query(`ALTER TABLE radio_sessions ADD COLUMN IF NOT EXISTS volume integer NOT NULL DEFAULT 100;`);
    ensured = true;
}

async function testRadioConnection() {
    try {
        const client = await radioPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Radio database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Radio database connection failed:', err.message);
        return false;
    }
}

module.exports = { radioPool, ensureRadioTables, testRadioConnection, resolveConnectionString };
