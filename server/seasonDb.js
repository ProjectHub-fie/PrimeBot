const { Pool } = require('pg');
const { drizzle } = require('drizzle-orm/node-postgres');
const schema = require('../shared/schema.js');

/**
 * Dedicated PostgreSQL pool for the "season" subsystem — the dashboard session
 * store (primebot_dashboard_session table) and the shardnode failover service
 * (bot_node_status + bot_failover_lock tables).
 *
 * Both previously rode on the main DATABASE_URL pool. They now get their own
 * connection string (SEASON_DATABASE_URL) so they can live in their own
 * database/schema if desired. If SEASON_DATABASE_URL is unset we fall back to
 * the main DATABASE_URL so the features still work in single-DB setups without
 * any extra configuration.
 *
 * Same-DB requirement (as with the other features): for the dashboard and bot
 * to see the same session rows / failover state, both deployments must point at
 * the same SEASON_DATABASE_URL (or the same DATABASE_URL fallback). Different
 * DBs → sessions aren't shared and failover heartbeats aren't visible across
 * nodes.
 */

function resolveConnectionString() {
    if (process.env.SEASON_DATABASE_URL) return process.env.SEASON_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ SEASON_DATABASE_URL (or DATABASE_URL) not set — dashboard sessions / shardnode failover will have no database.');
}

function shouldEnableSsl(connectionStr) {
    return /sslmode\s*=\s*(require|prefer|verify-ca|verify-full|allow)/i.test(connectionStr || '')
        || process.env.DB_SSL === 'require';
}

function configFromUrl(connectionStr) {
    const url = new URL(connectionStr);
    url.searchParams.delete('sslmode');
    return {
        connectionString: url.toString(),
        ssl: shouldEnableSsl(connectionStr) ? { rejectUnauthorized: false } : false,
    };
}

const seasonPool = new Pool(
    cs
        ? {
              ...configFromUrl(cs),
              max: 5,
              idleTimeoutMillis: 30000,
              connectionTimeoutMillis: 10000,
              allowExitOnIdle: true,
          }
        : { max: 0 } // no-op pool; queries will throw and be handled gracefully
);

seasonPool.on('error', (err) => {
    console.error('[SEASON DB] Unexpected pool error:', err.message);
});

// Drizzle instance for the season pool — used by nodeFailover.js, which runs
// raw SQL via `db.execute(sql`...`)` against the bot_node_status +
// bot_failover_lock tables. (The session store uses the raw seasonPool below.)
const seasonDb = drizzle(seasonPool, { schema });

async function testSeasonConnection() {
    try {
        const client = await seasonPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Season database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Season database connection failed:', err.message);
        return false;
    }
}

module.exports = { seasonPool, seasonDb, testSeasonConnection };
