const { Pool } = require('pg');
const { drizzle } = require('drizzle-orm/node-postgres');
const schema = require('../shared/schema.js');

/**
 * Dedicated PostgreSQL pool for the "community" features — the per-server
 * static polls (`$poll`/`/poll`), static giveaways (`$giveaway`/`$reroll`/
 * `$end`), and the counting game (`$cstart`/`$cstatus`/`$cend`).
 *
 * These previously rode on the main DATABASE_URL pool. They now get their own
 * connection string (COMMUNITY_DATABASE_URL) so they can live in their own
 * database/schema if desired. If COMMUNITY_DATABASE_URL is unset we fall back
 * to the main DATABASE_URL so the features still work in single-DB setups
 * without any extra configuration.
 *
 * Exports:
 *   - communityPool : raw pg.Pool (used by pollManager + countingManager, which
 *     run raw SQL via `pool.query(...)`).
 *   - communityDb   : a drizzle instance built on communityPool (used by
 *     giveawayManager, which uses the drizzle query builder against the
 *     `giveaways` + `giveaway_participants` tables).
 *
 * Same-DB requirement (as with the other features): for dashboard reads to
 * reflect the bot's state, both deployments must point at the same
 * COMMUNITY_DATABASE_URL (or the same DATABASE_URL fallback). Different DBs →
 * dashboard reads an empty/absent set of polls/giveaways/counting games.
 */

function resolveConnectionString() {
    if (process.env.COMMUNITY_DATABASE_URL) return process.env.COMMUNITY_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ COMMUNITY_DATABASE_URL (or DATABASE_URL) not set — polls / giveaways / counting will have no database.');
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

const communityPool = new Pool(
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

communityPool.on('error', (err) => {
    console.error('[COMMUNITY DB] Unexpected pool error:', err.message);
});

// Drizzle instance for the community pool — used by giveawayManager (drizzle
// query builder against the giveaways + giveaway_participants tables).
const communityDb = drizzle(communityPool, { schema });

async function testCommunityConnection() {
    try {
        const client = await communityPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Community database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Community database connection failed:', err.message);
        return false;
    }
}

module.exports = { communityPool, communityDb, testCommunityConnection };
