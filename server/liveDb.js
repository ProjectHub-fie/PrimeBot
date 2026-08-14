const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the Live features (live giveaways + live polls
 * dashboard surface).
 *
 * Live giveaways are a self-contained subsystem (their own `live_giveaways` +
 * `live_giveaway_participants` + `live_giveaway_winners` tables, their own cache
 * in LiveGiveawayManager), so — like the welcome / reaction-role / automod /
 * ticket features — they get a separate connection string (LIVE_DATABASE_URL)
 * so they can live in their own database/schema if desired. If
 * LIVE_DATABASE_URL is unset we fall back to the main DATABASE_URL so the
 * feature still works in single-DB setups without any extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard changes to
 * reach the bot, both deployments must point at the same LIVE_DATABASE_URL (or
 * the same DATABASE_URL fallback). Different DBs → dashboard writes never reach
 * the bot regardless of caching.
 */

function resolveConnectionString() {
    if (process.env.LIVE_DATABASE_URL) return process.env.LIVE_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ LIVE_DATABASE_URL (or DATABASE_URL) not set — live giveaways will have no database.');
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

const livePool = new Pool(
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

livePool.on('error', (err) => {
    console.error('[LIVE DB] Unexpected pool error:', err.message);
});

async function testLiveConnection() {
    try {
        const client = await livePool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Live database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Live database connection failed:', err.message);
        return false;
    }
}

module.exports = { livePool, testLiveConnection };
