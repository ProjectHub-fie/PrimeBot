const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the Premium Event Management feature.
 *
 * Events are a self-contained subsystem (their own `event_schedules` +
 * `event_tasks` tables, their own cache in EventManager), so — like the other
 * premium features — they get a separate connection string (EVENT_DATABASE_URL)
 * so they can live in their own database/schema if desired. If
 * EVENT_DATABASE_URL is unset we fall back to the main DATABASE_URL so the
 * feature still works in single-DB setups without any extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard changes to
 * reach the bot, both deployments must point at the same EVENT_DATABASE_URL
 * (or the same DATABASE_URL fallback). Different DBs → dashboard writes never
 * reach the bot regardless of caching.
 */

function resolveConnectionString() {
    if (process.env.EVENT_DATABASE_URL) return process.env.EVENT_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ EVENT_DATABASE_URL (or DATABASE_URL) not set — events will have no database.');
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

const eventPool = new Pool(
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

eventPool.on('error', (err) => {
    console.error('[EVENT DB] Unexpected pool error:', err.message);
});

async function testEventConnection() {
    try {
        const client = await eventPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Event database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Event database connection failed:', err.message);
        return false;
    }
}

module.exports = { eventPool, testEventConnection };
