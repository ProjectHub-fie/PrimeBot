const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the birthday feature (birthdays_guilds +
 * birthdays tables).
 *
 * These previously rode on the main DATABASE_URL pool. They now get their own
 * connection string (BIRTHDAY_DATABASE_URL) so they can live in their own
 * database/schema if desired. If BIRTHDAY_DATABASE_URL is unset we fall back
 * to the main DATABASE_URL so the feature still works in single-DB setups
 * without any extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard reads/writes
 * to reach the bot, both deployments must point at the same
 * BIRTHDAY_DATABASE_URL (or the same DATABASE_URL fallback). Different DBs →
 * dashboard edits never reach the bot regardless of caching.
 */

function resolveConnectionString() {
    if (process.env.BIRTHDAY_DATABASE_URL) return process.env.BIRTHDAY_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ BIRTHDAY_DATABASE_URL (or DATABASE_URL) not set — the birthday feature will have no database.');
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

const birthdayPool = new Pool(
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

birthdayPool.on('error', (err) => {
    console.error('[BIRTHDAY DB] Unexpected pool error:', err.message);
});

async function testBirthdayConnection() {
    try {
        const client = await birthdayPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Birthday database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Birthday database connection failed:', err.message);
        return false;
    }
}

module.exports = { birthdayPool, testBirthdayConnection };
