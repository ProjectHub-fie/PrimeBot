const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for the birthday feature (birthdays_guilds +
 * birthdays tables).
 *
 * These previously rode on the main DATABASE_URL pool. They now get their own
 * connection string (BIRTHDAY_DATABASE_URL) so they can live in their own
 * database/schema if desired. If BIRTHDAY_DATABASE_URL is unset we fall back
 * to the shared FALLBACK_DATABASE_URL/DATABASE_URL so the feature still works in single-DB setups
 * without any extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard reads/writes
 * to reach the bot, both deployments must point at the same
 * BIRTHDAY_DATABASE_URL (or the same FALLBACK_DATABASE_URL/DATABASE_URL fallback). Different DBs →
 * dashboard edits never reach the bot regardless of caching.
 */

function resolveConnectionString() {
    return resolveDbUrl('BIRTHDAY_DATABASE_URL');
}

const { createPool } = require('./createPool');

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ BIRTHDAY_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — the birthday feature will have no database.');
}

const birthdayPool = createPool(cs, { label: 'BIRTHDAY DB' });


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
