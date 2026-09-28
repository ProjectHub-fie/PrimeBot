const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for the Welcome feature.
 *
 * Like the other per-feature pools, it gets a separate connection string
 * (WELCOME_DATABASE_URL) so it can live in its own database/schema if desired.
 * If WELCOME_DATABASE_URL is unset we fall back to FALLBACK_DATABASE_URL (then DATABASE_URL) so the
 * feature still works in single-DB setups with zero extra configuration.
 *
 * Same-DB requirement: for dashboard saves to reach the bot, both deployments
 * must point at the same WELCOME_DATABASE_URL (or the same DATABASE_URL
 * fallback). Different DBs → dashboard writes never reach the bot regardless
 * of caching. (Note: previous versions of this file had NO fallback — a bare
 * `new Pool({ connectionString: undefined })` silently made every welcome read
 * fail, so the dashboard showed the feature as permanently off whenever only
 * DATABASE_URL was set.)
 */

function resolveConnectionString() {
    return resolveDbUrl('WELCOME_DATABASE_URL');
}

const { createPool } = require('./createPool');

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ WELCOME_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — welcome feature will have no database.');
}

const welcomePool = createPool(cs, { label: 'WELCOME DB' });


async function testWelcomeConnection() {
    try {
        const client = await welcomePool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Welcome database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Welcome database connection failed:', err.message);
        return false;
    }
}

module.exports = { welcomePool, testWelcomeConnection };
