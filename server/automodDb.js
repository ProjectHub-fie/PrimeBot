const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the Premium Automod feature.
 *
 * Automod is a self-contained subsystem (its own `automod_settings` +
 * `automod_warnings` tables, its own cache in AutomodManager), so — like the
 * welcome and reaction-role features — it gets a separate connection string
 * (AUTOMOD_DATABASE_URL) so it can live in its own database/schema if desired.
 * If AUTOMOD_DATABASE_URL is unset we fall back to the main DATABASE_URL so the
 * feature still works in single-DB setups without any extra configuration.
 */

function resolveConnectionString() {
    if (process.env.AUTOMOD_DATABASE_URL) return process.env.AUTOMOD_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ AUTOMOD_DATABASE_URL (or DATABASE_URL) not set — automod will have no database.');
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

const automodPool = new Pool(
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

automodPool.on('error', (err) => {
    console.error('[AUTOMOD DB] Unexpected pool error:', err.message);
});

async function testAutomodConnection() {
    try {
        const client = await automodPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Automod database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Automod database connection failed:', err.message);
        return false;
    }
}

module.exports = { automodPool, testAutomodConnection };
