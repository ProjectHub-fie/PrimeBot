const { Pool } = require('pg');
const { drizzle } = require('drizzle-orm/node-postgres');
const schema = require('../shared/schema');

/**
 * Dedicated PostgreSQL pool for the Beta program settings (beta_settings).
 *
 * Beta access is a self-contained subsystem (its own `beta_settings` table with
 * the per-guild allowed/enabled flags, read by both the bot — `/beta` command
 * — and the dashboard — the 📅 Events beta gate), so — like the welcome /
 * reaction-role / automod / ticket / event / live / leveling features — it gets
 * a separate connection string (BETA_DATABASE_URL) so it can live in its own
 * database/schema if desired. If BETA_DATABASE_URL is unset we fall back to the
 * main DATABASE_URL so the feature still works in single-DB setups without any
 * extra configuration.
 *
 * Same-DB requirement (as with the other features): for the dashboard's beta
 * gate to reflect the bot's `/beta enable` writes, both deployments must point
 * at the same BETA_DATABASE_URL (or the same DATABASE_URL fallback). Different
 * DBs → the dashboard never sees the bot's writes and a beta-enabled server
 * gets treated as non-beta.
 */

function resolveConnectionString() {
    if (process.env.BETA_DATABASE_URL) return process.env.BETA_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ BETA_DATABASE_URL (or DATABASE_URL) not set — beta settings will have no database.');
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

const betaPool = new Pool(
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

// drizzle instance bound to the beta pool so betaManager's typed queries
// (.select/.insert/.onConflictDoUpdate on betaSettings) hit the beta database.
const betaDb = drizzle(betaPool, { schema });

betaPool.on('error', (err) => {
    console.error('[BETA DB] Unexpected pool error:', err.message);
});

async function testBetaConnection() {
    try {
        const client = await betaPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Beta database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Beta database connection failed:', err.message);
        return false;
    }
}

module.exports = { betaPool, betaDb, testBetaConnection };
