const { Pool } = require('pg');
const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for Anti-Nuke protection settings.
 *
 * Anti-Nuke is its own moderation subsystem (`antinuke_settings`), so — like the
 * welcome/reaction/automod/logging features — it gets a separate connection
 * string (ANUKE_DATABASE_URL) so it can live in its own database/schema if
 * desired. If ANUKE_DATABASE_URL is unset we fall back to
 * FALLBACK_DATABASE_URL (then DATABASE_URL) so the feature still works in
 * single-DB setups without any extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard saves to
 * reach the bot, both deployments must point at the same ANUKE_DATABASE_URL
 * (or the same FALLBACK_DATABASE_URL/DATABASE_URL fallback). Different DBs →
 * dashboard writes never reach the bot regardless of caching.
 */

function resolveConnectionString() {
    return resolveDbUrl('ANUKE_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ ANUKE_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — anti-nuke will have no database.');
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

const anukePool = new Pool(
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

anukePool.on('error', (err) => {
    console.error('[ANUKE DB] Unexpected pool error:', err.message);
});

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_settings (
        guild_id           VARCHAR(50) PRIMARY KEY,
        enabled            BOOLEAN NOT NULL DEFAULT false,
        alert_channel_id   VARCHAR(50),
        responses          JSONB NOT NULL DEFAULT '[]',
        trusted_user_ids   JSONB NOT NULL DEFAULT '[]',
        trusted_role_ids   JSONB NOT NULL DEFAULT '[]',
        watched            JSONB NOT NULL DEFAULT '{}',
        dry_run            BOOLEAN NOT NULL DEFAULT true,
        updated_at         TIMESTAMP DEFAULT NOW()
    );
`;

async function ensureAnukeTables() {
    try {
        const client = await anukePool.connect();
        await client.query(CREATE_TABLE_SQL);
        client.release();
    } catch (err) {
        console.error('[ANUKE DB] Table init failed:', err.message);
    }
}

async function testAnukeConnection() {
    try {
        const client = await anukePool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Anti-nuke database connected successfully');
        await ensureAnukeTables();
        return true;
    } catch (err) {
        console.error('❌ Anti-nuke database connection failed:', err.message);
        return false;
    }
}

module.exports = {
    anukePool,
    testAnukeConnection,
    ensureAnukeTables,
};
