const { Pool } = require('pg');
const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for the ticket role add/remove settings.
 *
 * These per-panel role grants live in their own `ticket_role_settings` table
 * (separate from `ticket_panels`) — they get their own connection string
 * (TROLE_DATABASE_URL) so they can live in their own database/schema if
 * desired. If TROLE_DATABASE_URL is unset we fall back to
 * FALLBACK_DATABASE_URL (then DATABASE_URL) so the feature still works in
 * single-DB setups with no extra configuration.
 *
 * Same DB requirement: for dashboard-created role settings to reach the
 * bot, both deployments must point at the same TROLE_DATABASE_URL (or the
 * same DATABASE_URL fallback). Different DBs → dashboard writes never reach
 * the bot regardless of caching.
 */

function resolveConnectionString() {
    return resolveDbUrl('TROLE_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ TROLE_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — ticket role settings will have no database.');
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

const trolePool = new Pool(
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

trolePool.on('error', (err) => {
    console.error('[TROLE DB] Unexpected pool error:', err.message);
});

// Per-panel role add/remove settings (on open / on close). Keyed by panel id
// so panels can keep their own role grants/revocations. Self-created at first
// use (CREATE TABLE IF NOT EXISTS) so it works even if migrations were
// never applied to the TROLE database.
const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS ticket_role_settings (
        id              SERIAL PRIMARY KEY,
        panel_id        INTEGER NOT NULL UNIQUE,
        guild_id        VARCHAR(50) NOT NULL,
        open_enabled   BOOLEAN NOT NULL DEFAULT false,
        open_add_role   VARCHAR(50),
        open_remove_role VARCHAR(50),
        close_enabled   BOOLEAN NOT NULL DEFAULT false,
        close_add_role   VARCHAR(50),
        close_remove_role VARCHAR(50),
        created_at      TIMESTAMP DEFAULT NOW(),
        updated_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ticket_role_settings_guild_idx
        ON ticket_role_settings (guild_id);
`;

async function ensureTicketRoleTable() {
    try {
        const client = await trolePool.connect();
        await client.query(CREATE_TABLE_SQL);
        client.release();
    } catch (err) {
        // Table init failure is non-fatal — callers surface that gracefully.
        console.error('[TROLE DB] Table init failed:', err.message);
    }
}

async function testTroleConnection() {
    try {
        const client = await trolePool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Ticket role database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Ticket role database connection failed:', err.message);
        return false;
    }
}

module.exports = { trolePool, ensureTicketRoleTable, testTroleConnection };