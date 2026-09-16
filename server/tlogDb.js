const { Pool } = require('pg');
const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for per-panel ticket logging configuration.
 *
 * Ticket logging (per-panel "Ticket Logging" settings inside the existing
 * Logging bar of the ticket editor + the bot's ticket-log embed sender) lives
 * in its own `ticket_logging_settings` table so it can sit in a separate
 * database/schema from the rest of the ticket system if desired. The pool
 * falls back to DATABASE_URL (like every other dedicated pool) so single-DB
 * setups keep working with zero extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard saves to
 * reach the bot, both deployments must point at the same TLOG_DATABASE_URL
 * (or the same FALLBACK_DATABASE_URL/DATABASE_URL fallback). Different DBs → dashboard writes never
 * reach the bot regardless of caching.
 */

function resolveConnectionString() {
    return resolveDbUrl('TLOG_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ TLOG_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — ticket logging will have no database.');
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

const tlogPool = new Pool(
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

tlogPool.on('error', (err) => {
    console.error('[TLOG DB] Unexpected pool error:', err.message);
});

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS ticket_logging_settings (
        panel_id        INTEGER PRIMARY KEY,
        guild_id        VARCHAR(50) NOT NULL,
        enabled         BOOLEAN NOT NULL DEFAULT false,
        channel_id      VARCHAR(50),
        events          JSONB NOT NULL DEFAULT '[]',
        updated_at      TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE ticket_logging_settings ADD COLUMN IF NOT EXISTS events JSONB NOT NULL DEFAULT '[]';
    CREATE INDEX IF NOT EXISTS ticket_logging_guild_idx ON ticket_logging_settings (guild_id);
`;

async function ensureTlogTables() {
    try {
        const client = await tlogPool.connect();
        await client.query(CREATE_TABLE_SQL);
        client.release();
    } catch (err) {
        console.error('[TLOG DB] Table init failed:', err.message);
    }
}

async function testTlogConnection() {
    try {
        const client = await tlogPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Ticket-log database connected successfully');
        await ensureTlogTables();
        return true;
    } catch (err) {
        console.error('❌ Ticket-log database connection failed:', err.message);
        return false;
    }
}

module.exports = {
    tlogPool,
    testTlogConnection,
    ensureTlogTables,
};