const { Pool } = require('pg');
const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for the ticket claim system.
 *
 * Claim state (claimed_by / claimed_at / claim_history + the ticket's
 * claim status) lives in its own `ticket_claims` table, separate from the
 * `ticket_instances` row in the TICKET pool. It gets its own connection
 * string (TCLAIM_DATABASE_URL) so it can live in its own database/schema
 * if desired. If TCLAIM_DATABASE_URL is unset we fall back to FALLBACK_DATABASE_URL (then
 * DATABASE_URL) so the feature still works in single-DB setups with no extra
 * configuration.

 * Same DB requirement:for dashboard-created state to reach the bot,
 * both deployments must point at the same TCLAIM_DATABASE_URL (or the
 * same DATABASE_URL fallback. Different DBs → writes never reach the bot
 * regardless of caching.

 */

function resolveConnectionString() {
    return resolveDbUrl('TCLAIM_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ TCLAIM_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — ticket claim state will have no database.');
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

const tclaimPool = new Pool(
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

tclaimPool.on('error', (err) => {
    console.error('[TCLAIM DB] Unexpected pool error:', err.message);
});

// Claim state for a ticket instance, keyed by channel_id. Self-created at
// first use (CREATE TABLE IF NOT EXISTS) so it works even if migrations were
// never applied to the TCLAIM database. The `status` column mirrors the owning
// ticket instance's lifecycle so claim mutations can stay race-atomic within
// this table alone (a claim only succeeds while status = 'open').
const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS ticket_claims (
        id              SERIAL PRIMARY KEY,
        channel_id      VARCHAR(50) NOT NULL UNIQUE,
        guild_id        VARCHAR(50) NOT NULL,
        user_id        VARCHAR(50),
        status          VARCHAR(20) NOT NULL DEFAULT 'open',
        claimed_by      VARCHAR(50),
        claimed_at      BIGINT,
        claim_history   JSONB,
        created_at      TIMESTAMP DEFAULT NOW(),
        updated_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ticket_claims_status_idx
        ON ticket_claims (status);
    CREATE INDEX IF NOT EXISTS ticket_claims_claimed_by_idx
        ON ticket_claims (claimed_by) WHERE claimed_by IS NOT NULL;
`;

async function ensureTicketClaimsTable() {
    try {
        const client = await tclaimPool.connect();
        await client.query(CREATE_TABLE_SQL);
        client.release();
    } catch (err) {
        // Table init failure is non-fatal — callers surface that gracefully.
        console.error('[TCLAIM DB] Table init failed:', err.message);
    }
}

async function testTclaimConnection() {
    try {
        const client = await tclaimPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Ticket claim database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Ticket claim database connection failed:', err.message);
        return false;
    }
}

module.exports = { tclaimPool, ensureTicketClaimsTable, testTclaimConnection };