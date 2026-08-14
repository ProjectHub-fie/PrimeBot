const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the Premium Ticket feature.
 *
 * Tickets are a self-contained subsystem (their own `ticket_panels` +
 * `ticket_instances` tables, their own cache in TicketPanelManager), so — like
 * the welcome, reaction-role, and automod features — they get a separate
 * connection string (TICKET_DATABASE_URL) so they can live in their own
 * database/schema if desired. If TICKET_DATABASE_URL is unset we fall back to
 * the main DATABASE_URL so the feature still works in single-DB setups without
 * any extra configuration.
 *
 * Same DB requirement: for dashboard-created panels to reach the bot, both
 * deployments must point at the same TICKET_DATABASE_URL (or the same
 * DATABASE_URL fallback). Different DBs → dashboard writes never reach the
 * bot regardless of caching.
 */

function resolveConnectionString() {
    if (process.env.TICKET_DATABASE_URL) return process.env.TICKET_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ TICKET_DATABASE_URL (or DATABASE_URL) not set — tickets will have no database.');
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

const ticketPool = new Pool(
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

ticketPool.on('error', (err) => {
    console.error('[TICKET DB] Unexpected pool error:', err.message);
});

async function testTicketConnection() {
    try {
        const client = await ticketPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Ticket database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Ticket database connection failed:', err.message);
        return false;
    }
}

module.exports = { ticketPool, testTicketConnection };
