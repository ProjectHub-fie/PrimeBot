const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the Appeal / Ban-DM subsystem.
 *
 * The ban DM + appeal flow (DM banned members with an "all-fields" ban embed,
 * optional Appeal button that opens a floating modal, appeal rows landing in a
 * configured channel) is its own self-contained subsystem, so — like the
 * welcome / reaction-role / automod features — it gets a separate connection
 * string (APPEAL_DATABASE_URL) so it can live in its own database/schema
 * if desired. If APPEAL_DATABASE_URL is unset we fall back to the main
 * DATABASE_URL so the feature still works in single-DB setups.

 * The dashboard's automod tab reads/writes the same tables through this pool;
 * the bot's AppealManager caches them and re-reads on an interval, mirroring
 * the other settings managers.

 * Tables (self-created at first use, also in shared/schema.js and
 * migrations/0020_add_appeal_system.sql):
 *   - appeal_settings        per-guild dm_user / use_appeal / ban_embed_fields /
 *                              appeal_channel_id (where the sent appeal lands)
 *   - appeals                 rows recorded when a member files a ban appeal
 */

function resolveConnectionString() {
    if (process.env.APPEAL_DATABASE_URL) return process.env.APPEAL_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ APPEAL_DATABASE_URL (or DATABASE_URL) not set — ban-DM appeals will have no database.');
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

const appealPool = new Pool(
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

appealPool.on('error', (err) => {
    console.error('[APPEAL DB] Unexpected pool error:', err.message);
});

async function testAppealConnection() {
    try {
        const client = await appealPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Appeal database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Appeal database connection failed:', err.message);
        return false;
    }
}

module.exports = { appealPool, testAppealConnection };