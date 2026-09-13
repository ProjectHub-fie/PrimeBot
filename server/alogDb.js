const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the dashboard per-server audit log
 * (`website_logs` rows shown on the General settings page).
 *
 * This pool replaces the old arrangement where `website_logs` shared the
 * LOG_DATABASE_URL pool with the bot's server-logging `logging_settings`.
 * Audit logs are a dashboard-only concern and deserve their own connection
 * string (ALOG_DATABASE_URL) so they can live in their own database/schema.
 * It falls back to DATABASE_URL when ALOG_DATABASE_URL is unset so single-DB
 * setups keep working with zero extra configuration.
 *
 * Same-DB requirement (as with the other features): for the dashboard to read
 * audit rows, it must point at the same ALOG_DATABASE_URL it writes to (or a
 * shared DATABASE_URL fallback). Nothing in the bot reads these rows.
 */

function resolveConnectionString() {
    if (process.env.ALOG_DATABASE_URL) return process.env.ALOG_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ ALOG_DATABASE_URL (or DATABASE_URL) not set — dashboard audit log will have no database.');
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

const alogPool = new Pool(
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

alogPool.on('error', (err) => {
    console.error('[ALOG DB] Unexpected pool error:', err.message);
});

const CREATE_TABLES_SQL = `
    CREATE TABLE IF NOT EXISTS website_logs (
        id              SERIAL PRIMARY KEY,
        guild_id        VARCHAR(50) NOT NULL,
        admin_user_id   VARCHAR(50) NOT NULL,
        admin_username  VARCHAR(100) NOT NULL,
        content         TEXT NOT NULL,
        created_at      TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS website_logs_guild_idx ON website_logs (guild_id, created_at DESC);
`;

async function ensureAlogTables() {
    try {
        const client = await alogPool.connect();
        await client.query(CREATE_TABLES_SQL);
        client.release();
    } catch (err) {
        console.error('[ALOG DB] Table init failed:', err.message);
    }
}

async function testAlogConnection() {
    try {
        const client = await alogPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Audit-log database connected successfully');
        await ensureAlogTables();
        return true;
    } catch (err) {
        console.error('❌ Audit-log database connection failed:', err.message);
        return false;
    }
}

// ── Website logs (dashboard admin-action audit trail) ───────────────────────
// Each settings save on the dashboard records a row here so the General page
// can show "who changed what, when" for this server.

async function addWebsiteLog(guildId, { adminUserId, adminUsername, content }) {
    await ensureAlogTables();
    await alogPool.query(
        `INSERT INTO website_logs (guild_id, admin_user_id, admin_username, content, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [String(guildId), String(adminUserId || ''), String(adminUsername || ''), String(content || '')]
    );
}

async function getWebsiteLogs(guildId, limit = 100) {
    await ensureAlogTables();
    const res = await alogPool.query(
        `SELECT id, admin_user_id, admin_username, content, created_at
         FROM website_logs
         WHERE guild_id = $1
         ORDER BY created_at DESC
         LIMIT $2`,
        [String(guildId), Math.min(Math.max(Number(limit) || 100, 1), 500)]
    );
    return res.rows.map(r => ({
        id: r.id,
        adminUserId: r.admin_user_id,
        adminUsername: r.admin_username,
        content: r.content,
        createdAt: r.created_at ? new Date(r.created_at).toISOString() : null,
    }));
}

module.exports = {
    alogPool,
    testAlogConnection,
    ensureAlogTables,
    addWebsiteLog,
    getWebsiteLogs,
};