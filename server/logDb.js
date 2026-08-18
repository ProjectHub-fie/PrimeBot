const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the bot logging feature + dashboard website logs.
 *
 * This serves two related purposes:
 *   1. Per-guild "server logging" (member join/leave, bans, edits/deletes, …)
 *      via utils/serverLogger.js + utils/loggingSettingsManager.js — moved out of
 *      the main DATABASE_URL pool into this dedicated pool so logging can live in
 *      its own database/schema if desired.
 *   2. Dashboard website logs (an audit trail of admin actions per guild, shown on
 *      the General settings page) — stored in the `website_logs` table.
 *
 * Both subsystems use the same connection string (LOG_DATABASE_URL), which falls
 * back to the main DATABASE_URL so the feature still works in single-DB setups
 * with zero extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard saves to reach
 * the bot, both deployments must point at the same LOG_DATABASE_URL (or the same
 * DATABASE_URL fallback). Different DBs → dashboard writes never reach the bot.
 */

function resolveConnectionString() {
    if (process.env.LOG_DATABASE_URL) return process.env.LOG_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ LOG_DATABASE_URL (or DATABASE_URL) not set — logging feature will have no database.');
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

const logPool = new Pool(
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

logPool.on('error', (err) => {
    console.error('[LOG DB] Unexpected pool error:', err.message);
});

const CREATE_TABLES_SQL = `
    CREATE TABLE IF NOT EXISTS logging_settings (
        guild_id              VARCHAR(50) PRIMARY KEY,
        enabled               BOOLEAN NOT NULL DEFAULT false,
        channel_id            VARCHAR(50),
        webhook_url           TEXT,
        webhook_name          VARCHAR(100) DEFAULT 'PrimeBot Logs',
        events                JSONB NOT NULL DEFAULT '[]',
        include_bots          BOOLEAN NOT NULL DEFAULT false,
        color                 VARCHAR(20) DEFAULT '#5865F2',
        updated_at            TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS webhook_name  VARCHAR(100) DEFAULT 'PrimeBot Logs';
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS events        JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS include_bots  BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS color         VARCHAR(20) DEFAULT '#5865F2';

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

async function ensureLogTables() {
    try {
        const client = await logPool.connect();
        await client.query(CREATE_TABLES_SQL);
        client.release();
    } catch (err) {
        console.error('[LOG DB] Table init failed:', err.message);
    }
}

async function testLogConnection() {
    try {
        const client = await logPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Log database connected successfully');
        await ensureLogTables();
        return true;
    } catch (err) {
        console.error('❌ Log database connection failed:', err.message);
        return false;
    }
}

// ── Website logs (dashboard admin-action audit trail) ───────────────────────
// Each settings save on the dashboard records a row here so the General page
// can show "who changed what, when" for this server.

async function addWebsiteLog(guildId, { adminUserId, adminUsername, content }) {
    await ensureLogTables();
    await logPool.query(
        `INSERT INTO website_logs (guild_id, admin_user_id, admin_username, content, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [String(guildId), String(adminUserId || ''), String(adminUsername || ''), String(content || '')]
    );
}

async function getWebsiteLogs(guildId, limit = 100) {
    await ensureLogTables();
    const res = await logPool.query(
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
    logPool,
    testLogConnection,
    ensureLogTables,
    addWebsiteLog,
    getWebsiteLogs,
};
