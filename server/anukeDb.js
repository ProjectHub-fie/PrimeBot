const { resolveDbUrl } = require('./resolveDbUrl');
const { once } = require('./schemaBootstrap');

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

const { createPool } = require('./createPool');

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ ANUKE_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — anti-nuke will have no database.');
}

const anukePool = createPool(cs, { label: 'ANUKE DB' });


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

// Columns added after the first release of the table. `ADD COLUMN IF NOT
// EXISTS` keeps an existing deployment's rows intact — the new fields simply
// take their defaults until an admin edits them (safe migration).
const ADD_COLUMNS_SQL = [
    `ALTER TABLE antinuke_settings ADD COLUMN IF NOT EXISTS dangerous_permissions JSONB NOT NULL DEFAULT '["Administrator","ManageGuild","ManageRoles","ManageChannels"]'`,
    `ALTER TABLE antinuke_settings ADD COLUMN IF NOT EXISTS lockdown JSONB NOT NULL DEFAULT '{"enabled":true,"verificationLevel":"high","pauseInvites":true}'`,
    `ALTER TABLE antinuke_settings ADD COLUMN IF NOT EXISTS response_cooldown_seconds INTEGER NOT NULL DEFAULT 30`,
    `ALTER TABLE antinuke_settings ADD COLUMN IF NOT EXISTS setup_method VARCHAR(20)`,
    `ALTER TABLE antinuke_settings ADD COLUMN IF NOT EXISTS setup_status VARCHAR(20) NOT NULL DEFAULT 'not_started'`,
    `ALTER TABLE antinuke_settings ADD COLUMN IF NOT EXISTS setup_state JSONB NOT NULL DEFAULT '{}'`,
];

// One row per tripped threshold (a security incident). Deliberately narrow:
// ordinary Discord events are never persisted — only incidents and their
// response results. Indexed for the dashboard's actual query shapes.
const CREATE_INCIDENT_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_incidents (
        id                SERIAL PRIMARY KEY,
        guild_id          VARCHAR(50) NOT NULL,
        executor_id       VARCHAR(50),
        executor_name     VARCHAR(120),
        action            VARCHAR(60) NOT NULL,
        module            VARCHAR(30),
        severity          VARCHAR(20) NOT NULL DEFAULT 'medium',
        count             INTEGER NOT NULL DEFAULT 0,
        threshold         INTEGER NOT NULL DEFAULT 0,
        window_seconds    INTEGER NOT NULL DEFAULT 0,
        response_taken    JSONB NOT NULL DEFAULT '[]',
        response_result   JSONB NOT NULL DEFAULT '{}',
        response_ok       BOOLEAN NOT NULL DEFAULT false,
        dry_run           BOOLEAN NOT NULL DEFAULT false,
        attribution       VARCHAR(30) NOT NULL DEFAULT 'unknown',
        details           TEXT NOT NULL DEFAULT '',
        created_at        TIMESTAMP DEFAULT NOW()
    );
`;

const CREATE_INCIDENT_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS antinuke_incidents_guild_created_idx ON antinuke_incidents (guild_id, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS antinuke_incidents_guild_action_idx ON antinuke_incidents (guild_id, action)`,
    `CREATE INDEX IF NOT EXISTS antinuke_incidents_executor_idx ON antinuke_incidents (guild_id, executor_id)`,
    `CREATE INDEX IF NOT EXISTS antinuke_incidents_created_idx ON antinuke_incidents (created_at DESC)`,
];

// Cross-node dedup ledger: an incident that several shard nodes could observe
// (audit-log retries, a shared gateway event) is claimed atomically here so
// only one node responds. The row's `expires_at` bounds retention.
const CREATE_DEDUP_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_dedup (
        dedup_key   VARCHAR(255) PRIMARY KEY,
        guild_id    VARCHAR(50),
        created_at  TIMESTAMP DEFAULT NOW(),
        expires_at  TIMESTAMP NOT NULL
    );
`;
const CREATE_DEDUP_INDEX_SQL =
    `CREATE INDEX IF NOT EXISTS antinuke_dedup_expires_idx ON antinuke_dedup (expires_at)`;

// Lockdown record: the saved state needed to reverse a lockdown, stored
// per-guild so any node (or a restart) can restore it. Only one active lockdown
// per guild.
const CREATE_LOCKDOWN_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_lockdowns (
        guild_id        VARCHAR(50) PRIMARY KEY,
        active          BOOLEAN NOT NULL DEFAULT false,
        started_at      TIMESTAMP DEFAULT NOW(),
        started_by      VARCHAR(50),
        reason          TEXT NOT NULL DEFAULT '',
        state           JSONB NOT NULL DEFAULT '{}',
        updated_at      TIMESTAMP DEFAULT NOW()
    );
`;

async function ensureAnukeTables() {
    return once('anukeTables', async () => {
        const client = await anukePool.connect();
        try {
            await client.query(CREATE_TABLE_SQL);
            for (const sql of ADD_COLUMNS_SQL) await client.query(sql);
            await client.query(CREATE_INCIDENT_SQL);
            for (const sql of CREATE_INCIDENT_INDEXES_SQL) await client.query(sql);
            await client.query(CREATE_DEDUP_SQL);
            await client.query(CREATE_DEDUP_INDEX_SQL);
            await client.query(CREATE_LOCKDOWN_SQL);
        } finally {
            client.release();
        }
    }).catch((err) => {
        console.error('[ANUKE DB] Table init failed:', err.message);
    });
}

/**
 * Atomically claim a dedup key. Returns true when this caller owns the key (and
 * should respond) and false when another node already claimed it. The unique
 * PRIMARY KEY + `ON CONFLICT DO NOTHING` is the cross-node lock — not an
 * in-memory Map, which cannot span processes.
 */
async function claimDedupKey(key, { guildId = null, ttlSeconds = 120 } = {}) {
    const ttl = Math.max(5, Number(ttlSeconds) || 120);
    const res = await anukePool.query(`
        INSERT INTO antinuke_dedup (dedup_key, guild_id, expires_at)
        VALUES ($1, $2, NOW() + ($3 || ' seconds')::interval)
        ON CONFLICT (dedup_key) DO NOTHING
    `, [String(key).slice(0, 255), guildId ? String(guildId) : null, String(ttl)]);
    return res.rowCount === 1;
}

/** Best-effort purge of expired dedup rows (bounded; safe to skip). */
async function pruneDedupKeys() {
    try {
        await anukePool.query('DELETE FROM antinuke_dedup WHERE expires_at < NOW()');
    } catch (err) {
        console.error('[ANUKE DB] dedup prune failed:', err.message);
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
    claimDedupKey,
    pruneDedupKeys,
};
