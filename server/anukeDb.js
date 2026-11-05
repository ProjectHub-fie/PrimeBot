const { resolveDbUrl } = require('./resolveDbUrl');
const { once } = require('./schemaBootstrap');

/**
 * Dedicated PostgreSQL pool for Anti-Nuke protection settings.
 *
 * Anti-Nuke is its own moderation subsystem (`antinuke_settings`), so — like the
 * welcome/reaction/automod/logging features — it gets a separate connection
 * string. `ANTI_DATABASE_URL` is the canonical variable; `ANUKE_DATABASE_URL` is
 * kept as a backward-compatible alias so an existing deployment keeps working.
 * Whichever is unset falls through the shared resolver to
 * FALLBACK_DATABASE_URL (then DATABASE_URL), so the feature still works in
 * single-DB setups without any extra configuration.
 *
 * Same-DB requirement (as with the other features): for dashboard saves to
 * reach the bot, both deployments must point at the same Anti-Nuke database
 * (or the same FALLBACK_DATABASE_URL/DATABASE_URL fallback). Different DBs →
 * dashboard writes never reach the bot regardless of caching.
 */

function resolveConnectionString() {
    // ANTI_DATABASE_URL wins; ANUKE_DATABASE_URL is the legacy alias.
    if (process.env.ANTI_DATABASE_URL) return process.env.ANTI_DATABASE_URL;
    return resolveDbUrl('ANUKE_DATABASE_URL');
}

const { createPool } = require('./createPool');

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ ANTI_DATABASE_URL (or ANUKE_DATABASE_URL / FALLBACK_DATABASE_URL / DATABASE_URL) not set — anti-nuke will have no database.');
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

// ── Access control ──────────────────────────────────────────────────────────
//
// Bot-defined Anti-Nuke management access (Co-Owners + Trusted Admins). The
// ACTUAL Discord guild owner is never stored here — ownership is always read
// from Discord guild data, so the owner has implicit full access and can never
// be demoted or removed. One row per assigned user; `role` is `coOwner` or
// `trustedAdmin`; `permissions` is the explicit effective set the owner (or a
// delegated manager within their own authority) granted.
const CREATE_ACCESS_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_access (
        guild_id        VARCHAR(50) NOT NULL,
        user_id         VARCHAR(50) NOT NULL,
        role            VARCHAR(20) NOT NULL,
        permissions     JSONB NOT NULL DEFAULT '[]',
        preset          VARCHAR(24),
        granted_by      VARCHAR(50),
        granted_at      TIMESTAMP DEFAULT NOW(),
        updated_by      VARCHAR(50),
        updated_at      TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (guild_id, user_id)
    );
`;
const CREATE_ACCESS_INDEX_SQL = [
    `CREATE INDEX IF NOT EXISTS antinuke_access_guild_idx ON antinuke_access (guild_id)`,
];

// Append-only audit trail for sensitive access + setup changes. No endpoint
// deletes or rewrites rows. `previous_state` / `new_state` are JSONB snapshots
// (never secrets — only permission ids, role ids and plain-text actions).
const CREATE_ACCESS_HISTORY_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_access_history (
        id              SERIAL PRIMARY KEY,
        guild_id        VARCHAR(50) NOT NULL,
        actor_id        VARCHAR(50) NOT NULL,
        target_id       VARCHAR(50),
        action          VARCHAR(40) NOT NULL,
        previous_state  JSONB NOT NULL DEFAULT '{}',
        new_state       JSONB NOT NULL DEFAULT '{}',
        result          VARCHAR(20) NOT NULL DEFAULT 'success',
        reason          TEXT NOT NULL DEFAULT '',
        created_at      TIMESTAMP DEFAULT NOW()
    );
`;
const CREATE_ACCESS_HISTORY_INDEX_SQL = [
    `CREATE INDEX IF NOT EXISTS antinuke_access_history_guild_created_idx ON antinuke_access_history (guild_id, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS antinuke_access_history_guild_target_idx ON antinuke_access_history (guild_id, target_id)`,
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
            await client.query(CREATE_ACCESS_SQL);
            for (const sql of CREATE_ACCESS_INDEX_SQL) await client.query(sql);
            await client.query(CREATE_ACCESS_HISTORY_SQL);
            for (const sql of CREATE_ACCESS_HISTORY_INDEX_SQL) await client.query(sql);
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

// ── Access control queries ──────────────────────────────────────────────────
//
// These run against the shared ANUKE pool so every shard node and the dashboard
// see the same rows (Same-DB requirement — never one access DB per shard).
// Sensitive mutations use transactions + ON CONFLICT so concurrent nodes cannot
// clobber each other; history rows are append-only.

/** Load every assigned access row for a guild (owner-less; owner is implicit). */
async function listAccessRows(guildId) {
    const res = await anukePool.query(
        `SELECT guild_id, user_id, role, permissions, preset, granted_by, granted_at, updated_by, updated_at
         FROM antinuke_access WHERE guild_id = $1 ORDER BY updated_at DESC`,
        [String(guildId)],
    );
    return res.rows;
}

/** One assigned row or null. */
async function getAccessRow(guildId, userId) {
    const res = await anukePool.query(
        `SELECT guild_id, user_id, role, permissions, preset, granted_by, granted_at, updated_by, updated_at
         FROM antinuke_access WHERE guild_id = $1 AND user_id = $2`,
        [String(guildId), String(userId)],
    );
    return res.rows[0] || null;
}

/**
 * Insert or update an assignment atomically (transaction + upsert). The caller
 * has already validated authority; this is the durable write both shard nodes
 * and the dashboard share.
 */
async function upsertAccessRow(guildId, { userId, role, permissions = [], preset = null, grantedBy = null, updatedBy = null }) {
    const client = await anukePool.connect();
    try {
        await client.query('BEGIN');
        await client.query(
            `INSERT INTO antinuke_access (guild_id, user_id, role, permissions, preset, granted_by, granted_at, updated_by, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,NOW())
             ON CONFLICT (guild_id, user_id) DO UPDATE SET
                role = EXCLUDED.role,
                permissions = EXCLUDED.permissions,
                preset = EXCLUDED.preset,
                updated_by = EXCLUDED.updated_by,
                updated_at = NOW()`,
            [String(guildId), String(userId), role, JSON.stringify(permissions), preset, grantedBy ? String(grantedBy) : null, updatedBy ? String(updatedBy) : null],
        );
        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
    return true;
}

/** Remove an assignment atomically. */
async function deleteAccessRow(guildId, userId) {
    const client = await anukePool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM antinuke_access WHERE guild_id = $1 AND user_id = $2', [String(guildId), String(userId)]);
        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
    return true;
}

/** Append a row to the access/setup audit trail. Fire-and-forget safe. */
async function addAccessHistoryRow({ guildId, actorId, targetId = null, action, previousState = {}, newState = {}, result = 'success', reason = '' }) {
    await ensureAnukeTables();
    await anukePool.query(
        `INSERT INTO antinuke_access_history (guild_id, actor_id, target_id, action, previous_state, new_state, result, reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
            String(guildId), String(actorId), targetId ? String(targetId) : null,
            String(action).slice(0, 40),
            JSON.stringify(previousState || {}), JSON.stringify(newState || {}),
            ['success', 'denied', 'failed'].includes(result) ? result : 'success',
            String(reason || '').slice(0, 2000),
        ],
    );
}

/** Recent audit rows for a guild (newest first, bounded). */
async function listAccessHistory(guildId, { limit = 50 } = {}) {
    await ensureAnukeTables();
    const lim = Math.min(200, Math.max(1, parseInt(limit, 10) || 50));
    const res = await anukePool.query(
        `SELECT id, guild_id, actor_id, target_id, action, previous_state, new_state, result, reason, created_at
         FROM antinuke_access_history WHERE guild_id = $1 ORDER BY created_at DESC LIMIT $2`,
        [String(guildId), lim],
    );
    return res.rows;
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
    resolveConnectionString,
    testAnukeConnection,
    ensureAnukeTables,
    claimDedupKey,
    pruneDedupKeys,
    listAccessRows,
    getAccessRow,
    upsertAccessRow,
    deleteAccessRow,
    addAccessHistoryRow,
    listAccessHistory,
};
