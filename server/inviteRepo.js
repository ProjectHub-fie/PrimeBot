/**
 * Invite Tracking repository — raw SQL against the dedicated INVITE pool.
 *
 * Tables (self-created so a fresh database works without migrations):
 *   invite_settings   per-guild configuration
 *   invite_snapshots  the last known `uses` for every invite code (the baseline
 *                     used to attribute a join)
 *   invite_joins      one row per tracked join (inviter may be NULL = Unknown)
 *   invite_stats      per-inviter joins/leaves counters (the leaderboard)
 *   invite_activity   recent join/leave/config events for the dashboard feed
 *
 * Every query is scoped by guild_id. Attribution is stored honestly:
 * `attribution` is `exact`, `probable`, `vanity`, `ambiguous` or `unknown`.
 */

const { invitePool } = require('./inviteDb');
const { once } = require('./schemaBootstrap');

const DDL = `
CREATE TABLE IF NOT EXISTS invite_settings (
    guild_id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    log_channel_id TEXT,
    join_notifications BOOLEAN NOT NULL DEFAULT FALSE,
    leave_notifications BOOLEAN NOT NULL DEFAULT FALSE,
    vanity_tracking BOOLEAN NOT NULL DEFAULT TRUE,
    exclude_bots BOOLEAN NOT NULL DEFAULT TRUE,
    excluded_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS invite_snapshots (
    guild_id TEXT NOT NULL,
    invite_code TEXT NOT NULL,
    inviter_id TEXT,
    uses INTEGER NOT NULL DEFAULT 0,
    max_uses INTEGER,
    max_age INTEGER,
    temporary BOOLEAN NOT NULL DEFAULT FALSE,
    channel_id TEXT,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (guild_id, invite_code)
);

CREATE TABLE IF NOT EXISTS invite_joins (
    id SERIAL PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT,
    inviter_id TEXT,
    invite_code TEXT,
    source TEXT NOT NULL DEFAULT 'unknown',
    attribution TEXT NOT NULL DEFAULT 'unknown',
    is_bot BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS invite_stats (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT,
    joins INTEGER NOT NULL DEFAULT 0,
    leaves INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE IF NOT EXISTS invite_activity (
    id SERIAL PRIMARY KEY,
    guild_id TEXT NOT NULL,
    type TEXT NOT NULL,
    user_id TEXT,
    username TEXT,
    inviter_id TEXT,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS invite_joins_guild_joined_idx ON invite_joins (guild_id, joined_at DESC);
CREATE INDEX IF NOT EXISTS invite_joins_guild_inviter_idx ON invite_joins (guild_id, inviter_id);
CREATE INDEX IF NOT EXISTS invite_joins_guild_user_idx ON invite_joins (guild_id, user_id);
CREATE INDEX IF NOT EXISTS invite_joins_open_idx ON invite_joins (guild_id, user_id) WHERE left_at IS NULL;
CREATE INDEX IF NOT EXISTS invite_stats_leaderboard_idx ON invite_stats (guild_id, joins DESC);
CREATE INDEX IF NOT EXISTS invite_activity_guild_created_idx ON invite_activity (guild_id, created_at DESC);

ALTER TABLE invite_settings ADD COLUMN IF NOT EXISTS excluded_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE invite_settings ADD COLUMN IF NOT EXISTS vanity_tracking BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE invite_settings ADD COLUMN IF NOT EXISTS exclude_bots BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE invite_joins ADD COLUMN IF NOT EXISTS attribution TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE invite_joins ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT FALSE;
`;

async function ensureInviteTables() {
    return once('invite-tables', async () => {
        await invitePool.query(DDL);
    });
}

const DEFAULT_SETTINGS = {
    enabled: true,
    logChannelId: null,
    joinNotifications: false,
    leaveNotifications: false,
    vanityTracking: true,
    excludeBots: true,
    excludedUserIds: [],
};

function rowToSettings(row) {
    if (!row) return { ...DEFAULT_SETTINGS };
    return {
        enabled: row.enabled === true,
        logChannelId: row.log_channel_id || null,
        joinNotifications: row.join_notifications === true,
        leaveNotifications: row.leave_notifications === true,
        vanityTracking: row.vanity_tracking !== false,
        excludeBots: row.exclude_bots !== false,
        excludedUserIds: Array.isArray(row.excluded_user_ids) ? row.excluded_user_ids.map(String) : [],
        updatedAt: row.updated_at || null,
    };
}

function rowToJoin(row) {
    if (!row) return null;
    return {
        id: row.id,
        guildId: row.guild_id,
        userId: row.user_id,
        username: row.username,
        inviterId: row.inviter_id || null,
        inviteCode: row.invite_code || null,
        source: row.source,
        attribution: row.attribution,
        isBot: row.is_bot === true,
        joinedAt: row.joined_at,
        leftAt: row.left_at,
    };
}

function rowToStat(row) {
    if (!row) return null;
    return {
        guildId: row.guild_id,
        userId: row.user_id,
        username: row.username,
        joins: Number(row.joins) || 0,
        leaves: Number(row.leaves) || 0,
        net: (Number(row.joins) || 0) - (Number(row.leaves) || 0),
        activeInvites: row.active_invites != null ? Number(row.active_invites) : null,
        updatedAt: row.updated_at,
    };
}

// ── Settings ────────────────────────────────────────────────────────────────
async function getInviteSettings(guildId) {
    await ensureInviteTables();
    const res = await invitePool.query('SELECT * FROM invite_settings WHERE guild_id = $1', [guildId]);
    return rowToSettings(res.rows[0]);
}

async function getAllInviteSettings() {
    await ensureInviteTables();
    const res = await invitePool.query('SELECT * FROM invite_settings');
    return res.rows.map(r => ({ guildId: r.guild_id, ...rowToSettings(r) }));
}

/** Every guild id that has at least one persisted invite snapshot. */
async function getSnapshotGuildIds() {
    await ensureInviteTables();
    const res = await invitePool.query('SELECT DISTINCT guild_id FROM invite_snapshots');
    return res.rows.map(r => String(r.guild_id));
}

async function upsertInviteSettings(guildId, patch = {}) {
    await ensureInviteTables();
    const cur = await getInviteSettings(guildId);
    const next = { ...cur, ...patch };
    const res = await invitePool.query(
        `INSERT INTO invite_settings
            (guild_id, enabled, log_channel_id, join_notifications, leave_notifications,
             vanity_tracking, exclude_bots, excluded_user_ids, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NOW())
         ON CONFLICT (guild_id) DO UPDATE SET
            enabled = EXCLUDED.enabled,
            log_channel_id = EXCLUDED.log_channel_id,
            join_notifications = EXCLUDED.join_notifications,
            leave_notifications = EXCLUDED.leave_notifications,
            vanity_tracking = EXCLUDED.vanity_tracking,
            exclude_bots = EXCLUDED.exclude_bots,
            excluded_user_ids = EXCLUDED.excluded_user_ids,
            updated_at = NOW()
         RETURNING *`,
        [
            guildId,
            next.enabled !== false,
            next.logChannelId || null,
            next.joinNotifications === true,
            next.leaveNotifications === true,
            next.vanityTracking !== false,
            next.excludeBots !== false,
            JSON.stringify(Array.isArray(next.excludedUserIds) ? next.excludedUserIds.map(String) : []),
        ]
    );
    return rowToSettings(res.rows[0]);
}

// ── Snapshots ───────────────────────────────────────────────────────────────
async function getSnapshots(guildId) {
    await ensureInviteTables();
    const res = await invitePool.query('SELECT * FROM invite_snapshots WHERE guild_id = $1', [guildId]);
    return res.rows.map(r => ({
        code: r.invite_code,
        inviterId: r.inviter_id || null,
        uses: Number(r.uses) || 0,
        maxUses: r.max_uses,
        maxAge: r.max_age,
        temporary: r.temporary === true,
        channelId: r.channel_id || null,
        deleted: r.deleted === true,
    }));
}

/**
 * Upsert a batch of invites and mark any code that no longer exists as deleted.
 * Used both for the initial baseline and every re-sync.
 */
async function replaceGuildSnapshots(guildId, invites = []) {
    await ensureInviteTables();
    const client = await invitePool.connect();
    try {
        await client.query('BEGIN');
        for (const inv of invites) {
            await client.query(
                `INSERT INTO invite_snapshots
                    (guild_id, invite_code, inviter_id, uses, max_uses, max_age, temporary, channel_id, deleted, updated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,NOW())
                 ON CONFLICT (guild_id, invite_code) DO UPDATE SET
                    inviter_id = EXCLUDED.inviter_id,
                    uses = EXCLUDED.uses,
                    max_uses = EXCLUDED.max_uses,
                    max_age = EXCLUDED.max_age,
                    temporary = EXCLUDED.temporary,
                    channel_id = EXCLUDED.channel_id,
                    deleted = FALSE,
                    updated_at = NOW()`,
                [guildId, inv.code, inv.inviterId || null, inv.uses || 0,
                 inv.maxUses ?? null, inv.maxAge ?? null, inv.temporary === true, inv.channelId || null]
            );
        }
        const codes = invites.map(i => i.code);
        await client.query(
            `UPDATE invite_snapshots SET deleted = TRUE, updated_at = NOW()
             WHERE guild_id = $1 AND NOT (invite_code = ANY($2::text[]))`,
            [guildId, codes]
        );
        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}

async function upsertSnapshot(guildId, invite) {
    await ensureInviteTables();
    await invitePool.query(
        `INSERT INTO invite_snapshots
            (guild_id, invite_code, inviter_id, uses, max_uses, max_age, temporary, channel_id, deleted, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,NOW())
         ON CONFLICT (guild_id, invite_code) DO UPDATE SET
            inviter_id = EXCLUDED.inviter_id,
            uses = EXCLUDED.uses,
            max_uses = EXCLUDED.max_uses,
            max_age = EXCLUDED.max_age,
            temporary = EXCLUDED.temporary,
            channel_id = EXCLUDED.channel_id,
            deleted = FALSE,
            updated_at = NOW()`,
        [guildId, invite.code, invite.inviterId || null, invite.uses || 0,
         invite.maxUses ?? null, invite.maxAge ?? null, invite.temporary === true, invite.channelId || null]
    );
}

async function markSnapshotDeleted(guildId, code) {
    await ensureInviteTables();
    await invitePool.query(
        'UPDATE invite_snapshots SET deleted = TRUE, updated_at = NOW() WHERE guild_id = $1 AND invite_code = $2',
        [guildId, code]
    );
}

/** Active invite counts per inviter (SUM of uses on non-deleted codes). */
async function getActiveInviteCounts(guildId) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT inviter_id, SUM(uses)::int AS active, COUNT(*)::int AS codes
         FROM invite_snapshots
         WHERE guild_id = $1 AND deleted = FALSE AND inviter_id IS NOT NULL
         GROUP BY inviter_id`,
        [guildId]
    );
    return res.rows.map(r => ({ inviterId: r.inviter_id, active: Number(r.active) || 0, codes: Number(r.codes) || 0 }));
}

// ── Joins ───────────────────────────────────────────────────────────────────
async function addJoin(join) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `INSERT INTO invite_joins
            (guild_id, user_id, username, inviter_id, invite_code, source, attribution, is_bot)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         RETURNING *`,
        [join.guildId, join.userId, join.username || null, join.inviterId || null,
         join.inviteCode || null, join.source || 'unknown', join.attribution || 'unknown', join.isBot === true]
    );
    return rowToJoin(res.rows[0]);
}

/** The most recent open (not-yet-left) join for a member, if any. */
async function findOpenJoin(guildId, userId) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT * FROM invite_joins
         WHERE guild_id = $1 AND user_id = $2 AND left_at IS NULL AND is_bot = FALSE
         ORDER BY joined_at DESC LIMIT 1`,
        [guildId, userId]
    );
    return rowToJoin(res.rows[0]);
}

async function markJoinLeft(id) {
    await ensureInviteTables();
    const res = await invitePool.query(
        'UPDATE invite_joins SET left_at = NOW() WHERE id = $1 RETURNING *',
        [id]
    );
    return rowToJoin(res.rows[0]);
}

async function getRecentJoins(guildId, { limit = 25, offset = 0, includeBots = false } = {}) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT * FROM invite_joins
         WHERE guild_id = $1 ${includeBots ? '' : 'AND is_bot = FALSE'}
         ORDER BY joined_at DESC LIMIT $2 OFFSET $3`,
        [guildId, Math.min(limit, 100), Math.max(offset, 0)]
    );
    return res.rows.map(rowToJoin);
}

async function getRecentLeaves(guildId, { limit = 25 } = {}) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT * FROM invite_joins
         WHERE guild_id = $1 AND left_at IS NOT NULL AND is_bot = FALSE
         ORDER BY left_at DESC LIMIT $2`,
        [guildId, Math.min(limit, 100)]
    );
    return res.rows.map(rowToJoin);
}

async function getInvitesForMember(guildId, userId, { limit = 25, offset = 0 } = {}) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT * FROM invite_joins
         WHERE guild_id = $1 AND inviter_id = $2 AND is_bot = FALSE
         ORDER BY joined_at DESC LIMIT $3 OFFSET $4`,
        [guildId, userId, Math.min(limit, 100), Math.max(offset, 0)]
    );
    return res.rows.map(rowToJoin);
}

async function getJoinsForUser(guildId, userId, { limit = 10 } = {}) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT * FROM invite_joins
         WHERE guild_id = $1 AND user_id = $2
         ORDER BY joined_at DESC LIMIT $3`,
        [guildId, userId, Math.min(limit, 50)]
    );
    return res.rows.map(rowToJoin);
}

// ── Stats ───────────────────────────────────────────────────────────────────
/**
 * Atomically add to an inviter's counters. `joins`/`leaves` may be negative
 * (a reset correction), but the stored counters never go below zero.
 */
async function addInviteStat(guildId, userId, { username = null, joins = 0, leaves = 0 } = {}) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `INSERT INTO invite_stats (guild_id, user_id, username, joins, leaves, updated_at)
         VALUES ($1,$2,$3,GREATEST($4,0),GREATEST($5,0),NOW())
         ON CONFLICT (guild_id, user_id) DO UPDATE SET
            username = COALESCE(EXCLUDED.username, invite_stats.username),
            joins = GREATEST(invite_stats.joins + $4, 0),
            leaves = GREATEST(invite_stats.leaves + $5, 0),
            updated_at = NOW()
         RETURNING *`,
        [guildId, userId, username, joins, leaves]
    );
    return rowToStat(res.rows[0]);
}

async function getInviteStat(guildId, userId) {
    await ensureInviteTables();
    const res = await invitePool.query(
        'SELECT * FROM invite_stats WHERE guild_id = $1 AND user_id = $2',
        [guildId, userId]
    );
    return rowToStat(res.rows[0]) || { guildId, userId, username: null, joins: 0, leaves: 0, net: 0, activeInvites: 0 };
}

async function getLeaderboard(guildId, { limit = 10, offset = 0 } = {}) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT s.*, COALESCE(a.active, 0) AS active_invites
         FROM invite_stats s
         LEFT JOIN (
            SELECT inviter_id, SUM(uses)::int AS active
            FROM invite_snapshots
            WHERE guild_id = $1 AND deleted = FALSE AND inviter_id IS NOT NULL
            GROUP BY inviter_id
         ) a ON a.inviter_id = s.user_id
         WHERE s.guild_id = $1
         ORDER BY (s.joins - s.leaves) DESC, s.joins DESC, s.user_id ASC
         LIMIT $2 OFFSET $3`,
        [guildId, Math.min(limit, 100), Math.max(offset, 0)]
    );
    return res.rows.map(rowToStat);
}

async function countLeaderboard(guildId) {
    await ensureInviteTables();
    const res = await invitePool.query(
        'SELECT COUNT(*)::int AS n FROM invite_stats WHERE guild_id = $1',
        [guildId]
    );
    return Number(res.rows[0].n) || 0;
}

/** 1-based leaderboard position for a member (net invites, then joins). */
async function getInviteRank(guildId, userId) {
    await ensureInviteTables();
    const stat = await getInviteStat(guildId, userId);
    const res = await invitePool.query(
        `SELECT COUNT(*)::int AS n FROM invite_stats
         WHERE guild_id = $1
           AND ((joins - leaves) > $2 OR ((joins - leaves) = $2 AND joins > $3))`,
        [guildId, stat.net, stat.joins]
    );
    return { rank: (Number(res.rows[0].n) || 0) + 1, total: await countLeaderboard(guildId) };
}

// ── Guild totals ────────────────────────────────────────────────────────────
async function getGuildInviteTotals(guildId) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT
            COUNT(*) FILTER (WHERE is_bot = FALSE)::int AS total_joins,
            COUNT(*) FILTER (WHERE is_bot = FALSE AND left_at IS NOT NULL)::int AS total_leaves,
            COUNT(*) FILTER (WHERE is_bot = FALSE AND inviter_id IS NULL)::int AS unknown_joins,
            COUNT(*) FILTER (WHERE is_bot = FALSE AND joined_at >= NOW() - INTERVAL '24 hours')::int AS joins_24h,
            COUNT(*) FILTER (WHERE is_bot = FALSE AND joined_at >= NOW() - INTERVAL '7 days')::int AS joins_7d,
            COUNT(DISTINCT inviter_id) FILTER (WHERE inviter_id IS NOT NULL)::int AS unique_inviters
         FROM invite_joins WHERE guild_id = $1`,
        [guildId]
    );
    const r = res.rows[0] || {};
    const totalJoins = Number(r.total_joins) || 0;
    const totalLeaves = Number(r.total_leaves) || 0;
    return {
        totalJoins,
        totalLeaves,
        net: totalJoins - totalLeaves,
        unknownJoins: Number(r.unknown_joins) || 0,
        joins24h: Number(r.joins_24h) || 0,
        joins7d: Number(r.joins_7d) || 0,
        uniqueInviters: Number(r.unique_inviters) || 0,
        activeInvites: 0,
    };
}

// ── Activity feed ───────────────────────────────────────────────────────────
async function addInviteActivity(guildId, { type, userId = null, username = null, inviterId = null, detail = null }) {
    await ensureInviteTables();
    await invitePool.query(
        `INSERT INTO invite_activity (guild_id, type, user_id, username, inviter_id, detail)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [guildId, type, userId, username, inviterId, detail]
    );
}

async function getInviteActivity(guildId, { limit = 25 } = {}) {
    await ensureInviteTables();
    const res = await invitePool.query(
        `SELECT * FROM invite_activity WHERE guild_id = $1 ORDER BY created_at DESC LIMIT $2`,
        [guildId, Math.min(limit, 100)]
    );
    return res.rows.map(r => ({
        id: r.id,
        type: r.type,
        userId: r.user_id,
        username: r.username,
        inviterId: r.inviter_id,
        detail: r.detail,
        createdAt: r.created_at,
    }));
}

// ── Reset ───────────────────────────────────────────────────────────────────
/**
 * Reset a guild's tracking history. Snapshots (live Discord invite state) are
 * preserved so attribution keeps working immediately after a reset.
 */
async function resetGuildInviteStats(guildId) {
    await ensureInviteTables();
    const client = await invitePool.connect();
    try {
        await client.query('BEGIN');
        const joins = await client.query('DELETE FROM invite_joins WHERE guild_id = $1', [guildId]);
        const stats = await client.query('DELETE FROM invite_stats WHERE guild_id = $1', [guildId]);
        await client.query(
            `INSERT INTO invite_activity (guild_id, type, detail) VALUES ($1, 'reset', $2)`,
            [guildId, `Cleared ${joins.rowCount} joins and ${stats.rowCount} inviter records`]
        );
        await client.query('COMMIT');
        return { joins: joins.rowCount, stats: stats.rowCount };
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}

module.exports = {
    ensureInviteTables,
    DEFAULT_SETTINGS,
    rowToSettings, rowToJoin, rowToStat,
    getInviteSettings, getAllInviteSettings, upsertInviteSettings,
    getSnapshots, getSnapshotGuildIds, replaceGuildSnapshots, upsertSnapshot, markSnapshotDeleted, getActiveInviteCounts,
    addJoin, findOpenJoin, markJoinLeft, getRecentJoins, getRecentLeaves,
    getInvitesForMember, getJoinsForUser,
    addInviteStat, getInviteStat, getLeaderboard, countLeaderboard, getInviteRank,
    getGuildInviteTotals,
    addInviteActivity, getInviteActivity,
    resetGuildInviteStats,
};
