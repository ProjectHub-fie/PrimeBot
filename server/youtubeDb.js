const { resolveDbUrl } = require('./resolveDbUrl');
const { once } = require('./schemaBootstrap');

/**
 * Dedicated PostgreSQL pool for the YouTube Notifications feature.
 *
 * `YOUTUBE_DATABASE_URL` (falls back through the shared resolver to
 * FALLBACK_DATABASE_URL, then DATABASE_URL) so the feature can live in its own
 * database/schema but still works in single-DB deployments with zero extra
 * config — the same multi-pool pattern as every other feature.
 *
 * Same-DB requirement: the bot and the dashboard MUST point at the same
 * YOUTUBE_DATABASE_URL (or share the FALLBACK_DATABASE_URL/DATABASE_URL
 * fallback). The three shard nodes must also share it — that is what makes the
 * database-backed polling lease and the announcement dedup constraint work
 * across nodes.
 *
 * Tables:
 *   • youtube_subscriptions — one row per (guild, youtube channel). Carries the
 *     destination Discord channel, enabled flag, announcement template, the
 *     baseline/last-seen video id and the check bookkeeping.
 *   • youtube_announcements — the immutable announcement history; a UNIQUE
 *     (guild_id, youtube_channel_id, video_id) constraint is the cross-node
 *     duplicate guard (two nodes can never both announce the same video to the
 *     same guild).
 *   • youtube_poll_lease — a single-row lease (id = 1) that only one node may
 *     hold at a time, so only one active polling worker runs cluster-wide.
 */

function resolveConnectionString() {
    return resolveDbUrl('YOUTUBE_DATABASE_URL');
}

const { createPool } = require('./createPool');

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ YOUTUBE_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — YouTube notifications will have no database.');
}

const youtubePool = createPool(cs, { label: 'YOUTUBE DB' });

// The lease is a single logical row. `holder` is a stable per-process id; the
// row is only (re)claimed when its `expires_at` has passed, so a crashed node's
// lease is recovered automatically after the TTL.
const LEASE_ID = 1;

const CREATE_SQL = `
    CREATE TABLE IF NOT EXISTS youtube_subscriptions (
        id                   SERIAL PRIMARY KEY,
        guild_id             VARCHAR(50) NOT NULL,
        youtube_channel_id   VARCHAR(64) NOT NULL,
        channel_name         VARCHAR(255),
        channel_url          TEXT,
        channel_handle       VARCHAR(120),
        avatar_url           TEXT,
        channel_description  TEXT,
        discord_channel_id   VARCHAR(50),
        enabled              BOOLEAN NOT NULL DEFAULT true,
        paused               BOOLEAN NOT NULL DEFAULT false,
        group_name           VARCHAR(80),
        template             JSONB NOT NULL DEFAULT '{}',
        last_video_id        VARCHAR(32),
        baseline_done        BOOLEAN NOT NULL DEFAULT false,
        last_checked_at      TIMESTAMP,
        last_success_at      TIMESTAMP,
        last_error           TEXT,
        error_count          INTEGER NOT NULL DEFAULT 0,
        next_check_at        TIMESTAMP,
        created_at           TIMESTAMP DEFAULT NOW(),
        updated_at           TIMESTAMP DEFAULT NOW()
    );
    -- Columns added after the first release — ADD COLUMN IF NOT EXISTS keeps an
    -- existing deployment's rows intact (safe migration).
    ALTER TABLE youtube_subscriptions ADD COLUMN IF NOT EXISTS channel_description TEXT;
    ALTER TABLE youtube_subscriptions ADD COLUMN IF NOT EXISTS paused BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE youtube_subscriptions ADD COLUMN IF NOT EXISTS group_name VARCHAR(80);
    CREATE UNIQUE INDEX IF NOT EXISTS youtube_sub_guild_channel_uniq
        ON youtube_subscriptions (guild_id, youtube_channel_id);
    CREATE INDEX IF NOT EXISTS youtube_sub_due_idx
        ON youtube_subscriptions (enabled, next_check_at);
    CREATE INDEX IF NOT EXISTS youtube_sub_guild_idx
        ON youtube_subscriptions (guild_id);

    CREATE TABLE IF NOT EXISTS youtube_announcements (
        id                 SERIAL PRIMARY KEY,
        guild_id           VARCHAR(50) NOT NULL,
        youtube_channel_id VARCHAR(64) NOT NULL,
        subscription_id    INTEGER,
        video_id           VARCHAR(32) NOT NULL,
        video_title        TEXT,
        video_url          TEXT,
        video_published_at TIMESTAMP,
        thumbnail_url      TEXT,
        discord_channel_id VARCHAR(50),
        discord_message_id VARCHAR(50),
        status             VARCHAR(20) NOT NULL DEFAULT 'sent',
        error              TEXT,
        created_at         TIMESTAMP DEFAULT NOW()
    );
    -- The cross-node duplicate guard: at most one successful announcement per
    -- (guild, youtube channel, video). Two nodes racing to announce the same
    -- video collide here and only the first insert wins.
    CREATE UNIQUE INDEX IF NOT EXISTS youtube_announce_uniq
        ON youtube_announcements (guild_id, youtube_channel_id, video_id);
    CREATE INDEX IF NOT EXISTS youtube_announce_guild_created_idx
        ON youtube_announcements (guild_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS youtube_announce_status_idx
        ON youtube_announcements (status, created_at DESC);

    CREATE TABLE IF NOT EXISTS youtube_poll_lease (
        id          INTEGER PRIMARY KEY,
        holder      VARCHAR(120) NOT NULL,
        expires_at  TIMESTAMP NOT NULL,
        updated_at  TIMESTAMP DEFAULT NOW()
    );
`;

async function ensureYoutubeTables() {
    return once('youtubeTables', async () => {
        await youtubePool.query(CREATE_SQL);
    }).catch((err) => {
        console.error('[YOUTUBE DB] Table init failed:', err.message);
    });
}

/**
 * Try to acquire (or renew) the single polling lease.
 *
 * Atomic and crash-safe: the insert only succeeds when no live lease exists, and
 * an UPDATE only steals a lease whose `expires_at` has passed. Two nodes calling
 * this at the same instant can never both win (the PRIMARY KEY + WHERE clause
 * serialise them inside Postgres).
 *
 * @returns {Promise<boolean>} true when this holder owns the lease afterwards.
 */
async function acquirePollLease(holder, ttlSeconds = 90) {
    await ensureYoutubeTables();
    const ttl = Math.max(15, Number(ttlSeconds) || 90);
    const res = await youtubePool.query(`
        INSERT INTO youtube_poll_lease (id, holder, expires_at, updated_at)
        VALUES ($1, $2, NOW() + ($3 || ' seconds')::interval, NOW())
        ON CONFLICT (id) DO UPDATE
            SET holder = EXCLUDED.holder,
                expires_at = EXCLUDED.expires_at,
                updated_at = NOW()
            WHERE youtube_poll_lease.expires_at < NOW()
               OR youtube_poll_lease.holder = EXCLUDED.holder
        RETURNING holder
    `, [LEASE_ID, String(holder).slice(0, 120), String(ttl)]);
    return res.rowCount === 1 && res.rows[0].holder === String(holder).slice(0, 120);
}

/** Release the lease early (only if we hold it). */
async function releasePollLease(holder) {
    try {
        await youtubePool.query(
            'DELETE FROM youtube_poll_lease WHERE id = $1 AND holder = $2',
            [LEASE_ID, String(holder).slice(0, 120)]
        );
    } catch (err) {
        console.error('[YOUTUBE DB] release lease failed:', err.message);
    }
}

/** Read the current lease (for the dashboard's monitoring status). */
async function getPollLease() {
    await ensureYoutubeTables();
    const res = await youtubePool.query('SELECT holder, expires_at, updated_at FROM youtube_poll_lease WHERE id = $1', [LEASE_ID]);
    const row = res.rows[0];
    if (!row) return null;
    return {
        holder: row.holder,
        expiresAt: row.expires_at,
        updatedAt: row.updated_at,
        expired: row.expires_at ? new Date(row.expires_at).getTime() < Date.now() : true,
    };
}

/**
 * Claim a (guild, youtube channel, video) announcement atomically.
 *
 * Returns the created row on success, or null when another node already claimed
 * it. This is the transactional duplicate guard — NOT process-local memory.
 */
async function claimAnnouncement({ guildId, youtubeChannelId, subscriptionId, video, discordChannelId }) {
    await ensureYoutubeTables();
    const res = await youtubePool.query(`
        INSERT INTO youtube_announcements
            (guild_id, youtube_channel_id, subscription_id, video_id, video_title,
             video_url, video_published_at, thumbnail_url, discord_channel_id, status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending')
        ON CONFLICT (guild_id, youtube_channel_id, video_id) DO NOTHING
        RETURNING id
    `, [
        String(guildId), String(youtubeChannelId), subscriptionId || null,
        String(video.videoId), video.title || null, video.url || null,
        video.publishedAt ? new Date(video.publishedAt) : null, video.thumbnail || null,
        discordChannelId || null,
    ]);
    return res.rowCount === 1 ? res.rows[0].id : null;
}

/** Mark a claimed announcement as sent (records the Discord message id). */
async function markAnnouncementSent(id, discordMessageId) {
    await youtubePool.query(
        `UPDATE youtube_announcements SET status = 'sent', discord_message_id = $2, error = NULL WHERE id = $1`,
        [id, discordMessageId ? String(discordMessageId) : null]
    );
}

/** Mark a claimed announcement as failed (kept for history + retry awareness). */
async function markAnnouncementFailed(id, error) {
    await youtubePool.query(
        `UPDATE youtube_announcements SET status = 'failed', error = $2 WHERE id = $1`,
        [id, error ? String(error).slice(0, 2000) : null]
    );
}

/** Recent announcement history for a guild (newest first). */
async function listAnnouncements(guildId, { limit = 50 } = {}) {
    await ensureYoutubeTables();
    const lim = Math.min(200, Math.max(1, parseInt(limit, 10) || 50));
    const res = await youtubePool.query(
        `SELECT id, guild_id, youtube_channel_id, video_id, video_title, video_url,
                video_published_at, thumbnail_url, discord_channel_id, discord_message_id,
                status, error, created_at
         FROM youtube_announcements WHERE guild_id = $1
         ORDER BY created_at DESC LIMIT $2`,
        [String(guildId), lim]
    );
    return res.rows;
}

/** Count successful announcements for a guild (for the overview cards). */
async function countAnnouncements(guildId, status = 'sent') {
    await ensureYoutubeTables();
    const res = await youtubePool.query(
        'SELECT COUNT(*)::int AS n FROM youtube_announcements WHERE guild_id = $1 AND status = $2',
        [String(guildId), status]
    );
    return res.rows[0] ? res.rows[0].n : 0;
}

async function testYoutubeConnection() {
    try {
        const client = await youtubePool.connect();
        await client.query('SELECT NOW()');
        client.release();
        await ensureYoutubeTables();
        console.log('✅ YouTube database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ YouTube database connection failed:', err.message);
        return false;
    }
}

module.exports = {
    youtubePool,
    resolveConnectionString,
    ensureYoutubeTables,
    testYoutubeConnection,
    acquirePollLease,
    releasePollLease,
    getPollLease,
    claimAnnouncement,
    markAnnouncementSent,
    markAnnouncementFailed,
    listAnnouncements,
    countAnnouncements,
    LEASE_ID,
};
