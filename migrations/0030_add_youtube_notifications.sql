-- 0030_add_youtube_notifications.sql
--
-- YouTube Notifications (Creator Hub) — per-guild subscriptions to public
-- YouTube channels with RSS-based upload detection and Discord announcements.
--
-- The feature has its own pool (YOUTUBE_DATABASE_URL, falling back to
-- FALLBACK_DATABASE_URL/DATABASE_URL) so it can live in a separate
-- database/schema, but the tables are created here too so a single-database
-- deployment gets them applied by the migration runner. Everything is
-- IF NOT EXISTS / ADD COLUMN IF NOT EXISTS so the migration is idempotent; the
-- bot's YouTubeManager and the dashboard self-create the same objects at
-- runtime, so this migration is a convenience, never a hard requirement.
--
-- Tables:
--   youtube_subscriptions  — one row per (guild, YouTube channel)
--   youtube_announcements  — immutable announcement history; the UNIQUE
--                            (guild_id, youtube_channel_id, video_id) index is
--                            the cross-node duplicate guard
--   youtube_poll_lease     — single-row distributed lease so only one node polls

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
