-- Invite Tracking (INVITE_DATABASE_URL, falls back to FALLBACK_DATABASE_URL/DATABASE_URL).
-- Idempotent: the bot's InviteTracker and the dashboard's repo self-create the
-- same tables on first use, so this migration is only needed for a managed
-- schema (drizzle-kit) deployment.
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
