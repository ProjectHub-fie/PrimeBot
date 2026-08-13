-- Migration 0010: Premium Automod feature.
--
-- Per-guild automod configuration + a per-guild-per-user warnings ledger.
-- Both the bot (utils/automodManager.js) and the dashboard (dashboard/db.js)
-- read and write these tables through the AUTOMOD_DATABASE_URL pool
-- (server/automodDb.js; falls back to DATABASE_URL). Both deployments must
-- point at the same AUTOMOD_DATABASE_URL so dashboard saves reach the bot
-- through the manager's periodic cache reload (same pattern as
-- reaction_roles / welcome_settings).

CREATE TABLE IF NOT EXISTS automod_settings (
    guild_id            VARCHAR(50) PRIMARY KEY,
    enabled             BOOLEAN NOT NULL DEFAULT false,
    log_channel_id      VARCHAR(50),
    mute_role_id        VARCHAR(50),
    exempt_role_ids     JSONB NOT NULL DEFAULT '[]',
    exempt_channel_ids  JSONB NOT NULL DEFAULT '[]',
    rules               JSONB NOT NULL DEFAULT '[]',
    warn_threshold      INTEGER NOT NULL DEFAULT 3,
    warn_action         VARCHAR(20) DEFAULT 'timeout',
    updated_at          TIMESTAMP DEFAULT NOW()
);

ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS log_channel_id     VARCHAR(50);
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS mute_role_id       VARCHAR(50);
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_role_ids    JSONB NOT NULL DEFAULT '[]';
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_channel_ids JSONB NOT NULL DEFAULT '[]';
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS rules              JSONB NOT NULL DEFAULT '[]';
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_threshold     INTEGER NOT NULL DEFAULT 3;
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_action        VARCHAR(20) DEFAULT 'timeout';

-- Per-guild-per-user warning ledger. Moderators (via /warn or prefix warn) and
-- the automod itself both write here; escalation counts come from grouping by
-- (guild_id, user_id).
CREATE TABLE IF NOT EXISTS automod_warnings (
    id          SERIAL PRIMARY KEY,
    guild_id    VARCHAR(50) NOT NULL,
    user_id     VARCHAR(50) NOT NULL,
    moderator_id VARCHAR(50),
    reason      TEXT NOT NULL DEFAULT '',
    rule_type   VARCHAR(40),
    created_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS automod_warnings_guild_user_idx
    ON automod_warnings (guild_id, user_id);
CREATE INDEX IF NOT EXISTS automod_warnings_guild_idx
    ON automod_warnings (guild_id);
