-- Anti-Nuke owner-controlled access hierarchy + setup audit trail.
--
-- New tables on the existing ANUKE_DATABASE_URL pool (server/anukeDb.js; falls
-- back to FALLBACK_DATABASE_URL then DATABASE_URL), so every shard node and the
-- dashboard share the same rows. The ACTUAL Discord guild owner is never stored
-- — ownership is resolved from Discord at authorization time, so the owner has
-- implicit full access and can never be demoted or removed through these rows.
--
-- All statements are idempotent, and the application self-creates the same
-- objects at first use, so a deployment that never runs migrations still works.

-- One row per bot-defined assignment (Co-Owner or Trusted Admin), keyed by
-- (guild_id, user_id). `permissions` is the explicit effective set.
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

CREATE INDEX IF NOT EXISTS antinuke_access_guild_idx ON antinuke_access (guild_id);

-- Append-only audit trail for sensitive Anti-Nuke access + setup changes.
-- `previous_state` / `new_state` are JSONB snapshots (permission ids + role ids
-- only — never secrets). No endpoint deletes or rewrites rows.
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

CREATE INDEX IF NOT EXISTS antinuke_access_history_guild_created_idx
    ON antinuke_access_history (guild_id, created_at DESC);
CREATE INDEX IF NOT EXISTS antinuke_access_history_guild_target_idx
    ON antinuke_access_history (guild_id, target_id);