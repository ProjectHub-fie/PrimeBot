-- 0025_add_automod_premium_and_antinuke.sql
--
-- Premium AutoMod upgrade: incident ledger + analytics, dry-run mode, raid
-- protection settings and a configurable warning-escalation ladder.
--
-- Also adds `antinuke_settings`, the storage for the (upcoming) Anti-Nuke tab.
-- Anti-Nuke has its own pool (ANUKE_DATABASE_URL) but the table is created here
-- too so a single-database deployment gets it applied by the migration runner.
--
-- Everything is IF NOT EXISTS / ADD COLUMN IF NOT EXISTS so the migration is
-- idempotent and safe to re-run. The bot's AutomodManager and the dashboard's
-- db.js self-create the same objects at runtime, so this migration is a
-- convenience for DBs that *do* run migrations, never a hard requirement.

-- ── automod_settings: new premium columns ───────────────────────────────────
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS exempt_user_ids         JSONB NOT NULL DEFAULT '[]';
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_ladder             JSONB NOT NULL DEFAULT '[]';
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dry_run                 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS raid_lockdown           BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS raid_alert_channel_id   VARCHAR(50);
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS incident_retention_days INTEGER NOT NULL DEFAULT 30;

-- ── automod_incidents: one row per enforcement ──────────────────────────────
CREATE TABLE IF NOT EXISTS automod_incidents (
    id          SERIAL PRIMARY KEY,
    guild_id    VARCHAR(50) NOT NULL,
    user_id     VARCHAR(50),
    username    VARCHAR(120),
    channel_id  VARCHAR(50),
    message_id  VARCHAR(50),
    rule_type   VARCHAR(40) NOT NULL,
    actions     JSONB NOT NULL DEFAULT '[]',
    severity    VARCHAR(20) NOT NULL DEFAULT 'medium',
    reason      TEXT NOT NULL DEFAULT '',
    dry_run     BOOLEAN NOT NULL DEFAULT false,
    cid         INTEGER,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Indexes match the dashboard's actual query shapes (list by guild+time,
-- filter dropdowns by rule/severity, per-user lookups). No index on
-- message_id/cid — those are never filtered on.
CREATE INDEX IF NOT EXISTS automod_incidents_guild_created_idx
    ON automod_incidents (guild_id, created_at DESC);
CREATE INDEX IF NOT EXISTS automod_incidents_guild_rule_idx
    ON automod_incidents (guild_id, rule_type);
CREATE INDEX IF NOT EXISTS automod_incidents_guild_severity_idx
    ON automod_incidents (guild_id, severity);
CREATE INDEX IF NOT EXISTS automod_incidents_guild_user_idx
    ON automod_incidents (guild_id, user_id);

-- ── antinuke_settings: per-guild anti-nuke configuration (upcoming) ─────────
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
