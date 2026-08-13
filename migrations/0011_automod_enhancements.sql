-- Migration 0011: Automod enhancements — multi-action, DM messages, appeals.
--
-- Adds:
--   warn_actions      JSONB array of escalation actions (multi-action escalation).
--   dm_enabled        whether the bot DMs punished members.
--   dm_messages       JSONB overrides for the per-action DM templates.
--   appeal_channel_id optional channel for posting new appeal notifications.
--
-- Plus a new automod_appeals ledger for the appeal service. The bot's
-- AutomodManager (utils/automodManager.js) and the dashboard (dashboard/db.js)
-- both read/write these through the AUTOMOD_DATABASE_URL pool. Existing rows
-- keep working: warn_actions defaults to ["timeout"] (mirrors the old single
-- warn_action) and dm_messages defaults to '{}' (use the built-in templates).

ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS warn_actions       JSONB NOT NULL DEFAULT '["timeout"]';
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_enabled         BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS dm_messages        JSONB NOT NULL DEFAULT '{}';
ALTER TABLE automod_settings ADD COLUMN IF NOT EXISTS appeal_channel_id  VARCHAR(50);

CREATE TABLE IF NOT EXISTS automod_appeals (
    id            SERIAL PRIMARY KEY,
    guild_id      VARCHAR(50) NOT NULL,
    user_id       VARCHAR(50) NOT NULL,
    action        VARCHAR(20) NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    status        VARCHAR(20) NOT NULL DEFAULT 'pending',
    decision_note TEXT,
    decided_by    VARCHAR(50),
    decided_at    TIMESTAMP,
    reversed      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS automod_appeals_guild_idx
    ON automod_appeals (guild_id);
CREATE INDEX IF NOT EXISTS automod_appeals_guild_status_idx
    ON automod_appeals (guild_id, status);
ALTER TABLE automod_appeals ADD COLUMN IF NOT EXISTS reversed BOOLEAN NOT NULL DEFAULT false;
