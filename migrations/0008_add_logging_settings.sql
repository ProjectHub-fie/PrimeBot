-- Migration 0008: Per-guild logging settings.
--
-- Stores, for each guild: a log channel, an optional webhook URL (so logs can
-- be delivered to a channel the bot can't see, or to an external service), the
-- set of event types to log (JSONB), and a few display toggles. Both the bot
-- (utils/loggingSettingsManager.js) and the dashboard (dashboard/db.js) read
-- and write this table — they share the same DATABASE_URL so dashboard saves
-- reach the bot through the manager's periodic cache reload.

CREATE TABLE IF NOT EXISTS logging_settings (
    guild_id              VARCHAR(50) PRIMARY KEY,
    enabled               BOOLEAN NOT NULL DEFAULT false,
    channel_id            VARCHAR(50),
    webhook_url           TEXT,
    webhook_name          VARCHAR(100) DEFAULT 'PrimeBot Logs',
    events                JSONB NOT NULL DEFAULT '[]',
    include_bots          BOOLEAN NOT NULL DEFAULT false,
    color                 VARCHAR(20) DEFAULT '#5865F2',
    updated_at            TIMESTAMP DEFAULT NOW()
);

-- Backward-compatible column adds for deployments that created an older shape.
ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS webhook_name  VARCHAR(100) DEFAULT 'PrimeBot Logs';
ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS events        JSONB NOT NULL DEFAULT '[]';
ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS include_bots  BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS color         VARCHAR(20) DEFAULT '#5865F2';
