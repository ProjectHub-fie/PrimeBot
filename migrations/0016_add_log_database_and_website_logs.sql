-- Migration 0016: Dedicated LOG_DATABASE_URL pool for the bot logging feature
-- + dashboard website logs audit trail.
--
-- The per-guild `logging_settings` table previously lived in the main
-- DATABASE_URL pool. It now lives in the dedicated LOG_DATABASE_URL pool (which
-- falls back to DATABASE_URL when unset, so single-DB setups keep working).
-- Both the bot (utils/loggingSettingsManager.js) and the dashboard
-- (dashboard/db.js) read/write this table through the log pool
-- (server/logDb.js → logPool).
--
-- `website_logs` is the dashboard admin-action audit trail shown on the
-- General settings page (sl no, admin username, content, time). Each settings
-- save records a row here. Same pool as logging_settings so a single
-- LOG_DATABASE_URL connection string covers both subsystems.
--
-- logging_settings is re-created here (CREATE TABLE IF NOT EXISTS + the column
-- adds) so this migration is self-contained for a fresh log database; existing
-- rows in a database where 0008 already ran are left untouched.

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

ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS webhook_name  VARCHAR(100) DEFAULT 'PrimeBot Logs';
ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS events        JSONB NOT NULL DEFAULT '[]';
ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS include_bots  BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS color         VARCHAR(20) DEFAULT '#5865F2';

CREATE TABLE IF NOT EXISTS website_logs (
    id              SERIAL PRIMARY KEY,
    guild_id        VARCHAR(50) NOT NULL,
    admin_user_id   VARCHAR(50) NOT NULL,
    admin_username  VARCHAR(100) NOT NULL,
    content         TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS website_logs_guild_idx
    ON website_logs (guild_id, created_at DESC);
