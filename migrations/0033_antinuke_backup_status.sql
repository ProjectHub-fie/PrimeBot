-- Anti-Nuke backup pipeline: honest operation status + an operation log.
--
-- The backup system used to report SUCCESS the moment a snapshot row was
-- INSERTed, even when the Discord REST reads had failed and the row carried no
-- data. This migration gives every backup an explicit lifecycle
-- (PENDING / IN_PROGRESS / SUCCESS / PARTIAL / FAILED) plus the resource-level
-- detail needed to prove what was really captured, and adds an append-only
-- operation log so the dashboard can show real start/finish times, counts,
-- failures and verification state.
--
-- Everything lives in the existing ANUKE_DATABASE_URL pool (server/anukeDb.js;
-- falls back to FALLBACK_DATABASE_URL then DATABASE_URL). All statements are
-- idempotent, and the application self-creates the same objects at first use,
-- so a deployment that never runs migrations still works. Existing backup rows
-- are preserved: the new columns take safe defaults, and a row that already has
-- data is back-filled to SUCCESS while an empty row is back-filled to FAILED.

ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'PENDING';
ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS operation VARCHAR(16) NOT NULL DEFAULT 'create';
ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS started_at TIMESTAMP;
ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP;
ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS resources JSONB NOT NULL DEFAULT '{}';
ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS errors JSONB NOT NULL DEFAULT '[]';
ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS verification JSONB NOT NULL DEFAULT '{}';
ALTER TABLE antinuke_backups ADD COLUMN IF NOT EXISTS guild_settings JSONB;

-- Back-fill legacy rows so an old snapshot never reads as a false success.
UPDATE antinuke_backups
   SET status = CASE
           WHEN (jsonb_array_length(roles) + jsonb_array_length(channels)) > 0 THEN 'SUCCESS'
           ELSE 'FAILED'
       END,
       completed_at = COALESCE(completed_at, created_at)
 WHERE status = 'PENDING';

CREATE TABLE IF NOT EXISTS antinuke_backup_operations (
    id            SERIAL PRIMARY KEY,
    backup_id     INTEGER,
    guild_id      VARCHAR(50) NOT NULL,
    operation     VARCHAR(16) NOT NULL,
    status        VARCHAR(16) NOT NULL,
    actor_id      VARCHAR(50),
    started_at    TIMESTAMP DEFAULT NOW(),
    completed_at  TIMESTAMP,
    counts        JSONB NOT NULL DEFAULT '{}',
    errors        JSONB NOT NULL DEFAULT '[]',
    verification  JSONB NOT NULL DEFAULT '{}',
    details       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS antinuke_backup_ops_guild_created_idx
    ON antinuke_backup_operations (guild_id, started_at DESC);
CREATE INDEX IF NOT EXISTS antinuke_backup_ops_backup_idx
    ON antinuke_backup_operations (backup_id);
