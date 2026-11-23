-- Event Management schema repair (EVENTMGMT_DATABASE_URL).
--
-- Deployments that created `em_events` before recurrence / scheduled-event
-- support existed were left without `recurrence`, `recurrence_until`,
-- `recurrence_parent_id`, `scheduled_event_id` and `sync_scheduled_event`.
-- `CREATE TABLE IF NOT EXISTS` never alters an existing table, and the
-- recurrence index was created inside the same multi-statement query BEFORE the
-- ALTERs ran — so Postgres aborted the whole bootstrap with
-- `column "recurrence_parent_id" does not exist` and Event Management fell back
-- to "no events loaded".
--
-- Idempotent: safe on a fresh database and safe to re-run.

ALTER TABLE em_events ADD COLUMN IF NOT EXISTS recurrence VARCHAR(20) DEFAULT 'none';
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS recurrence_until TIMESTAMP;
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS recurrence_parent_id INTEGER;
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS scheduled_event_id VARCHAR(50);
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS sync_scheduled_event BOOLEAN DEFAULT true;
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS event_manager_role_id VARCHAR(50);
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS event_permissions JSONB DEFAULT '[]';
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS embed_fields JSONB DEFAULT '[]';
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS embed_footer VARCHAR(255);
ALTER TABLE em_events ADD COLUMN IF NOT EXISTS thumbnail_url TEXT;

ALTER TABLE em_participants ADD COLUMN IF NOT EXISTS attendance_status VARCHAR(20) DEFAULT 'unknown';
ALTER TABLE em_participants ADD COLUMN IF NOT EXISTS checked_in_at TIMESTAMP;
ALTER TABLE em_participants ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();

-- Indexes last: every column above now exists.
CREATE INDEX IF NOT EXISTS em_events_recurrence_parent_idx ON em_events (recurrence_parent_id);
CREATE INDEX IF NOT EXISTS em_events_guild_start_idx ON em_events (guild_id, start_at DESC);
CREATE INDEX IF NOT EXISTS em_participants_event_status_idx ON em_participants (event_id, status);
