-- Migration 0014: Event Management feature.
--
-- Per-guild event schedules. Each schedule has an optional start countdown; a
-- list of tasks (actions) to run at relative offsets (in seconds) from the
-- event start — lock/unlock/hide/unhide channels, add/remove roles, or send a
-- text/embed message. Lives in the dedicated EVENT_DATABASE_URL pool
-- (server/eventDb.js; falls back to DATABASE_URL). Both the bot
-- (utils/eventManager.js) and the dashboard (dashboard/db.js) read and write
-- these tables. Both deployments must point at the same EVENT_DATABASE_URL so
-- dashboard-created events reach the bot through its periodic cache reload.
--
-- A schedule's `status` is one of: scheduled | running | completed | cancelled.
-- `triggered` flips true once the event has fired its start so a bot restart
-- does not re-run offset-0 tasks. Tasks record `executed_at` when applied so
-- restarts resume the schedule without double-firing.

CREATE TABLE IF NOT EXISTS event_schedules (
    id                SERIAL PRIMARY KEY,
    guild_id          VARCHAR(50) NOT NULL,
    name              VARCHAR(100) NOT NULL,
    description       TEXT,
    status            VARCHAR(20) NOT NULL DEFAULT 'scheduled',
    countdown_seconds INTEGER NOT NULL DEFAULT 0,
    start_at          TIMESTAMP,
    triggered         BOOLEAN NOT NULL DEFAULT false,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_by_id     VARCHAR(50),
    created_at        TIMESTAMP DEFAULT NOW(),
    updated_at        TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS event_schedules_guild_idx ON event_schedules (guild_id);
CREATE INDEX IF NOT EXISTS event_schedules_status_idx ON event_schedules (status) WHERE status IN ('scheduled', 'running');

CREATE TABLE IF NOT EXISTS event_tasks (
    id                SERIAL PRIMARY KEY,
    schedule_id       INTEGER NOT NULL REFERENCES event_schedules(id) ON DELETE CASCADE,
    offset_seconds    INTEGER NOT NULL DEFAULT 0,
    action            VARCHAR(30) NOT NULL,
    target_type       VARCHAR(20) NOT NULL DEFAULT 'channel',
    target_ids        JSONB NOT NULL DEFAULT '[]',
    message_content   TEXT,
    embed_title       VARCHAR(255),
    embed_description TEXT,
    embed_color       VARCHAR(20) DEFAULT '#5865F2',
    embed_image_url   TEXT,
    channel_id        VARCHAR(50),
    executed_at       TIMESTAMP,
    created_at        TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS event_tasks_schedule_idx ON event_tasks (schedule_id);
CREATE INDEX IF NOT EXISTS event_tasks_pending_idx ON event_tasks (schedule_id) WHERE executed_at IS NULL;
