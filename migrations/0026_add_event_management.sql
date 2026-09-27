-- Migration 0026: Event Management feature (premium event platform).
--
-- A per-guild event platform: events, participants (with waiting-list +
-- attendance), pre-event reminders, per-user "Remind Me" subscriptions, and an
-- activity log. Lives in the dedicated EVENTMGMT_DATABASE_URL pool
-- (server/eventMgmtDb.js; falls back to FALLBACK_DATABASE_URL/DATABASE_URL).
-- Both the bot (utils/eventMgmtManager.js) and the dashboard
-- (server/eventMgmtRepo.js via dashboard/db.js) read and write these tables;
-- both deployments must point at the same EVENTMGMT_DATABASE_URL so dashboard
-- changes reach the bot through its periodic cache reload.
--
-- Tables are also self-created by ensureEventMgmtTables() so a fresh database
-- works without running migrations, but applying this migration on an existing
-- deployment keeps schema drift visible.
--
-- NOTE: this is a NEW, separate subsystem from the older `event_schedules` /
-- `event_tasks` tables (migration 0014), which remain for the legacy timed
-- lock/unlock event schedules.

CREATE TABLE IF NOT EXISTS em_events (
    id                       SERIAL PRIMARY KEY,
    guild_id                 VARCHAR(50) NOT NULL,
    creator_id               VARCHAR(50),
    name                     VARCHAR(100) NOT NULL,
    description              TEXT,
    type                     VARCHAR(30) NOT NULL DEFAULT 'custom',
    status                   VARCHAR(30) NOT NULL DEFAULT 'draft',
    start_at                 TIMESTAMP,
    end_at                   TIMESTAMP,
    timezone                 VARCHAR(64) DEFAULT 'UTC',
    location_type            VARCHAR(20) DEFAULT 'none',
    location_value           VARCHAR(500),
    registration_mode        VARCHAR(20) DEFAULT 'open',
    max_participants         INTEGER,
    waitlist_enabled         BOOLEAN DEFAULT true,
    registration_deadline    TIMESTAMP,
    track_attendance         BOOLEAN DEFAULT false,
    announcement_channel_id  VARCHAR(50),
    announcement_message_id  VARCHAR(50),
    participant_role_id      VARCHAR(50),
    staff_role_id            VARCHAR(50),
    winner_role_id           VARCHAR(50),
    attendance_role_id       VARCHAR(50),
    event_manager_role_id    VARCHAR(50),
    event_permissions        JSONB DEFAULT '[]',
    image_url                TEXT,
    thumbnail_url            TEXT,
    embed_title              VARCHAR(256),
    embed_description        TEXT,
    embed_color              VARCHAR(20) DEFAULT '#5865F2',
    embed_fields             JSONB DEFAULT '[]',
    embed_footer             VARCHAR(255),
    reminders                JSONB DEFAULT '[]',
    result                   JSONB,
    created_at               TIMESTAMP DEFAULT NOW(),
    updated_at               TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS em_events_guild_idx ON em_events (guild_id);
CREATE INDEX IF NOT EXISTS em_events_status_idx ON em_events (status);
CREATE INDEX IF NOT EXISTS em_events_start_idx ON em_events (start_at);
CREATE INDEX IF NOT EXISTS em_events_guild_start_idx ON em_events (guild_id, start_at DESC);

CREATE TABLE IF NOT EXISTS em_participants (
    id                SERIAL PRIMARY KEY,
    event_id          INTEGER NOT NULL REFERENCES em_events(id) ON DELETE CASCADE,
    guild_id          VARCHAR(50) NOT NULL,
    user_id           VARCHAR(50) NOT NULL,
    username          VARCHAR(100),
    status            VARCHAR(20) NOT NULL DEFAULT 'registered',
    role              VARCHAR(20) NOT NULL DEFAULT 'participant',
    attendance_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
    checked_in_at     TIMESTAMP,
    registered_at     TIMESTAMP DEFAULT NOW(),
    updated_at        TIMESTAMP DEFAULT NOW(),
    UNIQUE (event_id, user_id)
);
CREATE INDEX IF NOT EXISTS em_participants_event_idx ON em_participants (event_id);
CREATE INDEX IF NOT EXISTS em_participants_user_idx ON em_participants (user_id);
CREATE INDEX IF NOT EXISTS em_participants_event_status_idx ON em_participants (event_id, status);

CREATE TABLE IF NOT EXISTS em_reminders (
    id             SERIAL PRIMARY KEY,
    event_id       INTEGER NOT NULL REFERENCES em_events(id) ON DELETE CASCADE,
    guild_id       VARCHAR(50) NOT NULL,
    key            VARCHAR(10) NOT NULL,
    offset_minutes INTEGER NOT NULL,
    send_at        TIMESTAMP NOT NULL,
    sent_at        TIMESTAMP,
    created_at     TIMESTAMP DEFAULT NOW(),
    UNIQUE (event_id, key)
);
CREATE INDEX IF NOT EXISTS em_reminders_due_idx ON em_reminders (send_at) WHERE sent_at IS NULL;
CREATE INDEX IF NOT EXISTS em_reminders_event_idx ON em_reminders (event_id);

CREATE TABLE IF NOT EXISTS em_user_reminders (
    id         SERIAL PRIMARY KEY,
    event_id   INTEGER NOT NULL REFERENCES em_events(id) ON DELETE CASCADE,
    guild_id   VARCHAR(50) NOT NULL,
    user_id    VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (event_id, user_id)
);
CREATE INDEX IF NOT EXISTS em_user_reminders_event_idx ON em_user_reminders (event_id);
CREATE INDEX IF NOT EXISTS em_user_reminders_user_idx ON em_user_reminders (user_id);

CREATE TABLE IF NOT EXISTS em_activity (
    id         SERIAL PRIMARY KEY,
    event_id   INTEGER NOT NULL REFERENCES em_events(id) ON DELETE CASCADE,
    guild_id   VARCHAR(50) NOT NULL,
    user_id    VARCHAR(50),
    username   VARCHAR(100),
    action     VARCHAR(50) NOT NULL,
    detail     TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS em_activity_event_idx ON em_activity (event_id, created_at DESC);
