/**
 * Dedicated PostgreSQL pool + data access for the Event Management feature.
 *
 * Event Management is a self-contained subsystem (its own `em_events`,
 * `em_participants`, `em_reminders`, `em_activity` tables and its own cache in
 * EventMgmtManager), so — like the other premium features — it gets its own
 * connection string (EVENTMGMT_DATABASE_URL) so it can live in a separate
 * database/schema if desired. If EVENTMGMT_DATABASE_URL is unset we fall back
 * to FALLBACK_DATABASE_URL (then DATABASE_URL) so the feature works in single-DB
 * setups with zero extra configuration.
 *
 * Same-DB requirement: for dashboard changes to reach the bot, both deployments
 * must point at the same EVENTMGMT_DATABASE_URL (or the same
 * FALLBACK_DATABASE_URL/DATABASE_URL fallback).
 *
 * Tables are self-created (CREATE TABLE IF NOT EXISTS) so a fresh database
 * works even if migrations were never applied.
 */

const { resolveDbUrl } = require('./resolveDbUrl');

function resolveConnectionString() {
    return resolveDbUrl('EVENTMGMT_DATABASE_URL');
}

const { createPool } = require('./createPool');

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ EVENTMGMT_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — event management will have no database.');
}

const eventMgmtPool = createPool(cs, { label: 'EVENT MGMT DB' });


const CREATE_TABLES_SQL = `
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
`;

let _tablesReady = false;
let _ensurePromise = null;

/** Create the tables (idempotent, memoized per process). */
async function ensureEventMgmtTables() {
    if (_tablesReady) return true;
    if (!_ensurePromise) {
        _ensurePromise = eventMgmtPool.query(CREATE_TABLES_SQL)
            .then(() => { _tablesReady = true; return true; })
            .catch((err) => { _ensurePromise = null; throw err; });
    }
    return _ensurePromise;
}

async function testEventMgmtConnection() {
    try {
        const client = await eventMgmtPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Event Management database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Event Management database connection failed:', err.message);
        return false;
    }
}

module.exports = { eventMgmtPool, ensureEventMgmtTables, testEventMgmtConnection, CREATE_TABLES_SQL };
