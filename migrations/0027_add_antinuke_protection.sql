-- Anti-Nuke protection system: extend antinuke_settings with containment,
-- lockdown and setup-wizard state, and add the incident ledger + lockdown
-- tables. All live in the ANUKE_DATABASE_URL pool (server/anukeDb.js), which
-- falls back to FALLBACK_DATABASE_URL then DATABASE_URL. Every statement is
-- idempotent (IF NOT EXISTS), and the application self-creates the same objects
-- at first use, so a deployment that never runs migrations still works.

ALTER TABLE antinuke_settings
    ADD COLUMN IF NOT EXISTS dangerous_permissions JSONB NOT NULL
        DEFAULT '["Administrator","ManageGuild","ManageRoles","ManageChannels"]';

ALTER TABLE antinuke_settings
    ADD COLUMN IF NOT EXISTS lockdown JSONB NOT NULL
        DEFAULT '{"enabled":true,"verificationLevel":"high","pauseInvites":true}';

ALTER TABLE antinuke_settings
    ADD COLUMN IF NOT EXISTS response_cooldown_seconds INTEGER NOT NULL DEFAULT 30;

ALTER TABLE antinuke_settings
    ADD COLUMN IF NOT EXISTS setup_method VARCHAR(20);

ALTER TABLE antinuke_settings
    ADD COLUMN IF NOT EXISTS setup_status VARCHAR(20) NOT NULL DEFAULT 'not_started';

ALTER TABLE antinuke_settings
    ADD COLUMN IF NOT EXISTS setup_state JSONB NOT NULL DEFAULT '{}';

-- Incident ledger: only real security incidents are persisted.
CREATE TABLE IF NOT EXISTS antinuke_incidents (
    id                SERIAL PRIMARY KEY,
    guild_id          VARCHAR(50) NOT NULL,
    executor_id       VARCHAR(50),
    executor_name     VARCHAR(120),
    action            VARCHAR(60) NOT NULL,
    module            VARCHAR(30),
    severity          VARCHAR(20) NOT NULL DEFAULT 'medium',
    count             INTEGER NOT NULL DEFAULT 0,
    threshold         INTEGER NOT NULL DEFAULT 0,
    window_seconds    INTEGER NOT NULL DEFAULT 0,
    response_taken    JSONB NOT NULL DEFAULT '[]',
    response_result   JSONB NOT NULL DEFAULT '{}',
    response_ok       BOOLEAN NOT NULL DEFAULT false,
    dry_run           BOOLEAN NOT NULL DEFAULT false,
    attribution       VARCHAR(30) NOT NULL DEFAULT 'unknown',
    details           TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS antinuke_incidents_guild_created_idx
    ON antinuke_incidents (guild_id, created_at DESC);
CREATE INDEX IF NOT EXISTS antinuke_incidents_guild_action_idx
    ON antinuke_incidents (guild_id, action);
CREATE INDEX IF NOT EXISTS antinuke_incidents_executor_idx
    ON antinuke_incidents (guild_id, executor_id);

-- Reversible lockdown state.
CREATE TABLE IF NOT EXISTS antinuke_lockdowns (
    guild_id        VARCHAR(50) PRIMARY KEY,
    active          BOOLEAN NOT NULL DEFAULT false,
    started_at      TIMESTAMP DEFAULT NOW(),
    started_by      VARCHAR(50),
    reason          TEXT NOT NULL DEFAULT '',
    state           JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMP DEFAULT NOW()
);
