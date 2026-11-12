-- Infrastructure status monitoring (Stats page + shard-node heartbeats).
--
-- Tables live on the SAME database as the failover service (SEASON_DATABASE_URL
-- → FALLBACK_DATABASE_URL → DATABASE_URL). In a single-DB setup they reuse the
-- existing DATABASE_URL — no new database URL, Redis or paid service.
--
-- All tables are also self-created by server/monitorDb.js (CREATE TABLE IF NOT
-- EXISTS on first use), so this migration is belt-and-suspenders for setups
-- that run drizzle-kit migrations; the service works with or without it.

CREATE TABLE IF NOT EXISTS monitor_components (
    id SERIAL PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS monitor_node_pulse (
    node_name TEXT PRIMARY KEY,
    role TEXT NOT NULL DEFAULT 'sn1',
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    process_health TEXT DEFAULT 'unknown',
    gateway_connected BOOLEAN NOT NULL DEFAULT FALSE,
    gateway_ready BOOLEAN NOT NULL DEFAULT FALSE,
    shards_total INTEGER NOT NULL DEFAULT 0,
    shards_ready INTEGER NOT NULL DEFAULT 0,
    shards_active INTEGER NOT NULL DEFAULT 0,
    pid INTEGER,
    started_at TIMESTAMPTZ,
    resource JSONB,
    detail JSONB
);

CREATE TABLE IF NOT EXISTS monitor_observations (
    id BIGSERIAL PRIMARY KEY,
    component TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL,
    detail JSONB
);
CREATE INDEX IF NOT EXISTS idx_monitor_obs_comp_ts ON monitor_observations (component, ts);

CREATE TABLE IF NOT EXISTS monitor_daily (
    component TEXT NOT NULL,
    day DATE NOT NULL,
    monitored_ms BIGINT NOT NULL DEFAULT 0,
    operational_ms BIGINT NOT NULL DEFAULT 0,
    degraded_ms BIGINT NOT NULL DEFAULT 0,
    downtime_ms BIGINT NOT NULL DEFAULT 0,
    maintenance_ms BIGINT NOT NULL DEFAULT 0,
    samples INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (component, day)
);

CREATE TABLE IF NOT EXISTS monitor_incidents (
    id SERIAL PRIMARY KEY,
    component TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'notice',
    status TEXT NOT NULL DEFAULT 'investigating',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    duration_ms BIGINT,
    created_by TEXT NOT NULL DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS idx_monitor_inc_comp ON monitor_incidents (component, started_at DESC);

CREATE TABLE IF NOT EXISTS monitor_worker (
    id INTEGER PRIMARY KEY,
    holder TEXT,
    last_seen TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS monitor_maintenance (
    id SERIAL PRIMARY KEY,
    component TEXT NOT NULL,
    title TEXT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_monitor_maint_comp ON monitor_maintenance (component, starts_at);

-- Seed the component registry (idempotent).
INSERT INTO monitor_components (key, label)
VALUES
    ('bot', 'PrimeBot Bot'),
    ('website', 'Main Website'),
    ('api', 'Dashboard / API'),
    ('db', 'PostgreSQL Database'),
    ('gateway', 'Discord Gateway'),
    ('sn1', 'Shard Node 1'),
    ('sn2', 'Shard Node 2'),
    ('sn3', 'Shard Node 3')
ON CONFLICT (key) DO NOTHING;