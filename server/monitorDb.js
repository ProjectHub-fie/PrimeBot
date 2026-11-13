/**
 * Status monitoring storage.
 *
 * Lives on the SAME database as the shardnode failover service (seasonPool:
 * SEASON_DATABASE_URL → FALLBACK_DATABASE_URL → DATABASE_URL), so a
 * single-DB setup reuses the existing DATABASE_URL with zero extra config and
 * every shard node + the dashboard reads/writes the same rows. No new database
 * URL, no Redis, no paid service — per the project rules.
 *
 * Tables (all self-created, indexed, UTC via NOW()):
 *   monitor_components    component registry (key -> label/description/enabled)
 *   monitor_node_pulse    per-node rich heartbeat (node_name PK, upsert)
 *   monitor_observations  raw state observations for uptime math
 *   monitor_daily         per-component per-UTC-day aggregates
 *   monitor_incidents     incident ledger (auto + manual)
 *   monitor_worker        single-worker coordination (db-backed lease)
 *   monitor_maintenance   scheduled maintenance windows
 *
 * Uptime formula (per component, per bucket):
 *   Uptime% = (monitored_ms - downtime_ms) / monitored_ms * 100
 * A bucket's monitored_ms is the time inside the bucket that had at least one
 * observation; gaps (no data) are NEVER counted as operational — they reduce
 * the monitored duration instead.
 */

const { sql } = require('drizzle-orm');
const { resolveDbUrl } = require('./resolveDbUrl');
const { createPool } = require('./createPool');
const { seasonPool } = require('./seasonDb');

/**
 * Connection string for the monitoring tables. They ride the shardnode
 * failover database (the season pool: SEASON_DATABASE_URL → FALLBACK_DATABASE_URL
 * → DATABASE_URL) by default so a single-DB deployment reuses the one existing
 * pool with zero extra config. An explicit MONITOR_DATABASE_URL points them at
 * a dedicated database when one is configured.
 */
function resolveConnectionString() {
    return process.env.MONITOR_DATABASE_URL
        ? resolveDbUrl('MONITOR_DATABASE_URL')
        : resolveDbUrl('SEASON_DATABASE_URL');
}

// Default: the exact season pool object (shared — no second pool opened).
// Override: a dedicated pool for MONITOR_DATABASE_URL (createPool de-dupes by
// connection string, so this never leaks a duplicate pool on reload).
const monitorPool = process.env.MONITOR_DATABASE_URL
    ? createPool(resolveConnectionString(), { label: 'MONITOR DB' })
    : seasonPool;

const COMPONENT_KEYS = [
    'bot',          // PrimeBot overall bot
    'website',      // main website
    'api',          // dashboard/API
    'db',           // PostgreSQL database
    'gateway',      // Discord Gateway connectivity
    'sn1', 'sn2', 'sn3', // shard nodes
];

// A single row is used to protect the monitoring worker.
const WORKER_ID = 1;

// Observation/incident statuses.
const STATUS_OK = 'operational';
const STATUS_DEGRADED = 'degraded';
const STATUS_DOWN = 'unavailable';

const INCIDENT_ACTIVE = 'active';
const INCIDENT_STATUSES = ['investigating', 'identified', 'monitoring', 'resolved'];

// ── DDL (memoized once; a failed attempt is evicted so the next caller retries) ──

const _ddlDone = new Set();
async function ensureMonitorTables() {
    if (_ddlDone.has('monitor')) return;
    try {
        const p = await monitorPool.connect();
        try {
            await p.query(`
                CREATE TABLE IF NOT EXISTS monitor_components (
                    id SERIAL PRIMARY KEY,
                    key TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )`);
            await p.query(`
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
                )`);
            await p.query(`
                CREATE TABLE IF NOT EXISTS monitor_observations (
                    id BIGSERIAL PRIMARY KEY,
                    component TEXT NOT NULL,
                    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    status TEXT NOT NULL,
                    detail JSONB
                )`);
            await p.query(`CREATE INDEX IF NOT EXISTS idx_monitor_obs_comp_ts ON monitor_observations (component, ts)`);
            await p.query(`
                CREATE TABLE IF NOT EXISTS monitor_node_restarts (
                    id BIGSERIAL PRIMARY KEY,
                    node_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    restarted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    pid INTEGER,
                    detail JSONB
                )`);
            await p.query(`CREATE INDEX IF NOT EXISTS idx_monitor_restarts_node ON monitor_node_restarts (node_name, restarted_at DESC)`);
            await p.query(`
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
                )`);
            await p.query(`
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
                )`);
            await p.query(`CREATE INDEX IF NOT EXISTS idx_monitor_inc_comp ON monitor_incidents (component, started_at DESC)`);
            await p.query(`
                CREATE TABLE IF NOT EXISTS monitor_worker (
                    id INTEGER PRIMARY KEY,
                    holder TEXT,
                    last_seen TIMESTAMPTZ,
                    lease_expires_at TIMESTAMPTZ
                )`);
            await p.query(`
                CREATE TABLE IF NOT EXISTS monitor_maintenance (
                    id SERIAL PRIMARY KEY,
                    component TEXT NOT NULL,
                    title TEXT NOT NULL,
                    starts_at TIMESTAMPTZ NOT NULL,
                    ends_at TIMESTAMPTZ NOT NULL,
                    created_by TEXT NOT NULL DEFAULT 'system',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )`);
            await p.query(`CREATE INDEX IF NOT EXISTS idx_monitor_maint_comp ON monitor_maintenance (component, starts_at)`);
            // Seed the component registry.
            for (const [key, label] of [
                ['bot', 'PrimeBot Bot'],
                ['website', 'Main Website'],
                ['api', 'Dashboard / API'],
                ['db', 'PostgreSQL Database'],
                ['gateway', 'Discord Gateway'],
                ['sn1', 'Shard Node 1'],
                ['sn2', 'Shard Node 2'],
                ['sn3', 'Shard Node 3'],
            ]) {
                await p.query(`INSERT INTO monitor_components (key, label) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, [key, label]);
            }
        } finally {
            p.release();
        }
        _ddlDone.add('monitor');
    } catch (err) {
        _ddlDone.delete('monitor');
        throw err;
    }
}

// ── Node pulse ───────────────────────────────────────────────────────────────

async function upsertNodePulse(pulse) {
    await ensureMonitorTables();
    const {
        nodeName, role = 'sn1', processHealth = 'unknown',
        gatewayConnected = false, gatewayReady = false,
        shardsTotal = 0, shardsReady = 0, shardsActive = 0,
        pid = null, startedAt = null, resource = null, detail = null,
    } = pulse;
    await monitorPool.query(`
        INSERT INTO monitor_node_pulse
            (node_name, role, ts, process_health, gateway_connected, gateway_ready,
             shards_total, shards_ready, shards_active, pid, started_at, resource, detail)
        VALUES ($1,$2,NOW(),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT (node_name) DO UPDATE SET
            role = EXCLUDED.role,
            ts = NOW(),
            process_health = EXCLUDED.process_health,
            gateway_connected = EXCLUDED.gateway_connected,
            gateway_ready = EXCLUDED.gateway_ready,
            shards_total = EXCLUDED.shards_total,
            shards_ready = EXCLUDED.shards_ready,
            shards_active = EXCLUDED.shards_active,
            pid = EXCLUDED.pid,
            started_at = EXCLUDED.started_at,
            resource = EXCLUDED.resource,
            detail = EXCLUDED.detail
    `, [nodeName, role, processHealth, gatewayConnected, gatewayReady, shardsTotal, shardsReady, shardsActive, pid, startedAt, resource, detail]);
}

async function getNodePulses() {
    await ensureMonitorTables();
    const res = await monitorPool.query(`
        SELECT node_name, role, ts, process_health, gateway_connected, gateway_ready,
               shards_total, shards_ready, shards_active, pid, started_at, resource, detail,
               EXTRACT(EPOCH FROM (NOW() - ts)) * 1000 AS age_ms
        FROM monitor_node_pulse
    `).catch(() => ({ rows: [] }));
    return (res.rows || []).map(r => ({
        nodeName: r.node_name,
        role: r.role,
        ts: r.ts,
        ageMs: Math.round(Number(r.age_ms) || 0),
        processHealth: r.process_health,
        gatewayConnected: !!r.gateway_connected,
        gatewayReady: !!r.gateway_ready,
        shardsTotal: Number(r.shards_total) || 0,
        shardsReady: Number(r.shards_ready) || 0,
        shardsActive: Number(r.shards_active) || 0,
        pid: r.pid != null ? Number(r.pid) : null,
        startedAt: r.started_at,
        resource: r.resource || null,
        detail: r.detail || null,
    }));
}

// ── Node restarts ────────────────────────────────────────────────────────────

async function recordNodeRestart(nodeName, role, pid, detail) {
    await ensureMonitorTables();
    await monitorPool.query(`
        INSERT INTO monitor_node_restarts (node_name, role, restarted_at, pid, detail)
        VALUES ($1, $2, NOW(), $3, $4)
    `, [nodeName, role, pid || null, detail || null]).catch(() => {});
}

async function getNodeRestarts(nodeName, limit = 50) {
    await ensureMonitorTables();
    const res = await monitorPool.query(`
        SELECT node_name, role, restarted_at, pid, detail
        FROM monitor_node_restarts
        WHERE node_name = $1
        ORDER BY restarted_at DESC
        LIMIT $2
    `, [nodeName, Number(limit) || 50]).catch(() => ({ rows: [] }));
    return (res.rows || []).map(r => ({
        nodeName: r.node_name,
        role: r.role,
        restartedAt: r.restarted_at,
        pid: r.pid != null ? Number(r.pid) : null,
        detail: r.detail || null,
    }));
}

// ── Observations ─────────────────────────────────────────────────────────────

async function insertObservation(component, status, detail) {
    await ensureMonitorTables();
    await monitorPool.query(
        `INSERT INTO monitor_observations (component, ts, status, detail) VALUES ($1, NOW(), $2, $3)`,
        [component, status, detail || null]
    ).catch(() => {});
}

async function pruneObservations(keepDays) {
    // Retention: keep raw observations for the visible 31-day window plus the
    // daily aggregates cover the rest. Runs on the worker at a low cadence.
    const days = Math.max(3, Number(keepDays) || 31);
    await monitorPool.query(
        `DELETE FROM monitor_observations WHERE ts < NOW() - interval '1 day' * $1`,
        [days]
    ).catch(() => {});
}

// ── Worker lease ─────────────────────────────────────────────────────────────

async function acquireWorkerLease(holder, ttlSeconds = 45) {
    // Atomic claim: INSERT the row; on conflict, only take over a stale lease.
    const res = await monitorPool.query(`
        INSERT INTO monitor_worker (id, holder, last_seen, lease_expires_at)
        VALUES ($1, $2, NOW(), NOW() + make_interval(secs => $3))
        ON CONFLICT (id) DO UPDATE SET
            holder = EXCLUDED.holder,
            last_seen = NOW(),
            lease_expires_at = NOW() + make_interval(secs => $3)
        WHERE monitor_worker.lease_expires_at < NOW() OR monitor_worker.holder = EXCLUDED.holder
        RETURNING holder
    `, [WORKER_ID, holder, ttlSeconds]).catch(err => { console.error('[MONITOR] lease query failed:', err.message); return { rows: [] }; });
    return (res.rows && res.rows[0] && res.rows[0].holder) === holder;
}

async function refreshWorkerLease(holder, ttlSeconds = 45) {
    const res = await monitorPool.query(`
        UPDATE monitor_worker
        SET last_seen = NOW(), lease_expires_at = NOW() + make_interval(secs => $3)
        WHERE id = $1 AND holder = $2
        RETURNING holder
    `, [WORKER_ID, holder, ttlSeconds]).catch(() => ({ rows: [] }));
    return (res.rows && res.rows[0] && res.rows[0].holder) === holder;
}

async function getWorkerLease() {
    const res = await monitorPool.query(`SELECT holder, last_seen, lease_expires_at FROM monitor_worker WHERE id = $1`, [WORKER_ID])
        .catch(() => ({ rows: [] }));
    const row = res.rows && res.rows[0];
    if (!row) return { holder: null, lastSeen: null, leaseExpiresAt: null };
    return { holder: row.holder, lastSeen: row.last_seen, leaseExpiresAt: row.lease_expires_at };
}

// ── Incidents ────────────────────────────────────────────────────────────────

async function getOpenIncidents(component) {
    await ensureMonitorTables();
    const res = await monitorPool.query(
        `SELECT * FROM monitor_incidents WHERE status <> 'resolved'
         ${component ? 'AND component = $1' : ''}
         ORDER BY started_at DESC`,
        component ? [component] : []
    ).catch(() => ({ rows: [] }));
    return (res.rows || []).map(rowToIncident);
}

async function getIncidents({ component, status, limit = 50, offset = 0 } = {}) {
    await ensureMonitorTables();
    const where = [];
    const params = [];
    if (component) { params.push(component); where.push(`component = $${params.length}`); }
    if (status) { params.push(status); where.push(`status = $${params.length}`); }
    params.push(Number(limit) || 50); params.push(Number(offset) || 0);
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const res = await monitorPool.query(
        `SELECT * FROM monitor_incidents ${whereSql} ORDER BY started_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params
    ).catch(() => ({ rows: [] }));
    return (res.rows || []).map(rowToIncident);
}

async function getIncidentById(id) {
    const res = await monitorPool.query(`SELECT * FROM monitor_incidents WHERE id = $1`, [id]).catch(() => ({ rows: [] }));
    return res.rows && res.rows[0] ? rowToIncident(res.rows[0]) : null;
}

async function createIncident({ component, title, description = '', severity = 'notice', status = 'investigating', startedAt = null, createdBy = 'system' }) {
    await ensureMonitorTables();
    const res = await monitorPool.query(`
        INSERT INTO monitor_incidents (component, title, description, severity, status, started_at, detected_at, created_by)
        VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7)
        RETURNING *
    `, [component, title, description, severity, status, startedAt || new Date(), createdBy]).catch(() => ({ rows: [] }));
    return res.rows && res.rows[0] ? rowToIncident(res.rows[0]) : null;
}

async function updateIncident(id, patch) {
    const allowed = ['title', 'description', 'severity', 'status', 'startedAt', 'resolvedAt'];
    const sets = [];
    const params = [id];
    for (const key of allowed) {
        if (patch[key] !== undefined) {
            params.push(patch[key]);
            const col = key === 'startedAt' ? 'started_at' : key === 'resolvedAt' ? 'resolved_at' : key;
            sets.push(`${col} = $${params.length}`);
        }
    }
    if (patch.status === 'resolved' && patch.resolvedAt === undefined) {
        params.push(new Date());
        sets.push(`resolved_at = $${params.length}`);
        params.push('GREATEST(EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000, 0)::bigint');
        sets.push(`duration_ms = $${params.length}`);
    }
    if (!sets.length) return getIncidentById(id);
    const res = await monitorPool.query(
        `UPDATE monitor_incidents SET ${sets.join(', ')} WHERE id = $1 RETURNING *`,
        params
    ).catch(() => ({ rows: [] }));
    return res.rows && res.rows[0] ? rowToIncident(res.rows[0]) : null;
}

async function resolveIncident(id, resolvedAt) {
    const res = await monitorPool.query(`
        UPDATE monitor_incidents SET status = 'resolved',
            resolved_at = COALESCE($2, NOW()),
            duration_ms = EXTRACT(EPOCH FROM (COALESCE($2, NOW()) - started_at)) * 1000
        WHERE id = $1 RETURNING *
    `, [id, resolvedAt || null]).catch(() => ({ rows: [] }));
    return res.rows && res.rows[0] ? rowToIncident(res.rows[0]) : null;
}

function rowToIncident(r) {
    return {
        id: r.id,
        component: r.component,
        title: r.title,
        description: r.description || '',
        severity: r.severity,
        status: r.status,
        startedAt: r.started_at,
        detectedAt: r.detected_at,
        resolvedAt: r.resolved_at,
        durationMs: r.duration_ms != null ? Number(r.duration_ms) : null,
        createdBy: r.created_by || 'system',
    };
}

// ── Daily aggregates ─────────────────────────────────────────────────────────

async function rollDaily() {
    // Fold finished observations into the per-component per-day aggregate,
    // then drop the consumed raw rows. Each observation represents the interval
    // from its own timestamp until the next observation (LEAD), so cloudy gaps
    // shave the monitored duration instead of being counted as operational.
    // Only fully-finished days are rolled; the current UTC day stays raw.
    await ensureMonitorTables();
    // The next UTC midnight is built UTC-explicit (`NOW() AT TIME ZONE 'UTC'`
    // yields a naive timestamp we can add a day to, then re-tag as timestamptz)
    // so the rollover boundary does not drift with the session timezone, and
    // every operand of the subtraction is a timestamptz. LEAST() must be
    // parenthesized on both sides: `a + interval '1 day' - ts` parses as
    // `a + (interval '1 day' - ts)`, which makes LEAST() compare a timestamptz
    // against an interval and errors "LEAST types timestamp with time zone and
    // interval cannot be matched".
    try {
        await monitorPool.query(`
            INSERT INTO monitor_daily (component, day, monitored_ms, operational_ms, degraded_ms, downtime_ms, maintenance_ms, samples)
            WITH bucket AS (
                SELECT component,
                       (ts AT TIME ZONE 'UTC')::date AS day,
                       ts,
                       LEAD(ts) OVER (PARTITION BY component ORDER BY ts) AS next_ts,
                       status
                FROM monitor_observations
                WHERE ts < date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
            ),
            spans AS (
                SELECT component, day, status,
                       CASE
                           WHEN next_ts IS NULL THEN 0
                           ELSE GREATEST(EXTRACT(EPOCH FROM (
                               LEAST(next_ts, (date_trunc('day', NOW() AT TIME ZONE 'UTC') + interval '1 day') AT TIME ZONE 'UTC') - ts
                           )) * 1000, 0)
                       END AS span_ms
                FROM bucket
            )
            SELECT component, day,
                   COALESCE(SUM(span_ms) FILTER (WHERE status <> 'maintenance'), 0),
                   COALESCE(SUM(span_ms) FILTER (WHERE status = 'operational'), 0),
                   COALESCE(SUM(span_ms) FILTER (WHERE status = 'degraded'), 0),
                   COALESCE(SUM(span_ms) FILTER (WHERE status = 'unavailable'), 0),
                   COALESCE(SUM(span_ms) FILTER (WHERE status = 'maintenance'), 0),
                   COUNT(*)
            FROM spans
            GROUP BY component, day
            ON CONFLICT (component, day) DO UPDATE SET
                monitored_ms = EXCLUDED.monitored_ms,
                operational_ms = EXCLUDED.operational_ms,
                degraded_ms = EXCLUDED.degraded_ms,
                downtime_ms = EXCLUDED.downtime_ms,
                maintenance_ms = EXCLUDED.maintenance_ms,
                samples = EXCLUDED.samples
        `);
    } catch (err) {
        // The roll failed — do NOT delete the raw rows. They are the only copy
        // of that history until they are successfully folded into monitor_daily;
        // deleting on failure would lose the day permanently. Retry next tick.
        console.error('[MONITOR] rollDaily error:', err.message);
        return;
    }
    // Only prune once the aggregate is safely persisted. Same UTC-explicit
    // boundary as the roll above so the two never disagree by a timezone.
    await monitorPool.query(
        `DELETE FROM monitor_observations WHERE ts < date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`
    ).catch(() => {});
}

/**
 * Build a 30-day series for one component: exactly 30 daily buckets ending
 * today (UTC). Each bucket carries monitored/operational/degraded/downtime ms,
 * a computed uptime %, and flags for maintenance / missing data.
 */
async function getDailySeries(component, days = 30) {
    await ensureMonitorTables();
    const n = Math.max(7, Math.min(90, Number(days) || 30));
    const start = new Date();
    start.setUTCDate(start.getUTCDate() - (n - 1));
    start.setUTCHours(0, 0, 0, 0);
    const res = await monitorPool.query(`
        SELECT component, day, monitored_ms, operational_ms, degraded_ms, downtime_ms, maintenance_ms, samples
        FROM monitor_daily
        WHERE component = $1 AND day >= $2::date AND day <= (NOW() AT TIME ZONE 'UTC')::date
        ORDER BY day ASC
    `, [component, start.toISOString().slice(0, 10)]).catch(() => ({ rows: [] }));

    const byDay = new Map();
    for (const r of res.rows || []) {
        byDay.set(r.day instanceof Date ? r.day.toISOString().slice(0, 10) : String(r.day).slice(0, 10), {
            monitoredMs: Number(r.monitored_ms) || 0,
            operationalMs: Number(r.operational_ms) || 0,
            degradedMs: Number(r.degraded_ms) || 0,
            downtimeMs: Number(r.downtime_ms) || 0,
            maintenanceMs: Number(r.maintenance_ms) || 0,
            samples: Number(r.samples) || 0,
        });
    }

    // Today's numbers come straight from the raw observations (the current UTC
    // day is never rolled). Same LEAD-based span math as rollDaily.
    const todayStart = new Date();
    todayStart.setUTCHours(0, 0, 0, 0);
    const todayRes = await monitorPool.query(`
        WITH bucket AS (
            SELECT ts, LEAD(ts) OVER (ORDER BY ts) AS next_ts, status
            FROM monitor_observations
            WHERE component = $1 AND ts >= $2::timestamptz
        ),
        spans AS (
            SELECT status,
                   CASE WHEN next_ts IS NULL THEN 0
                        ELSE GREATEST(EXTRACT(EPOCH FROM (next_ts - ts)) * 1000, 0) END AS span_ms
            FROM bucket
        )
        SELECT
            COALESCE(SUM(span_ms) FILTER (WHERE status <> 'maintenance'), 0) AS monitored_ms,
            COALESCE(SUM(span_ms) FILTER (WHERE status = 'operational'), 0) AS operational_ms,
            COALESCE(SUM(span_ms) FILTER (WHERE status = 'degraded'), 0) AS degraded_ms,
            COALESCE(SUM(span_ms) FILTER (WHERE status = 'unavailable'), 0) AS downtime_ms,
            COALESCE(SUM(span_ms) FILTER (WHERE status = 'maintenance'), 0) AS maintenance_ms,
            COUNT(*) AS samples
        FROM spans
    `, [component, todayStart.toISOString()]).catch(() => ({ rows: [] }));

    const todayAgg = todayRes.rows && todayRes.rows[0]
        ? {
            monitoredMs: Math.round(Number(todayRes.rows[0].monitored_ms) || 0),
            operationalMs: Math.round(Number(todayRes.rows[0].operational_ms) || 0),
            degradedMs: Math.round(Number(todayRes.rows[0].degraded_ms) || 0),
            downtimeMs: Math.round(Number(todayRes.rows[0].downtime_ms) || 0),
            maintenanceMs: Math.round(Number(todayRes.rows[0].maintenance_ms) || 0),
            samples: Number(todayRes.rows[0].samples) || 0,
        }
        : null;

    const series = [];
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    for (let i = 0; i < n; i++) {
        const d = new Date(start.getTime() + i * 86400000);
        const day = d.toISOString().slice(0, 10);
        const isToday = d.getTime() === today.getTime();
        const agg = isToday ? (todayAgg || null) : (byDay.get(day) || null);
        if (!agg || agg.monitoredMs <= 0) {
            series.push({
                day,
                isToday,
                hasData: false,
                monitoredMs: 0, operationalMs: 0, degradedMs: 0, downtimeMs: 0, maintenanceMs: 0,
                uptime: null,
                samples: 0,
            });
            continue;
        }
        const uptime = agg.monitoredMs > 0
            ? ((agg.monitoredMs - agg.downtimeMs) / agg.monitoredMs) * 100
            : null;
        series.push({ day, isToday, hasData: true, ...agg, uptime });
    }
    return series;
}

// ── Components registry ──────────────────────────────────────────────────────

async function listComponents() {
    await ensureMonitorTables();
    const res = await monitorPool.query(`SELECT * FROM monitor_components ORDER BY id ASC`).catch(() => ({ rows: [] }));
    return (res.rows || []).map(r => ({
        key: r.key,
        label: r.label,
        description: r.description || '',
        enabled: !!r.enabled,
        updatedAt: r.updated_at,
    }));
}

async function updateComponent(key, patch) {
    const sets = [];
    const params = [key];
    if (patch.label !== undefined) { params.push(patch.label); sets.push(`label = $${params.length}`); }
    if (patch.description !== undefined) { params.push(patch.description); sets.push(`description = $${params.length}`); }
    if (patch.enabled !== undefined) { params.push(!!patch.enabled); sets.push(`enabled = $${params.length}`); }
    if (!sets.length) return null;
    await monitorPool.query(
        `UPDATE monitor_components SET ${sets.join(', ')}, updated_at = NOW() WHERE key = $1`,
        params
    ).catch(err => console.error('[MONITOR] updateComponent error:', err.message));
}

// ── Maintenance ──────────────────────────────────────────────────────────────

async function addMaintenance({ component, title, startsAt, endsAt, createdBy = 'admin' }) {
    await ensureMonitorTables();
    const res = await monitorPool.query(`
        INSERT INTO monitor_maintenance (component, title, starts_at, ends_at, created_by)
        VALUES ($1,$2,$3,$4,$5) RETURNING *
    `, [component, title, startsAt, endsAt, createdBy]).catch(() => ({ rows: [] }));
    return res.rows && res.rows[0] ? rowToMaintenance(res.rows[0]) : null;
}

async function deleteMaintenance(id) {
    await monitorPool.query(`DELETE FROM monitor_maintenance WHERE id = $1`, [id]).catch(() => {});
}

async function activeMaintenances() {
    await ensureMonitorTables();
    const res = await monitorPool.query(
        `SELECT * FROM monitor_maintenance WHERE ends_at > NOW() ORDER BY starts_at ASC`
    ).catch(() => ({ rows: [] }));
    return (res.rows || []).map(rowToMaintenance);
}

function rowToMaintenance(r) {
    return { id: r.id, component: r.component, title: r.title, startsAt: r.starts_at, endsAt: r.ends_at, createdBy: r.created_by || 'system' };
}

module.exports = {
    resolveConnectionString, monitorPool,
    COMPONENT_KEYS, STATUS_OK, STATUS_DEGRADED, STATUS_DOWN, INCIDENT_STATUSES,
    ensureMonitorTables, upsertNodePulse, getNodePulses,
    recordNodeRestart, getNodeRestarts,
    insertObservation, pruneObservations,
    acquireWorkerLease, refreshWorkerLease, getWorkerLease,
    getOpenIncidents, getIncidents, getIncidentById, createIncident, updateIncident, resolveIncident,
    rollDaily, getDailySeries,
    listComponents, updateComponent,
    addMaintenance, deleteMaintenance, activeMaintenances,
};