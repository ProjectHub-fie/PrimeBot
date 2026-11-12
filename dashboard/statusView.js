/**
 * Dashboard read-model for the infrastructure status page.
 *
 * All queries are thin, cached layers over the shared `server/monitorDb`
 * tables (same season DB as the failover service). The status page renders its
 * layout immediately and loads these aggregates asynchronously; each endpoint
 * here is cheap (indexed aggregates + a small incident list), so loading the
 * page never pulls raw heartbeat history.
 */

const monitorDb = require('../server/monitorDb');

// Cache public aggregates briefly (per the Neon/CPU rules).
const CACHE_TTL_MS = 15000;
const _cache = new Map();
function cached(key, fn) {
    const hit = _cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return Promise.resolve(hit.value);
    return Promise.resolve(fn()).then(value => {
        _cache.set(key, { at: Date.now(), value });
        return value;
    });
}

// Visual states for a component's CURRENT status.
const STATUS_RANK = { operational: 0, degraded: 1, unavailable: 2 };

// A component is "operational" only if its latest observation is operational
// AND that observation is recent. If we have never observed it, it is unknown.
async function currentStatusOf(component) {
    const series = await monitorDb.getDailySeries(component, 2);
    // Current status = the latest raw observation. Fetch it directly to stay
    // independent of daily aggregation.
    const latest = await latestObservation(component);
    return latest;
}

async function latestObservation(component) {
    const { seasonPool } = require('../server/seasonDb');
    const res = await seasonPool.query(`
        SELECT status, detail, ts,
               EXTRACT(EPOCH FROM (NOW() - ts)) * 1000 AS age_ms
        FROM monitor_observations
        WHERE component = $1
        ORDER BY ts DESC
        LIMIT 1
    `, [component]).catch(() => ({ rows: [] }));
    const row = res.rows && res.rows[0];
    if (!row) return { status: 'unknown', detail: null, ts: null, ageMs: null };
    return {
        status: row.status,
        detail: row.detail || null,
        ts: row.ts,
        ageMs: Math.round(Number(row.age_ms) || 0),
    };
}

function summarize(components, incidents) {
    // Overall: derived from the monitored components' actual statuses, never
    // from "no incidents recorded".
    const openIncidents = incidents.length;
    const ranks = Object.values(components)
        .map(c => STATUS_RANK[c.status])
        .filter(r => r !== undefined);
    const unknown = Object.values(components).some(c => c.status === 'unknown' || c.status === 'never');
    let overall;
    if (unknown && ranks.length === 0) {
        overall = { key: 'no_data', label: 'Monitoring Data Unavailable' };
    } else if (ranks.some(r => r === 2)) {
        overall = (ranks.filter(r => r === 2).length >= 2)
            ? { key: 'critical', label: 'Critical System Outage' }
            : { key: 'major', label: 'Major Service Outage' };
    } else if (ranks.some(r => r === 1)) {
        overall = { key: 'degraded', label: 'Partial System Degradation' };
    } else if (ranks.length > 0) {
        overall = { key: 'operational', label: 'All Systems Operational' };
    } else {
        overall = { key: 'no_data', label: 'Monitoring Data Unavailable' };
    }
    return { overall, openIncidents, unknown };
}

/**
 * Public-ish summary for the status page:
 *  { overall, components: [{key,label,status,uptime30,...}], incidents, lastChecked }
 */
async function getStatusSummary() {
    return cached('summary', async () => {
        const components = await monitorDb.listComponents();
        const componentsMap = {};
        for (const c of components) {
            const cur = await latestObservation(c.key);
            const series = await monitorDb.getDailySeries(c.key, 30);
            const uptime30 = computeUptime30(series);
            componentsMap[c.key] = {
                key: c.key,
                label: c.label,
                description: c.description || '',
                enabled: c.enabled,
                status: cur.status === 'never' ? 'unknown' : cur.status,
                detail: cur.detail,
                lastObservedAt: cur.ts,
                ageMs: cur.ageMs,
                uptime30,
                series,
            };
        }
        const incidents = await monitorDb.getIncidents({ limit: 50 });
        const active = incidents.filter(i => i.status !== 'resolved');
        const resolved = incidents.filter(i => i.status === 'resolved');
        const lastCheckedAt = new Date();
        const maintenances = await monitorDb.activeMaintenances();
        const { overall, openIncidents } = summarize(componentsMap, active);

        return {
            overall,
            openIncidents,
            components: Object.values(componentsMap),
            activeIncidents: active,
            resolvedIncidents: resolved.slice(0, 10),
            maintenances,
            lastCheckedAt,
            measurement: {
                intervalMs: parseInt(process.env.STATUS_MONITOR_INTERVAL_MS, 10) || 60000,
                staleFactor: 3,
            },
        };
    });
}

// Uptime over the full monitored 30-day window. Only counted while monitored;
// a missing day (hasData=false) does not count against the denominator.
function computeUptime30(series) {
    let monitored = 0;
    let downtime = 0;
    let degraded = 0;
    let maintenance = 0;
    for (const day of series) {
        if (!day.hasData) continue;
        monitored += day.monitoredMs;
        downtime += day.downtimeMs;
        degraded += day.degradedMs;
        maintenance += day.maintenanceMs;
    }
    if (monitored <= 0) return null;
    return {
        pct: ((monitored - downtime) / monitored) * 100,
        monitoredMs: monitored,
        downtimeMs: downtime,
        degradedMs: degraded,
        maintenanceMs: maintenance,
    };
}

/**
 * Detail view for one component:
 *  { component, series, incidents, pulseTimeline (nodes only) }
 */
async function getComponentDetail(component, { days = 30, heartbeatLimit = 200 } = {}) {
    const comps = await monitorDb.listComponents();
    const comp = comps.find(c => c.key === component);
    if (!comp) return null;

    const [series, incidents] = await Promise.all([
        monitorDb.getDailySeries(component, days),
        monitorDb.getIncidents({ component, limit: 100 }),
    ]);

    let pulseTimeline = null;
    let restarts = [];
    if (component === 'sn1' || component === 'sn2' || component === 'sn3') {
        const pulses = await monitorDb.getNodePulses();
        pulseTimeline = pulses
            .filter(p => p.role === component)
            .slice(-Number(heartbeatLimit) || -200);
        restarts = await monitorDb.getNodeRestarts(
            (pulseTimeline[0] && pulseTimeline[0].nodeName) || component,
            100
        );
    }

    return {
        component: { key: comp.key, label: comp.label, description: comp.description || '', enabled: comp.enabled },
        series,
        incidents,
        pulseTimeline,
        restarts,
    };
}

module.exports = { getStatusSummary, getComponentDetail, computeUptime30, latestObservation };