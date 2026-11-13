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
const statusWorker = require('../utils/statusWorker');

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
const STATUS_RANK = { operational: 0, stale: 1, degraded: 1, unavailable: 2 };
const NODE_KEYS = ['sn1', 'sn2', 'sn3'];

// The most recent observation for a non-node component, read from the same pool
// the writer uses (via monitorDb). Returns an 'unknown' shape when absent.
async function latestObservation(component) {
    const row = await monitorDb.getLatestObservation(component);
    if (!row) return { status: 'unknown', detail: null, ts: null, ageMs: null };
    return row;
}

// A standby node being down is a REDUNDANCY problem, not a service outage: the
// active node is still serving Discord. Nodes therefore never escalate the
// overall status past "degraded" (never Major/Critical) — the service-level
// components (`bot`/`gateway`/`website`/`api`/`db`) carry the outage states.
// This is what stops a healthy active node + dead standby from reading as a
// Major Service Outage, while still surfacing the redundancy loss.
function componentRank(comp) {
    const rank = STATUS_RANK[comp.status];
    if (rank === undefined) return undefined;
    if (NODE_KEYS.includes(comp.key) && rank === 2) return 1;
    return rank;
}

function summarize(components, incidents) {
    // Overall: derived from the monitored components' actual statuses, never
    // from "no incidents recorded".
    const openIncidents = incidents.length;
    const values = Object.values(components);
    const ranks = values.map(componentRank).filter(r => r !== undefined);
    const unknown = values.some(c => c.status === 'unknown' || c.status === 'never');
    let overall;
    if (ranks.length === 0) {
        overall = { key: 'no_data', label: 'Monitoring Data Unavailable' };
    } else if (ranks.some(r => r === 2)) {
        overall = (ranks.filter(r => r === 2).length >= 2)
            ? { key: 'critical', label: 'Critical System Outage' }
            : { key: 'major', label: 'Major Service Outage' };
    } else if (ranks.some(r => r === 1)) {
        overall = { key: 'degraded', label: 'Partial System Degradation' };
    } else {
        // Everything measured is operational. Components with no data are not
        // treated as outages (they are shown grey / "no data" on their own card).
        overall = { key: 'operational', label: 'All Systems Operational' };
    }
    return { overall, openIncidents, unknown };
}

/**
 * Node infrastructure counters, computed from ACTUAL node classifications (never
 * hardcoded):
 *   online/offline/unhealthy/unknown counts, active + standby role counts, and
 *   a combined availability built from real monitored/downtime intervals.
 */
function buildInfra(nodeComps) {
    const nodes = NODE_KEYS.map(k => nodeComps[k]).filter(Boolean);
    const isOnline = n => n.health === 'online' || n.health === 'stale'; // stale = still up, just late
    const online = nodes.filter(isOnline).length;
    const offline = nodes.filter(n => n.health === 'offline').length;
    const unknown = nodes.filter(n => n.health === 'unknown' || n.health === undefined).length;
    const active = nodes.filter(n => n.role === 'active').length;
    const standby = nodes.filter(n => n.role === 'standby').length;
    // "Healthy" = online AND not degraded (a standby with no shards is healthy).
    const healthy = nodes.filter(n => isOnline(n) && n.status !== 'degraded').length;
    const unhealthy = nodes.length - healthy;

    let combinedMonitored = 0;
    let combinedDown = 0;
    for (const n of nodes) {
        if (n.uptime30) {
            combinedMonitored += n.uptime30.monitoredMs || 0;
            combinedDown += n.uptime30.downtimeMs || 0;
        }
    }
    const combinedPct = combinedMonitored > 0
        ? ((combinedMonitored - combinedDown) / combinedMonitored) * 100
        : null;

    let mostReliable = null;
    let mostDown = null;
    for (const n of nodes) {
        if (!n.uptime30) continue;
        if (!mostReliable || (n.uptime30.pct || 0) > (mostReliable.uptime30.pct || 0)) mostReliable = n;
        if (!mostDown || (n.uptime30.downtimeMs || 0) > (mostDown.uptime30.downtimeMs || 0)) mostDown = n;
    }

    return {
        total: nodes.length,
        online, offline, unknown, healthy, unhealthy, active, standby,
        combinedPct,
        combinedMonitoredMs: combinedMonitored,
        combinedDowntimeMs: combinedDown,
        mostReliable: mostReliable ? mostReliable.key : null,
        mostDown: mostDown ? mostDown.key : null,
    };
}

/**
 * Public-ish summary for the status page:
 *  { overall, components: [{key,label,status,role,health,gateway,uptime30,...}],
 *    infra, incidents, lastChecked }
 */
async function getStatusSummary() {
    return cached('summary', async () => {
        const [components, pulses, lock] = await Promise.all([
            monitorDb.listComponents(),
            monitorDb.getNodePulses().catch(() => []),
            monitorDb.getFailoverLock().catch(() => ({ nodeName: null, role: null })),
        ]);
        const holderNode = lock && lock.nodeName;
        const pulseByRole = {};
        for (const p of pulses || []) if (p.role in { sn1: 1, sn2: 1, sn3: 1 }) pulseByRole[p.role] = p;

        const componentsMap = {};
        for (const c of components) {
            const isNode = NODE_KEYS.includes(c.key);
            const series = await monitorDb.getDailySeries(c.key, 30);
            const uptime30 = computeUptime30(series);

            let status;
            let detail = null;
            let lastObservedAt = null;
            let ageMs = null;
            let role = null;
            let health = null;
            let gateway = null;
            let shardIds = [];
            let shardsReady = 0;
            let shardsTotal = 0;

            if (isNode) {
                const p = pulseByRole[c.key];
                const isActive = Boolean(p) && p.nodeName === holderNode;
                const cls = statusWorker.classifyNode(p, { isActive });
                status = cls.status === 'never' ? 'unknown' : cls.status;
                detail = cls.detail || null;
                role = cls.role;
                health = cls.health;
                gateway = cls.gateway;
                shardIds = cls.shardIds || [];
                shardsReady = cls.shardsReady || 0;
                shardsTotal = cls.shardsTotal || 0;
                lastObservedAt = p ? p.ts : null;
                ageMs = p ? p.ageMs : null;
            } else {
                const cur = await latestObservation(c.key);
                status = cur.status === 'never' ? 'unknown' : cur.status;
                detail = cur.detail;
                lastObservedAt = cur.ts;
                ageMs = cur.ageMs;
            }

            componentsMap[c.key] = {
                key: c.key,
                label: c.label,
                description: c.description || '',
                enabled: c.enabled,
                status,
                detail,
                lastObservedAt,
                ageMs,
                role,
                health,
                gateway,
                shardIds,
                shardsReady,
                shardsTotal,
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
        const infra = buildInfra(componentsMap);

        return {
            overall,
            openIncidents,
            components: Object.values(componentsMap),
            infra,
            activeIncidents: active,
            resolvedIncidents: resolved.slice(0, 10),
            maintenances,
            lastCheckedAt,
            measurement: {
                intervalMs: parseInt(process.env.STATUS_MONITOR_INTERVAL_MS, 10) || 60000,
                staleFactor: parseFloat(process.env.STATUS_STALE_FACTOR) || 3,
                offlineFactor: parseFloat(process.env.STATUS_OFFLINE_FACTOR) || 6,
            },
        };
    });
}

// Uptime over the full monitored 30-day window. Only counted while monitored;
// a missing day (hasData=false) does not count against the denominator. The
// returned `coverageMs` / `windowMs` let the UI distinguish a real 30-day
// history from a few hours of genuine monitoring (so a fresh deployment never
// presents a partial window as if it were a full 30-day 100%).
function computeUptime30(series) {
    let monitored = 0;
    let downtime = 0;
    let degraded = 0;
    let maintenance = 0;
    let daysWithData = 0;
    for (const day of series) {
        if (!day.hasData) continue;
        daysWithData++;
        monitored += day.monitoredMs;
        downtime += day.downtimeMs;
        degraded += day.degradedMs;
        maintenance += day.maintenanceMs;
    }
    const windowMs = (series.length || 30) * 86400000;
    if (monitored <= 0) return null;
    return {
        pct: ((monitored - downtime) / monitored) * 100,
        monitoredMs: monitored,
        downtimeMs: downtime,
        degradedMs: degraded,
        maintenanceMs: maintenance,
        daysWithData,
        windowDays: series.length || 30,
        coverageMs: monitored,
        windowMs,
        partial: monitored < windowMs * 0.95,
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

module.exports = { getStatusSummary, getComponentDetail, computeUptime30, latestObservation, summarize, buildInfra, componentRank };