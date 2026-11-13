/**
 * Status monitoring worker.
 *
 * ONE node runs the worker at a time, chosen by a database-backed lease in
 * monitor_worker (atomic claim; a crashed holder's lease expires and another
 * node recovers the work — no duplicate workers, no duplicate incidents).
 *
 * Each tick the holder:
 *   • reads every monitor_node_pulse + the failover lease,
 *   • checks website/API over HTTP and the database with a single SELECT 1,
 *   • writes one monitor_observation per component when its state CHANGES,
 *   • opens/resolves monitor_incidents (restart-safe: an already-open incident
 *     for a component never gets a duplicate; recovery resolves it),
 *   • rolls finished days into monitor_daily and prunes raw observations.
 *
 * The timer is a single self-scheduling, unref'd timer (no timer per
 * component). It backs off while the bot is idle so a quiet deployment lets
 * Neon suspend.
 */

const monitorDb = require('../server/monitorDb');
const { seasonPool } = require('../server/seasonDb');

const ENABLED = process.env.STATUS_MONITOR_ENABLED !== 'false';
const INTERVAL_MS = parseInt(process.env.STATUS_MONITOR_INTERVAL_MS, 10) || 60000;
const WORKER_TTL_S = parseInt(process.env.STATUS_WORKER_TTL_S, 10) || 90;
const OBSERVATION_RETENTION_DAYS = parseInt(process.env.STATUS_RETENTION_DAYS, 10) || 31;
// A node is STALE (delayed heartbeat) after staleFactor × its own cadence, and
// OFFLINE after offlineFactor ×. Defaults: 3 beats then 6 beats — so a single
// missed heartbeat never marks a node down, and a standby that has backed off to
// a slow idle cadence is judged against THAT cadence, not a fixed 45s.
const STALE_FACTOR = parseFloat(process.env.STATUS_STALE_FACTOR) || 3;
const OFFLINE_FACTOR = parseFloat(process.env.STATUS_OFFLINE_FACTOR) || 6;
// Consecutive operational evaluations required before an open incident is
// resolved — stops a flapping node from resolving+recreating incidents forever.
const RECOVERY_CONFIRMATIONS = parseInt(process.env.STATUS_RECOVERY_CONFIRMATIONS, 10) || 2;

function nodeName() {
    try { return require('./nodeFailover').NODE_NAME; } catch (_) { return process.env.NODE_NAME || 'local'; }
}
const WORKER_ID = 'status-worker:' + nodeName() + ':' + process.pid;
const BASE_URL = process.env.MONITOR_WEBSITE_URL || process.env.DASHBOARD_BASE_URL || null;

let timer = null;
let running = false;

const COMPONENT_LABELS = {
    bot: 'PrimeBot Bot',
    website: 'Main Website',
    api: 'Dashboard / API',
    db: 'PostgreSQL Database',
    gateway: 'Discord Gateway',
    sn1: 'Shard Node 1',
    sn2: 'Shard Node 2',
    sn3: 'Shard Node 3',
};

const COMPONENT_SEVERITY = {
    bot: 'critical', website: 'minor', api: 'major', db: 'critical',
    gateway: 'major', sn1: 'major', sn2: 'major', sn3: 'major',
};

function log(msg) {
    console.log(`[STATUS] ${msg}`);
}

function idleBackoffMs() {
    try {
        if (require('./activityGate').isIdle()) return 5 * 60000;
    } catch (_) {}
    return INTERVAL_MS;
}

// ── HTTP checks (website + API) ──────────────────────────────────────────────

async function httpCheck(url) {
    if (!url) return { status: 'no_data', detail: { reason: 'not_configured' } };
    try {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 10000);
        const res = await fetch(url, { method: 'GET', signal: controller.signal, headers: { 'User-Agent': 'PrimeBot-Status' } });
        clearTimeout(t);
        const s = res.status;
        if (s >= 200 && s < 400) return { status: 'operational', detail: { httpStatus: s } };
        if (s >= 500) return { status: 'degraded', detail: { httpStatus: s } };
        return { status: 'operational', detail: { httpStatus: s } };
    } catch (err) {
        return {
            status: 'unavailable',
            detail: { error: err.name === 'AbortError' ? 'timeout' : err.message },
        };
    }
}

async function dbCheck() {
    try {
        await seasonPool.query('SELECT 1');
        return { status: 'operational', detail: {} };
    } catch (err) {
        return { status: 'unavailable', detail: { error: err.message } };
    }
}

// ── Per-node + derived statuses ──────────────────────────────────────────────

// How often this node actually reports, in ms. We read the cadence the node
// published in its own pulse (a standby that backed off to a slow idle cadence
// publishes that), falling back to the configured default.
function pulseIntervalMs(pulse) {
    const published = Number(pulse?.resource?.pulseIntervalMs);
    if (Number.isFinite(published) && published > 0) return published;
    return parseInt(process.env.MONITOR_PULSE_INTERVAL_MS, 10) || 30000;
}

function pulseStaleMs(pulse) {
    return pulseIntervalMs(pulse) * STALE_FACTOR;
}

function pulseOfflineMs(pulse) {
    return pulseIntervalMs(pulse) * OFFLINE_FACTOR;
}

/**
 * Classify ONE node independently into four orthogonal axes — never one status
 * field standing in for everything:
 *
 *   health : 'online' | 'stale' | 'offline' | 'unknown'
 *   role   : 'active' | 'standby'
 *   gateway: 'connected' | 'disconnected' | 'not_assigned'
 *   status : the single word the UI/overall-summary consumes, derived from the
 *            three above ('operational' | 'degraded' | 'stale' | 'unavailable'
 *            | 'never').
 *
 * Key rules:
 *   • A standby node is ONLINE + HEALTHY with NO gateway and NO shards — its
 *     lack of shards is NOT a fault and must never read as degraded/offline.
 *   • A node whose heartbeat is merely late is STALE, not offline, until the
 *     offline threshold (offlineFactor × its own cadence) is crossed.
 *   • Only the ACTIVE node's gateway matters for service health; an active node
 *     with a down gateway is DEGRADED, not offline.
 */
function classifyNode(pulse, { isActive }) {
    const role = isActive ? 'active' : 'standby';
    if (!pulse) {
        return {
            health: 'unknown', role, status: 'never',
            gateway: 'not_assigned', shardIds: [],
            detail: { reason: 'no_pulse' },
        };
    }

    const staleMs = pulseStaleMs(pulse);
    const offlineMs = pulseOfflineMs(pulse);
    const ageMs = pulse.ageMs;

    const base = {
        role,
        gatewayConnected: !!pulse.gatewayConnected,
        gatewayReady: !!pulse.gatewayReady,
        shardsTotal: pulse.shardsTotal || 0,
        shardsReady: pulse.shardsReady || 0,
        shardsActive: pulse.shardsActive || 0,
        shardIds: Array.isArray(pulse.shardIds) ? pulse.shardIds : [],
        processHealth: pulse.processHealth || 'unknown',
        pid: pulse.pid != null ? pulse.pid : null,
        startedAt: pulse.startedAt || null,
        ageMs: ageMs == null ? null : ageMs,
        nodeName: pulse.nodeName,
    };

    // Gateway axis — a standby that owns no shards is 'not_assigned', not
    // 'disconnected'. Only a node that has shards (or is the active node)
    // reports a real connection state.
    const hasShards = (pulse.shardsTotal || 0) > 0;
    let gateway;
    if (pulse.gatewayReady) gateway = 'connected';
    else if (pulse.gatewayConnected) gateway = 'connected';
    else if (isActive || hasShards) gateway = 'disconnected';
    else gateway = 'not_assigned';

    // Health axis — freshness first (a stale node's other fields are meaningless).
    if (ageMs == null || ageMs > offlineMs) {
        return { ...base, health: 'offline', gateway, status: 'unavailable', detail: { reason: 'offline', ageMs, offlineMs } };
    }
    if (ageMs > staleMs) {
        return { ...base, health: 'stale', gateway, status: 'stale', detail: { reason: 'stale', ageMs, staleMs } };
    }

    const proc = pulse.processHealth;
    if (proc === 'dead' || proc === 'stopped') {
        return { ...base, health: 'offline', gateway, status: 'unavailable', detail: { reason: 'process_' + proc } };
    }

    // Online + fresh. Only the ACTIVE node's gateway affects service health.
    if (isActive && !pulse.gatewayReady) {
        return {
            ...base, health: 'online', gateway, status: 'degraded',
            detail: { reason: 'gateway_not_ready', gatewayConnected: !!pulse.gatewayConnected },
        };
    }
    return { ...base, health: 'online', gateway, status: 'operational', detail: {} };
}

/**
 * Stateless evaluation: given the node pulses + the FAILOVER lease holder,
 * compute every component's status. Pure — no DB/network — so it is directly
 * unit-testable (and the tick path feeds it the same data).
 *
 * `lease` is the bot_failover_lock row ({ nodeName, role }), NOT the monitoring
 * worker lease. The active node is the one holding the Discord connection.
 */
function evaluateState(pulses, lease) {
    const pulsesArr = Array.isArray(pulses) ? pulses : [];
    // Accept either the failover-lock shape ({ nodeName, role }) or the legacy
    // ({ holder }) shape so older callers/tests keep working.
    const holderNode = (lease && (lease.nodeName || lease.holder)) || null;

    let holderPulse = null;
    if (holderNode) holderPulse = pulsesArr.find(p => p.nodeName === holderNode) || null;
    const activeRole = holderPulse ? holderPulse.role : ((lease && lease.role) || null);

    // One pulse per role. If a role has several pulses (a stale row from a
    // renamed node), prefer the ACTIVE node's pulse, then the freshest one, so
    // a node never disappears because a duplicate row shadowed it.
    const byRole = { sn1: null, sn2: null, sn3: null };
    for (const p of pulsesArr) {
        if (!p || !(p.role in byRole)) continue;
        const cur = byRole[p.role];
        if (!cur) { byRole[p.role] = p; continue; }
        const pActive = p.nodeName === holderNode;
        const curActive = cur.nodeName === holderNode;
        if (pActive && !curActive) { byRole[p.role] = p; continue; }
        if (pActive === curActive && (p.ageMs ?? Infinity) < (cur.ageMs ?? Infinity)) byRole[p.role] = p;
    }

    // ── node classifications ──────────────────────────────────────────────
    const nodes = {};
    let anyNodeOnline = false;
    let anyNodeEverReported = false;
    let activeNodeOperational = false;
    let activeNodeSeen = false;
    for (const role of ['sn1', 'sn2', 'sn3']) {
        const p = byRole[role];
        const isActive = Boolean(p) && p.nodeName === holderNode;
        const cls = classifyNode(p, { isActive });
        nodes[role] = cls;
        if (p) anyNodeEverReported = true;
        if (cls.health === 'online') anyNodeOnline = true;
        if (isActive) { activeNodeSeen = true; activeNodeOperational = cls.status === 'operational'; }
    }

    // ── gateway (from the active node's pulse) ───────────────────────────
    let gateway = { status: 'never', detail: { reason: 'no_active_node' } };
    if (holderPulse) {
        if (holderPulse.gatewayReady) gateway = { status: 'operational', detail: { shardsReady: holderPulse.shardsReady } };
        else if (holderPulse.gatewayConnected) gateway = { status: 'degraded', detail: { reason: 'connecting_or_reconnecting' } };
        else gateway = { status: 'unavailable', detail: { reason: 'disconnected' } };
    }

    // ── bot ──────────────────────────────────────────────────────────────
    // Bot health = is the ACTIVE node (the one serving Discord) healthy? A
    // standby node being down is a REDUNDANCY issue, not a service outage.
    let bot;
    if (!anyNodeEverReported) {
        bot = { status: 'never', detail: { reason: 'no_nodes_reported' } };
    } else if (!activeNodeSeen) {
        // No node holds the Discord lease: either the fleet is mid-failover or
        // every node is down. Distinguish via whether ANY node is online.
        bot = anyNodeOnline
            ? { status: 'degraded', detail: { reason: 'no_active_node' } }
            : { status: 'unavailable', detail: { reason: 'all_nodes_down' } };
    } else if (activeNodeOperational) {
        bot = { status: 'operational', detail: {} };
    } else {
        const activeCls = nodes[activeRole] || null;
        const reason = activeCls && activeCls.health !== 'online'
            ? 'active_node_' + activeCls.health
            : 'gateway:' + gateway.status;
        bot = { status: 'degraded', detail: { reason } };
    }

    return {
        nodes,
        gateway,
        bot,
        lease: holderNode,
        activeRole,
    };
}

async function evaluate() {
    const [pulses, lease] = await Promise.all([
        monitorDb.getNodePulses(),
        monitorDb.getFailoverLock().catch(() => ({ nodeName: null, role: null })),
    ]);
    const state = evaluateState(pulses, lease);
    const { nodes, gateway, bot } = state;

    // ── website + api + db ───────────────────────────────────────────────
    const website = await httpCheck(BASE_URL ? BASE_URL + '/' : null);
    const api = await httpCheck(BASE_URL ? BASE_URL + '/api/status/ping' : (process.env.MONITOR_API_URL || null));
    const db = await dbCheck();

    const components = {
        bot,
        website: { status: website.status, detail: website.detail },
        api: { status: api.status, detail: api.detail },
        db: { status: db.status, detail: db.detail },
        gateway,
        sn1: nodes.sn1, sn2: nodes.sn2, sn3: nodes.sn3,
    };

    return { components, snapshot: state };
}

// ── Observation + incident application ───────────────────────────────────────

// Consecutive operational evaluations per component. An incident is only
// resolved after RECOVERY_CONFIRMATIONS in a row, so a node that flaps
// (operational → unavailable → operational) does not resolve-and-recreate an
// incident every tick.
const recoveryStreak = new Map();

async function apply(components, monitor = monitorDb) {
    // Load open incidents once (restart-safe duplicate prevention).
    const openIncidents = await monitor.getOpenIncidents();
    const openByComponent = new Map();
    for (const inc of openIncidents) openByComponent.set(inc.component, inc);

    for (const [key, val] of Object.entries(components)) {
        const status = val.status;
        // Never fabricate data: 'never' = no pulse yet, 'no_data' = the check
        // could not run (e.g. the website/API URL is not configured). Both must
        // be excluded from observations so they are NOT counted as monitored
        // (which previously produced a bogus "100% uptime" on a NO DATA card).
        if (status === 'never' || status === 'no_data') continue;
        await monitor.insertObservation(key, status, val.detail || null);

        const open = openByComponent.get(key);

        // STALE means "heartbeat late / checking" — not a confirmed outage. We
        // record the observation but neither open a new incident nor resolve an
        // existing one (the node may still be down; we just don't know yet).
        if (status === 'stale') { recoveryStreak.delete(key); continue; }

        if (status === 'operational') {
            if (!open) { recoveryStreak.delete(key); continue; }
            const streak = (recoveryStreak.get(key) || 0) + 1;
            recoveryStreak.set(key, streak);
            if (streak >= RECOVERY_CONFIRMATIONS) {
                await monitor.resolveIncident(open.id);
                recoveryStreak.delete(key);
                openByComponent.delete(key);
                log(`Resolved incident #${open.id} (${COMPONENT_LABELS[key] || key}) after ${streak} healthy checks`);
            }
            continue;
        }

        // degraded / unavailable → unhealthy. Reset the recovery streak.
        recoveryStreak.delete(key);
        if (!open) {
            const title = incidentTitle(key, status, val);
            const severity = incidentSeverity(key, status, val);
            const created = await monitor.createIncident({
                component: key,
                title,
                description: incidentDescription(key, status, val),
                severity,
                status: 'investigating',
                createdBy: 'system',
            });
            if (created) log(`Opened incident #${created.id} — ${title}`);
            if (created) openByComponent.set(key, created);
        }
    }
}

// A standby node going down is a REDUNDANCY issue (failover capacity reduced),
// never a service outage — the active node is still serving Discord. Label it
// accordingly so the incident history is honest.
function isStandbyNode(component, val) {
    return (component === 'sn2' || component === 'sn3') && val && val.role === 'standby';
}

function incidentTitle(component, status, val = {}) {
    const label = COMPONENT_LABELS[component] || component;
    if (isStandbyNode(component, val)) {
        return status === 'degraded'
            ? `${label} (standby) degraded — failover capacity reduced`
            : `${label} (standby) offline — failover capacity reduced`;
    }
    if (status === 'degraded') return `Degraded performance on ${label}`;
    return `${label} down`;
}

function incidentDescription(component, status, val = {}) {
    const label = COMPONENT_LABELS[component] || component;
    if (isStandbyNode(component, val)) {
        return `${label} is not reporting. PrimeBot's active node is unaffected, but failover redundancy is reduced until this node recovers.`;
    }
    return status === 'degraded'
        ? `${label} is experiencing degraded performance.`
        : `${label} is currently unavailable.`;
}

function incidentSeverity(component, status, val = {}) {
    if (isStandbyNode(component, val)) return 'minor';
    if (status === 'degraded') return 'minor';
    return COMPONENT_SEVERITY[component] || 'minor';
}

// ── Restart detection ────────────────────────────────────────────────────────
// A node has restarted when its process `startedAt` is NEWER than the last
// baseline we recorded for that node (and we had a baseline). Best-effort but
// reliable while a worker is running (the common operational window); a worker
// crash re-baselines on its next tick.
const restartBaselines = new Map(); // nodeName -> startedAt (ms)

function detectRestart(nodeName, startedAt, prevStartedAt) {
    if (!startedAt || !prevStartedAt) return false;
    return startedAt.getTime() > prevStartedAt.getTime();
}

async function applyRestartDetection(pulses) {
    for (const p of pulses || []) {
        const started = p.startedAt ? new Date(p.startedAt) : null;
        if (!started) continue;
        const prev = restartBaselines.get(p.nodeName);
        if (prev) {
            if (detectRestart(p.nodeName, started, prev)) {
                await monitorDb.recordNodeRestart(p.nodeName, p.role, p.pid, { gatewayReady: p.gatewayReady });
                log(`Detected restart of node ${p.nodeName} (${p.role})`);
            }
        }
        restartBaselines.set(p.nodeName, started);
    }
}

// ── Worker loop ──────────────────────────────────────────────────────────────

function startWorker() {
    if (!ENABLED) { log('disabled via STATUS_MONITOR_ENABLED=false'); return; }
    if (timer) return;
    log(`Starting status monitor worker (${INTERVAL_MS}ms, lease TTL ${WORKER_TTL_S}s)`);

    const loop = async () => {
        if (running) { reschedule(); return; }
        running = true;
        try {
            const held = await monitorDb.acquireWorkerLease(WORKER_ID, WORKER_TTL_S);
            if (!held) { reschedule(); return; } // another node is the worker
            const pulses = await monitorDb.getNodePulses();
            const lock = await monitorDb.getFailoverLock().catch(() => ({ nodeName: null, role: null }));
            const state = evaluateState(pulses, lock);
            const { nodes, gateway, bot } = state;
            const website = await httpCheck(BASE_URL ? BASE_URL + '/' : null);
            const api = await httpCheck(BASE_URL ? BASE_URL + '/api/status/ping' : (process.env.MONITOR_API_URL || null));
            const db = await dbCheck();
            const components = {
                bot,
                website: { status: website.status, detail: website.detail },
                api: { status: api.status, detail: api.detail },
                db: { status: db.status, detail: db.detail },
                gateway,
                sn1: nodes.sn1, sn2: nodes.sn2, sn3: nodes.sn3,
            };
            await apply(components);
            await applyRestartDetection(pulses);
            await monitorDb.rollDaily();
            await monitorDb.pruneObservations(OBSERVATION_RETENTION_DAYS);
            await monitorDb.refreshWorkerLease(WORKER_ID, WORKER_TTL_S);
        } catch (err) {
            console.warn('[STATUS] worker tick error:', err.message);
        } finally {
            running = false;
            reschedule();
        }
    };

    const reschedule = () => {
        if (!timer) return;
        timer = setTimeout(loop, idleBackoffMs());
        timer.unref?.();
    };

    timer = setTimeout(loop, 3000);
    timer.unref?.();
}

function stopWorker() {
    if (timer) { clearTimeout(timer); timer = null; }
    running = false;
}

module.exports = {
    startWorker, stopWorker, evaluate, evaluateState, apply, applyRestartDetection,
    pulseStaleMs, pulseOfflineMs, pulseIntervalMs, classifyNode, detectRestart,
    incidentTitle, incidentDescription, incidentSeverity, isStandbyNode,
    STALE_FACTOR, OFFLINE_FACTOR, RECOVERY_CONFIRMATIONS, WORKER_ID,
};