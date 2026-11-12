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
const STALE_FACTOR = 3; // miss up to ~2 beats before a node is "unavailable"

const WORKER_ID = 'status-worker:' + process.env.NODE_NAME + ':' + process.pid;
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

function pulseStaleMs(pulse) {
    // The node publishes its own cadence; stale threshold scales with it so an
    // idle node that backs off to 5-minute beats is not misjudged as dead.
    const interval = Number(pulse?.resource?.pulseIntervalMs || 30000);
    return interval * STALE_FACTOR;
}

/**
 * Stateless evaluation: given the node pulses + current worker lease holder,
 * compute every component's status. Pure — no DB/network — so it is directly
 * unit-testable (and the tick path feeds it the same data).
 */
function evaluateState(pulses, lease) {
    const pulsesArr = Array.isArray(pulses) ? pulses : [];
    const holderNode = (lease && lease.holder) || null;

    // The lease holder's node name → its pulse and role.
    let holderPulse = null;
    if (holderNode) holderPulse = pulsesArr.find(p => p.nodeName === holderNode) || null;
    const activeRole = holderPulse ? holderPulse.role : null;
    const byRole = {
        sn1: pulsesArr.find(p => p.role === 'sn1') || null,
        sn2: pulsesArr.find(p => p.role === 'sn2') || null,
        sn3: pulsesArr.find(p => p.role === 'sn3') || null,
    };

    // ── node statuses ─────────────────────────────────────────────────────
    const nodes = {};
    let anyNodeOps = false;
    let anyNodeFresh = false;
    let anyNodeNever = false;
    for (const role of ['sn1', 'sn2', 'sn3']) {
        const p = byRole[role];
        if (!p) { nodes[role] = { status: 'never', detail: { reason: 'no_pulse' } }; anyNodeNever = true; continue; }
        const staleMs = pulseStaleMs(p);
        if (p.ageMs == null || p.ageMs > staleMs) {
            nodes[role] = { status: 'unavailable', detail: { reason: 'stale', ageMs: p.ageMs } };
            continue;
        }
        anyNodeFresh = true;
        const isActive = p.nodeName === holderNode;
        if (p.processHealth === 'dead' || p.processHealth === 'stopped') {
            nodes[role] = { status: 'unavailable', detail: { reason: 'process_' + p.processHealth } };
            continue;
        }
        // Active node must also have a live gateway to be fully operational.
        if (isActive && !p.gatewayReady) {
            nodes[role] = { status: 'degraded', detail: { reason: 'gateway_not_ready', gatewayConnected: p.gatewayConnected } };
            continue;
        }
        nodes[role] = { status: 'operational', detail: { gateway: p.gatewayReady } };
        anyNodeOps = true;
    }

    // ── gateway (from the active/lease-holder node's pulse) ──────────────
    let gateway = { status: 'never', detail: { reason: 'no_active_node' } };
    if (holderPulse) {
        if (holderPulse.gatewayReady) gateway = { status: 'operational', detail: { shardsReady: holderPulse.shardsReady } };
        else if (holderPulse.gatewayConnected) gateway = { status: 'degraded', detail: { reason: 'connecting_or_reconnecting' } };
        else gateway = { status: 'unavailable', detail: { reason: 'disconnected' } };
    }

    // ── bot ──────────────────────────────────────────────────────────────
    let bot;
    if (anyNodeNever && !anyNodeFresh) {
        bot = { status: 'never', detail: { reason: 'no_nodes_reported' } };
    } else if (!anyNodeFresh) {
        bot = { status: 'unavailable', detail: { reason: 'all_nodes_down' } };
    } else if (!anyNodeOps) {
        bot = { status: 'degraded', detail: { reason: 'nodes_running_but_gateway_down' } };
    } else if (gateway.status !== 'operational' && gateway.status !== 'never') {
        bot = { status: 'degraded', detail: { reason: 'gateway:' + gateway.status } };
    } else {
        bot = { status: 'operational', detail: {} };
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
        monitorDb.getWorkerLease().catch(() => ({ holder: null })),
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

async function apply(components, monitor = monitorDb) {
    // Load open incidents once (restart-safe duplicate prevention).
    const openIncidents = await monitor.getOpenIncidents();
    const openByComponent = new Map();
    for (const inc of openIncidents) openByComponent.set(inc.component, inc);

    for (const [key, val] of Object.entries(components)) {
        const status = val.status;
        if (status === 'never') continue; // never fabricate data for unknown state
        await monitor.insertObservation(key, status, val.detail || null);

        const open = openByComponent.get(key);
        if (status === 'operational') {
            if (open) {
                await monitor.resolveIncident(open.id);
                log(`Resolved incident #${open.id} (${COMPONENT_LABELS[key] || key})`);
            }
        } else {
            if (!open) {
                const title = incidentTitle(key, status);
                const severity = COMPONENT_SEVERITY[key] || 'minor';
                const created = await monitor.createIncident({
                    component: key,
                    title,
                    description: status === 'degraded'
                        ? `${COMPONENT_LABELS[key] || key} is experiencing degraded performance.`
                        : `${COMPONENT_LABELS[key] || key} is currently unavailable.`,
                    severity: status === 'unavailable' ? severity : 'minor',
                    status: 'investigating',
                    createdBy: 'system',
                });
                if (created) log(`Opened incident #${created.id} — ${title}`);
                openByComponent.set(key, { id: created?.id, component: key });
            }
        }
    }
}

function incidentTitle(component, status) {
    const label = COMPONENT_LABELS[component] || component;
    if (status === 'degraded') return `Degraded performance on ${label}`;
    return `${label} down`;
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
            const lease = await monitorDb.getWorkerLease().catch(() => ({ holder: null }));
            const state = evaluateState(pulses, lease);
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
    pulseStaleMs, detectRestart, incidentTitle, WORKER_ID,
};