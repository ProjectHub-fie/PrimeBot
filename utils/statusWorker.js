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

const WORKER_ID = 'status-worker:' + (require('./nodeIdentity').resolveNodeIdentity(process.env).nodeId) + ':' + process.pid;
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
    // The node publishes its own cadence; stale threshold scales with it so a
    // node on a slower cadence is not misjudged as dead. Defaults match the
    // 30s steady pulse.
    const interval = Number(pulse?.resource?.pulseIntervalMs || 30000);
    return interval * STALE_FACTOR;
}

const NODE_ROLES = ['sn1', 'sn2', 'sn3'];

/**
 * Normalize the two lease shapes we accept: the shardnode failover lease
 * (`{ activeNodeId, activeRole }`) and the legacy `{ holder }`. Node
 * classification MUST key off the failover lease (who serves Discord), never
 * the monitoring-worker lease (who runs monitoring) — conflating them is what
 * made a healthy standby look like the active node and therefore degraded.
 */
function normalizeLease(lease) {
    if (!lease) return { activeNodeId: null, activeRole: null };
    const activeNodeId = lease.activeNodeId || lease.holder || null;
    return { activeNodeId, activeRole: lease.activeRole || null };
}

/**
 * Classify ONE node from its pulse and whether it currently holds the failover
 * lease. Pure. Every signal stays independent so a standby is never punished
 * for the things it does not have (a gateway connection, assigned shards).
 *
 * @returns {{
 *   role, nodeId, online, healthy, status, statusReason,
 *   process: {health, uptimeSeconds},
 *   heartbeat: {fresh, ageMs, intervalMs},
 *   gateway: {connected, ready},
 *   shards: {assigned, ready, active, status},
 *   isActive, ageMs
 * }}
 */
function classifyNode(pulse, { isActive = false } = {}) {
    if (!pulse) {
        return {
            role: null,
            nodeId: null,
            online: false,
            healthy: false,
            status: 'never',
            statusReason: 'no_pulse',
            process: { health: 'unknown', uptimeSeconds: null },
            heartbeat: { fresh: false, ageMs: null, intervalMs: null },
            gateway: { connected: false, ready: false },
            shards: { assigned: 0, ready: 0, active: 0, status: 'unknown' },
            isActive: false,
            ageMs: null,
        };
    }

    const intervalMs = Number(pulse.resource?.pulseIntervalMs || 30000);
    const staleMs = pulseStaleMs(pulse);
    const ageMs = pulse.ageMs == null ? null : Number(pulse.ageMs);
    const fresh = ageMs != null && ageMs <= staleMs;

    const processHealth = pulse.processHealth || 'unknown';
    const processDead = processHealth === 'dead' || processHealth === 'stopped';
    const assigned = Number(pulse.shardsTotal) || 0;
    const ready = Number(pulse.shardsReady) || 0;
    const active = Number(pulse.shardsActive) || 0;
    // Zero assigned shards is a NORMAL standby state, never a failure.
    const shardStatus = assigned <= 0 ? 'none' : (ready >= assigned ? 'all' : (ready > 0 ? 'partial' : 'none'));

    const base = {
        role: pulse.role || null,
        nodeId: pulse.nodeId || pulse.nodeName || null,
        isActive,
        ageMs,
        process: { health: processHealth, uptimeSeconds: pulse.resource?.uptimeSeconds ?? null },
        heartbeat: { fresh, ageMs, intervalMs },
        gateway: { connected: !!pulse.gatewayConnected, ready: !!pulse.gatewayReady },
        shards: { assigned, ready, active, status: shardStatus },
    };

    // 1. Stale heartbeat — the process genuinely stopped reporting.
    if (!fresh) {
        return {
            ...base,
            online: false,
            healthy: false,
            status: 'unavailable',
            statusReason: ageMs == null ? 'stale' : 'stale',
        };
    }

    // 2. Fresh heartbeat but the process itself reported dead.
    if (processDead) {
        return { ...base, online: false, healthy: false, status: 'unavailable', statusReason: 'process_' + processHealth };
    }

    // 3. Fresh, live process. The only gateway expectation is on the ACTIVE
    //    node: a standby legitimately has no gateway connection because it is
    //    assigned no shards. Judging a standby by the gateway is the bug that
    //    showed healthy standbys as OFFLINE/DEGRADED.
    if (isActive && !pulse.gatewayReady) {
        return {
            ...base,
            online: true,
            healthy: false,
            status: 'degraded',
            statusReason: 'gateway_not_ready',
        };
    }

    return { ...base, online: true, healthy: true, status: 'operational', statusReason: isActive ? 'serving' : 'standby' };
}

/**
 * Fleet-level counts derived from the per-node classifications. Active/standby
 * come from the failover lease; online/healthy come from each node's own
 * heartbeat + process health.
 */
function summarizeFleet(nodes) {
    const list = NODE_ROLES.map(r => nodes[r]).filter(Boolean);
    const online = list.filter(n => n.online).length;
    const healthy = list.filter(n => n.healthy).length;
    const active = list.filter(n => n.isActive && n.online).length;
    const standby = list.filter(n => n.online && !n.isActive).length;
    const offline = list.filter(n => !n.online && n.status !== 'never').length;
    const unknown = list.filter(n => n.status === 'never').length;
    return {
        total: list.length,
        online,
        healthy,
        active,
        standby,
        offline,
        unknown,
        // Redundancy is intact only when every node is online AND at least one
        // node is serving Discord.
        redundancyIntact: online === list.length && active >= 1,
    };
}

/**
 * Stateless evaluation: given the node pulses + the shardnode FAILOVER lease,
 * compute every component's status. Pure — no DB/network — so it is directly
 * unit-testable (and the tick path feeds it the same data).
 *
 * @param {Array} pulses  per-node pulses from monitorDb.getNodePulses()
 * @param {object} lease  failover lease ({ activeNodeId } or legacy { holder })
 */
function evaluateState(pulses, lease) {
    const pulsesArr = Array.isArray(pulses) ? pulses : [];
    const { activeNodeId } = normalizeLease(lease);

    // Pick the FRESHEST pulse per role. A pre-upgrade deployment left an
    // orphaned row (node_name='local') that shares a role with a live node;
    // without this the stale row could shadow the real one and make a healthy
    // node look offline.
    const byRole = {};
    for (const p of pulsesArr) {
        const role = p.role;
        if (!role) continue;
        const cur = byRole[role];
        if (!cur || (Number(p.ageMs) || Infinity) < (Number(cur.ageMs) || Infinity)) byRole[role] = p;
    }
    for (const role of NODE_ROLES) if (!(role in byRole)) byRole[role] = null;
    const activeRoleFromLease = normalizeLease(lease).activeRole || null;

    const isNodeActive = (p) => {
        if (!p) return false;
        if (activeNodeId && (p.nodeId === activeNodeId || p.nodeName === activeNodeId)) return true;
        if (activeNodeId) return false;
        // No lease id at all: fall back to the lease role, else the highest
        // priority node that reports a ready gateway (so an unleased single
        // node is still treated as the active one).
        if (activeRoleFromLease) return p.role === activeRoleFromLease;
        return false;
    };

    // ── node classifications ─────────────────────────────────────────────
    const nodes = {};
    for (const role of NODE_ROLES) {
        const p = byRole[role];
        const cls = classifyNode(p, { isActive: isNodeActive(p) });
        nodes[role] = { ...cls, role, nodeId: p ? (p.nodeId || p.nodeName) : null, ...nodeDetail(cls) };
    }

    // ── gateway (from the active node's pulse) ───────────────────────────
    const activePulse = pulsesArr.find(p => isNodeActive(p)) || null;
    let gateway;
    if (!activePulse) {
        const anyFreshStandby = NODE_ROLES.some(r => nodes[r].online);
        gateway = anyFreshStandby
            ? { status: 'unavailable', detail: { reason: 'no_active_node' } }
            : { status: 'never', detail: { reason: 'no_active_node' } };
    } else if (activePulse.gatewayReady) {
        gateway = { status: 'operational', detail: { shardsReady: activePulse.shardsReady } };
    } else if (activePulse.gatewayConnected) {
        gateway = { status: 'degraded', detail: { reason: 'connecting_or_reconnecting' } };
    } else {
        gateway = { status: 'unavailable', detail: { reason: 'disconnected' } };
    }

    const fleet = summarizeFleet(nodes);

    // ── bot (overall PrimeBot service availability) ──────────────────────
    // The bot is available when the ACTIVE node's own CLASSIFICATION is
    // operational — i.e. it is online AND serving a ready gateway. Using the
    // classification (not the raw pulse) means a stale active node counts as
    // down even though its last pulse claimed a ready gateway. Standbys alone
    // (no active node) cannot serve, so the bot is degraded — but the nodes
    // themselves stay ONLINE/HEALTHY.
    const activeNodeState = activePulse ? nodes[activePulse.role] : null;
    let bot;
    if (fleet.online === 0 && fleet.unknown === fleet.total) {
        bot = { status: 'never', detail: { reason: 'no_nodes_reported' } };
    } else if (fleet.online === 0) {
        bot = { status: 'unavailable', detail: { reason: 'all_nodes_down' } };
    } else if (!activePulse || !activeNodeState) {
        bot = { status: 'degraded', detail: { reason: 'no_active_node' } };
    } else if (activeNodeState.status === 'operational') {
        bot = { status: 'operational', detail: {} };
    } else if (activeNodeState.status === 'unavailable') {
        // The node holding the lease is down: a real service outage.
        bot = { status: 'unavailable', detail: { reason: 'active_node_down' } };
    } else {
        bot = { status: 'degraded', detail: { reason: 'active_node:' + activeNodeState.statusReason } };
    }

    return {
        nodes,
        fleet,
        gateway,
        bot,
        lease: activeNodeId,
        activeRole: activePulse ? activePulse.role : activeRoleFromLease,
    };
}

/** Human-facing detail for a node classification (kept out of classifyNode so
 *  the pure classifier stays small). */
function nodeDetail(cls) {
    return {
        online: cls.online,
        healthy: cls.healthy,
        statusReason: cls.statusReason,
        detail: {
            reason: cls.statusReason,
            role: cls.isActive ? 'active' : 'standby',
            heartbeatAgeMs: cls.heartbeat.ageMs,
            gateway: cls.gateway,
            shards: cls.shards,
        },
    };
}

async function evaluate() {
    const [pulses, lease] = await Promise.all([
        monitorDb.getNodePulses(),
        monitorDb.getFailoverLease().catch(() => ({ activeNodeId: null })),
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

// Consecutive OPERATIONAL readings required before an open incident is
// resolved. Without this a single flapping sample (one missed heartbeat, one
// 5xx blip) would close and immediately re-open an incident, producing the
// endless "Shard Node 3 down" churn. Recovery must be CONFIRMED, not assumed.
const RECOVERY_CONFIRMATIONS = Math.max(1, parseInt(process.env.STATUS_RECOVERY_CONFIRMATIONS, 10) || 2);
const _recoveryStreak = new Map(); // component -> consecutive operational observations

/**
 * Apply a tick's component statuses: record observations, open/update/resolve
 * incidents. Restart-safe and duplicate-proof:
 *   • one open incident per component is reused (never duplicated);
 *   • a status change on an already-open incident UPDATES it in place;
 *   • resolution requires RECOVERY_CONFIRMATIONS consecutive healthy readings;
 *   • node incidents say whether the failed node was ACTIVE (service impact) or
 *     a STANDBY (redundancy loss) so a node failure is never confused with a
 *     service-wide outage.
 */
async function apply(components, monitor = monitorDb, snapshot = null) {
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
                // Confirm recovery before resolving: require N consecutive
                // healthy readings so a single flapping sample cannot close and
                // immediately re-open an incident.
                const streak = (_recoveryStreak.get(key) || 0) + 1;
                _recoveryStreak.set(key, streak);
                if (streak >= RECOVERY_CONFIRMATIONS) {
                    _recoveryStreak.delete(key);
                    await monitor.resolveIncident(open.id);
                    log(`Resolved incident #${open.id} (${COMPONENT_LABELS[key] || key}) after ${streak} healthy reading(s)`);
                    openByComponent.delete(key);
                } else {
                    log(`Incident #${open.id} (${COMPONENT_LABELS[key] || key}) healthy reading ${streak}/${RECOVERY_CONFIRMATIONS} — awaiting confirmation`);
                }
            } else {
                _recoveryStreak.delete(key);
            }
            continue;
        }

        // Non-operational: reset the recovery streak and open/update an incident.
        _recoveryStreak.delete(key);
        if (!open) {
            const title = incidentTitle(key, status);
            const severity = status === 'unavailable' ? (COMPONENT_SEVERITY[key] || 'minor') : 'minor';
            const created = await monitor.createIncident({
                component: key,
                title,
                description: incidentDescription(key, status, snapshot),
                severity,
                status: 'investigating',
                createdBy: 'system',
            });
            if (created) log(`Opened incident #${created.id} — ${title}`);
            openByComponent.set(key, { id: created?.id, component: key });
        } else if (monitor.updateIncident && typeof open.id === 'number') {
            // The component was already down and its state changed (e.g.
            // degraded → unavailable). Update the existing incident instead of
            // stacking a duplicate.
            const title = incidentTitle(key, status);
            if (open.title !== title || open.severity !== (status === 'unavailable' ? (COMPONENT_SEVERITY[key] || 'minor') : 'minor')) {
                await monitor.updateIncident(open.id, {
                    title,
                    description: incidentDescription(key, status, snapshot),
                    severity: status === 'unavailable' ? (COMPONENT_SEVERITY[key] || 'minor') : 'minor',
                }).catch(() => {});
            }
        }
    }
}

function incidentTitle(component, status) {
    const label = COMPONENT_LABELS[component] || component;
    if (status === 'degraded') return `Degraded performance on ${label}`;
    return `${label} down`;
}

/**
 * A node incident must say whether the node was the ACTIVE node (a real
 * service impact) or a STANDBY (redundancy reduced, no service impact) — that
 * is the difference between a node failure and a service-wide outage.
 */
function incidentDescription(component, status, snapshot) {
    const label = COMPONENT_LABELS[component] || component;
    if (component === 'sn1' || component === 'sn2' || component === 'sn3') {
        const node = snapshot && snapshot.nodes ? snapshot.nodes[component] : null;
        const role = node ? (node.isActive ? 'active' : 'standby') : 'shard';
        if (status === 'degraded') {
            return `${label} (${role}) is reporting degraded health.`;
        }
        if (role === 'active') {
            return `${label} (active node) is not responding — Discord service availability is affected.`;
        }
        return `${label} (standby node) is not responding — redundancy is reduced but Discord service is unaffected.`;
    }
    if (status === 'degraded') return `${label} is experiencing degraded performance.`;
    return `${label} is currently unavailable.`;
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
            // Node classification keys off the SHARDNODE FAILOVER lease (who is
            // serving Discord), never the monitoring-worker lease — otherwise a
            // healthy standby is mistaken for the active node.
            const lease = await monitorDb.getFailoverLease().catch(() => ({ activeNodeId: null }));
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
            await apply(components, monitorDb, state);
            await applyRestartDetection(pulses);
            await monitorDb.pruneStaleNodePulses();
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
    pulseStaleMs, detectRestart, incidentTitle, incidentDescription,
    classifyNode, summarizeFleet, normalizeLease, WORKER_ID,
    RECOVERY_CONFIRMATIONS,
};