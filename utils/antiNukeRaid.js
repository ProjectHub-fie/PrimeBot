/**
 * Anti-Nuke — Anti-Raid join detector.
 *
 * Discord does not emit audit-log entries for member joins, so join-based
 * attacks cannot ride the `guildAuditLogEntryCreate` pipeline. This detector is
 * fed directly by the `guildMemberAdd` gateway event and keeps an in-memory
 * sliding window of joins per guild. It is the single place that decides
 * whether a burst of joins trips a raid action.
 *
 * Signals (each corresponds to a `NUKE_ACTIONS` entry with `raidSignal`):
 *   • velocity     — more joins than `watched.joinBurst.threshold` in
 *                    `watched.joinBurst.seconds`.
 *   • newAccount   — more joins from accounts younger than `raid.accountAgeMinDays`
 *                    than `watched.newAccountWave.threshold` in
 *                    `watched.newAccountWave.seconds`.
 *   • coordinated  — both signals tripping within one `coordinatedJoin` window
 *                    (a sustained, mixed attack rather than a one-off burst).
 *
 * The detector is pure over its own state: `feed()` takes joins, `evaluate()`
 * returns the tripped actions. It never ban/kicks — the manager decides the
 * response (alerts + optional automatic lockdown when configured).
 */

const { NUKE_ACTIONS, NUKE_ACTION_BY_KEY } = require('./antiNukeRules');

/** Actions that belong to the raid module and carry a raid signal. */
const RAID_ACTIONS = NUKE_ACTIONS.filter(a => a.module === 'raid' && a.raidSignal);

const COORDINATED_WINDOW_MS = 60 * 1000;

function _trimWindow(window, now, windowMs) {
    return window.filter(e => now - e.ts < windowMs);
}

/**
 * Create a fresh raid-window store. `joins` maps guildId → array of
 * `{ ts, userId, accountAgeMs, isNewAccount }`.
 */
function createRaidState() {
    return new Map();
}

/** Prune all windows older than the longest raid window (bounded memory). */
function pruneRaidState(state, now = Date.now()) {
    const maxWindow = Math.max(
        ...RAID_ACTIONS.map(a => ((a.thresholds || {}).seconds) || a.seconds || 60),
        60,
    ) * 1000;
    for (const [guildId, joins] of state) {
        const kept = _trimWindow(joins, now, maxWindow + 1000);
        if (kept.length) state.set(guildId, kept);
        else state.delete(guildId);
    }
    return state;
}

/**
 * Record a member join and return the tripped raid actions (empty array when
 * nothing trips). `settings` is a normalized Anti-Nuke settings object. Returns
 * `[{ action, label, count, threshold, windowSeconds, newAccountCount }]`.
 */
function feedJoin(state, guildId, userId, { accountAgeMs = null, settings, now = Date.now() } = {}) {
    const raid = (settings && settings.raid) || {};
    // A disabled raid guard never accumulates window state.
    if (raid.enabled === false) {
        state.delete(guildId);
        return [];
    }
    const cutoffMs = (raid.accountAgeMinDays || 7) * 24 * 60 * 60 * 1000;
    const isNewAccount = accountAgeMs != null && accountAgeMs < cutoffMs;
    const window = state.get(guildId) || [];
    window.push({ ts: now, userId, accountAgeMs, isNewAccount });
    state.set(guildId, window);
    // Windows are capped per guild so a very large server cannot grow the map
    // unboundedly.
    const cap = 500;
    if (window.length > cap) {
        state.set(guildId, window.slice(-cap));
    }
    return evaluate(state, guildId, { userId, accountAgeMs, settings, now });
}

/**
 * Evaluate the current join window against the configured raid thresholds.
 * Returns the list of tripped raid actions (the same shape as `feedJoin`).
 */
function evaluate(state, guildId, { userId = null, accountAgeMs = null, settings, now = Date.now() } = {}) {
    const s = settings || {};
    const raid = s.raid || {};
    const joined = raid.enabled === false;
    if (joined) return [];
    const watched = s.watched || {};
    const joins = _trimWindow(state.get(guildId) || [], now, COORDINATED_WINDOW_MS);
    // Account-age cutoff for the "new account" signal. The reset join window is
    // only meaningful for the velocity signal; the new-account/vto signals use
    // the same window list.
    const cutoffMs = (raid.accountAgeMinDays || 7) * 24 * 60 * 60 * 1000;
    const tripped = [];

    for (const action of RAID_ACTIONS) {
        const watch = watched[action.key];
        if (!watch || watch.enabled === false) continue;
        const windowMs = (watch.seconds || action.seconds || 60) * 1000;
        // The windows per signal are the same join list — only the filter
        // differs.
        const recent = joins.filter(e => now - e.ts < windowMs);
        const threshold = watch.threshold || action.threshold || 5;
        if (recent.length < threshold) continue;

        switch (action.raidSignal) {
            case 'velocity': {
                // Count unique subscribers in the velocity window.
                tripped.push({
                    action: action.key,
                    label: action.label,
                    count: recent.length,
                    threshold,
                    windowSeconds: watch.seconds || action.seconds || 10,
                    signal: 'velocity',
                    details: `${recent.length} joins in ${windowMs / 1000}s window`,
                });
                break;
            }
            case 'newAccount': {
                const newOnes = recent.filter(e => e.isNewAccount === true).length;
                if (newOnes < threshold) continue;
                tripped.push({
                    action: action.key,
                    label: action.label,
                    count: newOnes,
                    threshold,
                    windowSeconds: watch.seconds || action.seconds || 60,
                    signal: 'newAccount',
                    details: `${newOnes} joins from accounts under ${raid.accountAgeMinDays || 7}d old in ${windowMs / 1000}s`,
                });
                break;
            }
            case 'coordinated': {
                // Both signals tripping at the same time = a coordinated raid.
                const vel = watched.joinBurst;
                const velThreshold = (vel && vel.enabled !== false && (vel.threshold || 5)) || 0;
                const velRecent = joins.length;
                const newCount = recent.filter(e => e.isNewAccount === true).length;
                const acctThreshold = (watched.newAccountWave && watched.newAccountWave.enabled !== false && (watched.newAccountWave.threshold || 5)) || 0;
                if (velThreshold > 0 && acctThreshold > 0
                    && velRecent >= velThreshold && newCount >= acctThreshold) {
                    tripped.push({
                        action: action.key,
                        label: action.label,
                        count: velRecent,
                        threshold,
                        windowSeconds: watch.seconds || action.seconds || 60,
                        signal: 'coordinated',
                        details: `join burst + ${newCount} new accounts in ${windowMs / 1000}s`,
                    });
                }
                continue;
            }
            default:
                break;
        }
    }
    return tripped;
}

/** A single evaluated signal result formatted for the incident ledger. */
function raidIncidentShape(trip, guildId) {
    return {
        guildId: String(guildId),
        action: trip.action,
        module: 'raid',
        severity: NUKE_ACTION_BY_KEY[trip.action] ? NUKE_ACTION_BY_KEY[trip.action].severity : 'high',
        count: trip.count || 1,
        threshold: trip.threshold || 0,
        windowSeconds: trip.windowSeconds || 60,
        attribution: 'raid_detector',
        details: trip.details || (trip.label || trip.action),
    };
}

module.exports = {
    RAID_ACTIONS,
    createRaidState,
    pruneRaidState,
    feedJoin,
    evaluate,
    raidIncidentShape,
};