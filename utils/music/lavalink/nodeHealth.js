/**
 * Lavalink node health tracking + selection.
 *
 * Keeps one health record per configured node so the engine can:
 *   • tell a healthy node from one that is down (availability detection),
 *   • pick a node that is actually usable instead of blindly taking the first,
 *   • back off exponentially (with jitter) instead of hammering a dead node,
 *   • stop handing new sessions to a node that keeps failing (cooldown),
 *   • route new sessions to a healthy alternative when one dies,
 *   • report diagnostics that name the affected node (never its credentials).
 *
 * This module is pure: it never opens a socket. Shoukaku owns the actual
 * connection; the manager feeds every lifecycle event in here.
 *
 * Reconnect scheduling is tracked per node but ENFORCED by the manager, which
 * owns the single retry timer (no timer per node — a timer storm is what makes
 * a flapping node keep a shared host busy).
 */

const HEALTH_STATES = {
    CONNECTING: 'connecting',
    CONNECTED: 'connected',
    RECONNECTING: 'reconnecting',
    DISCONNECTED: 'disconnected',
    FAILED: 'failed',
};

/** Bounded exponential backoff with jitter: base * 2^n, capped, ±20% jitter. */
function computeBackoff(attempt, { baseMs = 2000, maxMs = 120000, jitter = 0.2 } = {}) {
    const n = Math.max(0, Math.min(Number(attempt) || 0, 16));
    const raw = Math.min(maxMs, baseMs * Math.pow(2, n));
    if (!jitter) return Math.round(raw);
    // Deterministic spread is not required; a random jitter avoids a thundering
    // herd when several nodes die together.
    const delta = raw * jitter;
    return Math.round(Math.max(0, raw - delta + Math.random() * delta * 2));
}

class NodeHealthTracker {
    /**
     * @param {Array<{name:string}>} nodes configured nodes
     * @param {object} [opts]
     * @param {number} [opts.maxReconnectAttempts] attempts before a node is parked as failed
     * @param {number} [opts.cooldownMs] how long a failed node is skipped
     * @param {number} [opts.baseBackoffMs]
     * @param {number} [opts.maxBackoffMs]
     */
    constructor(nodes = [], opts = {}) {
        this.opts = {
            maxReconnectAttempts: Math.max(1, parseInt(opts.maxReconnectAttempts, 10) || 5),
            cooldownMs: Math.max(1000, parseInt(opts.cooldownMs, 10) || 60000),
            baseBackoffMs: Math.max(250, parseInt(opts.baseBackoffMs, 10) || 2000),
            maxBackoffMs: Math.max(1000, parseInt(opts.maxBackoffMs, 10) || 120000),
        };
        /** @type {Map<string, object>} */
        this.records = new Map();
        for (const node of nodes) this.ensure(node.name);
    }

    /** Create (or return) the health record for a node. */
    ensure(name) {
        const key = String(name);
        let rec = this.records.get(key);
        if (!rec) {
            rec = {
                name: key,
                state: HEALTH_STATES.CONNECTING,
                reconnectAttempts: 0,
                nextRetryAt: 0,
                lastReadyAt: 0,
                lastCloseAt: 0,
                lastErrorAt: 0,
                lastError: null,
                closeCode: null,
                closeReason: null,
                players: 0,
            };
            this.records.set(key, rec);
        }
        return rec;
    }

    get(name) { return this.records.get(String(name)) || null; }

    remove(name) { this.records.delete(String(name)); }

    /** A node became ready (connected + authenticated). Resets the backoff. */
    markReady(name) {
        const rec = this.ensure(name);
        rec.state = HEALTH_STATES.CONNECTED;
        rec.reconnectAttempts = 0;
        rec.nextRetryAt = 0;
        rec.lastReadyAt = Date.now();
        rec.lastError = null;
        rec.closeCode = null;
        rec.closeReason = null;
        return rec;
    }

    /** A connection attempt failed or the node reported an error. */
    markError(name, error) {
        const rec = this.ensure(name);
        rec.lastErrorAt = Date.now();
        rec.lastError = error ? String(error.message || error).slice(0, 500) : 'unknown error';
        if (rec.state !== HEALTH_STATES.CONNECTED) rec.state = HEALTH_STATES.FAILED;
        return rec;
    }

    /** The socket closed. Schedules the next retry (bounded) or parks the node. */
    markClose(name, code, reason) {
        const rec = this.ensure(name);
        rec.state = HEALTH_STATES.DISCONNECTED;
        rec.lastCloseAt = Date.now();
        rec.closeCode = code != null ? code : null;
        rec.closeReason = reason ? String(reason).slice(0, 300) : null;
        return rec;
    }

    /** The manager is about to retry the node; count it and set the deadline. */
    markReconnecting(name) {
        const rec = this.ensure(name);
        rec.reconnectAttempts += 1;
        const exhausted = rec.reconnectAttempts > this.opts.maxReconnectAttempts;
        rec.state = exhausted ? HEALTH_STATES.FAILED : HEALTH_STATES.RECONNECTING;
        const delay = exhausted
            ? this.opts.cooldownMs
            : computeBackoff(rec.reconnectAttempts - 1, {
                baseMs: this.opts.baseBackoffMs,
                maxMs: this.opts.maxBackoffMs,
            });
        rec.nextRetryAt = Date.now() + delay;
        return { rec, exhausted, delay };
    }

    /** Is the node currently usable for new players? */
    isHealthy(name, now = Date.now()) {
        const rec = this.records.get(String(name));
        if (!rec) return false;
        if (rec.state === HEALTH_STATES.CONNECTED) return true;
        // A node parked as failed becomes eligible again once its cooldown lapses.
        if (rec.state === HEALTH_STATES.FAILED && rec.nextRetryAt && now >= rec.nextRetryAt) return true;
        return false;
    }

    /**
     * Is the node worth ATTEMPTING right now? A node that is still connecting (or
     * waiting out a retry) counts, because Shoukaku owns the connection and will
     * fail fast if it cannot complete. Only a parked/failed node is refused.
     */
    isAvailable(name, now = Date.now()) {
        const rec = this.records.get(String(name));
        if (!rec) return false;
        if (rec.state === HEALTH_STATES.CONNECTED) return true;
        if (rec.state === HEALTH_STATES.CONNECTING || rec.state === HEALTH_STATES.RECONNECTING) return true;
        if (rec.state === HEALTH_STATES.FAILED) return !!(rec.nextRetryAt && now >= rec.nextRetryAt);
        return false;
    }

    /** Any node worth attempting? */
    hasAvailable(now = Date.now()) {
        return [...this.records.keys()].some(n => this.isAvailable(n, now));
    }

    /** Healthy node names, in configured order. */
    healthyNames(now = Date.now()) {
        return [...this.records.keys()].filter(n => this.isHealthy(n, now));
    }

    /**
     * Choose a node for a new player.
     *
     * Prefers a healthy node with the fewest players (a crude but effective load
     * balance for the 5–20 session target). While nodes are still connecting the
     * least-loaded one is returned so the first join is not delayed; `null` means
     * nothing is even worth attempting, and the caller must fail fast with a
     * clear reason instead of creating a player against a dead node.
     */
    selectNode(now = Date.now()) {
        const healthy = this.healthyNames(now)
            .map(n => this.records.get(n))
            .sort((a, b) => (a.players - b.players) || (a.name < b.name ? -1 : 1));
        if (healthy.length) return healthy[0].name;
        // Nothing confirmed healthy yet — pick the least-loaded node that is at
        // least worth attempting (connecting/reconnecting/cooldown-elapsed).
        const available = [...this.records.values()]
            .filter(rec => this.isAvailable(rec.name, now))
            .sort((a, b) => (a.players - b.players) || (a.name < b.name ? -1 : 1));
        return available.length ? available[0].name : null;
    }

    /** Update the player count attributed to a node (metrics + load balancing). */
    setPlayers(name, count) {
        const rec = this.ensure(name);
        rec.players = Math.max(0, Number(count) || 0);
        return rec;
    }

    incrementPlayers(name, by = 1) {
        const rec = this.ensure(name);
        rec.players = Math.max(0, rec.players + by);
        return rec;
    }

    /** Snapshot for logs / the dashboard. Never contains credentials. */
    describe(now = Date.now()) {
        return [...this.records.values()].map(rec => ({
            name: rec.name,
            state: rec.state,
            healthy: this.isHealthy(rec.name, now),
            players: rec.players,
            reconnectAttempts: rec.reconnectAttempts,
            nextRetryAt: rec.nextRetryAt || null,
            lastReadyAt: rec.lastReadyAt || null,
            lastCloseAt: rec.lastCloseAt || null,
            lastError: rec.lastError,
            closeCode: rec.closeCode,
            closeReason: rec.closeReason,
        }));
    }
}

module.exports = { HEALTH_STATES, computeBackoff, NodeHealthTracker };
