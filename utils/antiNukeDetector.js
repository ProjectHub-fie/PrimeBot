/**
 * Anti-Nuke — bounded sliding-window burst detector.
 *
 * Thresholds are "N actions within S seconds, per guild, per action, per
 * executor". Windows are held in memory only (they are short-lived and would be
 * wasteful to persist); the persistent cross-node record is the incident ledger
 * the manager writes when a threshold actually trips.
 *
 * Memory is the constraint this module is written around, because PrimeBot runs
 * on resource-limited hosting and must not grow without bound while it is
 * exposed to arbitrary Discord traffic:
 *
 *   • Each window keeps at most `maxEntriesPerWindow` timestamps (a flood of
 *     10,000 events still costs 200 numbers, not 10,000).
 *   • The number of live windows is capped at `maxWindows`; when the cap is hit
 *     the oldest window is evicted.
 *   • Windows older than their own span are dropped on the periodic prune, and
 *     the prune itself is throttled so it is not a per-event cost.
 *
 * Everything is deterministic given a clock, so the tests drive it directly.
 */

const DEFAULT_MAX_WINDOWS = 4000;
const DEFAULT_MAX_ENTRIES_PER_WINDOW = 200;
const PRUNE_INTERVAL_MS = 30000;

/** A single (guild, action, executor) sliding window of timestamps. */
class SlidingWindow {
    constructor({ seconds, maxEntries = DEFAULT_MAX_ENTRIES_PER_WINDOW } = {}) {
        this.windowMs = Math.max(1, Number(seconds) || 10) * 1000;
        this.maxEntries = maxEntries;
        this.timestamps = [];
        this.lastSeen = Date.now();
    }

    /** Record one action; returns the number of actions inside the window. */
    add(ts = Date.now()) {
        this.timestamps.push(ts);
        this.lastSeen = ts;
        // Bound the array: keep the most recent `maxEntries` only. The oldest
        // entries are the ones that would expire first anyway.
        if (this.timestamps.length > this.maxEntries) {
            this.timestamps.splice(0, this.timestamps.length - this.maxEntries);
        }
        return this.count(ts);
    }

    /** Number of actions inside the window at `now`. */
    count(now = Date.now()) {
        const cutoff = now - this.windowMs;
        // Trim from the front (timestamps are append-ordered).
        let i = 0;
        while (i < this.timestamps.length && this.timestamps[i] < cutoff) i++;
        if (i > 0) this.timestamps.splice(0, i);
        return this.timestamps.length;
    }

    /** True when nothing is left inside the window (safe to drop). */
    isExpired(now = Date.now()) {
        return this.timestamps.length === 0 || this.lastSeen < now - this.windowMs;
    }
}

class AntiNukeDetector {
    constructor({ maxWindows = DEFAULT_MAX_WINDOWS, maxEntriesPerWindow = DEFAULT_MAX_ENTRIES_PER_WINDOW } = {}) {
        this.windows = new Map();      // `${guildId}|${actionKey}|${executorId}` → SlidingWindow
        this.cooldowns = new Map();    // `${guildId}|${actionKey}` → expiresAt
        this.maxWindows = maxWindows;
        this.maxEntriesPerWindow = maxEntriesPerWindow;
        this._lastPrune = 0;
    }

    _key(guildId, actionKey, executorId) {
        return `${guildId}|${actionKey}|${executorId}`;
    }

    /**
     * Record an action and report whether it tripped the threshold.
     *
     * @param {object} p
     * @param {string} p.guildId
     * @param {string} p.actionKey
     * @param {string} p.executorId
     * @param {number} p.threshold   actions required within the window
     * @param {number} p.seconds     window length
     * @param {number} [p.ts]        event time (defaults to now)
     * @returns {{ count:number, tripped:boolean, threshold:number, seconds:number }}
     */
    record({ guildId, actionKey, executorId, threshold, seconds, ts = Date.now() }) {
        if (!guildId || !actionKey || !executorId) {
            return { count: 0, tripped: false, threshold, seconds };
        }
        this._maybePrune(ts);
        const key = this._key(guildId, actionKey, executorId);
        let win = this.windows.get(key);
        if (!win || win.windowMs !== Math.max(1, seconds) * 1000) {
            // A changed threshold window replaces the old one (config edit).
            win = new SlidingWindow({ seconds, maxEntries: this.maxEntriesPerWindow });
            this._evictIfNeeded(ts);
            this.windows.set(key, win);
        }
        const count = win.add(ts);
        return {
            count,
            tripped: count >= Math.max(1, Number(threshold) || 1),
            threshold: Math.max(1, Number(threshold) || 1),
            seconds,
        };
    }

    /** Current count for a window without recording (used by tests/diagnostics). */
    countFor(guildId, actionKey, executorId, now = Date.now()) {
        const win = this.windows.get(this._key(guildId, actionKey, executorId));
        return win ? win.count(now) : 0;
    }

    /**
     * Response cooldown. A guild+action that just triggered a response will not
     * trigger another until the cooldown elapses, so a sustained attack does not
     * produce a flood of identical alerts and containment attempts.
     *
     * @returns {boolean} true when the caller may respond
     */
    tryConsumeCooldown(guildId, actionKey, cooldownSeconds, now = Date.now()) {
        const secs = Math.max(0, Number(cooldownSeconds) || 0);
        if (secs === 0) return true;
        const key = `${guildId}|${actionKey}`;
        const expiresAt = this.cooldowns.get(key);
        if (expiresAt && now < expiresAt) return false;
        this.cooldowns.set(key, now + secs * 1000);
        return true;
    }

    /** Clear all state for a guild (config reset / guild removed). */
    clearGuild(guildId) {
        const prefix = `${guildId}|`;
        for (const key of this.windows.keys()) {
            if (key.startsWith(prefix)) this.windows.delete(key);
        }
        for (const key of this.cooldowns.keys()) {
            if (key.startsWith(prefix)) this.cooldowns.delete(key);
        }
    }

    /** Drop expired windows + cooldowns. Throttled so it is not per-event. */
    prune(now = Date.now()) {
        for (const [key, win] of this.windows) {
            if (win.isExpired(now)) this.windows.delete(key);
        }
        for (const [key, expiresAt] of this.cooldowns) {
            if (expiresAt <= now) this.cooldowns.delete(key);
        }
        this._lastPrune = now;
    }

    _maybePrune(now) {
        if (now - this._lastPrune < PRUNE_INTERVAL_MS) return;
        this.prune(now);
    }

    /** Keep the window map bounded by evicting the least-recently-seen entry. */
    _evictIfNeeded(now) {
        if (this.windows.size < this.maxWindows) return;
        let oldestKey = null;
        let oldestTs = Infinity;
        for (const [key, win] of this.windows) {
            if (win.lastSeen < oldestTs) { oldestTs = win.lastSeen; oldestKey = key; }
        }
        if (oldestKey) this.windows.delete(oldestKey);
        this._lastPrune = now;
    }

    /** Diagnostics (bounded sizes) — used by tests and the stats endpoint. */
    stats() {
        return { windows: this.windows.size, cooldowns: this.cooldowns.size, maxWindows: this.maxWindows };
    }
}

module.exports = { AntiNukeDetector, SlidingWindow, DEFAULT_MAX_WINDOWS, DEFAULT_MAX_ENTRIES_PER_WINDOW };
