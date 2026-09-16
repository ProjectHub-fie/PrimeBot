/**
 * Adaptive, jittered polling for settings caches.
 *
 * The bot runs as a separate process from the dashboard, so the only way it
 * learns about dashboard writes is by re-reading the shared tables. Polling
 * those tables on a fixed short interval (the previous 5s + 15s/30s pair run by
 * ~10 managers) keeps the Neon compute endpoint permanently awake: a suspended
 * Neon database is effectively free, a continuously-queried one is billed for
 * every second it is up.
 *
 * A poller therefore backs off while a table is quiet. Each tick runs `task`,
 * which must return `true` when it observed a change. On a change the interval
 * snaps back to the fast interval (so an admin editing settings sees them apply
 * within a few seconds); after `quietTicks` consecutive quiet ticks it grows
 * geometrically up to `maxMs`. Jitter avoids every manager waking at once.
 *
 * All timers are unref'd so they never keep the process alive.
 */

function envMs(name, fallback) {
    const raw = parseInt(process.env[name], 10);
    return Number.isFinite(raw) && raw > 0 ? raw : fallback;
}

// Fast interval: how soon after a change we re-check (and how long a poll cycle
// takes on a busy table). Max interval: the idle floor cost of one manager.
function resolveConfig(overrides = {}) {
    const initialMs =
        overrides.initialMs ||
        envMs('SETTINGS_POLL_INTERVAL_MS', envMs('SETTINGS_REFRESH_INTERVAL_MS', 30000));
    const maxMs =
        overrides.maxMs ||
        envMs('SETTINGS_POLL_MAX_INTERVAL_MS', envMs('SETTINGS_RELOAD_INTERVAL_MS', 600000));
    return {
        initialMs: Math.max(5000, initialMs),
        maxMs: Math.max(initialMs, maxMs),
        factor: overrides.factor || 2,
        // Number of quiet ticks before the interval starts doubling.
        quietTicks: overrides.quietTicks ?? 2,
        jitterRatio: overrides.jitterRatio ?? 0.1,
    };
}

class AdaptivePoller {
    /**
     * @param {object}   opts
     * @param {string}   opts.name     label used in error logs
     * @param {Function} opts.task     async () => boolean (true = changed)
     * @param {number}   [opts.initialMs]
     * @param {number}   [opts.maxMs]
     * @param {Function} [opts.onError]
     */
    constructor({ name, task, onError, ...overrides }) {
        this.name = name;
        this.task = task;
        this.onError = onError || ((err) => console.error(`[${this.name}] poll failed:`, err.message));
        this.cfg = resolveConfig(overrides);
        this.currentMs = this.cfg.initialMs;
        this.quietStreak = 0;
        this._timer = null;
        this._running = false;
        this._stopped = false;
    }

    start() {
        if (this._timer || this._stopped) return this;
        this._schedule(this.cfg.initialMs);
        return this;
    }

    stop() {
        this._stopped = true;
        if (this._timer) {
            clearTimeout(this._timer);
            this._timer = null;
        }
    }

    /** Exposed for tests / diagnostics. */
    get intervalMs() {
        return this.currentMs;
    }

    /**
     * Signal external activity (e.g. a new poll or giveaway was created). Resets
     * the backoff to the fast interval so the very next check happens promptly,
     * without the caller having to touch the timer.
     */
    notifyActivity() {
        this.quietStreak = 0;
        this.currentMs = this.cfg.initialMs;
        if (this._stopped) return this;
        if (this._timer) clearTimeout(this._timer);
        this._schedule(this.cfg.initialMs);
        return this;
    }

    _jitter(ms) {
        const delta = ms * this.cfg.jitterRatio;
        return Math.max(1000, Math.round(ms + (Math.random() * 2 - 1) * delta));
    }

    _schedule(ms) {
        if (this._stopped) return;
        this._timer = setTimeout(() => this._run(), this._jitter(ms));
        this._timer.unref?.();
    }

    async _run() {
        if (this._stopped || this._running) return;
        this._running = true;
        let changed = false;
        try {
            changed = await this.task();
        } catch (err) {
            // A transient DB error must not stretch the backoff — retry at the
            // fast interval so we recover as soon as the DB is reachable.
            this.onError(err);
            changed = true;
        } finally {
            this._running = false;
        }

        if (changed) {
            this.quietStreak = 0;
            this.currentMs = this.cfg.initialMs;
        } else {
            this.quietStreak++;
            if (this.quietStreak > this.cfg.quietTicks) {
                this.currentMs = Math.min(this.cfg.maxMs, Math.round(this.currentMs * this.cfg.factor));
            }
        }
        this._schedule(this.currentMs);
    }
}

module.exports = { AdaptivePoller, resolveConfig };
