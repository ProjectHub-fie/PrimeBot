/**
 * One coalesced timer for every in-memory settings cache.
 *
 * PrimeBot caches every guild configuration in memory and re-reads the shared
 * tables so dashboard saves reach the bot without a restart. That refresh used
 * to be one `AdaptivePoller` per manager (~15 of them), each with its own
 * independently jittered timer. Individually each backed off to 30 minutes, but
 * in aggregate they still woke the database every couple of minutes — which is
 * the whole problem on Neon, because a compute endpoint only suspends after a
 * period of inactivity (5 minutes by default). Fifteen unsynchronized timers can
 * never let that window elapse, so the endpoint stayed billed around the clock
 * even while the bot sat completely idle.
 *
 * This scheduler runs every registered refresh task off a SINGLE timer, so a
 * quiet deployment performs one wake-up per idle interval instead of ~15 spread
 * across it. All tasks that are due run together in that one window and the
 * compute endpoint then gets to suspend again.
 *
 * Semantics match the previous `AdaptivePoller`: a task returns `true` when it
 * observed a change. Any change (or error) resets the cadence to the fast
 * interval; after `quietTicks` all-quiet ticks the interval grows geometrically
 * to `maxMs`. `notifyActivity()` resets the shared cadence so an in-process
 * write (a bot command editing settings) is picked up promptly.
 *
 * All timers are unref'd so they never keep the process alive.
 */

const { resolveConfig } = require('./adaptivePoller');

/** True when the bot has seen no Discord activity for a while. */
function activityIsIdle() {
    try {
        return require('./activityGate').isIdle();
    } catch (_) {
        return false;
    }
}

class CacheScheduler {
    constructor(overrides = {}) {
        this.cfg = resolveConfig(overrides);
        this.tasks = new Set();
        this.currentMs = this.cfg.initialMs;
        this.quietStreak = 0;
        this._timer = null;
        this._running = false;
        this._stopped = false;
    }

    /**
     * Register a refresh task. Returns a small handle so a manager can keep its
     * existing `_reloadTimer` field — `stop()` unregisters, `notifyActivity()`
     * nudges the shared cadence back to the fast interval.
     *
     * @param {string}   name  label for error logs
     * @param {Function} task  async () => boolean (true = changed)
     * @param {object}   [opts]
     */
    register(name, task, opts = {}) {
        const entry = {
            name,
            task,
            onError: opts.onError || ((err) => console.error(`[${name}] poll failed:`, err.message)),
            stopped: false,
        };
        this.tasks.add(entry);
        this._scheduleNext();
        return {
            name,
            stop: () => {
                entry.stopped = true;
                this.tasks.delete(entry);
            },
            notifyActivity: () => this.notifyActivity(),
        };
    }

    /** Reset the shared cadence to the fast interval (a write just happened). */
    notifyActivity() {
        this.quietStreak = 0;
        this.currentMs = this.cfg.initialMs;
        if (this._stopped) return this;
        if (this._timer) clearTimeout(this._timer);
        this._timer = null;
        this._scheduleNext();
        return this;
    }

    stop() {
        this._stopped = true;
        if (this._timer) {
            clearTimeout(this._timer);
            this._timer = null;
        }
    }

    get intervalMs() {
        return this.currentMs;
    }

    _jitter(ms) {
        const delta = ms * this.cfg.jitterRatio;
        return Math.max(1000, Math.round(ms + (Math.random() * 2 - 1) * delta));
    }

    _scheduleNext() {
        if (this._stopped || this._timer) return;
        if (this.tasks.size === 0) return; // nothing to refresh — hold no timer
        this._timer = setTimeout(() => this._run(), this._jitter(this.currentMs));
        this._timer.unref?.();
    }

    async _run() {
        this._timer = null;
        if (this._stopped || this._running) return;
        this._running = true;
        let anyChanged = false;
        try {
            // Sequential by design: these are cheap single-table reads, and
            // running them one at a time keeps the shared pool small and the
            // wake window short instead of opening N connections at once.
            for (const entry of Array.from(this.tasks)) {
                if (entry.stopped) continue;
                try {
                    if (await entry.task()) anyChanged = true;
                } catch (err) {
                    // A transient DB error must not stretch the backoff — keep
                    // polling fast so we recover as soon as the DB is reachable.
                    entry.onError(err);
                    anyChanged = true;
                }
            }
        } finally {
            this._running = false;
        }

        if (anyChanged) {
            this.quietStreak = 0;
            this.currentMs = this.cfg.initialMs;
        } else if (activityIsIdle()) {
            // The bot is handling nothing right now, so there is no reason to
            // keep checking at the fast cadence: jump straight to the long idle
            // interval so the compute endpoint can actually suspend. Without
            // this the ramp from 2m to 30m spends ~10 minutes touching the DB
            // every few minutes, which is under Neon's suspend window.
            this.currentMs = this.cfg.maxMs;
            this.quietStreak = 0;
        } else {
            this.quietStreak++;
            if (this.quietStreak > this.cfg.quietTicks) {
                this.currentMs = Math.min(this.cfg.maxMs, Math.round(this.currentMs * this.cfg.factor));
            }
        }
        this._scheduleNext();
    }
}

// One scheduler per process, shared by every settings manager so the whole app
// wakes the database together. Lives on globalThis so a hot-reload reuses it
// instead of starting a second timer.
function getCacheScheduler() {
    return (globalThis.__primebotCacheScheduler ||= new CacheScheduler());
}

module.exports = { CacheScheduler, getCacheScheduler };
