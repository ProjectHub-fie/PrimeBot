/**
 * Dashboard website-latency recorder.
 *
 * Measures how long the dashboard takes to respond to real page/API requests
 * and stores the samples so the Stats page can draw a githubstatus-style
 * latency graph over a 7/30/90-day window.
 *
 * Neon-efficiency contract (see AGENTS.md "Neon CU-hour reduction"): samples
 * are kept in a bounded in-memory buffer and flushed to Postgres in one batched
 * INSERT, at most once per flush interval (default 60s) and only when there is
 * actually traffic. A quiet dashboard performs zero writes, so the compute
 * endpoint is free to suspend. The buffer is capped, so a burst cannot balloon
 * memory.
 *
 * The table lives on the shared season pool (SEASON_DATABASE_URL → fallback)
 * alongside the dashboard session store and the shardnode failover tables, so
 * latency history survives serverless instance churn and is readable from any
 * dashboards node. The table self-creates on first use and never in the hot
 * path of a request.
 */

const DEFAULTS = {
    FLUSH_INTERVAL_MS: 60 * 1000,
    MIN_FLUSH_GAP_MS: 15 * 1000, // coalesce traffic-driven flushes (serverless heat)
    MAX_BUFFER: 5000,          // samples kept before forcing a flush
    MAX_BOUND: 2000,           // in-memory recent window for fast reads
    SAMPLE_QUOTA_PER_FLUSH: 1000, // max rows written in one batched INSERT
};

class LatencyRecorder {
    /**
     * @param {object}   [opts]
     * @param {Function} [opts.poolFn]  async () => pg Pool (defaults to season pool)
     * @param {number}   [opts.flushIntervalMs]
     * @param {number}   [opts.minFlushGap] coalescing floor before a traffic-driven flush
     * @param {number}   [opts.maxBuffer]
     * @param {number}   [opts.maxBound]
     * @param {Function} [opts.setIntervalFn] injectable timer (tests)
     * @param {Function} [opts.clearIntervalFn]
     * @param {Function} [opts.nowFn]
     */
    constructor(opts = {}) {
        this._poolFn = opts.poolFn || defaultPoolFn;
        this._flushIntervalMs = opts.flushIntervalMs || DEFAULTS.FLUSH_INTERVAL_MS;
        this._minGapMs = opts.minFlushGap;
        this._maxBuffer = opts.maxBuffer || DEFAULTS.MAX_BUFFER;
        this._maxBound = opts.maxBound || DEFAULTS.MAX_BOUND;
        this._setInterval = opts.setIntervalFn || ((fn, ms, ...args) => setInterval(fn, ms, ...args));
        this._clearInterval = opts.clearIntervalFn || clearInterval;
        this._now = opts.nowFn || (() => Date.now());

        this._buffer = [];
        this._bound = [];
        this._flushTimer = null;
        this._flushing = false;
        this._lastFlushAt = 0;
        this._enabled = true;
    }

    /** A request finished; record its duration. Never throws. */
    record(ms, route) {
        if (!this._enabled) return;
        const dur = Number(ms);
        if (!Number.isFinite(dur) || dur < 0) return;
        const t = this._now();
        const sample = { t, ms: Math.round(dur), route: route || '' };
        this._buffer.push(sample);
        this._bound.push(sample);
        if (this._bound.length > this._maxBound) this._bound.splice(0, this._bound.length - this._maxBound);
        // Persist before a serverless instance could be recycled: flush when the
        // buffer fills OR after a quiet coalescing gap of traffic (at most once
        // per MIN_FLUSH_GAP_MS, so a burst still means one batched INSERT).
        if (this._buffer.length >= this._maxBuffer) {
            this.flush().catch(() => {});
        } else if (this._buffer.length && this._now() - this._lastFlushAt >= this._minFlushGap()) {
            this.flush().catch(() => {});
        }
    }

    /** Sync buffer into Postgres (best-effort). Returns flushed sample count. */
    async flush() {
        if (this._flushing) return 0;
        const batch = this._buffer.splice(0);
        if (!batch.length) return 0;
        this._flushing = true;
        try {
            const pool = await this._poolFn();
            if (!pool || !pool.query) return 0;
            // Insert in chunks so a very bursty build can't build a huge VALUES list.
            let flushed = 0;
            for (let i = 0; i < batch.length; i += this._quota) {
                const chunk = batch.slice(i, i + this._quota);
                await pool.query(
                    `INSERT INTO latency_samples (ts, ms, route) VALUES ${chunk.map((_, j) => `($${j * 3 + 1}, $${j * 3 + 2}, $${j * 3 + 3})`).join(', ')}`,
                    chunk.flatMap(s => [new Date(s.t), s.ms, s.route])
                );
                flushed += chunk.length;
            }
            this._lastFlushAt = this._now();
            return flushed;
        } catch (err) {
            // Put the batch back so future traffic isn't lost forever; if it was
            // dropped due to buffer pressure this keeps at least the tail.
            if (this._buffer.length + batch.length <= this._maxBuffer + this._maxBound) {
                this._buffer = batch.concat(this._buffer);
            }
            console.error('[LATENCY] flush failed:', err.message);
            return 0;
        } finally {
            this._flushing = false;
        }
    }

    get _quota() { return DEFAULTS.SAMPLE_QUOTA_PER_FLUSH; }

    _minFlushGap() {
        return this._minGapMs != null ? this._minGapMs : DEFAULTS.MIN_FLUSH_GAP_MS;
    }

    /** Start the periodic flush timer. No-op if already started. */
    start() {
        if (this._flushTimer) return this;
        this._flushTimer = this._setInterval(() => {
            if (this._buffer.length) this.flush().catch(() => {});
        }, this._flushIntervalMs);
        if (this._flushTimer && typeof this._flushTimer.unref === 'function') {
            try { this._flushTimer.unref(); } catch (_) {}
        }
        return this;
    }

    /** Stop the timer (e.g. during shutdown). */
    stop() {
        if (this._flushTimer) {
            this._clearInterval(this._flushTimer);
            this._flushTimer = null;
        }
        return this;
    }

    /** In-memory recent samples (used to merge into the series for the last hour). */
    recent() {
        return this._bound.map(s => ({ ...s }));
    }

    counts() {
        return { buffered: this._buffer.length, recentWindow: this._bound.length };
    }
}

function defaultPoolFn() {
    // Lazy require so the recorder can be constructed without a live DB.
    return require('../server/seasonDb').seasonPool;
}

let singleton = null;
let singletonOpts = null;

/** Get (and lazily start) the process-wide recorder. */
function getLatencyRecorder(opts = {}) {
    if (!singleton || opts.force) {
        if (singleton && opts.force) singleton.stop();
        singleton = new LatencyRecorder(opts);
        singletonOpts = opts;
        singleton.start();
    }
    return singleton;
}

module.exports = { LatencyRecorder, getLatencyRecorder, DEFAULTS };