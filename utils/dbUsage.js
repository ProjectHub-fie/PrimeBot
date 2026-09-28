/**
 * Always-on, in-memory database usage monitor.
 *
 * The Neon bill is driven by how often the compute endpoint is woken and how
 * long it stays busy, so the numbers that matter are: how many queries run, how
 * many are writes, how many are slow (they hold compute open), and how many
 * fail. `utils/dbMonitor.js` answers that but is opt-in and captures a stack
 * frame per query, which is too heavy to leave on in production.
 *
 * This module is the cheap always-on companion: it counts only — no stack
 * capture, no per-query string normalisation — so the overhead is a couple of
 * integer increments per query. It is instrumented centrally from
 * `server/createPool.js`, so every pool in the process is covered without each
 * feature opting in.
 *
 * It never writes metrics to Postgres (that would be the very workload it is
 * meant to measure). A periodic compact summary is logged for diagnostics and
 * the full snapshot is available via `snapshot()` — surfaced on the dashboard
 * at `/api/stats/db`.
 */

const SLOW_MS = parseInt(process.env.DB_SLOW_QUERY_MS, 10) || 100;
const LOG_INTERVAL_MS = process.env.DB_USAGE_LOG_MS != null
    ? parseInt(process.env.DB_USAGE_LOG_MS, 10)
    : 15 * 60 * 1000;

function classify(text) {
    const head = String(text || '').trimStart().slice(0, 6).toUpperCase();
    if (head === 'SELECT') return 'read';
    if (head === 'INSERT' || head === 'UPDATE' || head === 'DELETE') return 'write';
    if (head === 'WITH') return 'read';
    return 'other';
}

const metrics = {
    startedAt: Date.now(),
    queries: 0,
    reads: 0,
    writes: 0,
    other: 0,
    failures: 0,
    slow: 0,
    totalMs: 0,
    maxMs: 0,
    batches: 0,        // batched flush operations (e.g. leveling XP flushes)
    batchedRows: 0,    // rows written by those batches
    byPool: new Map(), // label -> counters
    cache: { hits: 0, misses: 0, byName: new Map() },
};

function poolCounters(label) {
    let c = metrics.byPool.get(label);
    if (!c) {
        c = { queries: 0, reads: 0, writes: 0, failures: 0, slow: 0, totalMs: 0 };
        metrics.byPool.set(label, c);
    }
    return c;
}

function recordQuery(label, text, ms, failed) {
    const kind = classify(text);
    metrics.queries++;
    metrics.totalMs += ms;
    if (ms > metrics.maxMs) metrics.maxMs = ms;
    if (kind === 'read') metrics.reads++;
    else if (kind === 'write') metrics.writes++;
    else metrics.other++;
    if (ms >= SLOW_MS) metrics.slow++;
    if (failed) metrics.failures++;

    const c = poolCounters(label);
    c.queries++;
    if (kind === 'read') c.reads++;
    else if (kind === 'write') c.writes++;
    c.totalMs += ms;
    if (ms >= SLOW_MS) c.slow++;
    if (failed) c.failures++;
}

/** Wrap a `pg` Pool (and its checked-out clients) so every query is counted. */
function instrumentPool(pool, label = 'pool') {
    if (!pool || pool.__usageMonitored) return pool;
    pool.__usageMonitored = true;

    const wrap = (obj) => {
        const raw = obj.query.bind(obj);
        obj.query = function monitoredQuery(...args) {
            const text = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].text);
            const start = process.hrtime.bigint();
            const done = (failed) => recordQuery(label, text, Number(process.hrtime.bigint() - start) / 1e6, failed);
            const result = raw(...args);
            if (result && typeof result.then === 'function') {
                return result.then((v) => { done(false); return v; }, (e) => { done(true); throw e; });
            }
            done(false);
            return result;
        };
    };

    wrap(pool);

    const rawConnect = pool.connect.bind(pool);
    pool.connect = function monitoredConnect(...args) {
        const maybe = rawConnect(...args);
        if (!maybe || typeof maybe.then !== 'function') return maybe;
        return maybe.then((client) => {
            if (client && !client.__usageMonitored) {
                client.__usageMonitored = true;
                wrap(client);
            }
            return client;
        });
    };

    return pool;
}

/** Record a batched flush (one statement covering N rows). */
function recordBatch(rows = 0) {
    metrics.batches++;
    metrics.batchedRows += rows;
}

/** Record a configuration-cache lookup. */
function recordCache(name, hit) {
    if (hit) metrics.cache.hits++;
    else metrics.cache.misses++;
    let c = metrics.cache.byName.get(name);
    if (!c) { c = { hits: 0, misses: 0 }; metrics.cache.byName.set(name, c); }
    if (hit) c.hits++; else c.misses++;
}

function snapshot() {
    const uptimeSec = Math.max(1, (Date.now() - metrics.startedAt) / 1000);
    const lookups = metrics.cache.hits + metrics.cache.misses;
    const byPool = Array.from(metrics.byPool.entries())
        .map(([label, c]) => ({ label, ...c, avgMs: c.queries ? Number((c.totalMs / c.queries).toFixed(2)) : 0 }))
        .sort((a, b) => b.queries - a.queries);
    return {
        uptimeSec: Number(uptimeSec.toFixed(0)),
        queries: metrics.queries,
        queriesPerSecond: Number((metrics.queries / uptimeSec).toFixed(3)),
        reads: metrics.reads,
        writes: metrics.writes,
        other: metrics.other,
        failures: metrics.failures,
        slow: metrics.slow,
        slowThresholdMs: SLOW_MS,
        avgMs: metrics.queries ? Number((metrics.totalMs / metrics.queries).toFixed(2)) : 0,
        maxMs: Number(metrics.maxMs.toFixed(1)),
        batchWrites: metrics.batches,
        batchedRows: metrics.batchedRows,
        cache: {
            hits: metrics.cache.hits,
            misses: metrics.cache.misses,
            hitRate: lookups ? Number(((metrics.cache.hits / lookups) * 100).toFixed(1)) : null,
            byName: Array.from(metrics.cache.byName.entries())
                .map(([name, c]) => ({ name, ...c, hitRate: (c.hits + c.misses) ? Number(((c.hits / (c.hits + c.misses)) * 100).toFixed(1)) : null })),
        },
        byPool,
    };
}

function formatReport() {
    const s = snapshot();
    return [
        'Database',
        '──────────────',
        `Queries:     ${s.queries.toLocaleString()}  (~${s.queriesPerSecond}/s over ${s.uptimeSec}s)`,
        `Reads:       ${s.reads.toLocaleString()}`,
        `Writes:      ${s.writes.toLocaleString()}`,
        `Batch writes:${String(s.batchWrites).padStart(7)}  (${s.batchedRows.toLocaleString()} rows)`,
        `Slow (>${s.slowThresholdMs}ms):${String(s.slow).padStart(5)}`,
        `Failed:      ${s.failures.toLocaleString()}`,
        `Avg:         ${s.avgMs}ms   Max: ${s.maxMs}ms`,
        `Cache hits:  ${s.cache.hitRate == null ? 'n/a' : s.cache.hitRate + '%'}  (${s.cache.hits} hit / ${s.cache.misses} miss)`,
    ].join('\n');
}

function startReporting() {
    if (!(LOG_INTERVAL_MS > 0)) return null;
    const t = setInterval(() => console.log(formatReport()), LOG_INTERVAL_MS);
    t.unref?.();
    return t;
}

/** Test-only: reset counters. */
function reset() {
    metrics.startedAt = Date.now();
    metrics.queries = metrics.reads = metrics.writes = metrics.other = 0;
    metrics.failures = metrics.slow = 0;
    metrics.totalMs = metrics.maxMs = 0;
    metrics.batches = metrics.batchedRows = 0;
    metrics.byPool.clear();
    metrics.cache.hits = metrics.cache.misses = 0;
    metrics.cache.byName.clear();
}

module.exports = {
    instrumentPool,
    recordBatch,
    recordCache,
    snapshot,
    formatReport,
    startReporting,
    reset,
    SLOW_MS,
    LOG_INTERVAL_MS,
};
