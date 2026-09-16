/**
 * Development-only PostgreSQL query monitor (opt-in via DB_QUERY_MONITOR=true).
 *
 * Wraps a `pg` Pool's `query`/`connect` so every statement is timed and
 * attributed to a calling module. It only records aggregates in memory and
 * prints a periodic summary to the application log — it does NOT write to the
 * database (persisting every query would itself be a workload) and adds no
 * overhead when disabled.
 *
 * Usage (per pool, after the Pool is constructed):
 *
 *     require('./utils/dbMonitor').instrumentPool(pool, 'main');
 *
 * The summary answers exactly the questions that matter for a Neon bill:
 * which statements run most often, which run longest, and which modules cause
 * them. Enable with DB_QUERY_MONITOR=true (optional DB_QUERY_MONITOR_INTERVAL_MS,
 * default 60000).
 */

const ENABLED = process.env.DB_QUERY_MONITOR === 'true' || process.env.DB_QUERY_MONITOR === '1';
const SUMMARY_INTERVAL_MS = parseInt(process.env.DB_QUERY_MONITOR_INTERVAL_MS, 10) || 60000;
const TOP_N = parseInt(process.env.DB_QUERY_MONITOR_TOP_N, 10) || 8;

/** Collapse the variable parts of a statement so identical shapes aggregate. */
function normalizeSql(text) {
    return String(text || '')
        .replace(/\s+/g, ' ')
        .replace(/'[^']*'/g, "'?'")
        .replace(/\$\d+/g, '$?')
        .replace(/\b\d+\b/g, '?')
        .trim()
        .slice(0, 180);
}

/** Classify a statement for the write/read breakdown. */
function classify(text) {
    const head = String(text || '').trim().slice(0, 12).toUpperCase();
    if (head.startsWith('SELECT')) return 'SELECT';
    if (head.startsWith('INSERT')) return 'INSERT';
    if (head.startsWith('UPDATE')) return 'UPDATE';
    if (head.startsWith('DELETE')) return 'DELETE';
    if (head.startsWith('WITH')) return 'SELECT';
    if (head.startsWith('BEGIN') || head.startsWith('COMMIT') || head.startsWith('ROLLBACK')) return 'TX';
    return 'OTHER';
}

/** Best-effort attribution: first stack frame inside the project that is not
 *  node_modules, this monitor, or the pg driver itself. */
function callerModule() {
    const err = new Error();
    const stack = (err.stack || '').split('\n').slice(2);
    for (const line of stack) {
        const m = line.match(/\(?([^()\s]+\.js):\d+:\d+\)?/);
        if (!m) continue;
        const file = m[1];
        if (file.includes('node_modules')) continue;
        if (file.includes('dbMonitor.js')) continue;
        const parts = file.split('/');
        return parts.slice(-2).join('/');
    }
    return 'unknown';
}

const stats = {
    total: 0,
    byShape: new Map(), // shape -> { count, totalMs, maxMs, kind, module, sample }
    startedAt: Date.now(),
};

function record(text, ms) {
    const kind = classify(text);
    const shape = normalizeSql(text);
    const key = `${kind}::${shape}`;
    let entry = stats.byShape.get(key);
    if (!entry) {
        entry = { count: 0, totalMs: 0, maxMs: 0, kind, module: callerModule(), sample: shape };
        stats.byShape.set(key, entry);
    }
    entry.count++;
    entry.totalMs += ms;
    if (ms > entry.maxMs) entry.maxMs = ms;
    stats.total++;
}

function instrumentPool(pool, label = 'pool') {
    if (!ENABLED || !pool || pool.__monitored) return;
    pool.__monitored = true;

    const rawQuery = pool.query.bind(pool);
    pool.query = function monitoredQuery(...args) {
        const start = process.hrtime.bigint();
        const text = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].text);
        const finish = () => {
            const ms = Number(process.hrtime.bigint() - start) / 1e6;
            record(text, ms);
        };
        const result = rawQuery(...args);
        if (result && typeof result.then === 'function') {
            return result.then(
                (v) => { finish(); return v; },
                (e) => { finish(); throw e; }
            );
        }
        finish();
        return result;
    };

    // `pool.connect()` hands out a client with its own `query`; wrap that too so
    // transaction/`client.query` paths are counted.
    const rawConnect = pool.connect.bind(pool);
    pool.connect = function monitoredConnect(...args) {
        const maybePromise = rawConnect(...args);
        if (!maybePromise || typeof maybePromise.then !== 'function') return maybePromise;
        return maybePromise.then((client) => {
            if (client && !client.__monitored) {
                client.__monitored = true;
                const rawClientQuery = client.query.bind(client);
                client.query = function (...qArgs) {
                    const start = process.hrtime.bigint();
                    const text = typeof qArgs[0] === 'string' ? qArgs[0] : (qArgs[0] && qArgs[0].text);
                    const result = rawClientQuery(...qArgs);
                    const finish = () => record(text, Number(process.hrtime.bigint() - start) / 1e6);
                    if (result && typeof result.then === 'function') {
                        return result.then((v) => { finish(); return v; }, (e) => { finish(); throw e; });
                    }
                    finish();
                    return result;
                };
            }
            return client;
        });
    };

    console.log(`[DB MONITOR] Instrumented pool "${label}" (summary every ${SUMMARY_INTERVAL_MS}ms).`);
    return pool;
}

function summary() {
    const uptimeSec = Math.max(1, (Date.now() - stats.startedAt) / 1000);
    const rows = Array.from(stats.byShape.values());
    if (rows.length === 0) return { total: 0, queriesPerSecond: 0, byFrequency: [], byDuration: [], byWorkload: [], writes: 0 };

    const writes = rows.filter(r => ['INSERT', 'UPDATE', 'DELETE', 'TX'].includes(r.kind))
        .reduce((n, r) => n + r.count, 0);

    return {
        total: stats.total,
        queriesPerSecond: Number((stats.total / uptimeSec).toFixed(3)),
        writes,
        byFrequency: rows.slice().sort((a, b) => b.count - a.count).slice(0, TOP_N),
        byDuration: rows.slice().sort((a, b) => b.maxMs - a.maxMs).slice(0, TOP_N),
        byWorkload: rows.slice().sort((a, b) => b.totalMs - a.totalMs).slice(0, TOP_N),
    };
}

function formatReport() {
    const s = summary();
    const lines = [
        `[DB MONITOR] ${s.total} queries in the last window (~${s.queriesPerSecond}/s), ${s.writes} writes`,
    ];
    const fmt = (r) => `  ${String(r.count).padStart(7)}x  avg ${(r.totalMs / r.count).toFixed(1)}ms  max ${r.maxMs.toFixed(1)}ms  ${r.kind.padEnd(6)} ${r.module}  ${r.sample}`;
    lines.push('  Top by frequency:', ...s.byFrequency.map(fmt));
    lines.push('  Top by max duration:', ...s.byDuration.map(fmt));
    lines.push('  Top by total workload:', ...s.byWorkload.map(fmt));
    return lines.join('\n');
}

/** Print (and reset) a summary. `reset:false` keeps cumulative counters. */
function dump({ reset = true } = {}) {
    const report = formatReport();
    console.log(report);
    if (reset) {
        stats.total = 0;
        stats.byShape.clear();
        stats.startedAt = Date.now();
    }
    return report;
}

function startReporting() {
    if (!ENABLED) return null;
    const t = setInterval(() => dump(), SUMMARY_INTERVAL_MS);
    t.unref?.();
    return t;
}

module.exports = { instrumentPool, summary, dump, formatReport, startReporting, normalizeSql, classify, ENABLED };
