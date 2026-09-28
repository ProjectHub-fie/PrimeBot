/**
 * The single shared `pg` pool factory for PrimeBot.
 *
 * Every feature used to construct its own `new Pool(...)` at module load. That
 * is fine until a module is hot-reloaded (or a bundler/`require` cache quirk
 * loads it twice), at which point the old pool is never closed and a new one is
 * opened — each leaked pool holds Neon compute awake forever. It also means two
 * features that resolve to the *same* connection string (the common single-DB
 * deployment, where every `*_DATABASE_URL` is unset and they all fall back to
 * `DATABASE_URL`) each open their own set of connections to the same database.
 *
 * This factory fixes both:
 *
 *   • pools are registered on `globalThis` keyed by their connection string, so
 *     a re-`require` returns the existing pool instead of leaking a new one;
 *   • two features on the same connection string share one pool, so a single-DB
 *     deployment opens one pool instead of twenty.
 *
 * A pool that is not configured (no connection string at all) becomes a stub
 * that throws on use — the same graceful degradation the per-feature files had
 * with `{ max: 0 }`, but without a half-constructed real pool.
 */

const { Pool } = require('pg');
const { configFromUrl, poolOptions } = require('./poolConfig');

// Survives module reloads: a fresh require of a *Db.js file must find the pool
// that already exists rather than opening a second one.
const REGISTRY = (globalThis.__primebotPgPools ||= new Map());

/** A stand-in for an unconfigured pool: every use fails loudly but safely. */
function createUnconfiguredPool(label) {
    const fail = async () => {
        throw new Error(`[${label}] database not configured`);
    };
    return {
        __primebotUnconfigured: true,
        label,
        query: fail,
        connect: fail,
        end: async () => {},
        on: () => {},
    };
}

/**
 * Get or create the shared pool for a connection string (or a raw pg config).
 *
 * @param {string|object|null} connection resolved via `resolveDbUrl`, or a
 *                             `pg` config object (host/port fallback)
 * @param {object}      [opts]
 * @param {string}      [opts.label] human label for logs
 * @param {number}      [opts.max]   connection ceiling (first creator wins)
 * @returns {import('pg').Pool|object}
 */
function createPool(connection, { label = 'pool', max } = {}) {
    if (!connection) return createUnconfiguredPool(label);

    let base;
    let key;
    if (typeof connection === 'string') {
        const parsed = configFromUrl(connection);
        if (!parsed) {
            console.warn(`[${label}] could not parse its connection string — pool disabled.`);
            return createUnconfiguredPool(label);
        }
        base = parsed;
        // Key on the normalized (sslmode/channel_binding-stripped) string so two
        // spellings of the same database share one pool.
        key = parsed.connectionString;
    } else {
        base = connection;
        key = `host:${base.host}:${base.port}:${base.database}:${base.user}`;
    }

    const existing = REGISTRY.get(key);
    if (existing) return existing;

    const pool = new Pool({ ...base, ...poolOptions({ max }) });
    pool.on('error', (err) => {
        console.error(`[${label}] Unexpected pool error:`, err.message);
    });

    // Count every query in memory (no DB writes) so the dashboard can show the
    // real Neon workload. Cheap: a couple of integer increments per query.
    try {
        require('../utils/dbUsage').instrumentPool(pool, label);
    } catch { /* monitor must never break the pool */ }

    REGISTRY.set(key, pool);
    return pool;
}

/** Test/diagnostic helper — how many distinct pools this process has opened. */
function poolCount() {
    return REGISTRY.size;
}

module.exports = { createPool, poolCount, REGISTRY };
