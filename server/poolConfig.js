/**
 * Conservative, shared `pg` pool configuration for every PrimeBot pool.
 *
 * Neon bills compute time, and every idle-but-open connection keeps the compute
 * endpoint awake. The bot runs a pool per feature (20+ of them), so an
 * oversized or long-lived pool per feature is the difference between a database
 * that suspends while the bot is idle and one that is billed around the clock.
 *
 * Two things live here:
 *
 *   1. `configFromUrl` — parse a connection string into a `pg` config, dropping
 *      the `sslmode` query param (pg-connection-string treats
 *      `require/prefer/verify-ca` as strict `verify-full`, which warns on every
 *      boot and rejects managed-DB cert chains) and setting `ssl` explicitly.
 *      The `channel_binding=require` param Neon's dashboard appends is dropped
 *      too — it asks for SCRAM-SHA-256-PLUS, which the driver does not implement.
 *
 *   2. `poolOptions` — the shared timeout/size defaults every pool spreads in,
 *      each overridable by env var so a deployment can tune without a code
 *      change.
 *
 * The defaults are deliberately small. A feature pool rarely needs more than a
 * couple of concurrent connections; a large `max` only holds more Neon compute
 * awake, it does not make the bot faster.
 */

// Per-pool connection ceiling. Feature pools that only ever run one query at a
// time (settings reads, cleanup sweeps) do not need a wide pool.
function poolMax(fallback = 3) {
    const raw = parseInt(process.env.DB_POOL_MAX, 10);
    return Number.isFinite(raw) && raw > 0 ? raw : fallback;
}

// How long a connection may sit unused before `pg` returns it to the OS (and
// Neon can idle the endpoint out). Shorter than the old 30s so a quiet bot
// releases its compute quickly; a burst just re-opens one connection.
function idleTimeoutMs() {
    const raw = parseInt(process.env.DB_POOL_IDLE_TIMEOUT_MS, 10);
    return Number.isFinite(raw) && raw >= 0 ? raw : 10000;
}

function connectionTimeoutMs() {
    const raw = parseInt(process.env.DB_POOL_CONNECTION_TIMEOUT_MS, 10);
    return Number.isFinite(raw) && raw > 0 ? raw : 10000;
}

// Cap on a single statement. A query that exceeds this is a runaway query
// holding Neon compute; cancelling it frees the connection instead of letting
// it run to completion. 0 disables (tests / unusual workloads).
function statementTimeoutMs() {
    const raw = parseInt(process.env.DB_STATEMENT_TIMEOUT_MS, 10);
    return Number.isFinite(raw) && raw >= 0 ? raw : 15000;
}

function shouldEnableSsl(connectionStr) {
    return /sslmode\s*=\s*(require|prefer|verify-ca|verify-full|allow)/i.test(connectionStr || '')
        || process.env.DB_SSL === 'require';
}

/**
 * Parse a PostgreSQL connection string into a `pg` pool config.
 * Returns null when the string is missing/unparseable so callers can fall back
 * to a no-op pool instead of constructing `new Pool({ connectionString: undefined })`
 * (which silently makes every query fail).
 */
function configFromUrl(connectionStr) {
    if (!connectionStr) return null;
    let url;
    try {
        url = new URL(connectionStr);
    } catch {
        return null;
    }
    url.searchParams.delete('sslmode');
    url.searchParams.delete('channel_binding');
    return {
        connectionString: url.toString(),
        ssl: shouldEnableSsl(connectionStr) ? { rejectUnauthorized: false } : false,
    };
}

/**
 * Shared pool options. `overrides.max` lets a pool that genuinely needs more
 * concurrency (the main pool, the dashboard session store) ask for it while
 * still inheriting the timeouts.
 */
function poolOptions(overrides = {}) {
    const { max, ...rest } = overrides;
    const statementTimeout = statementTimeoutMs();
    return {
        max: max != null ? max : poolMax(),
        idleTimeoutMillis: idleTimeoutMs(),
        connectionTimeoutMillis: connectionTimeoutMs(),
        allowExitOnIdle: true,
        // A runaway statement must not hold Neon compute open indefinitely.
        ...(statementTimeout > 0 ? { statement_timeout: statementTimeout } : {}),
        ...rest,
    };
}

module.exports = {
    configFromUrl,
    poolOptions,
    shouldEnableSsl,
    poolMax,
    idleTimeoutMs,
    connectionTimeoutMs,
    statementTimeoutMs,
};
