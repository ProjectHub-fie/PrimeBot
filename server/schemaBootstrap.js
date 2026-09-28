/**
 * Run a schema-bootstrap (DDL) task at most once per process.
 *
 * PrimeBot self-creates its tables (`CREATE TABLE IF NOT EXISTS` +
 * `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) so a fresh database works without
 * migrations. The problem is that callers awaited that DDL *before every read
 * and write*: it is a catalog write that takes a lock and forces a commit, so
 * on Neon it keeps the compute endpoint busy and dirties the catalog for a
 * no-op — on the hottest paths (settings reads, ticket/mailbox writes) that is
 * a large slice of the bill.
 *
 * The schema is stable after the first successful run, so the result is
 * memoized for the life of the process. A failed attempt is evicted so the next
 * caller retries — a transient outage at boot must not permanently disable a
 * feature.
 *
 * The registry lives on `globalThis` so a hot-reload (which re-evaluates the
 * module but not the process) does not re-run the DDL.
 */

const REGISTRY = (globalThis.__primebotSchemaOnce ||= new Map());

/**
 * @param {string}   key stable identifier for the bootstrap step
 * @param {Function} fn  async () => void, runs the DDL
 * @returns {Promise<void>}
 */
function once(key, fn) {
    let p = REGISTRY.get(key);
    if (!p) {
        p = Promise.resolve()
            .then(fn)
            .catch((err) => {
                REGISTRY.delete(key);
                throw err;
            });
        REGISTRY.set(key, p);
    }
    return p;
}

/** Test/diagnostic helper. */
function bootstrapCount() {
    return REGISTRY.size;
}

module.exports = { once, bootstrapCount };
