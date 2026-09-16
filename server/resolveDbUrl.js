/**
 * Single source of truth for resolving a database connection string.
 *
 * Every pool in the bot follows the same precedence:
 *
 *   1. its own dedicated env var (e.g. LOG_DATABASE_URL), then
 *   2. FALLBACK_DATABASE_URL — the shared "any feature without its own DB
 *      lands here" bucket, then
 *   3. DATABASE_URL — the main pool, kept last so existing single-DB
 *      deployments keep working with zero extra configuration.
 *
 * Keeping this in one place means a new pool can never silently skip the
 * FALLBACK_DATABASE_URL step, and the precedence is testable in isolation.
 */

function resolveDbUrl(specificVar) {
    if (specificVar && process.env[specificVar]) return process.env[specificVar];
    if (process.env.FALLBACK_DATABASE_URL) return process.env.FALLBACK_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

module.exports = { resolveDbUrl };