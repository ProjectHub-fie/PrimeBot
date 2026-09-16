const { Pool } = require('pg');
const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for the saved-embeds feature (saved_embeds table).
 *
 * Same multi-pool pattern as the other features (welcomeDb/reactionDb/…):
 * the table lives in its own connection string (EMBED_DATABASE_URL) so it can
 * be placed in a separate database/schema if desired, and falls back to the
 * main DATABASE_URL so single-DB setups work with zero extra config.
 *
 * The embed builder itself is 100% client-side (a draft lives in localStorage,
 * never written per keystroke). The database is only touched when the user
 * explicitly saves/loads/renames/duplicates/deletes a saved embed — at most a
 * handful of queries per explicit action, so Neon compute stays minimal.
 */

function resolveConnectionString() {
    return resolveDbUrl('EMBED_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ EMBED_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — the saved-embeds feature will have no database.');
}

function shouldEnableSsl(connectionStr) {
    return /sslmode\s*=\s*(require|prefer|verify-ca|verify-full|allow)/i.test(connectionStr || '')
        || process.env.DB_SSL === 'require';
}

function configFromUrl(connectionStr) {
    const url = new URL(connectionStr);
    url.searchParams.delete('sslmode');
    return {
        connectionString: url.toString(),
        ssl: shouldEnableSsl(connectionStr) ? { rejectUnauthorized: false } : false,
    };
}

const embedPool = new Pool(
    cs
        ? {
              ...configFromUrl(cs),
              max: 5,
              idleTimeoutMillis: 30000,
              connectionTimeoutMillis: 10000,
              allowExitOnIdle: true,
          }
        : { max: 0 }
);

embedPool.on('error', (err) => {
    console.error('[EMBED DB] Unexpected pool error:', err.message);
});

module.exports = { embedPool };