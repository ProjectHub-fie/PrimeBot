const { Pool } = require('pg');

/**
 * Dedicated PostgreSQL pool for the reaction-role feature.
 *
 * Reaction roles are a self-contained subsystem (their own tables, their own
 * cache in ReactionRoleManager), so — like the welcome feature — they get a
 * separate connection string (REACTION_DATABASE_URL) so they can live in their
 * own database/schema if desired. If REACTION_DATABASE_URL is unset we fall
 * back to the main DATABASE_URL so the feature still works in single-DB setups
 * without any extra configuration.
 */

function resolveConnectionString() {
    if (process.env.REACTION_DATABASE_URL) return process.env.REACTION_DATABASE_URL;
    if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
    return null;
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ REACTION_DATABASE_URL (or DATABASE_URL) not set — reaction roles will have no database.');
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

const reactionPool = new Pool(
    cs
        ? {
              ...configFromUrl(cs),
              max: 5,
              idleTimeoutMillis: 30000,
              connectionTimeoutMillis: 10000,
              allowExitOnIdle: true,
          }
        : { max: 0 } // no-op pool; queries will throw and be handled gracefully
);

reactionPool.on('error', (err) => {
    console.error('[REACTION DB] Unexpected pool error:', err.message);
});

async function testReactionConnection() {
    try {
        const client = await reactionPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Reaction database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Reaction database connection failed:', err.message);
        return false;
    }
}

module.exports = { reactionPool, testReactionConnection };
