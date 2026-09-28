const { resolveDbUrl } = require('./resolveDbUrl');

/**
 * Dedicated PostgreSQL pool for the reaction-role feature.
 *
 * Reaction roles are a self-contained subsystem (their own tables, their own
 * cache in ReactionRoleManager), so — like the welcome feature — they get a
 * separate connection string (REACTION_DATABASE_URL) so they can live in their
 * own database/schema if desired. If REACTION_DATABASE_URL is unset we fall
 * back to the shared FALLBACK_DATABASE_URL/DATABASE_URL so the feature still works in single-DB setups
 * without any extra configuration.
 */

function resolveConnectionString() {
    return resolveDbUrl('REACTION_DATABASE_URL');
}

const { createPool } = require('./createPool');

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ REACTION_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — reaction roles will have no database.');
}

const reactionPool = createPool(cs, { label: 'REACTION DB' });


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
