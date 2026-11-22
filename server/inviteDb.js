const { resolveDbUrl } = require('./resolveDbUrl');
const { createPool } = require('./createPool');

/**
 * Dedicated PostgreSQL pool for Invite Tracking (invite_settings,
 * invite_snapshots, invite_joins, invite_stats, invite_activity).
 *
 * Follows the same precedence as every other feature pool:
 *   INVITE_DATABASE_URL -> FALLBACK_DATABASE_URL -> DATABASE_URL
 * so it works in a single-DB deployment with zero extra configuration.
 *
 * Same-DB requirement: the bot and the dashboard must point at the same
 * database (or share the fallback) for dashboard reads/resets to reach the bot.
 */

function resolveConnectionString() {
    return resolveDbUrl('INVITE_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ INVITE_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — invite tracking will have no database.');
}

const invitePool = createPool(cs, { label: 'INVITE DB' });

async function testInviteConnection() {
    try {
        const client = await invitePool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Invite database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Invite database connection failed:', err.message);
        return false;
    }
}

module.exports = { invitePool, resolveConnectionString, testInviteConnection };
