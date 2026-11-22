const { resolveDbUrl } = require('./resolveDbUrl');
const { createPool } = require('./createPool');

/**
 * Dedicated PostgreSQL pool for the AI Assistant (settings, sessions, messages,
 * usage counters, server knowledge, provider health metadata).
 *
 * Same precedence as every other feature pool:
 *   AI_DATABASE_URL -> FALLBACK_DATABASE_URL -> DATABASE_URL
 * so a single-DB deployment needs no extra configuration.
 *
 * Provider API keys are NEVER stored here — only non-secret health metadata.
 */

function resolveConnectionString() {
    return resolveDbUrl('AI_DATABASE_URL');
}

const cs = resolveConnectionString();

if (!cs) {
    console.warn('⚠️ AI_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) not set — the AI Assistant will have no database.');
}

const aiPool = createPool(cs, { label: 'AI DB' });

async function testAiConnection() {
    try {
        const client = await aiPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ AI database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ AI database connection failed:', err.message);
        return false;
    }
}

module.exports = { aiPool, resolveConnectionString, testAiConnection };
