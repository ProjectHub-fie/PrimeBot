const { Pool } = require('pg');

if (!process.env.WELCOME_DATABASE_URL) {
    console.warn('⚠️ WELCOME_DATABASE_URL not set — welcome feature will have no database.');
}

const welcomePool = new Pool({
    connectionString: process.env.WELCOME_DATABASE_URL,
    ssl: process.env.WELCOME_DATABASE_URL && process.env.WELCOME_DATABASE_URL.includes('sslmode=require')
        ? { rejectUnauthorized: false }
        : false,
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    allowExitOnIdle: true,
});

welcomePool.on('error', (err) => {
    console.error('[WELCOME DB] Unexpected pool error:', err.message);
});

async function testWelcomeConnection() {
    try {
        const client = await welcomePool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Welcome database connected successfully');
        return true;
    } catch (err) {
        console.error('❌ Welcome database connection failed:', err.message);
        return false;
    }
}

module.exports = { welcomePool, testWelcomeConnection };
