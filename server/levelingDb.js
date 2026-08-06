const { Pool } = require('pg');
const { drizzle } = require('drizzle-orm/node-postgres');
const { userLevels, userBadges, userLevelsRelations, userBadgesRelations } = require('../shared/schema');

if (!process.env.LEVELING_DATABASE_URL) {
    console.warn('⚠️ LEVELING_DATABASE_URL not set — leveling feature will have no database.');
}

const levelingPool = new Pool({
    connectionString: process.env.LEVELING_DATABASE_URL,
    ssl: process.env.LEVELING_DATABASE_URL && process.env.LEVELING_DATABASE_URL.includes('sslmode=require')
        ? { rejectUnauthorized: false }
        : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    allowExitOnIdle: true,
});

levelingPool.on('error', (err) => {
    console.error('[LEVELING DB] Unexpected pool error:', err.message);
});

const levelingSchema = { userLevels, userBadges, userLevelsRelations, userBadgesRelations };
const levelingDb = drizzle(levelingPool, { schema: levelingSchema });

const CREATE_TABLES_SQL = `
    CREATE TABLE IF NOT EXISTS user_levels (
        id SERIAL PRIMARY KEY,
        guild_id VARCHAR(50) NOT NULL,
        user_id VARCHAR(50) NOT NULL,
        xp INTEGER DEFAULT 0,
        level INTEGER DEFAULT 0,
        messages INTEGER DEFAULT 0,
        last_message TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_badges (
        id SERIAL PRIMARY KEY,
        guild_id VARCHAR(50) NOT NULL,
        user_id VARCHAR(50) NOT NULL,
        badge_id VARCHAR(100) NOT NULL,
        badge_name VARCHAR(255) NOT NULL,
        badge_emoji VARCHAR(10) NOT NULL,
        badge_color VARCHAR(50) NOT NULL,
        badge_description TEXT NOT NULL,
        badge_type VARCHAR(50) NOT NULL,
        earned_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );
`;

async function initLevelingTables() {
    try {
        const client = await levelingPool.connect();
        await client.query(CREATE_TABLES_SQL);
        client.release();
        console.log('✅ Leveling database tables initialized');
    } catch (err) {
        console.error('[LEVELING DB] Table init failed:', err.message);
    }
}

async function testLevelingConnection() {
    try {
        const client = await levelingPool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ Leveling database connected successfully');
        await initLevelingTables();
        return true;
    } catch (err) {
        console.error('❌ Leveling database connection failed:', err.message);
        return false;
    }
}

module.exports = { levelingPool, levelingDb, levelingSchema, testLevelingConnection };
