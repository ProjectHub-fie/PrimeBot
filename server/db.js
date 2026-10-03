const { drizzle } = require('drizzle-orm/node-postgres');
const schema = require("../shared/schema.js");
const { configFromUrl, poolOptions } = require('./poolConfig');
const { createPool } = require('./createPool');

// Parse PostgreSQL connection string. The main pool prefers DATABASE_URL;
// FALLBACK_DATABASE_URL is used when it is unset so a deployment can run the
// whole bot off a single connection string without also defining DATABASE_URL.
function parseConnectionString() {
  const mainUrl = process.env.DATABASE_URL || process.env.FALLBACK_DATABASE_URL;
  if (mainUrl) {
    try {
      const sourceVar = process.env.DATABASE_URL ? 'DATABASE_URL' : 'FALLBACK_DATABASE_URL';
      console.log(`✅ Using PostgreSQL ${sourceVar} (sslmode=${/sslmode=([^&]+)/.exec(mainUrl)?.[1] || 'off'})`);
      const cfg = configFromUrl(mainUrl);
      if (cfg) return cfg;
    } catch (error) {
      console.warn('Failed to parse database URL, falling back to individual env vars:', error.message);
    }
  } else {
    console.warn('⚠️ DATABASE_URL not found. Set DATABASE_URL in your environment or .env file.');
  }

  const dbHost = process.env.DB_HOST || '';

  // Check if DB_HOST is a full PostgreSQL connection string
  if (dbHost.includes('postgresql://') || dbHost.includes('postgres://')) {
    const cfg = configFromUrl(dbHost);
    if (cfg) return cfg;
  }

  // Fallback to individual environment variables
  return {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 5432,
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'discord_bot',
    ssl: process.env.DB_SSL === 'require' ? { rejectUnauthorized: false } : false,
  };
}

const dbConfig = parseConnectionString();

// The main pool is the only one that needs real concurrency (commands,
// dashboard, managers). It goes through the shared factory so it is registered
// like every feature pool and can never be duplicated on a module reload; the
// explicit `max` overrides the small feature-pool default.
// Pass the parsed CONFIG (which carries `ssl`), never `dbConfig.connectionString`.
// Re-parsing the bare connection string inside createPool drops the `ssl` we
// just computed (configFromUrl strips `sslmode` from the URL and expresses SSL
// as the config's `ssl` field) — pg then connects without TLS and managed
// Postgres (Neon/Supabase) rejects every query with "connection is insecure".
const pool = createPool(
    dbConfig,
    { label: 'MAIN DB', max: poolOptions({ max: 8 }).max }
);

// Initialize Drizzle with PostgreSQL
const db = drizzle(pool, { schema });

// Test connection function
async function testConnection() {
  try {
    if (!process.env.DATABASE_URL && !process.env.FALLBACK_DATABASE_URL && !process.env.DB_HOST) {
      console.error('❌ No database configuration found');
      console.log('💡 Please create a PostgreSQL database in Replit:');
      console.log('   1. Open a new tab and type "Database"');
      console.log('   2. Click "Create a database"');
      return false;
    }
    
    const client = await pool.connect();
    await client.query('SELECT NOW()');
    console.log('✅ PostgreSQL database connected successfully');
    client.release();
    return true;
  } catch (error) {
    console.error('❌ PostgreSQL connection failed:', error.message);
    if (error.code === 'ECONNREFUSED') {
      console.log('💡 Database connection refused. Please create a PostgreSQL database in Replit:');
      console.log('   1. Open a new tab and type "Database"');
      console.log('   2. Click "Create a database"');
    } else {
      console.log('💡 Please check your database configuration');
    }
    return false;
  }
}

// Graceful database initialization
async function initializeGracefully() {
  try {
    const isConnected = await testConnection();
    if (isConnected) {
      console.log('✅ Database initialized successfully');
      return true;
    } else {
      console.log('⚠️ Bot will continue without PostgreSQL database');
      return false;
    }
  } catch (error) {
    console.error('Database initialization error:', error.message);
    console.log('⚠️ Bot will continue in fallback mode');
    return false;
  }
}

// Handle graceful shutdown - removed to prevent premature connection closing
// The pool will be closed when the process exits naturally

module.exports = { pool, db, testConnection, initializeGracefully };