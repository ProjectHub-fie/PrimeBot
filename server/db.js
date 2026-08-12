const { Pool } = require('pg');
const { drizzle } = require('drizzle-orm/node-postgres');
const schema = require("../shared/schema.js");

// Decide whether SSL should be enabled for a connection. Managed Postgres on
// Vercel/Neon/Supabase requires SSL; we accept self-signed certs via
// rejectUnauthorized:false so connections still succeed without a CA bundle.
function shouldEnableSsl(connectionStr) {
  return /sslmode\s*=\s*(require|prefer|verify-ca|verify-full|allow)/i.test(connectionStr || '')
    || process.env.DB_SSL === 'require';
}

// Build an explicit pool config from a postgres:// connection string. We parse
// the URL ourselves and DROP the `sslmode` query param before handing the
// string to `pg`. Reason: pg-connection-string (used by `pg`) treats
// `sslmode=require/prefer/verify-ca` as aliases for `verify-full` (strict cert
// validation), which (a) prints a deprecation/security warning on every boot
// and (b) breaks connections to hosts whose cert chain can't be fully verified
// (common with managed DBs). We instead set `ssl` explicitly here.
function configFromUrl(connectionStr) {
  const url = new URL(connectionStr);
  const sslmode = url.searchParams.get('sslmode');
  url.searchParams.delete('sslmode');
  // Re-serialize the cleaned query string (URL strips empty `?` automatically).
  const clean = url.toString();
  return {
    connectionString: clean,
    ssl: shouldEnableSsl(connectionStr) ? { rejectUnauthorized: false } : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    _sslmode: sslmode, // for logging only
  };
}

// Parse PostgreSQL connection string - uses DATABASE_URL env var (set per-host in .env or secrets)
function parseConnectionString() {
  if (process.env.DATABASE_URL) {
    try {
      const databaseUrl = process.env.DATABASE_URL;
      console.log(`✅ Using PostgreSQL DATABASE_URL (sslmode=${/sslmode=([^&]+)/.exec(databaseUrl)?.[1] || 'off'})`);
      return configFromUrl(databaseUrl);
    } catch (error) {
      console.warn('Failed to parse DATABASE_URL, falling back to individual env vars:', error.message);
    }
  } else {
    console.warn('⚠️ DATABASE_URL not found. Set DATABASE_URL in your environment or .env file.');
  }

  const dbHost = process.env.DB_HOST || '';
  
  // Check if DB_HOST is a full PostgreSQL connection string
  if (dbHost.includes('postgresql://') || dbHost.includes('postgres://')) {
    try {
      return configFromUrl(dbHost);
    } catch (error) {
      console.warn('Failed to parse PostgreSQL connection string, using individual env vars:', error.message);
    }
  }
  
  // Fallback to individual environment variables
  return {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 5432,
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'discord_bot',
    ssl: process.env.DB_SSL === 'require' ? { rejectUnauthorized: false } : false,
    max: 10, // Connection pool size
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  };
}

const dbConfig = parseConnectionString();

// Create PostgreSQL connection pool with better timeout settings
const pool = new Pool({
    ...dbConfig,
    connectionTimeoutMillis: 10000, // 10 seconds
    idleTimeoutMillis: 30000, // 30 seconds
    max: 10, // maximum number of connections
    allowExitOnIdle: true
});

// Initialize Drizzle with PostgreSQL
const db = drizzle(pool, { schema });

// Test connection function
async function testConnection() {
  try {
    if (!process.env.DATABASE_URL && !process.env.DB_HOST) {
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