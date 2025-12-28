// PostgreSQL Database initialization script
const { Pool } = require('pg');
const { db, testConnection } = require('./db.js');

// Parse PostgreSQL connection string if DB_HOST contains full URL
function parseConnectionConfig() {
  // Use hardcoded DATABASE_URL
  const hardcodedDatabaseUrl = 'postgresql://neondb_owner:npg_fQMmC0N3dbXk@ep-tiny-fire-adfvcy9p-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';
  
  if (hardcodedDatabaseUrl || process.env.DATABASE_URL) {
    try {
      const databaseUrl = hardcodedDatabaseUrl || process.env.DATABASE_URL;
      console.log('✅ Using hardcoded PostgreSQL DATABASE_URL for initialization');
      return {
        connectionString: databaseUrl,
        ssl: databaseUrl.includes('sslmode=require') ? { rejectUnauthorized: false } : false,
      };
    } catch (error) {
      console.warn('Failed to parse DATABASE_URL, falling back to individual env vars:', error.message);
    }
  }

  const dbHost = process.env.DB_HOST || '';
  
  // Check if DB_HOST is a full PostgreSQL connection string
  if (dbHost.includes('postgresql://') || dbHost.includes('postgres://')) {
    try {
      const url = new URL(dbHost);
      return {
        host: url.hostname || 'localhost',
        port: parseInt(url.port) || 5432,
        user: decodeURIComponent(url.username) || 'postgres',
        password: decodeURIComponent(url.password) || '',
        database: url.pathname.slice(1) || 'discord_bot', // Remove leading slash
        ssl: url.searchParams.get('sslmode') === 'require' ? { rejectUnauthorized: false } : false,
      };
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
  };
}

async function createDatabase() {
  try {
    console.log('🔄 Ensuring PostgreSQL database exists...');
    
    const config = parseConnectionConfig();
    
    // If using connection string (Neon), skip database creation as it's managed
    if (config.connectionString) {
      console.log('ℹ️ Using managed database (Neon), skipping database creation');
      return;
    }
    
    // Connect to PostgreSQL server (to postgres database)
    const adminConfig = { ...config, database: 'postgres' };
    const adminPool = new Pool(adminConfig);
    
    try {
      // Check if database exists
      const client = await adminPool.connect();
      const result = await client.query(
        'SELECT 1 FROM pg_database WHERE datname = $1',
        [config.database]
      );
      
      if (result.rows.length === 0) {
        // Create database if it doesn't exist
        await client.query(`CREATE DATABASE "${config.database}"`);
        console.log(`✅ Database '${config.database}' created successfully`);
      } else {
        console.log(`✅ Database '${config.database}' already exists`);
      }
      
      client.release();
    } finally {
      await adminPool.end();
    }
  } catch (error) {
    // If we can't create the database, it might already exist or we might not have permissions
    console.log('ℹ️ Database creation skipped (might already exist or insufficient permissions)');
    console.log('Continuing with table initialization...');
  }
}

async function initializeTables() {
  try {
    console.log('🔄 Initializing PostgreSQL database tables...');
    
    // Test connection first
    const isConnected = await testConnection();
    if (!isConnected) {
      throw new Error('Cannot connect to PostgreSQL database');
    }

    // Use the existing connection pool from db.js
    const config = parseConnectionConfig();
    const pool = new Pool(config);
    const client = await pool.connect();

    try {
      // Create live_polls table
      await client.query(`
        CREATE TABLE IF NOT EXISTS live_polls (
          id SERIAL PRIMARY KEY,
          poll_id VARCHAR(100) NOT NULL UNIQUE,
          pass_code VARCHAR(20) NOT NULL,
          question TEXT NOT NULL,
          creator_id VARCHAR(50) NOT NULL,
          is_active BOOLEAN DEFAULT TRUE,
          allow_multiple_votes BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT NOW(),
          expires_at TIMESTAMP,
          message_id VARCHAR(50),
          channel_id VARCHAR(50)
        )
      `);

      // Add missing columns if they don't exist (for existing tables)
      try {
        // Check if columns exist before adding
        const checkColumns = await client.query(`
          SELECT column_name 
          FROM information_schema.columns 
          WHERE table_name = 'live_polls' AND column_name IN ('message_id', 'channel_id')
        `);
        
        if (checkColumns.rows.length < 2) {
          // Add columns that don't exist
          const existingColumns = checkColumns.rows.map(row => row.column_name);
          if (!existingColumns.includes('message_id')) {
            await client.query('ALTER TABLE live_polls ADD COLUMN message_id VARCHAR(50)');
          }
          if (!existingColumns.includes('channel_id')) {
            await client.query('ALTER TABLE live_polls ADD COLUMN channel_id VARCHAR(50)');
          }
        }
      } catch (error) {
        console.warn('Warning adding columns to live_polls:', error.message);
      }

      // Create live_poll_options table
      await client.query(`
        CREATE TABLE IF NOT EXISTS live_poll_options (
          id SERIAL PRIMARY KEY,
          poll_id VARCHAR(100) NOT NULL,
          option_text TEXT NOT NULL,
          option_index INTEGER NOT NULL,
          vote_count INTEGER DEFAULT 0,
          FOREIGN KEY (poll_id) REFERENCES live_polls(poll_id) ON DELETE CASCADE
        )
      `);

      // Create live_poll_votes table
      await client.query(`
        CREATE TABLE IF NOT EXISTS live_poll_votes (
          id SERIAL PRIMARY KEY,
          poll_id VARCHAR(100) NOT NULL,
          user_id VARCHAR(50) NOT NULL,
          option_index INTEGER NOT NULL,
          voted_at TIMESTAMP DEFAULT NOW(),
          FOREIGN KEY (poll_id) REFERENCES live_polls(poll_id) ON DELETE CASCADE
        )
      `);

      // Create regular polls table (unified database approach)
      await client.query(`
        CREATE TABLE IF NOT EXISTS polls (
          id SERIAL PRIMARY KEY,
          message_id VARCHAR(50) NOT NULL UNIQUE,
          channel_id VARCHAR(50) NOT NULL,
          guild_id VARCHAR(50) NOT NULL,
          question TEXT NOT NULL,
          creator_id VARCHAR(50) NOT NULL,
          is_active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT NOW(),
          expires_at TIMESTAMP,
          ended BOOLEAN DEFAULT FALSE
        )
      `);

      // Create regular poll options table
      await client.query(`
        CREATE TABLE IF NOT EXISTS poll_options (
          id SERIAL PRIMARY KEY,
          message_id VARCHAR(50) NOT NULL,
          option_text TEXT NOT NULL,
          option_index INTEGER NOT NULL,
          emoji VARCHAR(10) NOT NULL,
          vote_count INTEGER DEFAULT 0,
          FOREIGN KEY (message_id) REFERENCES polls(message_id) ON DELETE CASCADE
        )
      `);

      // Create regular poll votes table
      await client.query(`
        CREATE TABLE IF NOT EXISTS poll_votes (
          id SERIAL PRIMARY KEY,
          message_id VARCHAR(50) NOT NULL,
          user_id VARCHAR(50) NOT NULL,
          option_index INTEGER NOT NULL,
          voted_at TIMESTAMP DEFAULT NOW(),
          FOREIGN KEY (message_id) REFERENCES polls(message_id) ON DELETE CASCADE
        )
      `);

      // Create giveaways table
      await client.query(`
        CREATE TABLE IF NOT EXISTS giveaways (
          id SERIAL PRIMARY KEY,
          message_id VARCHAR(50) NOT NULL UNIQUE,
          channel_id VARCHAR(50) NOT NULL,
          guild_id VARCHAR(50) NOT NULL,
          prize TEXT NOT NULL,
          description TEXT,
          winner_count INTEGER DEFAULT 1,
          host_id VARCHAR(50) NOT NULL,
          is_active BOOLEAN DEFAULT TRUE,
          ended BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT NOW(),
          ends_at TIMESTAMP NOT NULL
        )
      `);

      // Create giveaway participants table
      await client.query(`
        CREATE TABLE IF NOT EXISTS giveaway_participants (
          id SERIAL PRIMARY KEY,
          giveaway_id VARCHAR(50) NOT NULL,
          user_id VARCHAR(50) NOT NULL,
          joined_at TIMESTAMP DEFAULT NOW(),
          FOREIGN KEY (giveaway_id) REFERENCES giveaways(message_id) ON DELETE CASCADE
        )
      `);

      // Create giveaway winners table
      await client.query(`
        CREATE TABLE IF NOT EXISTS giveaway_winners (
          id SERIAL PRIMARY KEY,
          giveaway_id VARCHAR(50) NOT NULL,
          user_id VARCHAR(50) NOT NULL,
          selected_at TIMESTAMP DEFAULT NOW(),
          FOREIGN KEY (giveaway_id) REFERENCES giveaways(message_id) ON DELETE CASCADE
        )
      `);

      // Create user levels table
      await client.query(`
        CREATE TABLE IF NOT EXISTS user_levels (
          id SERIAL PRIMARY KEY,
          guild_id VARCHAR(50) NOT NULL,
          user_id VARCHAR(50) NOT NULL,
          xp INTEGER DEFAULT 0,
          level INTEGER DEFAULT 0,
          messages INTEGER DEFAULT 0,
          last_message TIMESTAMP,
          created_at TIMESTAMP DEFAULT NOW(),
          updated_at TIMESTAMP DEFAULT NOW(),
          UNIQUE (guild_id, user_id)
        )
      `);

      // Create user badges table
      await client.query(`
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
        )
      `);

      // Create sessions table for authentication
      await client.query(`
        CREATE TABLE IF NOT EXISTS sessions (
          sid VARCHAR(255) PRIMARY KEY,
          sess TEXT NOT NULL,
          expire TIMESTAMP NOT NULL
        )
      `);

      // Create users table for authentication
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(255) PRIMARY KEY,
          email VARCHAR(255) UNIQUE,
          first_name VARCHAR(255),
          last_name VARCHAR(255),
          profile_image_url VARCHAR(500),
          created_at TIMESTAMP DEFAULT NOW(),
          updated_at TIMESTAMP DEFAULT NOW()
        )
      `);

      // Create indexes for better performance
      const indexes = [
        { name: 'idx_live_polls_poll_id', table: 'live_polls', columns: 'poll_id' },
        { name: 'idx_live_polls_pass_code', table: 'live_polls', columns: 'pass_code' },
        { name: 'idx_live_poll_options_poll_id', table: 'live_poll_options', columns: 'poll_id' },
        { name: 'idx_live_poll_votes_poll_id', table: 'live_poll_votes', columns: 'poll_id' },
        { name: 'idx_live_poll_votes_user_id', table: 'live_poll_votes', columns: 'user_id' },
        { name: 'idx_user_levels_guild_user', table: 'user_levels', columns: 'guild_id, user_id' },
        { name: 'idx_user_levels_guild_level', table: 'user_levels', columns: 'guild_id, level DESC' },
        { name: 'idx_user_levels_guild_xp', table: 'user_levels', columns: 'guild_id, xp DESC' },
        { name: 'idx_user_badges_guild_user', table: 'user_badges', columns: 'guild_id, user_id' },
        { name: 'idx_user_badges_badge_id', table: 'user_badges', columns: 'badge_id' },
        { name: 'idx_session_expire', table: 'sessions', columns: 'expire' }
      ];

      for (const index of indexes) {
        try {
          await client.query(`
            CREATE INDEX IF NOT EXISTS ${index.name} ON ${index.table}(${index.columns})
          `);
          console.log(`✅ Created/verified index ${index.name} on ${index.table}`);
        } catch (indexError) {
          console.warn(`Warning: Could not create index ${index.name}:`, indexError.message);
        }
      }

      // Create trigger for updating updated_at timestamp on user_levels
      await client.query(`
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
          NEW.updated_at = NOW();
          RETURN NEW;
        END;
        $$ language 'plpgsql'
      `);

      await client.query(`
        DROP TRIGGER IF EXISTS update_user_levels_updated_at ON user_levels
      `);

      await client.query(`
        CREATE TRIGGER update_user_levels_updated_at
        BEFORE UPDATE ON user_levels
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column()
      `);

      // Create trigger for updating updated_at timestamp on users
      await client.query(`
        DROP TRIGGER IF EXISTS update_users_updated_at ON users
      `);

      await client.query(`
        CREATE TRIGGER update_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column()
      `);

      console.log('✅ Database tables initialized successfully (including leveling system)');
    } finally {
      client.release();
      await pool.end();
    }
  } catch (error) {
    console.error('❌ Database table initialization failed:', error);
    throw error;
  }
}

async function initializeDatabase() {
  try {
    await createDatabase();
    await initializeTables();
    console.log('🎉 PostgreSQL database setup completed successfully!');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Run initialization if this file is executed directly
if (require.main === module) {
  initializeDatabase()
    .then(() => {
      console.log('Database initialization complete');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Database initialization failed:', error);
      process.exit(1);
    });
}

module.exports = { initializeDatabase, createDatabase, initializeTables };