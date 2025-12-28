export default async function handler(req, res) {
  try {
    // Check if we're in a database-enabled environment
    if (!process.env.DB_HOST && !process.env.DATABASE_URL) {
      return res.status(200).json({ 
        success: true, 
        message: "Database not configured - running in demo mode",
        serverTime: new Date().toISOString(),
        environment: "demo"
      });
    }

    // Try to use the existing db connection from server
    let connection;
    let isUsingPool = false;

    try {
      // Check if we can access the existing database pool
      const dbModule = require('../../../server/db.js');
      if (dbModule && dbModule.pool) {
        connection = await dbModule.pool.getConnection();
        isUsingPool = true;
      } else {
        throw new Error('Pool not available');
      }
    } catch (poolError) {
      console.log('Pool connection failed, trying direct connection:', poolError.message);
      // Fallback to direct MySQL connection for Vercel
      const mysql = require('mysql2/promise');
      
      // Support both individual env vars and DATABASE_URL
      let dbConfig;
      if (process.env.DATABASE_URL) {
        // Parse DATABASE_URL format: mysql://user:password@host:port/database
        const url = new URL(process.env.DATABASE_URL);
        dbConfig = {
          host: url.hostname,
          port: url.port || 3306,
          user: url.username,
          password: url.password,
          database: url.pathname.slice(1), // Remove leading slash
          ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        };
      } else {
        dbConfig = {
          host: process.env.DB_HOST,
          user: process.env.DB_USER,
          password: process.env.DB_PASS || process.env.DB_PASSWORD,
          database: process.env.DB_NAME,
          port: parseInt(process.env.DB_PORT) || 3306,
          ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        };
      }

      connection = await mysql.createConnection(dbConfig);
    }

    // Test the connection with a simple query
    const query = "SELECT NOW() AS time, 'Database connected successfully' AS status";
    let result;

    if (isUsingPool) {
      const [rows] = await connection.execute(query);
      result = rows[0];
      connection.release(); // Return connection to pool
    } else {
      const [rows] = await connection.execute(query);
      result = rows[0];
      await connection.end();
    }

    res.status(200).json({ 
      success: true, 
      serverTime: result.time,
      status: result.status,
      environment: process.env.NODE_ENV || "development"
    });

  } catch (err) {
    console.error('Database test error:', err);
    res.status(500).json({ 
      success: false, 
      error: err.message,
      environment: process.env.NODE_ENV || "development"
    });
  }
}
