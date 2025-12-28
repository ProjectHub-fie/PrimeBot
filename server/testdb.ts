
import { drizzle } from 'drizzle-orm/mysql2';
import mysql from 'mysql2/promise';
import * as schema from "@shared/schema";

// Test database configuration for Vercel
export function createTestDatabase() {
  const testConfig = {
    host: process.env.TEST_MYSQL_HOST || process.env.MYSQL_HOST || 'localhost',
    port: parseInt(process.env.TEST_MYSQL_PORT || process.env.MYSQL_PORT || '3306'),
    user: process.env.TEST_MYSQL_USER || process.env.MYSQL_USER || 'root',
    password: process.env.TEST_MYSQL_PASSWORD || process.env.MYSQL_PASSWORD || '',
    database: process.env.TEST_MYSQL_DATABASE || 'projecthub_test',
    multipleStatements: true,
    connectTimeout: 60000,
  };

  console.log('Creating test database connection with config:', {
    host: testConfig.host,
    port: testConfig.port,
    user: testConfig.user,
    database: testConfig.database
  });

  const connection = mysql.createPool(testConfig);
  return drizzle(connection, { schema, mode: 'default' });
}

// Initialize test database tables
export async function initializeTestDatabase() {
  const testDb = createTestDatabase();
  
  try {
    // Test connection
    const [rows] = await testDb.execute('SELECT 1 as test');
    console.log("✅ Test database connected successfully");
    
    // Create tables if they don't exist
    await testDb.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) UNIQUE,
        firstName VARCHAR(255),
        lastName VARCHAR(255),
        passwordHash VARCHAR(255),
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    
    await testDb.execute(`
      CREATE TABLE IF NOT EXISTS project_requests (
        id VARCHAR(255) PRIMARY KEY,
        userId VARCHAR(255),
        title VARCHAR(255) NOT NULL,
        description TEXT,
        projectType VARCHAR(100),
        budget VARCHAR(100),
        timeline VARCHAR(100),
        contactMethod VARCHAR(100),
        urgency VARCHAR(50),
        additionalInfo TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id)
      )
    `);
    
    console.log("✅ Test database tables initialized");
    return testDb;
    
  } catch (error) {
    console.error("❌ Test database initialization failed:", (error as Error).message);
    throw error;
  }
}

// Seed test data
export async function seedTestData() {
  const testDb = createTestDatabase();
  
  try {
    // Insert test user
    await testDb.execute(`
      INSERT IGNORE INTO users (id, email, firstName, lastName, passwordHash) 
      VALUES (
        'test-user-1', 
        'test@example.com', 
        'Test', 
        'User', 
        '$2b$10$test.hash.for.development'
      )
    `);
    
    // Insert test project request
    await testDb.execute(`
      INSERT IGNORE INTO project_requests (
        id, userId, title, description, projectType, budget, timeline, contactMethod, urgency
      ) VALUES (
        'test-project-1',
        'test-user-1',
        'Test Project',
        'This is a test project for Vercel deployment',
        'website',
        '$1000-$5000',
        '1-2 months',
        'email',
        'medium'
      )
    `);
    
    console.log("✅ Test data seeded successfully");
    
  } catch (error) {
    console.error("❌ Test data seeding failed:", (error as Error).message);
    throw error;
  }
}
