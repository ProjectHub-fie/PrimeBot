import { drizzle } from 'drizzle-orm/mysql2';
import mysql from 'mysql2/promise';
import * as schema from "@shared/schema";

// Parse MySQL connection string if it's a JDBC URL
function parseMySQLConfig() {
  const host = process.env.MYSQL_HOST || 'localhost';
  
  // Check if host is a JDBC URL
  if (host.startsWith('jdbc:mysql://')) {
    try {
      // Extract from JDBC URL: jdbc:mysql://user:pass@host:port/database
      const urlPart = host.replace('jdbc:mysql://', '');
      const [credentials, hostAndDb] = urlPart.split('@');
      const [user, password] = credentials.split(':');
      const [hostPort, database] = hostAndDb.split('/');
      const [hostname, port] = hostPort.split(':');
      
      return {
        host: hostname,
        port: parseInt(port || '3306'),
        user: decodeURIComponent(user),
        password: decodeURIComponent(password),
        database: database,
        multipleStatements: true,
        connectTimeout: 60000,
      };
    } catch (error) {
      console.error('Failed to parse JDBC URL, falling back to individual env vars');
    }
  }
  
  // Use individual environment variables
  return {
    host: process.env.MYSQL_HOST || 'localhost',
    port: parseInt(process.env.MYSQL_PORT || '3306'),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQL_DATABASE || 'projecthub',
    multipleStatements: true,
    connectTimeout: 60000,
  };
}

const mysqlConfig = parseMySQLConfig();

// Create MySQL connection
export const connection = mysql.createPool(mysqlConfig);

export const db = drizzle(connection, { schema, mode: 'default' });

// Test database for Vercel
export function getTestDb() {
  const testConfig = {
    host: process.env.TEST_MYSQL_HOST || process.env.MYSQL_HOST || 'localhost',
    port: parseInt(process.env.TEST_MYSQL_PORT || process.env.MYSQL_PORT || '3306'),
    user: process.env.TEST_MYSQL_USER || process.env.MYSQL_USER || 'root',
    password: process.env.TEST_MYSQL_PASSWORD || process.env.MYSQL_PASSWORD || '',
    database: process.env.TEST_MYSQL_DATABASE || 'projecthub_test',
    multipleStatements: true,
    connectTimeout: 60000,
  };

  const testConnection = mysql.createPool(testConfig);
  return drizzle(testConnection, { schema, mode: 'default' });
}