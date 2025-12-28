
require('dotenv').config();

console.log('=== DATABASE CONNECTION INFO ===');
console.log('DATABASE_URL:', process.env.DATABASE_URL || 'Not set');
console.log('DB_HOST:', process.env.DB_HOST || 'Not set');
console.log('DB_PORT:', process.env.DB_PORT || 'Not set');
console.log('DB_USER:', process.env.DB_USER || 'Not set');
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '[HIDDEN]' : 'Not set');
console.log('DB_NAME:', process.env.DB_NAME || 'Not set');
console.log('DB_SSL:', process.env.DB_SSL || 'Not set');
console.log('================================');

// Show parsed configuration
const { parseConnectionString } = require('./server/db');
try {
    const dbConfig = parseConnectionString();
    console.log('Parsed config:', {
        host: dbConfig.host,
        port: dbConfig.port,
        user: dbConfig.user,
        database: dbConfig.database,
        ssl: dbConfig.ssl
    });
} catch (error) {
    console.error('Error parsing connection:', error.message);
}
