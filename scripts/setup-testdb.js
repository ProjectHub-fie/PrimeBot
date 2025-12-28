
import { initializeTestDatabase, seedTestData } from '../server/testdb.js';

async function setupTestDatabase() {
  console.log('🚀 Setting up test database for Vercel...');
  
  try {
    // Initialize database and tables
    await initializeTestDatabase();
    
    // Seed with test data
    await seedTestData();
    
    console.log('✅ Test database setup completed successfully!');
    console.log('');
    console.log('Environment variables needed for Vercel:');
    console.log('- TEST_MYSQL_HOST (your MySQL host)');
    console.log('- TEST_MYSQL_PORT (default: 3306)');
    console.log('- TEST_MYSQL_USER (your MySQL username)');
    console.log('- TEST_MYSQL_PASSWORD (your MySQL password)');
    console.log('- TEST_MYSQL_DATABASE (default: projecthub_test)');
    console.log('');
    console.log('Or use the regular MYSQL_* variables if you want to share the same database.');
    
  } catch (error) {
    console.error('❌ Test database setup failed:', error.message);
    process.exit(1);
  }
}

setupTestDatabase();
