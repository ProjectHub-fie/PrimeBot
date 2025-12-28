const { users } = require('../shared/schema');
const { db } = require('./db');
const { eq } = require('drizzle-orm');

// Interface for storage operations
class DatabaseStorage {
  // User operations for Replit Auth
  async getUser(id) {
    try {
      if (!db) return undefined;
      const [user] = await db.select().from(users).where(eq(users.id, id));
      return user;
    } catch (error) {
      console.warn('Failed to get user from database:', error.message);
      return undefined;
    }
  }

  async upsertUser(userData) {
    try {
      if (!db) {
        console.warn('Database not available for user upsert');
        return userData;
      }
      
      const [user] = await db
        .insert(users)
        .values(userData)
        .onConflictDoUpdate({
          target: users.id,
          set: {
            ...userData,
            updatedAt: new Date(),
          },
        })
        .returning();
      return user;
    } catch (error) {
      console.warn('Failed to upsert user in database:', error.message);
      return userData;
    }
  }
}

const storage = new DatabaseStorage();

module.exports = { storage, DatabaseStorage };