import {
  users,
  projectRequests,
  type User,
  type UpsertUser,
  type InsertProjectRequest,
  type ProjectRequest,
} from "@shared/schema";
import { db } from "./db";
import { eq } from "drizzle-orm";

export interface IStorage {
  // User operations
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUserBySocialId(provider: string, socialId: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  
  // Project request operations
  createProjectRequest(request: InsertProjectRequest): Promise<ProjectRequest>;
  getProjectRequests(userId: string): Promise<ProjectRequest[]>;
  getAllProjectRequests(): Promise<ProjectRequest[]>;
  updateProjectRequestStatus(id: string, status: string): Promise<ProjectRequest>;
}

export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async getUserBySocialId(provider: string, socialId: string): Promise<User | undefined> {
    let whereCondition;
    switch (provider) {
      case 'google':
        whereCondition = eq(users.googleId, socialId);
        break;
      case 'discord':
        whereCondition = eq(users.discordId, socialId);
        break;
      case 'facebook':
        whereCondition = eq(users.facebookId, socialId);
        break;
      default:
        return undefined;
    }
    
    const [user] = await db.select().from(users).where(whereCondition);
    return user;
  }

  async getUserByResetToken(token: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.resetToken, token));
    return user;
  }

  async updateUserResetToken(id: string, token: string, expiry: Date): Promise<void> {
    await db
      .update(users)
      .set({
        resetToken: token,
        resetTokenExpiry: expiry,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id));
  }

  async resetUserPassword(id: string, hashedPassword: string): Promise<void> {
    await db
      .update(users)
      .set({
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id));
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    // Check if user exists by ID
    let existingUser: User | undefined;
    if (userData.id) {
      existingUser = await this.getUser(userData.id);
    }
    
    if (existingUser) {
      // Update existing user
      await db
        .update(users)
        .set({
          ...userData,
          updatedAt: new Date(),
        })
        .where(eq(users.id, userData.id!));
      
      // Return updated user
      const updatedUser = await this.getUser(userData.id!);
      return updatedUser!;
    } else {
      // Generate ID if not provided
      const { randomUUID } = await import("crypto");
      const userId = userData.id || randomUUID();
      
      const userWithId = {
        ...userData,
        id: userId
      };
      
      // Insert new user
      await db.insert(users).values(userWithId);
      
      // Return inserted user
      const newUser = await this.getUser(userId);
      return newUser!;
    }
  }

  // Project request operations
  async createProjectRequest(requestData: InsertProjectRequest): Promise<ProjectRequest> {
    // Generate a UUID for the request
    const { randomUUID } = await import("crypto");
    const requestId = randomUUID();
    
    const requestWithId = {
      ...requestData,
      id: requestId
    };
    
    await db.insert(projectRequests).values(requestWithId);
    
    // Return the created request
    const [createdRequest] = await db
      .select()
      .from(projectRequests)
      .where(eq(projectRequests.id, requestId));
    return createdRequest;
  }

  async getProjectRequests(userId: string): Promise<ProjectRequest[]> {
    return db.select().from(projectRequests).where(eq(projectRequests.userId, userId));
  }

  async getAllProjectRequests(): Promise<ProjectRequest[]> {
    return db.select().from(projectRequests);
  }

  async updateProjectRequestStatus(id: string, status: string): Promise<ProjectRequest> {
    await db
      .update(projectRequests)
      .set({ status, updatedAt: new Date() })
      .where(eq(projectRequests.id, id));
    
    // Return the updated request
    const [updatedRequest] = await db
      .select()
      .from(projectRequests)
      .where(eq(projectRequests.id, id));
    return updatedRequest;
  }
}

export const storage = new DatabaseStorage();
