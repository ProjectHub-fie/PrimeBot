import { sql } from "drizzle-orm";
import { index } from "drizzle-orm/mysql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { mysqlTable, varchar, text, timestamp, json } from "drizzle-orm/mysql-core";

// Session storage table for authentication
export const sessions = mysqlTable(
  "sessions",
  {
    sid: varchar("sid", { length: 255 }).primaryKey(),
    sess: json("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => ({
    sessionExpireIdx: index("IDX_session_expire").on(table.expire),
  }),
);

// Users table with social authentication support
export const users = mysqlTable("users", {
  id: varchar("id", { length: 36 }).primaryKey().default(sql`(UUID())`),
  email: varchar("email", { length: 255 }).unique(),
  firstName: varchar("first_name", { length: 255 }),
  lastName: varchar("last_name", { length: 255 }),
  profileImageUrl: varchar("profile_image_url", { length: 500 }),
  // Social provider IDs
  googleId: varchar("google_id", { length: 255 }).unique(),
  discordId: varchar("discord_id", { length: 255 }).unique(),
  facebookId: varchar("facebook_id", { length: 255 }).unique(),
  // Traditional email/password (optional)
  username: text("username").unique(),
  password: text("password"),
  // Password reset
  resetToken: varchar("reset_token", { length: 255 }).unique(),
  resetTokenExpiry: timestamp("reset_token_expiry"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow(),
});

// Project requests table
export const projectRequests = mysqlTable("project_requests", {
  id: varchar("id", { length: 36 }).primaryKey().default(sql`(UUID())`),
  userId: varchar("user_id", { length: 36 }).references(() => users.id).notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  budget: varchar("budget", { length: 100 }),
  timeline: varchar("timeline", { length: 100 }),
  technologies: json("technologies").$type<string[]>(),
  status: varchar("status", { length: 50 }).default("pending"), // pending, approved, rejected, in-progress, completed
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow(),
});

// Schemas for validation
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const upsertUserSchema = createInsertSchema(users).pick({
  id: true,
  email: true,
  firstName: true,
  lastName: true,
  profileImageUrl: true,
  googleId: true,
  discordId: true,
  facebookId: true,
  username: true,
  password: true,
});

export const insertProjectRequestSchema = createInsertSchema(projectRequests).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
}).extend({
  technologies: z.array(z.string()).optional(),
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type UpsertUser = z.infer<typeof upsertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertProjectRequest = z.infer<typeof insertProjectRequestSchema>;
export type ProjectRequest = typeof projectRequests.$inferSelect;