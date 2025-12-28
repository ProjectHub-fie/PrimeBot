
/** @type { import("drizzle-kit").Config } */
module.exports = {
  schema: "./shared/schema.js",
  out: "./migrations",
  dialect: "postgresql",
  dbCredentials: {
    connectionString: 'postgresql://neondb_owner:npg_fQMmC0N3dbXk@ep-tiny-fire-adfvcy9p-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    ssl: true,
  },
};
