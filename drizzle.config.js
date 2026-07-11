
/** @type { import("drizzle-kit").Config } */
module.exports = {
  schema: "./shared/schema.js",
  out: "./migrations",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL,
  },
};
