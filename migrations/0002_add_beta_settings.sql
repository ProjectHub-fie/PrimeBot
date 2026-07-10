-- Migration: Add beta_settings table for dynamic beta program management

CREATE TABLE IF NOT EXISTS beta_settings (
  guild_id VARCHAR(50) PRIMARY KEY,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMP DEFAULT NOW()
);
