-- Migration: Add allowed column to beta_settings for dynamic server allowlist

ALTER TABLE beta_settings ADD COLUMN IF NOT EXISTS allowed BOOLEAN NOT NULL DEFAULT FALSE;
