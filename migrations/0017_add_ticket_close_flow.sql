-- Ticket panel close flow: confirmation buttons, optional close embed,
-- transcript channel, and configurable post-close action buttons.
-- `close_flow` is a single JSONB column (to avoid ~18 individual columns);
-- `close_button_style` makes the initial Close button's colour configurable
-- (its label/emoji already exist as columns).
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_button_style VARCHAR(20) DEFAULT 'Danger';
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_flow JSONB;

-- Fix: live giveaways auto-ending immediately when a duration (e.g. "1h") is
-- set. The `ends_at` column was plain TIMESTAMP (no tz); the bot's expiry sweep
-- compares `ends_at <= NOW()`. On a DB server whose timezone is ahead of UTC,
-- a freshly-created future `ends_at` (stored as a UTC wall-clock) reads as
-- already in the past, so the giveaway is auto-ended the moment it is created.
-- Converting the columns to TIMESTAMPTZ makes NOW() and the stored instant
-- comparable as UTC, so the sweep only ends giveaways whose time has truly
-- passed. (The bot's self-create DDL in utils/liveGiveawayManager.js does the
-- same ALTERs at runtime for deployments that never ran drizzle-kit.)
ALTER TABLE live_giveaways        ALTER COLUMN created_at TYPE TIMESTAMPTZ;
ALTER TABLE live_giveaways        ALTER COLUMN ends_at     TYPE TIMESTAMPTZ USING ends_at AT TIME ZONE 'UTC';
ALTER TABLE live_giveaway_participants ALTER COLUMN joined_at   TYPE TIMESTAMPTZ;
ALTER TABLE live_giveaway_winners      ALTER COLUMN selected_at TYPE TIMESTAMPTZ;
