-- Migration 0023: Ticket claim system.
--
-- Adds claim-tracking columns to the per-ticket instances table so tickets
-- can be claimed / unclaimed / transferred by support staff (utils/ticketClaimService.js).
--
--   claimed_at     — epoch ms when the ticket was last claimed (null = unclaimed).
--   claim_history   — JSONB array of claim actions (claimed / unclaimed /
--                     transferred / overridden). Each entry:
--                     { action, previous_claimer, new_claimer, performed_by, timestamp }
--
-- Both columns are idempotent (ALTER TABLE ... ADD COLUMN IF NOT EXISTS) so they
-- work on existing installs and are mirrored by the bot's self-ensure SQL in
-- utils/ticketManager.js + the shared drizzle schema (shared/schema.js).

ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claimed_by      VARCHAR(50);
ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claimed_at      BIGINT;
ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claim_history   JSONB;
CREATE INDEX IF NOT EXISTS ticket_instances_claimed_by_idx ON ticket_instances (claimed_by) WHERE claimed_by IS NOT NULL;