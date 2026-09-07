-- Migration 0022: Ticket panel claim button colour.
--
-- The claim button previously rendered with a hardcoded Secondary style. The
-- Buttons tab's embed-builder dropdown now exposes a per-button Colour field,
-- including Claim, so the claim button's style is stored like its siblings.

ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_style VARCHAR(20) DEFAULT 'Secondary';
