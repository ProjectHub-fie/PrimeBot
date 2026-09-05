-- Migration 0021: Ticket panel embed-builder author fields.
--
-- The embed builder surfaced on the ticket editor's Message tab needs an
-- embed *author* row (name + optional icon URL), matching the "Panel Embed
-- Settings" editor found on Ticket Tool. The author row renders at the top of
-- the panel embed inset (above the title) when either field is set.

ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS author_name      VARCHAR(255);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS author_icon_url  TEXT;