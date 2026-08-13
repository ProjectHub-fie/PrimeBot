-- Migration 0012: Premium Ticket feature.
--
-- Per-guild ticket *panels* (configurable only from the dashboard) and the
-- per-ticket *instances* created when members click a panel button. Both the
-- bot (utils/ticketPanelManager.js / utils/ticketManager.js) and the dashboard
-- (dashboard/db.js) read and write these tables through the TICKET_DATABASE_URL
-- pool (server/ticketDb.js; falls back to DATABASE_URL). Both deployments must
-- point at the same TICKET_DATABASE_URL so dashboard saves reach the bot through
-- the manager's periodic cache reload (same pattern as reaction_roles /
-- automod_settings).
--
-- A "panel" stores everything needed to render the panel message (title,
-- description, color, message type = embed/plain, support roles, the button
-- label/style/emoji, naming options, category, cooldown, etc.) plus where it
-- was last sent (channel_id + message_id) so the dashboard's "update panel"
-- flow can re-render an existing message by id.

CREATE TABLE IF NOT EXISTS ticket_panels (
    id              SERIAL PRIMARY KEY,
    guild_id        VARCHAR(50) NOT NULL,
    name            VARCHAR(100) NOT NULL DEFAULT 'Support Ticket',
    -- Where the panel message lives (NULL until first sent).
    channel_id      VARCHAR(50),
    message_id      VARCHAR(50),
    -- Panel message content.
    message_type    VARCHAR(20) NOT NULL DEFAULT 'embed', -- 'embed' | 'plain'
    title           VARCHAR(255),
    description     TEXT,
    color           VARCHAR(20) DEFAULT '#5865F2',
    thumbnail_url   TEXT,
    image_url       TEXT,
    footer_text     VARCHAR(255),
    content         TEXT, -- for plain message type, or @mentions above the embed
    -- Button that opens a ticket.
    button_label    VARCHAR(80) NOT NULL DEFAULT 'Open Ticket',
    button_style    VARCHAR(20) NOT NULL DEFAULT 'Primary', -- Primary|Secondary|Success|Danger
    button_emoji    VARCHAR(100),
    -- Ticket channel behaviour.
    category        VARCHAR(50) DEFAULT 'general',
    ticket_name     VARCHAR(100), -- null → use username
    -- Roles pinged / given access to a ticket.
    support_role_ids    JSONB NOT NULL DEFAULT '[]',
    ping_role_ids       JSONB NOT NULL DEFAULT '[]',
    ticket_category_id  VARCHAR(50), -- Discord channel category for created channels
    -- Premium-ish options.
    cooldown_seconds        INTEGER NOT NULL DEFAULT 0,
    max_open_per_user      INTEGER NOT NULL DEFAULT 1,
    ask_reason             BOOLEAN NOT NULL DEFAULT false,
    reason_placeholder     VARCHAR(255),
    welcome_message        TEXT,
    -- The control buttons shown inside an open ticket.
    close_button_label     VARCHAR(80) DEFAULT 'Close Ticket',
    close_button_emoji     VARCHAR(100),
    claim_button_label     VARCHAR(80), -- empty → no claim button
    claim_button_emoji     VARCHAR(100),
    -- Misc.
    enabled             BOOLEAN NOT NULL DEFAULT true,
    created_by          VARCHAR(50),
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ticket_panels_guild_idx ON ticket_panels (guild_id);
CREATE UNIQUE INDEX IF NOT EXISTS ticket_panels_guild_name_idx ON ticket_panels (guild_id, name);

-- Per-ticket instances. A ticket is a private channel (or thread) tied to a
-- panel + opener, with a control message holding the close/reopen/claim
-- buttons.
CREATE TABLE IF NOT EXISTS ticket_instances (
    id                  SERIAL PRIMARY KEY,
    panel_id            INTEGER REFERENCES ticket_panels(id) ON DELETE SET NULL,
    guild_id            VARCHAR(50) NOT NULL,
    channel_id          VARCHAR(50) NOT NULL,
    user_id             VARCHAR(50) NOT NULL,
    category            VARCHAR(50) DEFAULT 'general',
    is_thread           BOOLEAN NOT NULL DEFAULT false,
    parent_channel_id   VARCHAR(50),
    control_message_id  VARCHAR(50),
    reason              TEXT,
    status              VARCHAR(20) NOT NULL DEFAULT 'open', -- open|closed|claimed
    claimed_by          VARCHAR(50),
    created_at          BIGINT NOT NULL,
    closed_at           BIGINT,
    closed_by           VARCHAR(50),
    reopened_at         BIGINT,
    reopened_by         VARCHAR(50)
);
CREATE UNIQUE INDEX IF NOT EXISTS ticket_instances_channel_idx ON ticket_instances (channel_id);
CREATE INDEX IF NOT EXISTS ticket_instances_guild_idx ON ticket_instances (guild_id);
CREATE INDEX IF NOT EXISTS ticket_instances_panel_idx ON ticket_instances (panel_id);
CREATE INDEX IF NOT EXISTS ticket_instances_guild_user_idx ON ticket_instances (guild_id, user_id);

-- Add columns added after initial ship (idempotent) so existing installs pick
-- them up without recreating the table.
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS message_type        VARCHAR(20) NOT NULL DEFAULT 'embed';
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS thumbnail_url       TEXT;
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS image_url           TEXT;
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS footer_text         VARCHAR(255);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS content             TEXT;
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS button_emoji        VARCHAR(100);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ticket_name         VARCHAR(100);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ping_role_ids      JSONB NOT NULL DEFAULT '[]';
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ticket_category_id  VARCHAR(50);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS cooldown_seconds        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS max_open_per_user        INTEGER NOT NULL DEFAULT 1;
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ask_reason               BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS reason_placeholder       VARCHAR(255);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS welcome_message         TEXT;
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_button_label       VARCHAR(80) DEFAULT 'Close Ticket';
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_button_emoji       VARCHAR(100);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_label      VARCHAR(80);
ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_emoji      VARCHAR(100);
ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS panel_id     INTEGER REFERENCES ticket_panels(id) ON DELETE SET NULL;
ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS reason       TEXT;
ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS status       VARCHAR(20) NOT NULL DEFAULT 'open';
ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claimed_by   VARCHAR(50);
