-- Migration 0009: Reaction-role menus.
--
-- A "menu" is a message the bot watches for reactions that grant roles. Menus
-- support two creation paths:
--   1. The bot sends a role embed to a channel (title/description/color stored
--      here) and the bot's own message becomes the watched message.
--   2. The bot attaches reaction-role mappings to ANY existing message by its
--      channel id + message id (description is null in that case).
--
-- Premium behavior is encoded in `mode`:
--   normal  — toggle (react adds, unreact removes)
--   sticky  — react adds role, bot removes the reaction but keeps the role
--   verify  — react grants once; unreact does not remove
--   unique  — only one role from the menu at a time (swap)
--
-- `persistent` lets the bot re-apply roles on startup by reading the watched
-- message's current reactions. `required_role_id` gates who can use the menu,
-- and `exclusive_role_id` is removed when a member takes a role from this menu
-- (cross-menu mutually-exclusive roles).
--
-- Both the bot (utils/reactionRoleManager.js) and the dashboard
-- (dashboard/db.js) read/write these tables. They share the same
-- REACTION_DATABASE_URL (falling back to DATABASE_URL) so dashboard changes
-- reach the bot through the manager's periodic cache reload.

CREATE TABLE IF NOT EXISTS reaction_roles (
    id                   SERIAL PRIMARY KEY,
    guild_id             VARCHAR(50) NOT NULL,
    channel_id           VARCHAR(50) NOT NULL,
    message_id           VARCHAR(50) NOT NULL,
    title                VARCHAR(255),
    description          TEXT,
    color                VARCHAR(20) DEFAULT '#5865F2',
    mode                 VARCHAR(20) DEFAULT 'normal',
    persistent           BOOLEAN DEFAULT true,
    include_bots         BOOLEAN DEFAULT false,
    required_role_id     VARCHAR(50),
    exclusive_role_id    VARCHAR(50),
    created_by           VARCHAR(50),
    enabled              BOOLEAN DEFAULT true,
    created_at           TIMESTAMP DEFAULT NOW(),
    updated_at           TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS reaction_roles_message_idx
    ON reaction_roles (guild_id, channel_id, message_id);

CREATE INDEX IF NOT EXISTS reaction_roles_guild_idx
    ON reaction_roles (guild_id);

CREATE TABLE IF NOT EXISTS reaction_role_mappings (
    id         SERIAL PRIMARY KEY,
    menu_id    INTEGER NOT NULL REFERENCES reaction_roles(id) ON DELETE CASCADE,
    emoji      VARCHAR(100) NOT NULL,
    role_id    VARCHAR(50) NOT NULL,
    label      VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS reaction_role_mappings_menu_idx
    ON reaction_role_mappings (menu_id);

CREATE UNIQUE INDEX IF NOT EXISTS reaction_role_mappings_menu_emoji_idx
    ON reaction_role_mappings (menu_id, emoji);
