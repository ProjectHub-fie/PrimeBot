-- Migration: Add server_settings and tickets tables
-- These replace the JSON file storage for serverSettingsManager and ticketManager.
-- polls and poll_options tables were already defined in earlier migrations.

CREATE TABLE IF NOT EXISTS server_settings (
    guild_id              VARCHAR(50) PRIMARY KEY,
    receive_broadcasts    BOOLEAN NOT NULL DEFAULT true,
    broadcast_channel_id  VARCHAR(50),
    welcome_enabled       BOOLEAN NOT NULL DEFAULT false,
    welcome_channel_id    VARCHAR(50),
    welcome_message       TEXT DEFAULT 'Welcome to the server, {member}! Enjoy your stay!',
    welcome_banner_url    TEXT,
    welcome_color         VARCHAR(20) DEFAULT '#5865F2',
    welcome_dm_enabled    BOOLEAN NOT NULL DEFAULT false,
    welcome_dm_message    TEXT DEFAULT 'Hey {username}! Welcome to **{server}**!',
    welcome_show_member_count  BOOLEAN NOT NULL DEFAULT true,
    welcome_show_join_date     BOOLEAN NOT NULL DEFAULT true,
    welcome_show_account_age   BOOLEAN NOT NULL DEFAULT true,
    welcome_custom_title  VARCHAR(255),
    welcome_custom_footer VARCHAR(255),
    leveling_enabled      BOOLEAN NOT NULL DEFAULT true,
    leveling_channel_id   VARCHAR(50),
    xp_multiplier         REAL NOT NULL DEFAULT 1.0,
    xp_cooldown           INTEGER NOT NULL DEFAULT 60000,
    auto_reactions_enabled BOOLEAN NOT NULL DEFAULT false,
    auto_reactions         JSONB NOT NULL DEFAULT '[]',
    no_prefix_users        JSONB NOT NULL DEFAULT '{}',
    updated_at             TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tickets (
    channel_id         VARCHAR(50) PRIMARY KEY,
    user_id            VARCHAR(50) NOT NULL,
    guild_id           VARCHAR(50) NOT NULL,
    category           VARCHAR(50) NOT NULL DEFAULT 'general',
    created_at         BIGINT NOT NULL,
    closed             BOOLEAN NOT NULL DEFAULT false,
    is_thread          BOOLEAN NOT NULL DEFAULT false,
    parent_channel_id  VARCHAR(50),
    control_message_id VARCHAR(50),
    closed_at          BIGINT,
    closed_by          VARCHAR(50),
    reopened_at        BIGINT,
    reopened_by        VARCHAR(50)
);
