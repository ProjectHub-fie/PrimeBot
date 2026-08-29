-- Appeal / Ban-DM subsystem (dedicated APPEAL_DATABASE_URL pool).
--
-- 1. appeal_settings — per-guild switches for the ban-DM flow that lives on the
--       dashboard's Automod tab:
--         dm_user             send an "all available fields" ban embed to the
--                              banned member whenever anyone is banned.
--         use_appeal          attach an "Appeal ban" button to that DM, opening
--                              a floating Discord form (modal) whose submission is
--                              posted to the configured appeal channel.
--         appeal_channel_id   where submitted ban appeals are posted (selectable
--                              from the dashboard's Automod tab.
--         ban_embed_fields     which fields the ban DM embed includes, driven by the
--                              same "all available fields" list on the dashboard.
--
-- 2. appeals — recorded ban-appeal rows (one per submitted appeal) for
--      the dashboard/moderators.
--
-- 3. automod_embeds — every automod log embed gets a per-server **CID**
--      (the embed number, the primary key per guild). The embed title becomes
--      "<moderation type> (CID <n>)". $rmr / $rename (CID) [reason] sets,
--      changes, or removes (empty) the reason. This table lives in the
--      AUTOMOD_DATABASE_URL pool alongside automod_settings -- the CID is an
--      automod-embed property, not part of the appeal pool.

CREATE TABLE IF NOT EXISTS appeal_settings (
    guild_id            varchar(50) PRIMARY KEY,
    dm_user             boolean NOT NULL DEFAULT true,
    use_appeal          boolean NOT NULL DEFAULT false,
    appeal_channel_id   varchar(50),
    ban_embed_fields     jsonb   NOT NULL DEFAULT '["server","user","moderator","action","reason","rule","cid","time"]',
    updated_at          timestamp DEFAULT NOW()
);

ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS dm_user           boolean NOT NULL DEFAULT true;
ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS use_appeal        boolean NOT NULL DEFAULT false;
ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS appeal_channel_id varchar(50);
ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS ban_embed_fields   jsonb NOT NULL DEFAULT '["server","user","moderator","action","reason","rule","cid","time"]';

CREATE TABLE IF NOT EXISTS appeals (
    id         serial PRIMARY KEY,
    guild_id   varchar(50) NOT NULL,
    user_id    varchar(50) NOT NULL,
    action      varchar(50) NOT NULL,
    reason      text NOT NULL DEFAULT '',
    cid        integer,
    status      varchar(20) NOT NULL DEFAULT 'pending',
    created_at timestamp DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS appeals_guild_idx ON appeals (guild_id);
CREATE INDEX IF NOT EXISTS appeals_guild_status_idx ON appeals (guild_id, status);

CREATE TABLE IF NOT EXISTS automod_embeds (
    guild_id   varchar(50) NOT NULL,
    cid        integer      NOT NULL,
    action      varchar(60),
    rule_type   varchar(40),
    user_id     varchar(50),
    reason      text NOT NULL DEFAULT '',
    message_id  varchar(50),
    channel_id   varchar(50),
    created_at  timestamp DEFAULT NOW(),
    PRIMARY KEY (guild_id, cid)
);

CREATE INDEX IF NOT EXISTS automod_embeds_guild_idx ON automod_embeds (guild_id);