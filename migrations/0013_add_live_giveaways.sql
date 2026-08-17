-- Migration 0013: Live Giveaways feature.
--
-- Cross-server giveaways created with $lgiveway / /lgiveway. Mirrors the live
-- polls system (shareable via giveaway ID + pass code, joinable from any
-- server), but lives in the dedicated LIVE_DATABASE_URL pool (server/liveDb.js;
-- falls back to DATABASE_URL). Both the bot (utils/liveGiveawayManager.js) and
-- the dashboard (dashboard/db.js) read and write these tables. Both deployments
-- must point at the same LIVE_DATABASE_URL so dashboard views reflect the bot's
-- state and any dashboard-driven changes reach the bot through its periodic
-- cache reload.
--
-- A live giveaway has participants (users who ran `$lgiveway join <key>` or
-- clicked the Join button on a join interface) and, when ended, winners.

CREATE TABLE IF NOT EXISTS live_giveaways (
    id              SERIAL PRIMARY KEY,
    giveaway_id     VARCHAR(100) NOT NULL UNIQUE,
    pass_code       VARCHAR(20) NOT NULL,
    prize           TEXT NOT NULL,
    description     TEXT,
    creator_id      VARCHAR(50) NOT NULL,
    winner_count    INTEGER NOT NULL DEFAULT 1,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    ended           BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    ends_at         TIMESTAMPTZ,
    message_id      VARCHAR(50),
    channel_id      VARCHAR(50)
);
CREATE INDEX IF NOT EXISTS live_giveaways_creator_idx ON live_giveaways (creator_id);
CREATE INDEX IF NOT EXISTS live_giveaways_active_idx ON live_giveaways (is_active) WHERE is_active = true;

CREATE TABLE IF NOT EXISTS live_giveaway_participants (
    id          SERIAL PRIMARY KEY,
    giveaway_id VARCHAR(100) NOT NULL,
    user_id     VARCHAR(50) NOT NULL,
    joined_at   TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (giveaway_id, user_id)
);
CREATE INDEX IF NOT EXISTS live_giveaway_participants_giveaway_idx ON live_giveaway_participants (giveaway_id);

CREATE TABLE IF NOT EXISTS live_giveaway_winners (
    id          SERIAL PRIMARY KEY,
    giveaway_id VARCHAR(100) NOT NULL,
    user_id     VARCHAR(50) NOT NULL,
    selected_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS live_giveaway_winners_giveaway_idx ON live_giveaway_winners (giveaway_id);
