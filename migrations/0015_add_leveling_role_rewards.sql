-- Leveling role rewards persisted in the dedicated LEVELING_DATABASE_URL pool.
-- Previously roleRewards lived only in the bot's in-memory cache (and were lost
-- on restart / never synced to the dashboard). This table makes them durable
-- and lets the bot re-read them on a cache reload (like welcome settings).
CREATE TABLE IF NOT EXISTS leveling_role_rewards (
    id          SERIAL PRIMARY KEY,
    guild_id    VARCHAR(50) NOT NULL,
    level       INTEGER NOT NULL,
    role_id     VARCHAR(50) NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW(),
    UNIQUE (guild_id, level)
);

CREATE INDEX IF NOT EXISTS leveling_role_rewards_guild_idx
    ON leveling_role_rewards (guild_id);
