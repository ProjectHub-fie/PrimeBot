-- PrimeBot staff role service (bot_roles) — one row per assigned user, living
-- in the dedicated COMMUNITY_DATABASE_URL pool (server/communityDb.js).
-- Power order: user < moderator < admin < developer < owner. The owner role is
-- reserved for the ids in config.developerIds and is never assignable via
-- $dev add / /dev add; utils/botRoles.js self-creates this table too, so this
-- migration is a belt-and-braces parity file like the other features.
CREATE TABLE IF NOT EXISTS bot_roles (
    user_id    VARCHAR(32) PRIMARY KEY,
    role       VARCHAR(20) NOT NULL,
    updated_by VARCHAR(32),
    updated_at TIMESTAMP DEFAULT NOW()
);
