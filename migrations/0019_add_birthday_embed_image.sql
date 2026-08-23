-- Birthdays: dedicated pool + custom embed image.
--
-- The birthdays_guilds + birthdays tables now live in the dedicated
-- BIRTHDAY_DATABASE_URL pool (server/birthdayDb.js, falls back to
-- DATABASE_URL). This migration also adds the dashboard-configurable
-- embed_image_url column — when set, the image overrides the built-in
-- image on every birthday announcement embed for the guild.

CREATE TABLE IF NOT EXISTS birthdays_guilds (
    guild_id varchar(50) PRIMARY KEY,
    announcement_channel varchar(50),
    role_id varchar(50),
    embed_image_url text
);

ALTER TABLE birthdays_guilds ADD COLUMN IF NOT EXISTS embed_image_url text;

CREATE TABLE IF NOT EXISTS birthdays (
    id serial PRIMARY KEY,
    guild_id varchar(50) NOT NULL,
    user_id varchar(50) NOT NULL,
    month integer NOT NULL,
    day integer NOT NULL,
    year integer,
    last_celebrated varchar(50)
);

CREATE UNIQUE INDEX IF NOT EXISTS birthdays_guild_user_uniq ON birthdays (guild_id, user_id);
