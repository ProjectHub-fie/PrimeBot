-- Migration: Add birthdays and counting tables

CREATE TABLE IF NOT EXISTS birthdays_guilds (
  guild_id varchar(50) PRIMARY KEY,
  announcement_channel varchar(50),
  role_id varchar(50)
);

CREATE TABLE IF NOT EXISTS birthdays (
  id serial PRIMARY KEY,
  guild_id varchar(50) NOT NULL,
  user_id varchar(50) NOT NULL,
  month integer NOT NULL,
  day integer NOT NULL,
  year integer,
  last_celebrated varchar(50),
  CONSTRAINT fk_birthdays_guild FOREIGN KEY (guild_id) REFERENCES birthdays_guilds(guild_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS counting_games (
  channel_id varchar(50) PRIMARY KEY,
  start_number integer NOT NULL DEFAULT 1,
  current_number integer NOT NULL DEFAULT 0,
  goal_number integer NOT NULL DEFAULT 100,
  last_user_id varchar(50),
  highest_number integer NOT NULL DEFAULT 0,
  fail_count integer NOT NULL DEFAULT 0,
  participants jsonb,
  updated_at timestamp with time zone DEFAULT now()
);
