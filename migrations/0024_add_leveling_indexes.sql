-- Neon workload reduction: indexes for the hottest leveling lookups.
--
-- `user_levels` is the most-accessed table in PrimeBot — every XP flush,
-- profile read, `$rank` lookup, leaderboard sort and dashboard stat touches it —
-- and it shipped with no index at all, so each `WHERE guild_id = ? AND
-- user_id = ?` was a full sequential scan and each leaderboard was a full sort.
-- On a Neon instance billed by compute time that is exactly the kind of
-- repeated expensive read worth eliminating.
--
-- All statements are idempotent and additive (no data is touched, nothing is
-- dropped or rewritten), so this is safe to apply to a live database. The same
-- indexes are also created by the self-bootstrapping `initLevelingTables()`
-- (server/levelingDb.js) and `ensureBadgesTable()` (dashboard/db.js), so
-- deployments that never run migrations still get them.

-- Primary lookup: (guild_id, user_id) — XP flush, profile reads.
-- Intentionally NOT unique: the pair was historically unconstrained and a
-- UNIQUE index would fail if any duplicate rows exist.
CREATE INDEX IF NOT EXISTS user_levels_guild_user_idx
    ON user_levels (guild_id, user_id);

-- Leaderboard: WHERE guild_id = ? ORDER BY level DESC, xp DESC.
CREATE INDEX IF NOT EXISTS user_levels_guild_level_idx
    ON user_levels (guild_id, level DESC, xp DESC);

-- Badge list / award / revoke are always scoped to a guild + user.
CREATE INDEX IF NOT EXISTS user_badges_guild_user_idx
    ON user_badges (guild_id, user_id);