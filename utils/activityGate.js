/**
 * Tracks whether the process has seen Discord activity recently.
 *
 * The bot's recurring database work (failover heartbeat, settings-cache
 * refreshes) used to run on a short fixed cadence for the life of the process,
 * whether or not anyone was using the bot. On Neon a compute endpoint only
 * suspends after a period of inactivity, so a fixed 30-second heartbeat kept a
 * paid endpoint awake around the clock and consumed the entire free compute
 * allowance on its own — the reason caching alone never reduced the bill.
 *
 * This gate lets those refresh loops switch cadence: while the bot is handling
 * Discord events (messages, commands, joins) they refresh at the snappy
 * interval, and once the bot has been quiet for a while they drop to a much
 * longer interval so the endpoint can actually suspend between touches.
 *
 * It deliberately knows nothing about the database. `touch()` is called from
 * the Discord event handlers; readers ask `isIdle()`.
 */

// How long with no Discord activity before the refresh loops slow down.
const IDLE_AFTER_MS = parseInt(process.env.BOT_IDLE_AFTER_MS, 10) || 4 * 60 * 1000;

let lastActivityAt = Date.now();

/** Record a Discord activity (any event the bot actually handles). */
function touch() {
    lastActivityAt = Date.now();
}

/** Milliseconds since the last recorded activity. */
function idleMs() {
    return Date.now() - lastActivityAt;
}

/** True once the process has been quiet for `idleAfterMs`. */
function isIdle(idleAfterMs = IDLE_AFTER_MS) {
    return idleMs() >= idleAfterMs;
}

/** Test-only reset. */
function reset() {
    lastActivityAt = Date.now();
}

module.exports = { touch, idleMs, isIdle, reset, IDLE_AFTER_MS };
