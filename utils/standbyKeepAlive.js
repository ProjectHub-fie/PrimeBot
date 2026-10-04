/**
 * Keeps a pure standby (not-yet-connected) node alive.
 *
 * Every timer a standby node owns is `unref`'d — the standby monitor, the
 * failover heartbeat, the settings-cache scheduler — so that once the node has
 * finished booting and is merely waiting for a higher-priority node to go down,
 * nothing keeps the Node event loop alive. The loop empties and the process
 * exits with code 0. A hosting panel (Wispbyte/Pterodactyl) reads that clean
 * exit as a crash ("Detected server process in a crashed state! Exit code: 0")
 * and restarts the container every few seconds, so the standby node never gets
 * the chance to take over when the primary actually dies.
 *
 * This module owns the single ref'd timer that prevents that. The timer is
 * deliberately NOT unref'd — that is the whole point: it is the only thing
 * keeping a standby process alive.
 *
 * It must be cleared the moment the node connects to Discord: the gateway
 * socket is then the real keep-alive, and leaving this interval armed would be
 * a permanent wake source that stops a quiet node from letting Neon suspend.
 */

// Long by design. It is not a work timer; it only needs to fire far less often
// than the process would otherwise exit, and a shorter value would needlessly
// wake the event loop (and, indirectly, any timer-driven DB work) more often.
const KEEP_ALIVE_INTERVAL_MS =
    parseInt(process.env.STANDBY_KEEP_ALIVE_INTERVAL_MS, 10) || 60 * 60 * 1000;

let handle = null;

/** Arm the keep-alive if it is not already armed. Returns the timer handle. */
function arm() {
    if (handle) return handle;
    handle = setInterval(() => {}, KEEP_ALIVE_INTERVAL_MS);
    return handle;
}

/** Clear the keep-alive (the node is now connected). Returns true if one was armed. */
function clear() {
    if (!handle) return false;
    clearInterval(handle);
    handle = null;
    return true;
}

/** Whether the keep-alive is currently armed. */
function isArmed() {
    return handle !== null;
}

module.exports = { arm, clear, isArmed, KEEP_ALIVE_INTERVAL_MS };
