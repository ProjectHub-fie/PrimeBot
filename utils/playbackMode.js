/**
 * Per-guild playback MODE registry + transition lock.
 *
 * A guild has exactly ONE voice connection, so at most one audio feature may
 * own it: the 24/7 Radio (a SoundCloud stream via @discordjs/voice) OR on-demand
 * Music (a Lavalink player). They must never run together — two `op 4` voice
 * updates for the same guild leave the bot in one channel with two competing
 * audio sources, which is heard as silence or a stutter.
 *
 * `PlaybackModeRegistry` tracks the active mode per guild (`idle`/`music`/
 * `radio`) and serialises mode TRANSITIONS through `runExclusive`. The lock is
 * a per-guild promise chain, so two commands that arrive together (a rapid
 * `$play` + `$radio start`, or two `$play`s) run one after the other instead of
 * racing — the second transition then sees the first one's committed mode and
 * tears it down correctly.
 *
 * IMPORTANT: only the mode ENTRY points take the lock (MusicManager.play /
 * RadioManager.start). The stop side is a plain internal call so a transition
 * can never deadlock on its own lock.
 */

const { PLAYBACK_MODES } = require('../shared/musicConstants');

class PlaybackModeRegistry {
    constructor() {
        /** guildId → PLAYBACK_MODES.* */
        this._modes = new Map();
        /** guildId → tail promise of the in-flight transition chain. */
        this._locks = new Map();
    }

    /** The committed mode for a guild (defaults to IDLE). */
    getMode(guildId) {
        return this._modes.get(String(guildId)) || PLAYBACK_MODES.IDLE;
    }

    /** Commit a mode for a guild. */
    setMode(guildId, mode) {
        const key = String(guildId);
        if (mode === PLAYBACK_MODES.IDLE) this._modes.delete(key);
        else this._modes.set(key, mode);
        return mode;
    }

    /** Is a mode transition currently queued/running for this guild? */
    isTransitioning(guildId) {
        return this._locks.has(String(guildId));
    }

    /**
     * Run `fn` as a serialized transition for `guildId`. Calls for the same
     * guild are chained (never concurrent); calls for different guilds are
     * independent. Always resolves/rejects with `fn`'s own result — the lock
     * itself never throws.
     */
    runExclusive(guildId, fn) {
        const key = String(guildId);
        const tail = this._locks.get(key) || Promise.resolve();
        // Chain on both fulfil and reject so a failed transition never wedges
        // the queue for that guild.
        const run = tail.then(() => fn(), () => fn());
        const settled = run.then(() => {}, () => {});
        this._locks.set(key, settled);
        // Release the map entry once we are the tail again (no new waiter).
        settled.then(() => {
            if (this._locks.get(key) === settled) this._locks.delete(key);
        });
        return run;
    }

    /** Test/teardown helper — forget a guild entirely. */
    reset(guildId) {
        const key = String(guildId);
        this._modes.delete(key);
        this._locks.delete(key);
    }
}

/** Process-wide shared registry (both managers default to this instance). */
let _shared = null;
function getPlaybackModeRegistry() {
    if (!_shared) _shared = new PlaybackModeRegistry();
    return _shared;
}

module.exports = { PlaybackModeRegistry, getPlaybackModeRegistry };
