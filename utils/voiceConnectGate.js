/**
 * Per-guild single-flight gate for voice connection attempts.
 *
 * The voice handshake is asynchronous (signalling → connecting → ready). When
 * two commands arrive close together — e.g. `/join` immediately followed by
 * `/music 247 enable`, or a repeated `247 enable`, or a `/play` while the
 * connection is still establishing — the naive "check, then join" pattern runs
 * two handshakes for the same guild. The second one destroys the first
 * connection while it is still in flight, and the first handshake's
 * `entersState(Ready)` then rejects with `The operation was aborted` even
 * though nothing was actually wrong.
 *
 * This gate guarantees exactly one in-flight attempt per guild: callers that
 * arrive while an attempt is pending await that same attempt instead of
 * starting another. The lock is always released when the attempt settles, and
 * only by the attempt that still owns it (so a stale attempt can never clear a
 * newer one's lock).
 */
class VoiceConnectGate {
    constructor() {
        /** @type {Map<string, { promise: Promise<any>, id: number }>} */
        this._attempts = new Map();
        this._seq = 0;
    }

    /** Is an attempt currently in flight for this guild? */
    isPending(guildId) {
        return this._attempts.has(String(guildId));
    }

    /** The attempt id currently in flight for this guild, or null. */
    pendingId(guildId) {
        const entry = this._attempts.get(String(guildId));
        return entry ? entry.id : null;
    }

    /**
     * Run `factory` as the single in-flight attempt for `guildId`.
     *
     * @param {string} guildId
     * @param {(ctx: { id: number, reused: boolean }) => Promise<any>} factory
     * @returns {Promise<any>}
     */
    run(guildId, factory) {
        const key = String(guildId);
        const existing = this._attempts.get(key);
        if (existing) return existing.promise;

        const id = ++this._seq;
        const promise = (async () => {
            try {
                return await factory({ id, reused: false });
            } finally {
                // Only the owning attempt releases the lock. If a newer attempt
                // somehow replaced ours, leave theirs intact.
                const current = this._attempts.get(key);
                if (current && current.id === id) this._attempts.delete(key);
            }
        })();

        this._attempts.set(key, { promise, id });
        return promise;
    }

    /** Drop a guild's lock (used by tests and hard resets). */
    clear(guildId) {
        this._attempts.delete(String(guildId));
    }
}

module.exports = { VoiceConnectGate };
