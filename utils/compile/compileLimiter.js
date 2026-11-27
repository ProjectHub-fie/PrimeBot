/**
 * In-memory guard rails for the Code Compile feature.
 *
 * Four independent limits, all per process (no database):
 *   • per-user cooldown between submissions
 *   • per-user concurrent submissions
 *   • per-guild concurrent submissions
 *   • per-user / per-guild sliding request windows
 */

const DEFAULTS = Object.freeze({
    cooldownMs: 10000,
    userConcurrent: 1,
    guildConcurrent: 3,
    userRateLimit: 6,
    guildRateLimit: 20,
    rateWindowMs: 60000,
});

function secondsLabel(ms) {
    const seconds = Math.max(1, Math.ceil(ms / 1000));
    return `${seconds} second${seconds === 1 ? '' : 's'}`;
}

class CompileLimiter {
    constructor(options = {}) {
        this.options = { ...DEFAULTS, ...options };
        this.active = new Map();   // key -> in-flight count
        this.hits = new Map();     // key -> [timestamps]
        this.lastUse = new Map();  // user key -> timestamp of the last accepted request
    }

    _userKey(userId) { return `user:${userId}`; }
    _guildKey(guildId) { return `guild:${guildId || 'dm'}`; }

    _prune(now) {
        const cutoff = now - this.options.rateWindowMs;
        for (const [key, stamps] of this.hits) {
            const kept = stamps.filter(ts => ts > cutoff);
            if (kept.length) this.hits.set(key, kept);
            else this.hits.delete(key);
        }
        for (const [key, count] of this.active) {
            if (count <= 0) this.active.delete(key);
        }
    }

    _count(key) {
        return this.active.get(key) || 0;
    }

    _record(key, now) {
        const stamps = this.hits.get(key) || [];
        stamps.push(now);
        this.hits.set(key, stamps);
    }

    /**
     * Try to start a submission.
     * @returns {{ ok: true, release: Function } | { ok: false, reason: string, retryAfterMs: number, message: string }}
     */
    acquire({ userId, guildId = null, now = Date.now() } = {}) {
        if (!userId) throw new TypeError('CompileLimiter.acquire needs a userId');
        this._prune(now);

        const userKey = this._userKey(userId);
        const guildKey = this._guildKey(guildId);

        const last = this.lastUse.get(userKey);
        if (this.options.cooldownMs > 0 && last != null && (now - last) < this.options.cooldownMs) {
            const retryAfterMs = this.options.cooldownMs - (now - last);
            return {
                ok: false,
                reason: 'cooldown',
                retryAfterMs,
                message: `Please wait **${secondsLabel(retryAfterMs)}** before compiling again.`,
            };
        }

        if (this._count(userKey) >= this.options.userConcurrent) {
            return {
                ok: false,
                reason: 'concurrency',
                retryAfterMs: 0,
                message: 'Your previous compile is still running. Wait for it to finish, then try again.',
            };
        }

        if (guildId && this._count(guildKey) >= this.options.guildConcurrent) {
            return {
                ok: false,
                reason: 'concurrency',
                retryAfterMs: 0,
                message: 'Too many compiles are running in this server right now. Try again in a moment.',
            };
        }

        const userHits = (this.hits.get(userKey) || []).length;
        if (userHits >= this.options.userRateLimit) {
            const oldest = this.hits.get(userKey)[0] || now;
            const retryAfterMs = Math.max(0, this.options.rateWindowMs - (now - oldest));
            return {
                ok: false,
                reason: 'rate_limit',
                retryAfterMs,
                message: `You have reached the compile limit (${this.options.userRateLimit} per ${secondsLabel(this.options.rateWindowMs)}). Try again in **${secondsLabel(retryAfterMs)}**.`,
            };
        }

        const guildHits = (this.hits.get(guildKey) || []).length;
        if (guildId && guildHits >= this.options.guildRateLimit) {
            const oldest = this.hits.get(guildKey)[0] || now;
            const retryAfterMs = Math.max(0, this.options.rateWindowMs - (now - oldest));
            return {
                ok: false,
                reason: 'rate_limit',
                retryAfterMs,
                message: `This server has reached the compile limit (${this.options.guildRateLimit} per ${secondsLabel(this.options.rateWindowMs)}). Try again in **${secondsLabel(retryAfterMs)}**.`,
            };
        }

        this.active.set(userKey, this._count(userKey) + 1);
        if (guildId) this.active.set(guildKey, this._count(guildKey) + 1);
        this.lastUse.set(userKey, now);
        this._record(userKey, now);
        this._record(guildKey, now);

        let released = false;
        return {
            ok: true,
            release: () => {
                if (released) return;
                released = true;
                this.active.set(userKey, Math.max(0, this._count(userKey) - 1));
                if (guildId) this.active.set(guildKey, Math.max(0, this._count(guildKey) - 1));
            },
        };
    }

    /** Test / diagnostics helper. */
    snapshot(now = Date.now()) {
        this._prune(now);
        return {
            active: Object.fromEntries(this.active),
            hits: Object.fromEntries([...this.hits].map(([k, v]) => [k, v.length])),
        };
    }
}

module.exports = { CompileLimiter, DEFAULTS, secondsLabel };
