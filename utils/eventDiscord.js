/**
 * Event Management — Discord side-effects with rate-limit protection.
 *
 * Role assignment and DM fan-out are the two operations that can hit Discord
 * many times at once (an event with hundreds of participants). Both run through
 * a small serial queue with a fixed delay between calls so a large event never
 * bursts the REST API, and every call is individually caught so one failure
 * can never abort the batch.
 *
 * A no-op stub is returned when discord.js is unavailable (tests) so requiring
 * this module never throws.
 */

let ChannelType = null;
try {
    ({ ChannelType } = require('discord.js'));
} catch { /* discord.js unavailable (tests) — all ops become no-ops */ }

// Role ops: Discord's per-guild role-modify bucket tolerates ~1/sec safely.
const ROLE_OP_DELAY_MS = parseInt(process.env.EVENT_ROLE_OP_DELAY_MS, 10) || 1100;
// DM fan-out: participant DMs are fire-and-forget, paced modestly.
const DM_DELAY_MS = parseInt(process.env.EVENT_DM_DELAY_MS, 10) || 150;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * A tiny serial queue: tasks run one at a time with a fixed spacing. Each task
 * is awaited and its rejection swallowed (optionally reported), so the queue
 * never stalls and callers never see an unhandled rejection.
 */
class SerialQueue {
    constructor({ delayMs = 0, onError = null, name = 'queue' } = {}) {
        this.delayMs = delayMs;
        this.onError = onError;
        this.name = name;
        this._chain = Promise.resolve();
        this._pending = 0;
    }

    get size() { return this._pending; }

    push(task) {
        this._pending++;
        this._chain = this._chain.then(async () => {
            try {
                await task();
            } catch (err) {
                if (this.onError) this.onError(err);
            } finally {
                this._pending--;
                if (this.delayMs > 0) await sleep(this.delayMs);
            }
        });
        return this._chain;
    }

    /** Resolve when everything queued so far has run. */
    drain() { return this._chain; }
}

/**
 * Apply or remove a role for a user, guarding against the three failure modes:
 * the role is missing, the member is missing, or the bot's role hierarchy is
 * too low (Discord error 50013/50007). Returns true when it succeeded.
 */
async function applyRole(guild, userId, roleId, { add = true, reason = 'PrimeBot Event' } = {}) {
    if (!guild || !roleId || !userId) return false;
    try {
        const role = guild.roles.cache.get(roleId) || await guild.roles.fetch(roleId).catch(() => null);
        if (!role) return false;
        // Never attempt an operation the bot cannot perform: the bot's highest
        // role must sit above the target role, and it needs Manage Roles.
        const me = guild.members.me;
        if (me && role.position >= me.roles.highest.position) return false;
        if (me && !me.permissions.has('ManageRoles')) return false;
        const member = await guild.members.fetch(userId).catch(() => null);
        if (!member) return false;
        if (add) {
            if (member.roles.cache.has(roleId)) return true;
            await member.roles.add(role, reason);
        } else {
            if (!member.roles.cache.has(roleId)) return true;
            await member.roles.remove(role, reason);
        }
        return true;
    } catch (err) {
        console.warn(`[EVENTMGMT] role ${add ? 'add' : 'remove'} (${roleId}) for ${userId} failed:`, err.message);
        return false;
    }
}

/** Post a message to a channel id, at most once per key per process lifetime. */
class DedupSender {
    constructor() {
        this._sent = new Set();
    }
    has(key) { return this._sent.has(key); }
    mark(key) { this._sent.add(key); }
    /** Prune old keys so the set cannot grow unbounded. */
    prune(keep = 5000) {
        if (this._sent.size <= keep) return;
        const arr = Array.from(this._sent);
        this._sent = new Set(arr.slice(arr.length - keep));
    }
}

/** Only text/news channels are valid announcement targets. */
function isSendableChannel(channel) {
    if (!channel) return false;
    const type = channel.type;
    if (ChannelType) {
        return type === ChannelType.GuildText || type === ChannelType.GuildAnnouncement
            || type === ChannelType.GuildNews || type === ChannelType.PublicThread
            || type === ChannelType.PrivateThread;
    }
    // Fallback numeric types: 0 text, 5 news, 10/11/12 threads.
    return [0, 5, 10, 11, 12].includes(type);
}

module.exports = { SerialQueue, applyRole, DedupSender, isSendableChannel, sleep, ROLE_OP_DELAY_MS, DM_DELAY_MS };
