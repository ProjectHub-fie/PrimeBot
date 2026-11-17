/**
 * Voice defense — the bot is DEFENDED in voice by default.
 *
 * "Defended" means the bot's own voice state is **self-deafened** (`selfDeaf`).
 * A music/radio bot never needs to hear anyone, and a deafened member cannot be
 * un-deafened by the Discord client's automatic behaviour — so the bot can never
 * accidentally receive/relay audio or be dragged into voice interaction. We
 * deliberately do NOT self-mute: the bot must still TRANSMIT its playback, so
 * `selfMute` stays false (matching the `selfDeaf: true, selfMute: false` the
 * join calls already use).
 *
 * The `joinVoiceChannel()` calls pass `selfDeaf: true`, but nothing re-asserted
 * it at runtime. An admin toggling the bot's state in the Discord UI, a server
 * undeafen, or a fresh connection could therefore leave the bot undeafened.
 * This module makes "defended" a guaranteed default:
 *
 *   1. `defendGuild()` / `defendVoiceState()` re-assert the deafen (called after
 *      every successful voice join), and
 *   2. `handleVoiceStateUpdate()` watches the BOT's own voice state and
 *      re-asserts the deafen whenever it is lost.
 *
 * Every call is fire-and-forget, throttled per guild, and can never throw into
 * an event handler. Disable with `VOICE_DEFEND_ENABLED=false` (not recommended).
 */

const DEFAULT_COOLDOWN_MS = 30000;
const REASON = 'PrimeBot voice defense — the bot is always self-deafened.';

/**
 * The voice-join options that make the bot "defended". Kept here so the join
 * calls cannot drift from the runtime enforcement: the bot is always
 * self-deafened and never self-muted (it must still transmit playback).
 */
const JOIN_OPTIONS = Object.freeze({ selfDeaf: true, selfMute: false });

/** Per-guild last-assert timestamps (bounded by the number of guilds). */
const _lastAssert = new Map();

function isEnabled() {
    const raw = process.env.VOICE_DEFEND_ENABLED;
    if (raw == null || raw === '') return true;
    return String(raw).toLowerCase() !== 'false';
}

function cooldownMs() {
    const v = parseInt(process.env.VOICE_DEFEND_COOLDOWN_MS, 10);
    return Number.isFinite(v) && v >= 0 ? v : DEFAULT_COOLDOWN_MS;
}

/**
 * True when a voice state is already defended. Discord applies
 * `deaf = self_deaf || server_deaf`, so the bot is defended when EITHER flag is
 * set — it cannot hear anyone in either case. (`selfDeaf` is set at join time;
 * `deaf` is the server-deafen we re-assert at runtime, since discord.js exposes
 * no direct API for a bot to re-set its own `self_deaf` without rejoining.)
 */
function isDefended(state) {
    return !!(state && (state.selfDeaf === true || state.deaf === true));
}

/**
 * Low-level: re-assert the defended state on a discord.js VoiceState.
 * Returns true when a deafen was issued, false when already defended / throttled
 * / impossible. Never throws.
 */
async function defendVoiceState(voiceState, { force = false } = {}) {
    if (!isEnabled()) return false;
    if (!voiceState || typeof voiceState.setDeaf !== 'function') return false;
    if (isDefended(voiceState)) return false;

    const guildId = (voiceState.guild && voiceState.guild.id) || voiceState.guildId || 'unknown';
    const key = String(guildId);
    const now = Date.now();
    if (!force) {
        const last = _lastAssert.get(key) || 0;
        if (now - last < cooldownMs()) return false;
    }
    _lastAssert.set(key, now);
    try {
        await voiceState.setDeaf(true, REASON);
        return true;
    } catch (err) {
        // Missing Move Members, a disconnected member, or a transient REST
        // failure — never fatal, the next voiceStateUpdate retries.
        console.warn(`[VOICE] could not re-assert deafen for guild ${guildId}: ${err.message}`);
        return false;
    }
}

/**
 * Re-assert the defended state for a guild's bot member. Used right after a
 * successful voice join (before the first voiceStateUpdate arrives).
 */
async function defendGuild(client, guildId, { force = false } = {}) {
    if (!isEnabled()) return false;
    if (!client || !guildId) return false;
    try {
        const guild = client.guilds && client.guilds.cache && client.guilds.cache.get(guildId);
        if (!guild) return false;
        const me = guild.members && (guild.members.me || guild.members.cache?.get(client.user?.id));
        const state = me && me.voice;
        if (!state) return false;
        return await defendVoiceState(state, { force });
    } catch (err) {
        console.warn(`[VOICE] could not resolve voice state for guild ${guildId}: ${err.message}`);
        return false;
    }
}

/**
 * voiceStateUpdate entry point. Only the BOT's own, connected state is policed:
 * when the deafen has been lost it is re-asserted (throttled). Fire-and-forget.
 */
function handleVoiceStateUpdate(oldState, newState) {
    try {
        const client = (newState && newState.client) || (oldState && oldState.client);
        if (!client || !client.user) return;
        const state = newState || oldState;
        if (!state || state.id !== client.user.id) return; // only the bot itself
        if (!state.channelId) return;                      // not connected → nothing to defend
        if (isDefended(state)) return;
        defendVoiceState(state).catch(() => {});
    } catch (err) {
        console.error('[VOICE] defense handler failed:', err.message);
    }
}

/** Test helper — clear the throttle so a fresh scenario is not rate-limited. */
function resetCooldowns() {
    _lastAssert.clear();
}

module.exports = {
    isEnabled, cooldownMs, isDefended,
    defendVoiceState, defendGuild, handleVoiceStateUpdate, resetCooldowns,
    DEFAULT_COOLDOWN_MS, REASON, JOIN_OPTIONS,
};
