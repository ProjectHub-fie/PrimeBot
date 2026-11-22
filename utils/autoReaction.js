/**
 * Auto-reaction application.
 *
 * The settings manager returns the configured emoji strings. This module
 * validates a custom emoji against the centralized EmojiManager before asking
 * Discord to react, checks the channel permissions once, and degrades a
 * missing/inaccessible custom emoji to its Unicode fallback instead of
 * throwing into the message handler.
 */

const { PermissionFlagsBits } = require('discord.js');
const { parseEmojiInput } = require('../shared/emojiValidation');
const { getEmojiManager, fallbackFor } = require('./emoji');

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function channelPermissions(message) {
    const me = message?.guild?.members?.me;
    if (!me || !message.channel || typeof message.channel.permissionsFor !== 'function') return null;
    try {
        return message.channel.permissionsFor(me);
    } catch (_) {
        return null;
    }
}

function canReact(message) {
    const perms = channelPermissions(message);
    if (!perms) return true; // unknown permissions: let Discord decide
    return perms.has(PermissionFlagsBits.ViewChannel)
        && perms.has(PermissionFlagsBits.AddReactions)
        && perms.has(PermissionFlagsBits.ReadMessageHistory);
}

/**
 * Resolve one configured emoji for `message.guild`.
 * - Unicode → returned unchanged (Discord handles it).
 * - Validated custom emoji → `{ id, name, animated }`.
 * - Custom emoji from an external emoji server without UseExternalEmojis →
 *   its Unicode fallback, or null when no fallback exists.
 * - Unknown/deleted custom emoji → null.
 */
function resolveReactionEmoji(raw, guild) {
    const parsed = parseEmojiInput(raw);
    if (!parsed) return raw;
    const manager = getEmojiManager();
    if (!manager) return null;
    const entry = parsed.id ? manager.getById(parsed.id) : manager.getByName(parsed.name);
    if (!entry) return null;
    // Only enforce the external-emoji permission when the bot member is
    // actually resolvable; an unhydrated cache should not turn a usable
    // custom emoji into a Unicode fallback.
    if (guild?.members?.me && typeof manager.canUseIn === 'function' && !manager.canUseIn(guild)) {
        const fallback = fallbackFor(entry.key || entry.name);
        return fallback || null;
    }
    return { id: entry.id, name: entry.name, animated: entry.animated };
}

/**
 * Apply every configured reaction in order. Never throws.
 * @returns {Promise<{applied:number, skipped:number}>}
 */
async function applyAutoReactions(message, rawEmojis, options = {}) {
    const delayMs = Number.isFinite(options.delayMs) ? options.delayMs : 500;
    const logger = options.logger || console;
    const result = { applied: 0, skipped: 0 };
    if (!message || !Array.isArray(rawEmojis) || rawEmojis.length === 0) return result;
    if (!canReact(message)) {
        logger.warn?.('[AUTO-REACT] Missing View Channel / Read Message History / Add Reactions permission — skipping.');
        result.skipped = rawEmojis.length;
        return result;
    }

    for (let i = 0; i < rawEmojis.length; i++) {
        const emoji = resolveReactionEmoji(rawEmojis[i], message.guild);
        if (!emoji) {
            result.skipped++;
            logger.warn?.(`[AUTO-REACT] Emoji unavailable to PrimeBot — skipping ${String(rawEmojis[i]).slice(0, 80)}`);
        } else {
            try {
                await message.react(emoji);
                result.applied++;
            } catch (err) {
                result.skipped++;
                logger.error?.(`[AUTO-REACT] Failed to add reaction: ${err.message}`);
            }
        }
        if (i < rawEmojis.length - 1 && delayMs > 0) await sleep(delayMs);
    }
    return result;
}

module.exports = {
    applyAutoReactions,
    resolveReactionEmoji,
    canReact,
};
