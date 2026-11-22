/**
 * Resolve a configured button/embed emoji against the centralized EmojiManager.
 *
 * The manager only contains emojis that were validated against the live guild
 * collections, so an entry returned here is known to be accessible. A missing
 * emoji degrades to the caller's fallback (or no emoji) instead of throwing.
 */

const { getEmojiManager, fallbackFor } = require('./emojiManager');
const { parseEmojiInput, formatEmoji } = require('../shared/emojiValidation');

function resolveConfiguredEmoji(input, fallback) {
    const parsed = parseEmojiInput(input);
    const manager = getEmojiManager();
    if (manager) {
        const entry = parsed
            ? (parsed.id ? manager.getById(parsed.id) : manager.resolve(parsed.name))
            : (typeof input === 'string' ? manager.resolve(input) : null);
        if (entry) {
            return {
                id: entry.id,
                name: entry.name,
                animated: entry.animated === true,
                raw: formatEmoji(entry),
                sourceGuildId: entry.sourceGuildId || null,
            };
        }
    }
    if (fallback !== undefined) return fallback;
    return null;
}

function componentEmojiFor(input, fallback) {
    const resolved = resolveConfiguredEmoji(input, fallback);
    if (!resolved) return null;
    if (typeof resolved === 'string') return resolved;
    return { id: resolved.id, name: resolved.name, animated: resolved.animated };
}

function emojiFallback(name) {
    return fallbackFor(name);
}

module.exports = { resolveConfiguredEmoji, componentEmojiFor, emojiFallback };
