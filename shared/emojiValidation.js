/**
 * Shared custom-emoji parsing/formatting.
 *
 * A configured emoji may arrive as a component object, a Discord token
 * (`<:name:id>` / `<a:name:id>`), a bare `name:id`, an id, or a name. The
 * dashboard validates against the live guild collections; the bot validates
 * against the EmojiManager cache. Both use these helpers so the stored form is
 * always the canonical Discord token.
 */

const CUSTOM_EMOJI_RE = /<(a?):([A-Za-z0-9_~]+):(\d{15,22})>/;
const NAME_ID_RE = /^([A-Za-z0-9_~]+):(\d{15,22})$/;
const ID_RE = /^\d{15,22}$/;
const NAME_RE = /^[A-Za-z0-9_~]{2,32}$/;

function parseEmojiInput(input) {
    if (input == null) return null;
    if (typeof input === 'object') {
        const id = input.id != null ? String(input.id) : null;
        const name = input.name != null ? String(input.name) : null;
        if (id && ID_RE.test(id)) return { id, name, animated: input.animated === true };
        return null;
    }
    const value = String(input).trim();
    if (!value) return null;

    const custom = CUSTOM_EMOJI_RE.exec(value);
    if (custom) return { animated: custom[1] === 'a', name: custom[2], id: custom[3] };

    const nameId = NAME_ID_RE.exec(value);
    if (nameId) return { animated: false, name: nameId[1], id: nameId[2] };

    if (ID_RE.test(value)) return { animated: false, name: null, id: value };
    if (NAME_RE.test(value)) return { animated: false, name: value, id: null };
    return null;
}

function formatEmoji(entry) {
    if (!entry || !entry.id) return '';
    const name = entry.name || 'emoji';
    return `<${entry.animated ? 'a' : ''}:${name}:${entry.id}>`;
}

function normalizeEmojiEntry(entry) {
    if (!entry || !entry.id) return null;
    return {
        id: String(entry.id),
        name: entry.name != null ? String(entry.name) : null,
        animated: entry.animated === true,
        sourceGuildId: entry.sourceGuildId != null ? String(entry.sourceGuildId) : null,
        semanticKey: entry.semanticKey || entry.key || null,
        category: entry.category || null,
    };
}

function resolveEmojiInput(input, { byId, byName } = {}) {
    const parsed = parseEmojiInput(input);
    if (!parsed) return null;
    if (parsed.id && byId && byId.has(parsed.id)) return normalizeEmojiEntry(byId.get(parsed.id));
    if (parsed.name && byName && byName.has(parsed.name)) return normalizeEmojiEntry(byName.get(parsed.name));
    return null;
}

module.exports = {
    CUSTOM_EMOJI_RE,
    parseEmojiInput,
    formatEmoji,
    normalizeEmojiEntry,
    resolveEmojiInput,
};
