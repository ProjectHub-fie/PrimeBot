// Resolve a target token ("<@id>", "<@!id>", or a bare Discord user id) to
// a snowflake string, or null when it isn't a user reference.
function resolveUserId(token) {
    if (!token) return null;
    const trimmed = String(token).trim();
    const mention = trimmed.match(/^<@!?(\d{15,22})>$/);
    if (mention) return mention[1];
    if (/^\d{15,22}$/.test(trimmed)) return trimmed;
    return null;
}

module.exports = resolveUserId;