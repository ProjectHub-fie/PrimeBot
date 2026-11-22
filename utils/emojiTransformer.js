/**
 * Outgoing-payload emoji transformer.
 *
 * The EmojiManager validates which custom emojis PrimeBot can actually use.
 * This installer applies that mapping to EVERY message Discord receives from
 * the bot — plain replies, slash-command replies, edits, webhook posts and
 * interaction callbacks — at the REST boundary, so a call site cannot forget
 * to opt in.
 *
 * What is rewritten:
 *   • message `content`
 *   • embed title / description / field names + values / footer / author name
 *   • component `emoji` fields (Unicode → validated emoji object)
 *
 * What is NOT rewritten:
 *   • code spans and fenced code blocks (they render literally)
 *   • URLs
 *   • existing custom emoji markup (never double-wrapped)
 *   • component labels/placeholders (Discord does not render custom emoji
 *     markup inside labels — the Unicode fallback stays)
 *   • application-command registration and any non-message route
 */

const MESSAGE_ROUTE_RE = /^\/(?:channels\/\d+\/messages(?:\/\d+)?|webhooks\/\d+\/[^/]+(?:\/messages(?:\/\d+)?)?|interactions\/\d+\/[^/]+\/callback)$/;

/**
 * Install the transformer on a discord.js client's REST layer.
 * Idempotent; safe when `client.rest` is absent (test doubles).
 */
function installEmojiTransformer(client, manager) {
    if (!client || !client.rest || !manager) return false;
    const rest = client.rest;
    if (rest.__primebotEmojiTransformerInstalled) return true;
    rest.__primebotEmojiTransformerInstalled = true;

    for (const method of ['post', 'patch', 'put']) {
        if (typeof rest[method] !== 'function') continue;
        const original = rest[method].bind(rest);
        rest[method] = function emojiAwareRequest(route, options, ...restArgs) {
            try {
                if (MESSAGE_ROUTE_RE.test(String(route)) && options && options.body) {
                    options = { ...options, body: manager.transformPayload(options.body) };
                }
            } catch (_) {
                // A transformer failure must never block a Discord request.
            }
            return original(route, options, ...restArgs);
        };
    }
    return true;
}

module.exports = {
    installEmojiTransformer,
    MESSAGE_ROUTE_RE,
};
