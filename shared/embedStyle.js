/**
 * Embed presentation policy — PrimeBot embeds carry no colour.
 *
 * Discord renders an embed's `color` as a coloured bar down the left edge.
 * PrimeBot uses a monochrome Linix-style card instead, so every outgoing
 * payload is passed through `stripEmbedColors` before it reaches Discord.
 * The transform is intentionally narrow: it removes `color` only and leaves
 * every other embed field (title, description, fields, footer, author, images,
 * timestamp, components) untouched.
 */

function stripEmbedColor(embed) {
    if (!embed || typeof embed !== 'object' || Array.isArray(embed)) return embed;
    if (!Object.prototype.hasOwnProperty.call(embed, 'color')) return embed;
    const copy = { ...embed };
    delete copy.color;
    return copy;
}

function stripEmbedColors(payload) {
    if (!payload || typeof payload !== 'object') return payload;
    if (Array.isArray(payload)) return payload.map(stripEmbedColors);

    const out = { ...payload };
    if (Array.isArray(out.embeds)) out.embeds = out.embeds.map(stripEmbedColor);
    if (out.embed) out.embed = stripEmbedColor(out.embed);
    return out;
}

module.exports = { stripEmbedColor, stripEmbedColors };
