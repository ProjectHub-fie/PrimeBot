/**
 * Shared embed-payload helpers (saved embeds, EMBED_DATABASE_URL).
 *
 * A saved embed's `payload` column stores the Embed Builder's *state* shape
 * (camelCase builder fields, e.g. `authorEnabled`/`icon_url`-free keys). The
 * dashboard writes it, and the bot's `$embed` / `/embed` commands read it to
 * render a message in Discord. Both sides therefore need the exact same
 * state -> Discord API embed conversion, which lives here.
 *
 * Pure + dependency-free (no discord.js, no DB), so it is safe to require from
 * the bot, the dashboard, and tests.
 */

const LIMITS = {
    CONTENT: 2000,
    TITLE: 256,
    DESCRIPTION: 4096,
    FIELD_NAME: 256,
    FIELD_VALUE: 1024,
    FIELD_COUNT: 25,
    FOOTER: 2048,
    AUTHOR: 256,
    TOTAL: 6000,
};

const DEFAULT_COLOR = '#5865F2';

function isValidHttpUrl(str) {
    if (!str || typeof str !== 'string') return false;
    try {
        const u = new URL(str);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
}

function colorToHex(color) {
    if (typeof color === 'number' && Number.isFinite(color)) {
        return '#' + ('000000' + (color & 0xffffff).toString(16)).slice(-6);
    }
    if (typeof color === 'string' && /^#[0-9a-fA-F]{6}$/.test(color)) return color.toLowerCase();
    return DEFAULT_COLOR;
}

function hexToInt(hex) {
    return parseInt(colorToHex(hex).slice(1), 16);
}

function truncate(str, max) {
    if (typeof str !== 'string') return '';
    return str.length > max ? str.slice(0, max) : str;
}

/**
 * True when the object is the Embed Builder's own flat state shape.
 *
 * The builder's `readState()` always emits these boolean switches, which no
 * Discord API embed object ever contains — so the check is unambiguous and
 * does not depend on which optional fields happen to be filled in.
 */
function isBuilderState(src) {
    if (!src || typeof src !== 'object') return false;
    return ('authorEnabled' in src) || ('footerEnabled' in src)
        || ('thumbnailEnabled' in src) || ('imageEnabled' in src);
}

/** Normalize the builder's flat state (what the dashboard saves). */
function fromBuilderState(src) {
    return {
        content: typeof src.content === 'string' ? src.content : '',
        title: typeof src.title === 'string' ? src.title : '',
        description: typeof src.description === 'string' ? src.description : '',
        url: typeof src.url === 'string' ? src.url : '',
        color: colorToHex(src.color),
        timestamp: !!src.timestamp,
        authorEnabled: !!src.authorEnabled,
        authorName: typeof src.authorName === 'string' ? src.authorName : '',
        authorUrl: typeof src.authorUrl === 'string' ? src.authorUrl : '',
        authorIcon: typeof src.authorIcon === 'string' ? src.authorIcon : '',
        thumbnailEnabled: !!src.thumbnailEnabled,
        thumbnailUrl: typeof src.thumbnailUrl === 'string' ? src.thumbnailUrl : '',
        imageEnabled: !!src.imageEnabled,
        imageUrl: typeof src.imageUrl === 'string' ? src.imageUrl : '',
        footerEnabled: !!src.footerEnabled,
        footerText: typeof src.footerText === 'string' ? src.footerText : '',
        footerIcon: typeof src.footerIcon === 'string' ? src.footerIcon : '',
        fields: (Array.isArray(src.fields) ? src.fields : []).slice(0, LIMITS.FIELD_COUNT).map((f) => ({
            name: typeof f.name === 'string' ? f.name : '',
            value: typeof f.value === 'string' ? f.value : '',
            inline: !!f.inline,
        })),
    };
}

/**
 * Normalize a stored payload into the builder state shape.
 *
 * Accepts the builder state itself, a full message payload
 * (`{ content, embeds: [...] }`), or a bare Discord API embed object — so a
 * payload imported from Discord JSON still renders correctly.
 */
function normalizeEmbedState(raw) {
    const src = raw && typeof raw === 'object' ? raw : {};
    if (isBuilderState(src)) return fromBuilderState(src);

    const embeds = Array.isArray(src.embeds) ? src.embeds
        : (Array.isArray(src.embed) ? src.embed : (src.embed ? [src.embed] : []));
    let embed;
    if (embeds.length) embed = embeds[0] || {};
    else if (src.title !== undefined || src.description !== undefined || src.fields !== undefined
        || src.color !== undefined || src.footer || src.author || src.image || src.thumbnail) {
        embed = src;
    } else {
        embed = {};
    }

    const fields = Array.isArray(embed.fields) ? embed.fields : [];

    return {
        content: typeof src.content === 'string' ? src.content : '',
        title: typeof embed.title === 'string' ? embed.title : '',
        description: typeof embed.description === 'string' ? embed.description : '',
        url: typeof embed.url === 'string' ? embed.url : '',
        color: colorToHex(embed.color),
        timestamp: embed.timestamp != null ? !!embed.timestamp : false,
        authorEnabled: !!embed.author,
        authorName: (embed.author && embed.author.name) || '',
        authorUrl: (embed.author && (embed.author.url || embed.author.iconURL)) || '',
        authorIcon: (embed.author && (embed.author.icon_url || embed.author.iconURL)) || '',
        thumbnailEnabled: !!embed.thumbnail,
        thumbnailUrl: (embed.thumbnail && (embed.thumbnail.url || embed.thumbnail.proxy_url)) || '',
        imageEnabled: !!embed.image,
        imageUrl: (embed.image && (embed.image.url || embed.image.proxy_url)) || '',
        footerEnabled: !!embed.footer,
        footerText: (embed.footer && embed.footer.text) || '',
        footerIcon: (embed.footer && (embed.footer.icon_url || embed.footer.iconURL)) || '',
        fields: fields.slice(0, LIMITS.FIELD_COUNT).map((f) => ({
            name: typeof f.name === 'string' ? f.name : '',
            value: typeof f.value === 'string' ? f.value : '',
            inline: !!f.inline,
        })),
    };
}

/**
 * Convert a stored payload into a Discord API embed object.
 * Returns null when there is nothing renderable.
 */
function toApiEmbed(raw) {
    const s = normalizeEmbedState(raw);
    const embed = {};

    if (s.authorEnabled && s.authorName) {
        embed.author = { name: truncate(s.authorName, LIMITS.AUTHOR) };
        if (isValidHttpUrl(s.authorUrl)) embed.author.url = s.authorUrl;
        if (isValidHttpUrl(s.authorIcon)) embed.author.icon_url = s.authorIcon;
    }
    if (s.title) embed.title = truncate(s.title, LIMITS.TITLE);
    if (s.description) embed.description = truncate(s.description, LIMITS.DESCRIPTION);
    if (s.url && isValidHttpUrl(s.url)) embed.url = s.url;
    embed.color = hexToInt(s.color);
    if (s.timestamp) embed.timestamp = new Date().toISOString();
    if (s.thumbnailEnabled && isValidHttpUrl(s.thumbnailUrl)) embed.thumbnail = { url: s.thumbnailUrl };
    if (s.imageEnabled && isValidHttpUrl(s.imageUrl)) embed.image = { url: s.imageUrl };
    if (s.footerEnabled && s.footerText) {
        embed.footer = { text: truncate(s.footerText, LIMITS.FOOTER) };
        if (isValidHttpUrl(s.footerIcon)) embed.footer.icon_url = s.footerIcon;
    }
    const fields = s.fields
        .filter((f) => f.name || String(f.value || '').trim())
        .map((f) => ({
            name: truncate(f.name, LIMITS.FIELD_NAME) || '\u200b',
            value: truncate(f.value, LIMITS.FIELD_VALUE) || '\u200b',
            inline: !!f.inline,
        }));
    if (fields.length) embed.fields = fields;

    // An embed needs at least one visible component (colour alone is not enough).
    const visible = embed.title || embed.description || embed.author || embed.footer
        || embed.fields || embed.image || embed.thumbnail;
    if (!visible) return null;
    return embed;
}

/**
 * Convert a stored payload into a sendable message payload.
 * Returns null when the payload has neither content nor a renderable embed.
 */
function toMessagePayload(raw) {
    const s = normalizeEmbedState(raw);
    const content = truncate(s.content, LIMITS.CONTENT);
    const embed = toApiEmbed(s);
    if (!content && !embed) return null;
    const payload = {};
    if (content) payload.content = content;
    if (embed) payload.embeds = [embed];
    return payload;
}

module.exports = {
    LIMITS,
    DEFAULT_COLOR,
    isValidHttpUrl,
    colorToHex,
    hexToInt,
    normalizeEmbedState,
    toApiEmbed,
    toMessagePayload,
};
