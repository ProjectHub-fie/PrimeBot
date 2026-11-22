/**
 * Components V2 embed card with integrated buttons.
 *
 * Discord does not support buttons inside a traditional embed. Components V2
 * (Container / TextDisplay / Section / MediaGallery / Separator / ActionRow)
 * is the supported way to render one unified card whose buttons sit inside the
 * same visual container. This module converts an existing embed (or embed
 * builder) plus its action rows into that V2 payload while preserving every
 * button customId and callback.
 *
 * The resulting message has no `content` and no `embeds` — Discord rejects
 * those alongside `MessageFlags.IsComponentsV2`. Embed text becomes
 * TextDisplay components; the colour is intentionally dropped.
 */

const {
    ActionRowBuilder,
    ButtonBuilder,
    ButtonStyle,
    ContainerBuilder,
    MediaGalleryBuilder,
    MessageFlags,
    SectionBuilder,
    SeparatorBuilder,
    TextDisplayBuilder,
    ThumbnailBuilder,
} = require('discord.js');
const { parseEmojiInput } = require('../shared/emojiValidation');
const { componentEmojiFor } = require('./buttonEmoji');

const MAX_TEXT = 4000;
const MAX_TITLE = 256;
const MAX_FIELD_NAME = 256;
const MAX_FIELD_VALUE = 1024;
const MAX_FOOTER = 2048;
const MAX_CONTAINER_CHILDREN = 40;
const MAX_ACTION_ROWS = 5;
const MAX_BUTTONS_PER_ROW = 5;
const SELECT_TYPES = new Set([3, 5, 6, 7, 8]);
const STYLE_NAMES = {
    primary: ButtonStyle.Primary,
    secondary: ButtonStyle.Secondary,
    success: ButtonStyle.Success,
    danger: ButtonStyle.Danger,
    link: ButtonStyle.Link,
};

function clamp(value, max) {
    const text = value == null ? '' : String(value);
    return text.length > max ? text.slice(0, max) : text;
}

function toJSON(value) {
    if (!value || typeof value !== 'object') return null;
    try {
        return typeof value.toJSON === 'function' ? value.toJSON() : value;
    } catch (_) {
        return value;
    }
}

function textDisplay(content) {
    const text = clamp(content, MAX_TEXT);
    return text ? new TextDisplayBuilder().setContent(text) : null;
}

function separator() {
    return new SeparatorBuilder().setDivider(true);
}

function normalizeStyle(style, hasUrl) {
    if (hasUrl) return ButtonStyle.Link;
    if (typeof style === 'string') return STYLE_NAMES[style.toLowerCase()] || ButtonStyle.Secondary;
    if (typeof style === 'number' && style >= 1 && style <= 5) return style;
    return ButtonStyle.Secondary;
}

function buttonFrom(input) {
    const json = toJSON(input);
    if (!json || (json.type && json.type !== 2)) return null;
    const customId = json.custom_id || json.customId || json.action;
    const url = json.url;
    if (!customId && !url) return null;

    const button = new ButtonBuilder();
    if (url) {
        button.setURL(String(url));
        button.setStyle(ButtonStyle.Link);
    } else {
        button.setCustomId(String(customId));
        button.setStyle(normalizeStyle(json.style, false));
    }
    if (json.label != null) button.setLabel(clamp(json.label, 80));
    if (json.disabled === true) button.setDisabled(true);
    if (json.emoji != null) {
        const parsed = parseEmojiInput(json.emoji);
        if (parsed) {
            const resolved = componentEmojiFor(json.emoji);
            if (resolved) button.setEmoji(resolved);
        } else {
            // ButtonBuilder serializes a Unicode emoji as { name, animated }.
            const unicode = typeof json.emoji === 'string' ? json.emoji : json.emoji.name;
            const resolved = unicode ? componentEmojiFor(unicode) : null;
            if (resolved) button.setEmoji(resolved);
            else if (unicode) button.setEmoji(unicode);
        }
    }
    return button;
}

function selectFrom(json) {
    if (!json || !SELECT_TYPES.has(json.type)) return null;
    return { type: 1, components: [json] };
}

function rowsFromComponents(components) {
    const rows = [];
    const pushRow = (row) => {
        if (row && rows.length < MAX_ACTION_ROWS) rows.push(row);
    };

    for (const input of Array.isArray(components) ? components : []) {
        const json = toJSON(input);
        if (!json) continue;
        if (json.type === 2) {
            const button = buttonFrom(json);
            if (button) pushRow(new ActionRowBuilder().addComponents(button));
            continue;
        }
        if (SELECT_TYPES.has(json.type)) {
            const row = selectFrom(json);
            if (row) pushRow(row);
            continue;
        }
        if (json.type === 17 && Array.isArray(json.components)) {
            for (const row of rowsFromComponents(json.components)) pushRow(row);
            continue;
        }
        if (json.type !== 1 || !Array.isArray(json.components)) continue;

        const select = json.components.find(c => c && SELECT_TYPES.has(c.type));
        if (select) {
            const row = selectFrom(select);
            if (row) pushRow(row);
            continue;
        }

        const buttons = json.components
            .filter(c => c && c.type === 2)
            .map(buttonFrom)
            .filter(Boolean);
        for (let i = 0; i < buttons.length; i += MAX_BUTTONS_PER_ROW) {
            pushRow(new ActionRowBuilder().addComponents(...buttons.slice(i, i + MAX_BUTTONS_PER_ROW)));
        }
    }
    return rows;
}

function rowsFromButtons(buttons) {
    const rows = [];
    const built = (Array.isArray(buttons) ? buttons : []).map(buttonFrom).filter(Boolean);
    for (let i = 0; i < built.length && rows.length < MAX_ACTION_ROWS; i += MAX_BUTTONS_PER_ROW) {
        rows.push(new ActionRowBuilder().addComponents(...built.slice(i, i + MAX_BUTTONS_PER_ROW)));
    }
    return rows;
}

function embedChildren(embed) {
    const data = toJSON(embed);
    if (!data) return [];
    const children = [];

    if (data.author && data.author.name) {
        children.push(textDisplay(`-# ${clamp(data.author.name, MAX_TITLE)}`));
    }

    const title = data.title
        ? (data.url ? `## [${clamp(data.title, MAX_TITLE)}](${data.url})` : `## ${clamp(data.title, MAX_TITLE)}`)
        : '';
    const description = data.description ? clamp(data.description, MAX_TEXT) : '';
    const body = [title, description].filter(Boolean).join('\n');

    if (data.thumbnail && data.thumbnail.url && body) {
        const section = new SectionBuilder()
            .addTextDisplayComponents(textDisplay(body))
            .setThumbnailAccessory(new ThumbnailBuilder().setURL(data.thumbnail.url));
        children.push(section);
    } else {
        if (title) children.push(textDisplay(title));
        if (description) children.push(textDisplay(description));
    }

    for (const field of Array.isArray(data.fields) ? data.fields : []) {
        if (!field || (!field.name && !field.value)) continue;
        const name = clamp(field.name, MAX_FIELD_NAME);
        const value = clamp(field.value, MAX_FIELD_VALUE);
        children.push(textDisplay(name ? `**${name}**\n${value}` : value));
    }

    if (data.image && data.image.url) {
        children.push(new MediaGalleryBuilder().addItems({ media: { url: data.image.url } }));
    }

    const footer = data.footer && data.footer.text ? clamp(data.footer.text, MAX_FOOTER) : '';
    let timestamp = '';
    if (data.timestamp) {
        const ms = new Date(data.timestamp).getTime();
        if (Number.isFinite(ms)) timestamp = `<t:${Math.floor(ms / 1000)}:F>`;
    }
    if (footer || timestamp) {
        children.push(separator());
        children.push(textDisplay(`-# ${[footer, timestamp].filter(Boolean).join(' • ')}`));
    }

    return children.filter(Boolean);
}

function addChild(container, child) {
    const type = child && (child.data?.type || child.type);
    switch (type) {
        case 1: container.addActionRowComponents(child); break;
        case 9: container.addSectionComponents(child); break;
        case 10: container.addTextDisplayComponents(child); break;
        case 12: container.addMediaGalleryComponents(child); break;
        case 14: container.addSeparatorComponents(child); break;
        default: break;
    }
}

/**
 * Build a Components V2 message payload.
 *
 * @param {object} options
 * @param {string} [options.content]       Plain text (becomes a TextDisplay).
 * @param {object|object[]} [options.embed] EmbedBuilder or API embed object.
 * @param {object[]} [options.embeds]      Multiple embeds.
 * @param {object[]} [options.components]  Existing ActionRow builders/JSON.
 * @param {object[]} [options.buttons]     Button builders/JSON (chunked into rows).
 * @param {number} [options.flags]         Extra MessageFlags to preserve.
 * @param {boolean} [options.ephemeral]    Adds MessageFlags.Ephemeral.
 * @param {object} [options.allowedMentions]
 * @returns {object|null}
 */
function buildEmbedWithButtons(options = {}) {
    const children = [];
    if (options.content) children.push(textDisplay(options.content));

    const embeds = Array.isArray(options.embeds)
        ? options.embeds
        : (options.embed ? [options.embed] : []);
    for (const embed of embeds) {
        const next = embedChildren(embed);
        if (!next.length) continue;
        if (children.length) children.push(separator());
        children.push(...next);
    }

    const rows = [
        ...rowsFromComponents(options.components),
        ...rowsFromButtons(options.buttons),
    ].slice(0, MAX_ACTION_ROWS);
    children.push(...rows);

    if (!children.length) return null;

    const container = new ContainerBuilder();
    for (const child of children.slice(0, MAX_CONTAINER_CHILDREN)) addChild(container, child);

    let flags = Number(options.flags) || 0;
    flags |= MessageFlags.IsComponentsV2;
    if (options.ephemeral) flags |= MessageFlags.Ephemeral;

    const payload = {
        components: [container.toJSON()],
        flags,
    };
    if (options.allowedMentions) payload.allowedMentions = options.allowedMentions;
    return payload;
}

async function sendEmbedWithButtons(target, options) {
    const payload = buildEmbedWithButtons(options);
    if (!payload) return null;
    return target.send(payload);
}

async function editEmbedWithButtons(target, options) {
    const payload = buildEmbedWithButtons(options);
    if (!payload) return null;
    return target.edit(payload);
}

module.exports = {
    buildEmbedWithButtons,
    sendEmbedWithButtons,
    editEmbedWithButtons,
    // Exposed for tests / advanced callers.
    _internal: { buttonFrom, rowsFromComponents, rowsFromButtons, embedChildren },
};
