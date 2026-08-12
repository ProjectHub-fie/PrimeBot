/**
 * serverLogger.js
 *
 * Builds and delivers rich log embeds for server events (member join/leave,
 * bans, message edits/deletes, command use, ...). Delivery supports two
 * independent channels per guild:
 *
 *   1. A Discord channel  (settings.channelId) — posted as the bot via
 *      discord.js, so it requires the bot to have View Channel + Send Messages
 *      there.
 *   2. A Discord webhook   (settings.webhookUrl) — posted via a raw HTTPS
 *      request. Works even in channels the bot cannot see, and can be shared
 *      with external services that accept a Discord webhook payload.
 *
 * If both are configured, the log is sent to both. If neither is configured,
 * nothing happens. Every path is fire-and-forget: a logging failure never
 * throws back into the event handler that triggered it.
 */

const https = require('https');
const { URL } = require('url');
const { EmbedBuilder } = require('discord.js');
const { isEventEnabled, metaFor } = require('./logEvents');

// Escape a hex color like "#5865F2" -> 0x5865F2; falls back to blurple.
function colorInt(hex) {
    if (!hex) return 0x5865F2;
    const m = /^#?([0-9a-fA-F]{6})$/.exec(String(hex));
    return m ? parseInt(m[1], 16) : 0x5865F2;
}

/** Build (but do not send) a Discord EmbedBuilder for a log event. Pure + sync. */
function buildLogEmbed({ type, title, description = '', fields = [], color, footer, timestamp, thumbnail }) {
    const meta = metaFor(type);
    const embed = new EmbedBuilder()
        .setColor(colorInt(color || meta.color))
        .setTitle(`${meta.icon} ${title || meta.label}`)
        .setTimestamp(timestamp || new Date());

    if (description) embed.setDescription(description);
    if (thumbnail) embed.setThumbnail(thumbnail);

    for (const f of fields) {
        if (f && f.name && f.value != null && f.value !== '') {
            embed.addFields({ name: f.name, value: String(f.value), inline: !!f.inline });
        }
    }

    embed.setFooter({ text: footer || `PrimeBot Logging · ${type}` });
    return embed;
}

/** Plain-object form of buildLogEmbed, for webhook payloads and tests. */
function buildLogEmbedObject(opts) {
    return buildLogEmbed(opts).toJSON();
}

/** POST a Discord webhook payload (fire-and-forget, never throws). */
function postWebhook(webhookUrl, payload, webhookName) {
    const body = JSON.stringify({
        username: webhookName || 'PrimeBot Logs',
        embeds: [payload],
    });
    try {
        const url = new URL(webhookUrl);
        const req = https.request(
            {
                hostname: url.hostname,
                path: url.pathname + url.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                },
            },
            (res) => {
                res.resume();
                if (res.statusCode >= 400) {
                    console.error(`[LOGGER] Webhook responded HTTP ${res.statusCode}`);
                }
            }
        );
        req.on('error', (err) => console.error('[LOGGER] Webhook request error:', err.message));
        req.write(body);
        req.end();
    } catch (err) {
        console.error('[LOGGER] Failed to post webhook:', err.message);
    }
}

/**
 * Send a log event for a guild.
 *
 * @param {object} client      - discord.js client (for channel.send)
 * @param {string} guildId
 * @param {object} evt
 * @param {string} evt.type    - one of the LOG_EVENTS keys
 * @param {string} [evt.title] - override embed title
 * @param {string} [evt.description]
 * @param {Array}  [evt.fields] - [{name,value,inline?}]
 * @param {string} [evt.color]
 * @param {string} [evt.footer]
 * @param {string} [evt.thumbnail]
 * @param {boolean} [evt.isBot] - true when the actor is a bot (filtered out unless includeBots)
 */
async function logEvent(client, guildId, evt = {}) {
    try {
        if (!client || !guildId || !evt.type) return;

        const manager = client.loggingSettingsManager;
        if (!manager || typeof manager.getSettings !== 'function') return;

        const settings = manager.getSettings(guildId);
        if (!isEventEnabled(settings, evt.type)) return;

        // Optionally suppress bot-originated events.
        if (evt.isBot && !settings.includeBots) return;

        const embed = buildLogEmbed({
            type: evt.type,
            title: evt.title,
            description: evt.description,
            fields: evt.fields,
            color: evt.color || settings.color,
            footer: evt.footer,
            thumbnail: evt.thumbnail,
        });

        // 1. Channel delivery (bot must be able to see + send in the channel).
        if (settings.channelId) {
            try {
                const channel = await client.channels.fetch(settings.channelId).catch(() => null);
                if (channel && typeof channel.send === 'function') {
                    await channel.send({ embeds: [embed] });
                }
            } catch (err) {
                console.error('[LOGGER] Channel send failed:', err.message);
            }
        }

        // 2. Webhook delivery (works regardless of bot channel access).
        if (settings.webhookUrl) {
            postWebhook(settings.webhookUrl, embed.toJSON(), settings.webhookName);
        }
    } catch (err) {
        console.error('[LOGGER] logEvent failed:', err.message);
    }
}

module.exports = {
    logEvent,
    buildLogEmbed,
    buildLogEmbedObject,
    postWebhook,
    colorInt,
};
