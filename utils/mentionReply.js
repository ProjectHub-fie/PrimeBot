/**
 * Bare-mention reply — one Components V2 container holding the card text and
 * the action buttons, so the buttons read as part of the message instead of a
 * detached action row below it.
 *
 * The four buttons keep their original destinations (invite, support, dashboard,
 * docs). They are Link buttons, so they never emit interactions and therefore
 * carry no customId (Discord rejects a Link button that has one).
 */

const {
    ContainerBuilder, TextDisplayBuilder, SeparatorBuilder,
    ActionRowBuilder, ButtonBuilder, ButtonStyle, MessageFlags,
} = require('discord.js');
const config = require('../config');
const { getFleetGuildCount, getFleetMemberCount } = require('./fleetStats');

/** Custom emoji from the central EmojiManager, Unicode fallback otherwise. */
function componentEmoji(client, name, fallback) {
    try {
        const manager = client?.emojiManager;
        if (manager && typeof manager.forComponent === 'function') {
            return manager.forComponent(name, fallback);
        }
    } catch (_) { /* fall back below */ }
    return fallback;
}

function linkButton({ label, url, emoji }) {
    return new ButtonBuilder()
        .setStyle(ButtonStyle.Link)
        .setLabel(label)
        .setURL(url)
        .setEmoji(emoji);
}

function buildMentionReplyPayload(client, {
    prefix = config.prefix,
    ping = 0,
    uptime = '0s',
    guildCount = 0,
    totalUsers = 0,
    author = null,
} = {}) {
    const container = new ContainerBuilder();

    container.addTextDisplayComponents(
        new TextDisplayBuilder().setContent('## Hello there!\n**PrimeBot** — premium features, free for every server.')
    );
    container.addSeparatorComponents(new SeparatorBuilder().setDivider(true));
    container.addTextDisplayComponents(
        new TextDisplayBuilder().setContent([
            `**Prefix** \`${prefix}\`  •  **Ping** ${ping}ms  •  **Uptime** ${uptime}`,
            `**Servers** ${Number(guildCount).toLocaleString()}  •  **Members** ${Number(totalUsers).toLocaleString()}`,
            '',
            `Type \`${prefix}help\` for every command, or ask me anything with \`/ai ask\` or by mentioning me.`,
        ].join('\n'))
    );

    const row = new ActionRowBuilder().addComponents(
        linkButton({
            label: 'Invite Me',
            url: `https://discord.com/api/oauth2/authorize?client_id=${client.user.id}&permissions=563242011339808&scope=bot%20applications.commands`,
            emoji: componentEmoji(client, 'premium', '💎'),
        }),
        linkButton({
            label: 'Support',
            url: config.supportServer,
            emoji: componentEmoji(client, 'staff', '🛠️'),
        }),
        linkButton({
            label: 'Dashboard',
            url: config.website,
            emoji: componentEmoji(client, 'config', '⚙️'),
        }),
        linkButton({
            label: 'Docs',
            url: config.doc,
            emoji: componentEmoji(client, 'information', 'ℹ️'),
        }),
    );
    // Inside the container (not a sibling) so the buttons are part of the card.
    container.addActionRowComponents(row);

    const payload = {
        components: [container],
        flags: MessageFlags.IsComponentsV2,
        allowedMentions: { parse: [] },
    };
    if (author) {
        container.addTextDisplayComponents(
            new TextDisplayBuilder().setContent(`-# Requested by ${author.username} • v${config.version}`)
        );
    }
    return payload;
}

/** Send the card. Returns true when it was delivered. */
async function sendMentionReply(client, message, { prefix, formatUptime } = {}) {
    try {
        const payload = buildMentionReplyPayload(client, {
            prefix,
            ping: client.ws?.ping || 0,
            uptime: typeof formatUptime === 'function' ? formatUptime(process.uptime()) : '0s',
            // Fleet totals, not this shard's share (see utils/fleetStats.js).
            guildCount: getFleetGuildCount(client),
            totalUsers: getFleetMemberCount(client),
            author: message.author,
        });
        await message.reply(payload);
        return true;
    } catch (err) {
        console.error('[MENTION] failed to send the help card:', err.message);
        return false;
    }
}

module.exports = { buildMentionReplyPayload, sendMentionReply, componentEmoji };
