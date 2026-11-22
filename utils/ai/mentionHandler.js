/**
 * Mention / reply AI entry point.
 *
 * All three interaction paths (slash, prefix, mention) call the same
 * `AiManager.chat`, so memory, provider failover, quotas and cooldowns are
 * identical. This module only decides *whether* to answer.
 */

const { sanitizeUserText } = require('./promptSafety');
const { answerEmbed, helpEmbed } = require('./aiEmbeds');
const { aiError } = require('./aiCommands');

function stripMention(client, content) {
    return String(content || '')
        .replace(new RegExp(`<@!?${client.user.id}>`, 'g'), ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function imageAttachments(message) {
    const urls = [];
    for (const att of message.attachments?.values?.() || []) {
        if (/^image\//i.test(att.contentType || '')) urls.push(att.url);
    }
    return urls.slice(0, 2);
}

/**
 * @returns {Promise<boolean>} true when the message was handled (caller stops).
 */
async function handleAiMention(client, message, { prefix = '$', auto = false } = {}) {
    if (!message.guild || !client.user) return false;
    if (message.author?.bot || message.webhookId) return false;   // never answer bots/webhooks
    if (message.system) return false;

    const manager = client.aiManager;
    if (!manager) return false;

    const settings = manager.getSettings(message.guild.id);
    if (!settings.enabled) return false;
    if (auto && settings.mode !== 'auto') return false;

    const access = manager.checkAccess({
        guildId: message.guild.id,
        channelId: message.channelId,
        member: message.member,
    });
    if (!access.ok) {
        // Only explain a channel/role block when the member explicitly asked.
        if (!auto && (access.reason === 'channel' || access.reason === 'role')) {
            const payload = aiError({ reason: access.reason });
            await message.reply({ embeds: payload.embeds, allowedMentions: { parse: [] } }).catch(() => {});
            return true;
        }
        return false;
    }

    const prompt = sanitizeUserText(stripMention(client, message.content), 6000);
    const images = imageAttachments(message);

    if (!prompt && !images.length) {
        if (!auto) {
            await message.reply({ embeds: [helpEmbed(prefix)], allowedMentions: { parse: [] } }).catch(() => {});
            return true;
        }
        return false;
    }

    if (auto && prompt.length < 4) return false;   // ignore "lol", "ok", reactions-as-text

    await message.channel.sendTyping?.().catch?.(() => {});
    const result = await manager.chat({
        guildId: message.guild.id,
        userId: message.author.id,
        channelId: message.channelId,
        guildName: message.guild.name,
        prompt: prompt || 'Describe this image and point out anything important.',
        images,
        capability: images.length ? 'vision' : 'chat',
        useSession: true,
        maxTokens: 900,
    });

    if (!result.ok) {
        const payload = aiError(result);
        await message.reply({ embeds: payload.embeds, allowedMentions: { parse: [] } }).catch(() => {});
        return true;
    }

    const chunks = result.chunks || [result.text];
    try {
        await message.reply({
            embeds: [answerEmbed({ text: chunks[0], provider: result.provider })],
            allowedMentions: { parse: [] },
        });
        for (const chunk of chunks.slice(1)) {
            await message.channel.send({ content: chunk, allowedMentions: { parse: [] } });
        }
    } catch (err) {
        console.error('[AI] mention reply failed:', err.message);
    }
    return true;
}

module.exports = { handleAiMention, stripMention, imageAttachments };
