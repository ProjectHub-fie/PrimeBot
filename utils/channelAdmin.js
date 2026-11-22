/**
 * Channel / category admin helpers shared by the prefix commands
 * (`$cp`, `$rm #channel`, `$mkdir`, `$hmkdir`) and the `/channel` slash group.
 *
 * Everything here is guild-scoped: lookups only ever search the guild's own
 * channel cache, so a mention or id from another guild can never resolve.
 * Discord's own validation still applies on top (name format, limits, perms).
 */

const { ChannelType } = require('discord.js');

const NAME_MAX = 100;
const MENTION_RE = /^<#(\d{15,22})>$/;
const ID_RE = /^\d{15,22}$/;

function sanitizeName(input, fallback = 'new-channel') {
    const cleaned = String(input == null ? '' : input)
        .trim()
        .toLowerCase()
        .replace(/^#+/, '')
        .replace(/[^a-z0-9\-_\s]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-{2,}/g, '-')
        .replace(/^[-_]+|[-_]+$/g, '')
        .slice(0, NAME_MAX);
    return cleaned || fallback;
}

function mentionId(arg) {
    const m = MENTION_RE.exec(String(arg == null ? '' : arg).trim());
    return m ? m[1] : null;
}

function bareId(arg) {
    const value = String(arg == null ? '' : arg).trim();
    return ID_RE.test(value) ? value : null;
}

function allChannels(guild) {
    const cache = guild && guild.channels && guild.channels.cache;
    if (!cache) return [];
    return typeof cache.values === 'function' ? [...cache.values()] : Object.values(cache);
}

function findCategory(guild, arg) {
    const id = mentionId(arg) || bareId(arg);
    const categories = allChannels(guild).filter(c => c.type === ChannelType.GuildCategory);
    if (id) return categories.find(c => c.id === id) || null;
    const query = String(arg == null ? '' : arg).trim().toLowerCase();
    if (!query) return null;
    return categories.find(c => c.name.toLowerCase() === query)
        || categories.find(c => c.name.toLowerCase().includes(query))
        || null;
}

function findChannel(guild, arg, mentions = null) {
    const id = mentionId(arg) || bareId(arg);
    if (id) {
        return allChannels(guild).find(c => c.id === id)
            || (mentions && typeof mentions.get === 'function' ? mentions.get(id) : null)
            || null;
    }
    const query = String(arg == null ? '' : arg).trim().toLowerCase();
    if (!query) return null;
    const channels = allChannels(guild).filter(c => c.type !== ChannelType.GuildCategory);
    return channels.find(c => c.name.toLowerCase() === query)
        || channels.find(c => c.name.toLowerCase().includes(query))
        || null;
}

async function createTextChannel(guild, rawName, rawCategory, { invokerId } = {}) {
    const name = sanitizeName(rawName);
    let parent = null;
    if (rawCategory) {
        parent = findCategory(guild, rawCategory);
        if (!parent) return { ok: false, text: `I could not find a category matching **${rawCategory}**.` };
    }
    try {
        const channel = await guild.channels.create({
            name,
            type: ChannelType.GuildText,
            ...(parent ? { parent: parent.id } : {}),
            reason: `Created by ${invokerId || 'a moderator'} (cp)`,
        });
        return {
            ok: true,
            channel,
            text: `Created ${channel}${parent ? ` under **${parent.name}**` : ''}.`,
        };
    } catch (err) {
        return { ok: false, error: err, text: `I could not create that channel: ${err.message}` };
    }
}

async function deleteChannel(guild, target, { invokerId, mentions = null, currentChannelId = null } = {}) {
    const channel = findChannel(guild, target, mentions);
    if (!channel) return { ok: false, text: 'I could not find that channel.' };
    if (channel.type === ChannelType.GuildCategory) {
        return { ok: false, text: `**${channel.name}** is a category — use \`hmkdir\` to delete categories.` };
    }
    if (channel.id === currentChannelId) {
        return { ok: false, text: 'I will not delete the channel this command was used in. Run it from another channel.' };
    }
    if (typeof channel.deletable === 'boolean' && !channel.deletable) {
        return { ok: false, text: `I am not allowed to delete **${channel.name}**.` };
    }
    const name = channel.name;
    try {
        await channel.delete(`Deleted by ${invokerId || 'a moderator'} (rm)`);
        return { ok: true, text: `Deleted **#${name}**.` };
    } catch (err) {
        return { ok: false, error: err, text: `I could not delete that channel: ${err.message}` };
    }
}

async function createCategory(guild, rawName, { invokerId } = {}) {
    const name = sanitizeName(rawName, 'new-category');
    try {
        const category = await guild.channels.create({
            name,
            type: ChannelType.GuildCategory,
            reason: `Created by ${invokerId || 'a moderator'} (mkdir)`,
        });
        return { ok: true, category, text: `Created category **${category.name}**.` };
    } catch (err) {
        return { ok: false, error: err, text: `I could not create that category: ${err.message}` };
    }
}

async function deleteCategory(guild, target, { invokerId, mentions = null } = {}) {
    const category = findCategory(guild, target)
        || (mentions && typeof mentions.get === 'function'
            ? [...(mentions.values ? mentions.values() : [])].find(c => c && c.type === ChannelType.GuildCategory)
            : null);
    if (!category) return { ok: false, text: 'I could not find that category.' };
    const children = allChannels(guild).filter(c => c.parentId === category.id).length;
    const name = category.name;
    try {
        await category.delete(`Deleted by ${invokerId || 'a moderator'} (hmkdir)`);
        return {
            ok: true,
            text: children
                ? `Deleted category **${name}**. ${children} channel${children === 1 ? '' : 's'} moved out of it (nothing was deleted).`
                : `Deleted category **${name}**.`,
        };
    } catch (err) {
        return { ok: false, error: err, text: `I could not delete that category: ${err.message}` };
    }
}

module.exports = {
    NAME_MAX,
    sanitizeName,
    mentionId,
    findCategory,
    findChannel,
    createTextChannel,
    deleteChannel,
    createCategory,
    deleteCategory,
};
