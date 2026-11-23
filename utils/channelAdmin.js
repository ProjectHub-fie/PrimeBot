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
const PRIVATE_WORDS = new Set(['private', 'priv', 'hidden', 'secret']);
const PUBLIC_WORDS = new Set(['public', 'pub', 'open', 'visible']);
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

/** `private`/`public` (with a few synonyms), or null when the token is neither. */
function parseVisibility(arg) {
    const value = String(arg == null ? '' : arg).trim().toLowerCase();
    if (PRIVATE_WORDS.has(value)) return 'private';
    if (PUBLIC_WORDS.has(value)) return 'public';
    return null;
}

function permissionOverwrites(guild, visibility) {
    if (visibility !== 'private') return undefined;
    const everyone = guild && guild.roles && guild.roles.everyone;
    if (!everyone) return undefined;
    return [{ id: everyone.id, deny: ['ViewChannel'] }];
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

async function createChannelOfType(guild, type, rawName, rawCategory, { invokerId, visibility = 'public', command = 'cp' } = {}) {
    const name = sanitizeName(rawName, type === ChannelType.GuildVoice ? 'new-voice' : 'new-channel');
    let parent = null;
    if (rawCategory) {
        parent = findCategory(guild, rawCategory);
        if (!parent) return { ok: false, text: `I could not find a category matching **${rawCategory}**.` };
    }
    const kind = type === ChannelType.GuildVoice ? 'voice channel' : 'channel';
    try {
        const channel = await guild.channels.create({
            name,
            type,
            ...(parent ? { parent: parent.id } : {}),
            ...(permissionOverwrites(guild, visibility) ? { permissionOverwrites: permissionOverwrites(guild, visibility) } : {}),
            reason: `Created by ${invokerId || 'a moderator'} (${command})`,
        });
        return {
            ok: true,
            channel,
            text: `Created ${visibility === 'private' ? 'private ' : ''}${kind} ${channel}${parent ? ` under **${parent.name}**` : ''}.`,
        };
    } catch (err) {
        return { ok: false, error: err, text: `I could not create that ${kind}: ${err.message}` };
    }
}

function createTextChannel(guild, rawName, rawCategory, options = {}) {
    return createChannelOfType(guild, ChannelType.GuildText, rawName, rawCategory, { ...options, command: 'cp' });
}

function createVoiceChannel(guild, rawName, rawCategory, options = {}) {
    return createChannelOfType(guild, ChannelType.GuildVoice, rawName, rawCategory, { ...options, command: 'cv' });
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
    parseVisibility,
    mentionId,
    findCategory,
    findChannel,
    createTextChannel,
    createVoiceChannel,
    createChannelOfType,
    deleteChannel,
    createCategory,
    deleteCategory,
};
