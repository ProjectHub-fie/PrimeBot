/**
 * Server information embed — shared by `/si` and `$si` so both render identically.
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../config');

const VERIFICATION_LABELS = {
    0: 'None',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Highest',
};

const BOOST_TIERS = { 0: 'None', 1: 'Tier 1', 2: 'Tier 2', 3: 'Tier 3' };

function timestamp(ms) {
    return `<t:${Math.floor(ms / 1000)}:F> (<t:${Math.floor(ms / 1000)}:R>)`;
}

function iconUrl(guild, size) {
    if (typeof guild.iconURL !== 'function') return null;
    try {
        return guild.iconURL({ size }) || null;
    } catch (_) {
        return null;
    }
}

function buildServerInfoEmbed(guild) {
    // Collections and plain Maps both work: count by iterating values.
    const channelList = guild.channels?.cache ? [...guild.channels.cache.values()] : [];
    const text = channelList.filter(c => c.type === 0 || c.type === 5).length;
    const voice = channelList.filter(c => c.type === 2 || c.type === 13).length;
    const categories = channelList.filter(c => c.type === 4).length;

    const owner = guild.ownerId ? `<@${guild.ownerId}>` : 'Unknown';
    const members = guild.memberCount ?? 0;

    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setAuthor({ name: guild.name, iconURL: iconUrl(guild, 128) || undefined })
        .setTitle('Server information')
        .setThumbnail(iconUrl(guild, 256))
        .addFields(
            { name: 'Owner', value: owner, inline: true },
            { name: 'Members', value: `${members.toLocaleString('en-US')}`, inline: true },
            { name: 'Roles', value: `${guild.roles?.cache?.size ?? 0}`, inline: true },
            { name: 'Channels', value: `${text} text • ${voice} voice • ${categories} categories`, inline: true },
            { name: 'Boosts', value: `${guild.premiumSubscriptionCount ?? 0} (${BOOST_TIERS[guild.premiumTier] ?? 'None'})`, inline: true },
            { name: 'Verification', value: VERIFICATION_LABELS[guild.verificationLevel] ?? 'Unknown', inline: true },
        );

    const createdMs = guild.createdTimestamp
        ?? (guild.createdAt instanceof Date ? guild.createdAt.getTime() : null);
    if (createdMs) {
        embed.addFields({ name: 'Created', value: timestamp(createdMs), inline: false });
    }
    if (guild.vanityURLCode) {
        embed.addFields({ name: 'Vanity URL', value: `discord.gg/${guild.vanityURLCode}`, inline: false });
    }
    if (guild.emojis?.cache) {
        const emojis = guild.emojis.cache;
        embed.addFields({
            name: 'Emojis & stickers',
            value: `${emojis.size} emoji • ${guild.stickers?.cache?.size ?? 0} stickers`,
            inline: false,
        });
    }

    return embed
        .setFooter({ text: `Server ID: ${guild.id} • PrimeBot v${config.version}` })
        .setTimestamp();
}

module.exports = { buildServerInfoEmbed };
