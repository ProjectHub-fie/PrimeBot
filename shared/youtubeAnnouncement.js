/**
 * YouTube announcement payload builder — shared by the bot
 * (`utils/youtubeManager.js`, via discord.js EmbedBuilder) and the dashboard
 * (raw REST `sendChannelMessage`). Keeping the *data* shape here means the
 * dashboard's "Test announcement" produces byte-for-byte the same embed the bot
 * posts, and a change to the template only has to happen in one place.
 *
 * Pure + synchronous: no network, no DB, no discord.js. Callers adapt the
 * returned plain object into their transport (EmbedBuilder / REST JSON).
 */

const {
    DEFAULT_TEMPLATE,
    normalizeTemplate,
    renderTemplate,
    buildAllowedMentions,
    buildAnnouncementContent,
} = require('./youtubeConstants');

/**
 * Build a Discord message payload for a video announcement.
 *
 * @param {object} args
 * @param {object} args.subscription  { channelName, channelUrl, youtubeChannelId, discordChannelId }
 * @param {object} args.video         { videoId, title, url, publishedAt, thumbnail }
 * @param {object} [args.template]    announcement template (already normalized or raw)
 * @param {boolean} [args.test]       when true, prefixes a "(Test)" marker
 * @returns {{ content: string, embeds: object[], allowed_mentions: object }}
 */
function buildAnnouncementPayload({ subscription = {}, video = {}, template, test = false } = {}) {
    const t = template ? normalizeTemplate(template) : DEFAULT_TEMPLATE;
    const creator = subscription.channelName || 'A YouTube creator';
    const videoTitle = video.title || 'New video';
    const videoUrl = video.url || (video.videoId ? `https://www.youtube.com/watch?v=${video.videoId}` : subscription.channelUrl || '');

    const vars = {
        creator,
        channel: creator,
        creatorHandle: subscription.channelHandle ? `@${subscription.channelHandle}` : creator,
        videoTitle,
        videoUrl,
        videoId: video.videoId || '',
        server: subscription.guildName || '',
        url: videoUrl,
    };

    const title = renderTemplate(t.title, vars).slice(0, 256) || `${creator} just uploaded a new video!`;
    const description = renderTemplate(t.description, vars).slice(0, 4096) || videoTitle;

    const embed = {
        title: test ? `[Test] ${title}`.slice(0, 256) : title,
        description,
        color: parseInt(t.color.replace('#', ''), 16),
        url: videoUrl || undefined,
        timestamp: (t.showTimestamp ? new Date().toISOString() : undefined),
    };

    if (t.showCreator) {
        embed.author = {
            name: creator.slice(0, 256),
            url: subscription.channelUrl || undefined,
            icon_url: subscription.avatarUrl || undefined,
        };
    }
    if (t.showThumbnail && (video.thumbnail || (video.videoId ? `https://i.ytimg.com/vi/${video.videoId}/hqdefault.jpg` : null))) {
        embed.image = { url: video.thumbnail || `https://i.ytimg.com/vi/${video.videoId}/hqdefault.jpg` };
    }
    if (t.showVideoUrl && videoUrl) {
        embed.fields = [{ name: 'Watch now', value: `[${videoTitle.slice(0, 200)}](${videoUrl})`, inline: false }];
    }
    if (t.footer) embed.footer = { text: renderTemplate(t.footer, vars).slice(0, 2048) };

    // The leading content line (role ping / @everyone) and the explicit custom
    // message, if any. Both are optional.
    const mention = buildAnnouncementContent(t);
    const customMessage = t.message ? renderTemplate(t.message, vars).slice(0, 2000) : '';
    const content = [mention, customMessage].filter(Boolean).join('\n').slice(0, 2000);

    return {
        content,
        embeds: [embed],
        allowed_mentions: buildAllowedMentions(t),
    };
}

module.exports = { buildAnnouncementPayload };
