class SnipeManager {
    constructor() {
        this.lastDeleted = new Map();
    }

    getKey(guildId, channelId) {
        return `${guildId}:${channelId}`;
    }

    store(message) {
        if (!message || !message.guildId || !message.channelId) return;
        if (message.author?.bot) return;

        const key = this.getKey(message.guildId, message.channelId);
        const snapshot = {
            content: message.content || null,
            authorId: message.author?.id || null,
            authorUsername: message.author?.tag || message.author?.username || null,
            createdTimestamp: message.createdTimestamp || Date.now(),
            attachments: message.attachments?.map(att => ({
                url: att.url,
                name: att.name,
                contentType: att.contentType,
            })) || [],
            embeds: message.embeds?.length || 0,
            pinned: Boolean(message.pinned),
        };

        this.lastDeleted.set(key, snapshot);
    }

    get(guildId, channelId) {
        if (!guildId || !channelId) return null;
        return this.lastDeleted.get(this.getKey(guildId, channelId)) || null;
    }
}

module.exports = SnipeManager;
