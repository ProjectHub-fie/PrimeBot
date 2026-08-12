const { logEvent } = require('../utils/serverLogger');

module.exports = {
    name: 'messageDelete',
    once: false,
    async execute(message, client) {
        try {
            if (!message || message.author?.bot) return;
            if (!message.guildId || !message.channelId) return;

            if (typeof client.snipeManager?.store === 'function') {
                client.snipeManager.store(message);
            }

            // Log the deletion (no-op unless logging is enabled for this guild).
            const content = message.content
                ? (message.content.length > 1024 ? message.content.slice(0, 1021) + '…' : message.content)
                : '*No text content*';
            logEvent(client, message.guildId, {
                type: 'messageDelete',
                title: 'Message Deleted',
                description: `By ${message.author.tag} (\`${message.author.id}\`) in <#${message.channelId}>`,
                fields: [
                    { name: 'Content', value: content, inline: false },
                    { name: 'Message ID', value: `\`${message.id}\``, inline: true },
                ],
                isBot: message.author.bot,
            });
        } catch (error) {
            console.error('[MESSAGE DELETE] Snipe capture failed:', error);
        }
    },
};
