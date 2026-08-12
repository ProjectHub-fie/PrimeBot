const { logEvent } = require('../utils/serverLogger');

module.exports = {
    name: 'messageUpdate',
    once: false,
    async execute(oldMessage, newMessage, client) {
        try {
            // Ignore unchanged content, bot authors, and non-guild messages.
            if (!oldMessage || !newMessage) return;
            if (oldMessage.author?.bot) return;
            if (!newMessage.guildId || !newMessage.channelId) return;
            // Only log when the text actually changed (embed/pin updates are noisy).
            if (oldMessage.content === newMessage.content) return;

            const oldContent = oldMessage.content
                ? (oldMessage.content.length > 1024 ? oldMessage.content.slice(0, 1021) + '…' : oldMessage.content)
                : '*No text content*';
            const newContent = newMessage.content
                ? (newMessage.content.length > 1024 ? newMessage.content.slice(0, 1021) + '…' : newMessage.content)
                : '*No text content*';

            logEvent(client, newMessage.guildId, {
                type: 'messageUpdate',
                title: 'Message Edited',
                description: `By ${newMessage.author.tag} (\`${newMessage.author.id}\`) in <#${newMessage.channelId}>`,
                fields: [
                    { name: 'Before', value: oldContent, inline: false },
                    { name: 'After', value: newContent, inline: false },
                    { name: 'Jump', value: `[View message](${newMessage.url})`, inline: true },
                ],
                isBot: newMessage.author.bot,
            });
        } catch (error) {
            console.error('[MESSAGE UPDATE] Logging failed:', error.message);
        }
    },
};
