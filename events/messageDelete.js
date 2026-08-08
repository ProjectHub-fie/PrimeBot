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
        } catch (error) {
            console.error('[MESSAGE DELETE] Snipe capture failed:', error);
        }
    },
};
