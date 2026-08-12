const { logEvent } = require('../utils/serverLogger');

module.exports = {
    name: 'guildBanRemove',
    once: false,
    async execute(ban, client) {
        try {
            if (!ban || !ban.guild) return;
            const user = ban.user || ban;

            logEvent(client, ban.guild.id, {
                type: 'memberUnban',
                title: 'Member Unbanned',
                description: `${user.tag} (\`${user.id}\`)`,
                thumbnail: user.displayAvatarURL?.(),
                isBot: user.bot,
            });
        } catch (error) {
            console.error('[GUILD BAN REMOVE] Logging failed:', error.message);
        }
    },
};
