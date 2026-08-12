const { logEvent } = require('../utils/serverLogger');

module.exports = {
    name: 'guildBanAdd',
    once: false,
    async execute(ban, client) {
        try {
            if (!ban || !ban.guild) return;
            const user = ban.user || ban;

            logEvent(client, ban.guild.id, {
                type: 'memberBan',
                title: 'Member Banned',
                description: `${user.tag} (\`${user.id}\`)`,
                thumbnail: user.displayAvatarURL?.(),
                isBot: user.bot,
            });
        } catch (error) {
            console.error('[GUILD BAN ADD] Logging failed:', error.message);
        }
    },
};
