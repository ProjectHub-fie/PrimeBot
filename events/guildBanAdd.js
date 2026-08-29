const { logEvent } = require('../utils/serverLogger');

module.exports = {
    name: 'guildBanAdd',
    once: false,
    async execute(ban, client) {
        try {
            if (!ban || !ban.guild) return;
            const user = ban.user || ban;

            // "Ban DM" — when the guild's dashboard Automod tab has "DM user"
            // enabled, the banned member gets an all-fields ban DM (plus an Appeal
            // button when "Use appeal" is on). The manager dedupes the 30s window
            // so our own /ban, $ban, and automod paths (which send the DM right
            // before the event fires) don't double-send.

            client.appealManager?.sendBanDm?.({
                guild: ban.guild,
                user,
                reason: '',
                action: 'ban',
                moderator: null,
                cid: null,
            }).catch(() => {});

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
