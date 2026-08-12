const { logEvent } = require('../utils/serverLogger');

module.exports = {
    name: 'guildMemberRemove',
    once: false,
    async execute(member, client) {
        try {
            if (!member || !member.guild) return;

            logEvent(client, member.guild.id, {
                type: 'memberLeave',
                title: 'Member Left',
                description: `${member.user.tag} (\`${member.id}\`)`,
                fields: [
                    { name: 'Joined', value: member.joinedTimestamp ? `<t:${Math.floor(member.joinedTimestamp / 1000)}:R>` : 'Unknown', inline: true },
                    { name: 'Roles', value: member.roles.cache.size > 0
                        ? member.roles.cache.filter(r => r.id !== member.guild.id).map(r => r.name).join(', ') || 'None'
                        : 'None', inline: false },
                ],
                thumbnail: member.user.displayAvatarURL?.(),
                isBot: member.user.bot,
            });
        } catch (error) {
            console.error('[MEMBER REMOVE] Logging failed:', error.message);
        }
    },
};
