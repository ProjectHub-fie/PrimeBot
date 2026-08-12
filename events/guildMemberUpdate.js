const { logEvent } = require('../utils/serverLogger');

module.exports = {
    name: 'guildMemberUpdate',
    once: false,
    async execute(oldMember, newMember, client) {
        try {
            if (!oldMember || !newMember || !newMember.guild) return;
            if (newMember.user.bot && !client.loggingSettingsManager?.getSettings(newMember.guild.id)?.includeBots) {
                // Bot members are filtered by logEvent too, but skip heavy diffing early.
            }

            // Role changes
            const oldRoles = oldMember.roles.cache;
            const newRoles = newMember.roles.cache;
            const added = newRoles.filter(r => !oldRoles.has(r.id) && r.id !== newMember.guild.id);
            const removed = oldRoles.filter(r => !newRoles.has(r.id) && r.id !== newMember.guild.id);

            if (added.size > 0 || removed.size > 0) {
                const fields = [];
                if (added.size > 0) fields.push({ name: 'Roles added', value: added.map(r => r.name).join(', '), inline: false });
                if (removed.size > 0) fields.push({ name: 'Roles removed', value: removed.map(r => r.name).join(', '), inline: false });
                fields.push({ name: 'Member', value: `${newMember.user.tag} (\`${newMember.id}\`)`, inline: false });

                logEvent(client, newMember.guild.id, {
                    type: 'memberUpdate',
                    title: 'Member Roles Updated',
                    fields,
                    isBot: newMember.user.bot,
                });
                return;
            }

            // Nickname changes
            if (oldMember.nickname !== newMember.nickname) {
                logEvent(client, newMember.guild.id, {
                    type: 'memberUpdate',
                    title: 'Member Nickname Updated',
                    description: `${newMember.user.tag} (\`${newMember.id}\`)`,
                    fields: [
                        { name: 'Before', value: oldMember.nickname || '*None*', inline: true },
                        { name: 'After', value: newMember.nickname || '*None*', inline: true },
                    ],
                    isBot: newMember.user.bot,
                });
            }
        } catch (error) {
            console.error('[MEMBER UPDATE] Logging failed:', error.message);
        }
    },
};
