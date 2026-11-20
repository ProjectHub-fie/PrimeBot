const { Events } = require('discord.js');
const { getSecurityAuditLogger } = require('../utils/securityAuditLogger');

/**
 * Private security audit — PrimeBot left (or was removed from) a server.
 *
 * Discord may deliver a partial guild object here, so the logger merges it with
 * the in-memory snapshot taken while the guild was still cached and reports
 * anything it never knew as "Unavailable" rather than guessing.
 */
module.exports = {
    name: Events.GuildDelete,
    async execute(guild, client) {
        try {
            await getSecurityAuditLogger().onGuildDelete(guild, client);
        } catch (err) {
            console.error('[SECURITY AUDIT] guildDelete handler failed:', err.message);
        }
    },
};
