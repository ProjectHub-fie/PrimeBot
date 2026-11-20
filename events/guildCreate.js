const { Events } = require('discord.js');
const { getSecurityAuditLogger } = require('../utils/securityAuditLogger');

/**
 * Private security audit — PrimeBot joined a server.
 *
 * The audit itself is fire-and-forget: a delivery failure (missing channel,
 * permissions, rate limit) is logged as a safe diagnostic and can never affect
 * the guild-join handling in index.js (presence / server count).
 */
module.exports = {
    name: Events.GuildCreate,
    async execute(guild, client) {
        try {
            await getSecurityAuditLogger().onGuildCreate(guild, client);
        } catch (err) {
            console.error('[SECURITY AUDIT] guildCreate handler failed:', err.message);
        }
    },
};
