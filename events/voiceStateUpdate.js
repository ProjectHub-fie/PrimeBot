const { Events } = require('discord.js');

/**
 * Voice-state handling.
 *
 * Two independent, fire-and-forget consumers:
 *
 *   1. Voice defense — the bot is always self-deafened, so a lost deafen
 *      (admin toggle, server undeafen, fresh connect) is re-asserted.
 *   2. Private security audit — member/bot voice joins, leaves and moves are
 *      posted to the owner-controlled audit channel (no database; sessions are
 *      tracked in memory).
 *
 * The music engine does NOT need this file: Shoukaku's `Connectors.DiscordJS`
 * subscribes to the gateway `raw` stream and forwards VOICE_STATE_UPDATE /
 * VOICE_SERVER_UPDATE to Lavalink directly.
 *
 * Neither consumer may throw into the gateway.
 */
module.exports = {
    name: Events.VoiceStateUpdate,
    async execute(oldState, newState, client) {
        try {
            require('../utils/voiceDefense').handleVoiceStateUpdate(oldState, newState);
        } catch (err) {
            console.error('[VOICE] defense handler failed:', err.message);
        }

        try {
            await require('../utils/securityAuditLogger').getSecurityAuditLogger().onVoiceStateUpdate(oldState, newState, client);
        } catch (err) {
            console.error('[SECURITY AUDIT] voiceStateUpdate handler failed:', err.message);
        }
    },
};
