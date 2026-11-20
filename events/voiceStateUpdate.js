const { Events } = require('discord.js');

/**
 * Voice-state forwarding for the Linix music system.
 *
 * The music engine itself does not need this: Shoukaku's `Connectors.DiscordJS`
 * subscribes to the gateway `raw` stream and forwards VOICE_STATE_UPDATE /
 * VOICE_SERVER_UPDATE to Lavalink directly, so voice routing (including across
 * shards) is handled by the connector, exactly as in Linix.
 *
 * What remains here is the bot's voice defense — the bot is always
 * self-deafened, so a lost deafen (admin toggle, server undeafen, fresh
 * connect) is re-asserted. It is fully fire-and-forget so it can never throw
 * into the gateway.
 */
module.exports = {
    name: Events.VoiceStateUpdate,
    async execute(oldState, newState) {
        try {
            require('../utils/voiceDefense').handleVoiceStateUpdate(oldState, newState);
        } catch (err) {
            console.error('[VOICE] defense handler failed:', err.message);
        }
    },
};
