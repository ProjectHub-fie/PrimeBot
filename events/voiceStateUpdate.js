const { Events } = require('discord.js');

/**
 * Voice-state updates drive the 24/7 radio's pause/resume behaviour.
 *
 * When the configured radio channel empties the radio pauses (the voice
 * connection is kept alive); when a listener returns it resumes. The heavy
 * lifting (and the "only the owning shard node reacts" rule) lives in
 * RadioManager.handleVoiceStateUpdate — this handler is a thin, guarded
 * forwarder so an unrelated voice-state storm can never throw into the
 * gateway.
 */
module.exports = {
    name: Events.VoiceStateUpdate,
    async execute(oldState, newState) {
        try {
            const manager = newState.client.radioManager || (oldState.client && oldState.client.radioManager);
            if (!manager || typeof manager.handleVoiceStateUpdate !== 'function') return;
            await manager.handleVoiceStateUpdate(oldState, newState);
        } catch (err) {
            console.error('[RADIO] voiceStateUpdate handler failed:', err.message);
        }
    },
};
