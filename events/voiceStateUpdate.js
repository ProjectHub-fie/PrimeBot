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
        // Voice defense: the bot is always self-deafened. If the deafen is ever
        // lost (admin toggled it in the UI, a server undeafen, a fresh connect)
        // it is re-asserted here. Runs first and is fully fire-and-forget so it
        // can never delay or break the radio/music forwarding below.
        try {
            require('../utils/voiceDefense').handleVoiceStateUpdate(oldState, newState);
        } catch (err) {
            console.error('[VOICE] defense handler failed:', err.message);
        }
        try {
            const manager = newState.client.radioManager || (oldState.client && oldState.client.radioManager);
            if (manager && typeof manager.handleVoiceStateUpdate === 'function') {
                await manager.handleVoiceStateUpdate(oldState, newState);
            }
        } catch (err) {
            console.error('[RADIO] voiceStateUpdate handler failed:', err.message);
        }
        // Music: an empty channel does NOT pause or disconnect (24/7 rule). This
        // forwarder only lets a listener-join restart a queue that is waiting.
        try {
            const mm = newState.client.musicManager || (oldState.client && oldState.client.musicManager);
            if (mm && typeof mm.handleVoiceStateUpdate === 'function') {
                await mm.handleVoiceStateUpdate(oldState, newState);
            }
        } catch (err) {
            console.error('[MUSIC] voiceStateUpdate handler failed:', err.message);
        }
    },
};
