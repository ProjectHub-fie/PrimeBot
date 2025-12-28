const { Events } = require('discord.js');

module.exports = {
    name: Events.MessageReactionRemove,
    async execute(reaction, user) {
        try {
            // Ignore bot reactions
            if (user.bot) return;

            // Handle partial reactions
            if (reaction.partial) {
                try {
                    await reaction.fetch();
                } catch (error) {
                    console.error('Something went wrong when fetching the reaction:', error);
                    return;
                }
            }

            // Get client from reaction.client
            const client = reaction.client;

            // Check if this is a giveaway reaction
            const messageId = reaction.message.id;

            if (!client.giveawayManager) {
                console.error('[GIVEAWAY] GiveawayManager not found on client');
                return;
            }

            const giveaway = client.giveawayManager.giveaways.get(messageId);

            if (!giveaway) return;

            // Check if the reaction is the giveaway emoji
            if (reaction.emoji.name === '🎉') {
                // Remove user from participants using the manager method
                const removed = await client.giveawayManager.removeParticipant(messageId, user.id);

                if (removed) {
                    console.log(`[GIVEAWAY] User ${user.tag} left giveaway ${messageId}. Total participants: ${giveaway.participants.size}`);
                }
            }

        } catch (error) {
            console.error('Error handling message reaction remove:', error);
        }
    },
};