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

            // Resolve the message fully. With MessageManager maxSize 50 and
            // ReactionManager maxSize 0, the message a reaction happened on is
            // almost always a partial — and a partial message has no `.guild`,
            // which would silently break reaction-role handling. Fetch it first.
            if (reaction.message && reaction.message.partial) {
                try {
                    await reaction.message.fetch();
                } catch (error) {
                    console.error('Something went wrong when fetching the reaction message:', error);
                    return;
                }
            }

            // Get client from reaction.client
            const client = reaction.client;

            // Reaction-role menus (checked before giveaways).
            if (client.reactionRoleManager && typeof client.reactionRoleManager.handleReactionRemove === 'function') {
                try {
                    await client.reactionRoleManager.handleReactionRemove(reaction, user);
                } catch (rrErr) {
                    console.error('[REACTION ROLES] handleReactionRemove error:', rrErr.message);
                }
            }

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