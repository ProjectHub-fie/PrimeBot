const { Events } = require('discord.js');

module.exports = {
    name: Events.MessageReactionAdd,
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
            
            // Check if giveawayManager exists
            if (!client.giveawayManager) {
                console.error('[GIVEAWAY] GiveawayManager not found on client');
                return;
            }
            
            const giveaway = client.giveawayManager.giveaways.get(messageId);
            
            if (!giveaway) return;

            // Check if the reaction is the giveaway emoji
            console.log(`[GIVEAWAY] Checking reaction: ${reaction.emoji.name} for message ${messageId}`);
            
            if (reaction.emoji.name === '🎉') {
                console.log(`[GIVEAWAY] User ${user.tag} reacted to giveaway ${messageId}`);
                
                // Check if giveaway has ended
                if (giveaway.ended) {
                    console.log(`[GIVEAWAY] Giveaway ${messageId} has already ended`);
                    return;
                }

                // Check if user has required role (if specified)
                if (giveaway.requiredRoleId) {
                    const guild = reaction.message.guild;
                    const member = await guild.members.fetch(user.id).catch(() => null);
                    if (!member || !member.roles.cache.has(giveaway.requiredRoleId)) {
                        const role = guild.roles.cache.get(giveaway.requiredRoleId);
                        const roleName = role ? role.name : 'required role';
                        
                        // Remove the reaction and notify user
                        await reaction.users.remove(user.id);
                        
                        try {
                            await user.send(`You need the **${roleName}** role to enter this giveaway.`);
                        } catch (dmError) {
                            console.log(`Could not DM user ${user.tag} about role requirement`);
                        }
                        return;
                    }
                }

                // Add user to participants using the manager method
                const added = await client.giveawayManager.addParticipant(messageId, user.id);
                
                if (added) {
                    console.log(`[GIVEAWAY] User ${user.tag} entered giveaway ${messageId}. Total participants: ${giveaway.participants.size}`);
                    
                    // Send confirmation DM
                    try {
                        await user.send(`You have entered the giveaway for **${giveaway.prize}**! Good luck! 🍀`);
                    } catch (dmError) {
                        console.log(`Could not DM user ${user.tag} about giveaway entry`);
                    }
                } else {
                    console.log(`[GIVEAWAY] User ${user.tag} already entered giveaway ${messageId} or giveaway ended`);
                }
            }
            
        } catch (error) {
            console.error('Error handling message reaction add:', error);
        }
    },
};