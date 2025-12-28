const { EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder } = require('discord.js');
const { eq, and, lt } = require('drizzle-orm');
const config = require('../config');

class GiveawayManager {
    constructor(client) {
        this.client = client;
        this.giveaways = new Map(); // Store active giveaways
        this.checkInterval = null;
        this.db = null;
        this.schema = null;
        this.dbReady = false;
        this.startupComplete = false;
        
        // Initialize database connection
        this.initializeDatabase();
    }

    async initializeDatabase() {
        try {
            // Wait for client database to be ready
            if (this.client.db && this.client.schema) {
                this.db = this.client.db;
                this.schema = this.client.schema;
                this.dbReady = true;
                console.log('✅ GiveawayManager database connection established');
                await this.loadGiveaways();
            } else {
                // Retry after a short delay if database isn't ready yet
                console.log('[GIVEAWAY] Waiting for database to be ready...');
                setTimeout(() => this.initializeDatabase(), 2000);
            }
        } catch (error) {
            console.error('❌ GiveawayManager database initialization failed:', error);
            console.log('[GIVEAWAY] Will operate in memory-only mode until database is available');
            // Retry after a longer delay
            setTimeout(() => this.initializeDatabase(), 10000);
        }
    }

    /**
     * Load saved giveaways from the database
     */
    async loadGiveaways() {
        if (!this.dbReady) {
            return; // Database not ready yet
        }

        try {
            // Load active giveaways from database
            const activeGiveaways = await this.db.select()
                .from(this.schema.giveaways)
                .where(and(
                    eq(this.schema.giveaways.isActive, true),
                    eq(this.schema.giveaways.ended, false)
                ));

            let loadedCount = 0;
            let silentlyEndedCount = 0;
            const now = Date.now();

            for (const giveaway of activeGiveaways) {
                // Load participants for this giveaway
                const participants = await this.db.select()
                    .from(this.schema.giveawayParticipants)
                    .where(eq(this.schema.giveawayParticipants.giveawayId, giveaway.messageId));

                const endTime = new Date(giveaway.endsAt).getTime();
                
                // If giveaway has already ended, mark it as ended in database without processing
                if (endTime <= now) {
                    console.log(`[GIVEAWAY] Silently marking expired giveaway ${giveaway.messageId} as ended (startup cleanup)`);
                    
                    try {
                        await this.db.update(this.schema.giveaways)
                            .set({
                                isActive: false,
                                ended: true
                            })
                            .where(eq(this.schema.giveaways.messageId, giveaway.messageId));
                        silentlyEndedCount++;
                    } catch (dbError) {
                        console.error(`[GIVEAWAY] Error marking giveaway ${giveaway.messageId} as ended:`, dbError);
                    }
                    continue;
                }

                // Convert to the format expected by the giveaway system
                const giveawayData = {
                    messageId: giveaway.messageId,
                    channelId: giveaway.channelId,
                    guildId: giveaway.guildId,
                    prize: giveaway.prize,
                    description: giveaway.description || '',
                    winnerCount: giveaway.winnerCount,
                    hostId: giveaway.hostId,
                    endTime: endTime,
                    participants: new Set(participants.map(p => p.userId)),
                    active: true,
                    ended: false
                };

                this.giveaways.set(giveaway.messageId, giveawayData);
                loadedCount++;
            }

            console.log(`[GIVEAWAY] Loaded ${loadedCount} active giveaways from database.`);
            if (silentlyEndedCount > 0) {
                console.log(`[GIVEAWAY] Silently ended ${silentlyEndedCount} expired giveaways during startup cleanup.`);
            }
            
            // Mark startup as complete and start the checking system with a delay
            this.startupComplete = true;
            this.startCheckingGiveaways();
        } catch (error) {
            console.error('[GIVEAWAY] Error loading giveaways from database:', error);
        }
    }
    
    /**
     * Save giveaways to the database (no longer uses files)
     */
    async saveGiveaways() {
        if (!this.dbReady) {
            console.log('[GIVEAWAY] Database not ready for saving giveaways');
            return;
        }

        try {
            console.log(`[GIVEAWAY] Saving ${this.giveaways.size} giveaways to database...`);
            
            let validCount = 0;
            let invalidCount = 0;
            
            for (const [messageId, giveaway] of this.giveaways.entries()) {
                // Skip invalid entries
                if (!giveaway || typeof giveaway !== 'object') {
                    console.warn(`[GIVEAWAY] Skipping invalid giveaway entry with ID ${messageId}`);
                    this.giveaways.delete(messageId);
                    invalidCount++;
                    continue;
                }
                
                // Update giveaway in database
                await this.updateGiveawayInDatabase(giveaway);
                validCount++;
            }
            
            console.log(`[GIVEAWAY] Successfully saved ${validCount} giveaways to database (${invalidCount} invalid entries removed).`);
        } catch (error) {
            console.error('[GIVEAWAY] Error saving giveaways to database:', error);
        }
    }

    /**
     * Update a single giveaway in the database
     */
    async updateGiveawayInDatabase(giveaway) {
        if (!this.dbReady) return;

        try {
            // Update the main giveaway record
            await this.db.update(this.schema.giveaways)
                .set({
                    isActive: giveaway.active,
                    ended: !giveaway.active
                })
                .where(eq(this.schema.giveaways.messageId, giveaway.messageId));

            // Update participants if needed
            const existingParticipants = await this.db.select()
                .from(this.schema.giveawayParticipants)
                .where(eq(this.schema.giveawayParticipants.giveawayId, giveaway.messageId));

            const existingUserIds = new Set(existingParticipants.map(p => p.userId));
            const currentUserIds = giveaway.participants;

            // Add new participants
            for (const userId of currentUserIds) {
                if (!existingUserIds.has(userId)) {
                    await this.db.insert(this.schema.giveawayParticipants)
                        .values({
                            giveawayId: giveaway.messageId,
                            userId: userId
                        });
                }
            }
        } catch (error) {
            console.error(`[GIVEAWAY] Error updating giveaway ${giveaway.messageId} in database:`, error);
        }
    }
    
    /**
     * Start checking for ended giveaways at a regular interval
     */
    startCheckingGiveaways() {
        // Add a delay before starting the checking system to avoid startup spam
        setTimeout(() => {
            this.checkInterval = setInterval(() => {
                this.checkGiveaways();
            }, config.giveaway.checkInterval);
            
            console.log('Giveaway checking system started.');
        }, 10000); // Wait 10 seconds after startup before starting checks
    }

    /**
     * Check for ended giveaways and process them
     */
    async checkGiveaways() {
        const now = Date.now();
        const activeCount = Array.from(this.giveaways.values()).filter(g => !g.ended).length;
        console.log(`[GIVEAWAY] Checking for ended giveaways. Total: ${this.giveaways.size}, Active: ${activeCount}`);
        
        // Clean up old ended giveaways that are older than 24 hours
        const oneDayAgo = now - (24 * 60 * 60 * 1000);
        for (const [messageId, giveaway] of this.giveaways.entries()) {
            if (giveaway.ended && giveaway.endTime < oneDayAgo) {
                console.log(`[GIVEAWAY] Removing old ended giveaway ${messageId} from memory`);
                this.giveaways.delete(messageId);
                continue;
            }
            
            if (giveaway.endTime <= now && !giveaway.ended) {
                console.log(`[GIVEAWAY] Found ended giveaway: ${messageId} for prize "${giveaway.prize}". Ending now...`);
                try {
                    const result = await this.endGiveaway(messageId);
                    console.log(`[GIVEAWAY] Result of ending giveaway ${messageId}: ${result ? 'SUCCESS' : 'FAILED'}`);
                } catch (error) {
                    console.error(`[GIVEAWAY] Error ending giveaway ${messageId}:`, error);
                }
            }
        }
        
        // Save changes if we cleaned up any old giveaways
        await this.saveGiveaways();
    }

    /**
     * Create and start a new giveaway
     * @param {Object} options - Giveaway options
     * @returns {Promise<Object>} The created giveaway object
     */
    async startGiveaway({ channelId, duration, prize, winnerCount, thumbnail = null, description = null, requiredRoleId = null }) {
        try {
            const channel = await this.client.channels.fetch(channelId);
            if (!channel) throw new Error(`Channel with ID ${channelId} not found`);
            
            const endTime = Date.now() + duration;
            
            // Create giveaway embed
            const giveawayEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('🎉 GIVEAWAY 🎉')
                .setDescription(`**Prize**: ${prize}`)
                .addFields(
                    { name: '🏆 Winners', value: `${winnerCount}`, inline: true },
                    { name: '⏱️ Ends', value: `<t:${Math.floor(endTime / 1000)}:R>`, inline: true }
                );
                
            // Add description if provided
            if (description) {
                giveawayEmbed.addFields(
                    { name: '\u200B', value: '\u200B' },
                    { name: '📋 Description', value: description }
                );
            }
            
            // Add required role info if specified
            if (requiredRoleId) {
                const role = channel.guild.roles.cache.get(requiredRoleId);
                if (role) {
                    giveawayEmbed.addFields(
                        { name: '🎭 Required Role', value: `${role}`, inline: true }
                    );
                }
            }
            
            // Add entry instructions
            let entryInstructions = 'React with 🎉 to enter the giveaway!';
            if (requiredRoleId) {
                entryInstructions += '\n**Note:** You must have the required role to participate.';
            }
            
            giveawayEmbed.addFields(
                { name: '\u200B', value: '\u200B' },
                { name: '📝 How to Enter', value: entryInstructions }
            );
            
            // Add thumbnail or image
            if (thumbnail) {
                giveawayEmbed.setThumbnail(thumbnail);
            }
            
            // Always set the banner image
         //   giveawayEmbed.setImage('https://i.imgur.com/4MfQzYa.png');
            
            // Set footer
            giveawayEmbed.setFooter({ text: 'Good luck! • Powered by ProjectHub' })
                         .setTimestamp();
            
            // Send giveaway message
            const giveawayMessage = await channel.send({
                embeds: [giveawayEmbed]
            });
            
            // Add the reaction emoji for entering
            await giveawayMessage.react('🎉');
            
            // Store giveaway data in database first
            if (this.dbReady) {
                try {
                    await this.db.insert(this.schema.giveaways)
                        .values({
                            messageId: giveawayMessage.id,
                            channelId: channelId,
                            guildId: channel.guild.id,
                            prize: prize,
                            description: description,
                            winnerCount: winnerCount,
                            hostId: this.client.user.id,
                            isActive: true,
                            ended: false,
                            endsAt: new Date(endTime)
                        });
                    console.log(`[GIVEAWAY] Created giveaway ${giveawayMessage.id} in database`);
                } catch (dbError) {
                    console.error('[GIVEAWAY] Error saving giveaway to database:', dbError);
                    // Still continue with in-memory storage as fallback
                }
            }

            // Store giveaway data in memory
            const giveaway = {
                messageId: giveawayMessage.id,
                channelId,
                guildId: channel.guild.id,
                prize,
                winnerCount,
                endTime,
                ended: false,
                description,
                thumbnail,
                requiredRoleId,
                participants: new Set(),
                active: true
            };
            
            this.giveaways.set(giveawayMessage.id, giveaway);
            console.log(`[GIVEAWAY] Started giveaway in channel ${channelId} with ID ${giveawayMessage.id}`);
            
            return giveaway;
        } catch (error) {
            console.error('Error starting giveaway:', error);
            throw error;
        }
    }
    

    
    /**
     * End a giveaway and select winners
     * @param {string} messageId - The message ID of the giveaway
     * @returns {Promise<boolean>} Whether the giveaway was successfully ended
     */
    async endGiveaway(messageId) {
        try {
            const giveaway = this.giveaways.get(messageId);
            if (!giveaway || giveaway.ended) return false;
            
            // Mark as ended
            giveaway.ended = true;
            console.log(`[GIVEAWAY] Marked giveaway ${messageId} as ended. Updating in storage.`);
            
            // Get channel and message
            let channel, message;
            try {
                channel = await this.client.channels.fetch(giveaway.channelId);
                if (!channel) throw new Error(`Channel with ID ${giveaway.channelId} not found`);
                
                message = await channel.messages.fetch(messageId);
                if (!message) throw new Error(`Message with ID ${messageId} not found`);
            } catch (fetchError) {
                console.log(`[GIVEAWAY] Could not fetch message/channel for giveaway ${messageId}: ${fetchError.message}`);
                
                // If we can't fetch the message, still announce winners in a fallback way
                if (channel) {
                    const participants = Array.from(giveaway.participants);
                    const winners = this.selectWinners(participants, giveaway.winnerCount);
                    
                    if (winners.length > 0) {
                        const winnersText = winners.map(id => `<@${id}>`).join(', ');
                        await channel.send({
                            content: `🎉 **GIVEAWAY ENDED** 🎉\nCongratulations ${winnersText}! You won the **${giveaway.prize}**!\n*(Original giveaway message was deleted)*`,
                            allowedMentions: { users: winners }
                        });
                    } else {
                        await channel.send(`🎉 **GIVEAWAY ENDED** 🎉\nThe giveaway for **${giveaway.prize}** has ended, but no one entered!\n*(Original giveaway message was deleted)*`);
                    }
                }
                
                // Save and return
                await this.saveGiveaways();
                console.log(`[GIVEAWAY] Giveaway ${messageId} ended with deleted message.`);
                return true;
            }
            
            // Select winners
            const participants = Array.from(giveaway.participants);
            const winners = this.selectWinners(participants, giveaway.winnerCount);
            
            // Create winners text
            let winnersText = 'No one entered the giveaway!';
            if (winners.length > 0) {
                winnersText = winners.map(id => `<@${id}>`).join(', ');
            }
            
            // Update giveaway embed
            const endedEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('🎉 GIVEAWAY ENDED 🎉')
                .setDescription(`**Prize**: ${giveaway.prize}`)
                .addFields(
                    { name: '🏆 Winner(s)', value: winnersText, inline: false },
                    { name: '⏱️ Ended', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true },
                    { name: '📊 Entries', value: `${participants.length}`, inline: true },
                );
                
            // Add description if it exists
            if (giveaway.description) {
                endedEmbed.addFields(
                    { name: '\u200B', value: '\u200B' },
                    { name: '📋 Description', value: giveaway.description }
                );
            }
            
            // Add thumbnail if it exists
            if (giveaway.thumbnail) {
                endedEmbed.setThumbnail(giveaway.thumbnail);
            }
            
            // Set banner for ended giveaways
           endedEmbed.setFooter({ text: 'Thanks for participating! • Powered by ProjectHub' })
                      .setTimestamp();
            
            // Update giveaway message
            await message.edit({
                embeds: [endedEmbed]
            });
            
            // Announce winners
            if (winners.length > 0) {
                await channel.send({
                    content: `Congratulations ${winnersText}! You won the **${giveaway.prize}**!`,
                    allowedMentions: { users: winners }
                });
            } else {
                await channel.send('No one entered the giveaway, so there are no winners!');
            }
            
            // Save the updated giveaway with ended=true
            await this.saveGiveaways();
            console.log(`[GIVEAWAY] Giveaway ${messageId} successfully ended and saved.`);
            
            return true;
        } catch (error) {
            console.error(`Error ending giveaway ${messageId}:`, error);
            return false;
        }
    }
    
    /**
     * Reroll winners for a giveaway
     * @param {string} messageId - The message ID of the giveaway
     * @returns {Promise<boolean>} Whether the giveaway was successfully rerolled
     */
    async rerollGiveaway(messageId) {
        try {
            const giveaway = this.giveaways.get(messageId);
            if (!giveaway || !giveaway.ended) return false;
            
            // Get channel
            const channel = await this.client.channels.fetch(giveaway.channelId);
            if (!channel) throw new Error(`Channel with ID ${giveaway.channelId} not found`);
            
            // Select new winners
            const participants = Array.from(giveaway.participants);
            const winners = this.selectWinners(participants, giveaway.winnerCount);
            
            // Create winners text
            let winnersText = 'No one entered the giveaway!';
            if (winners.length > 0) {
                winnersText = winners.map(id => `<@${id}>`).join(', ');
            }
            
            // Announce rerolled winners
            if (winners.length > 0) {
                await channel.send({
                    content: `🎉 **GIVEAWAY REROLLED!** 🎉\nNew winner(s) for the **${giveaway.prize}**: ${winnersText}`,
                    allowedMentions: { users: winners }
                });
            } else {
                await channel.send(`Could not reroll the giveaway for **${giveaway.prize}** because no one entered.`);
            }
            
            return true;
        } catch (error) {
            console.error(`Error rerolling giveaway ${messageId}:`, error);
            return false;
        }
    }
    
    /**
     * Select random winners from participants
     * @param {Array<string>} participants - Array of participant user IDs
     * @param {number} count - Number of winners to select
     * @returns {Array<string>} - Array of winner user IDs
     */
    selectWinners(participants, count) {
        if (participants.length === 0) return [];
        
        // If fewer participants than winner count, return all participants
        if (participants.length <= count) return participants;
        
        const winners = [];
        const participantsCopy = [...participants];
        
        // Randomly select winners
        for (let i = 0; i < count; i++) {
            if (participantsCopy.length === 0) break;
            
            const winnerIndex = Math.floor(Math.random() * participantsCopy.length);
            winners.push(participantsCopy[winnerIndex]);
            participantsCopy.splice(winnerIndex, 1);
        }
        
        return winners;
    }

    /**
     * Add a participant to a giveaway
     * @param {string} messageId - The message ID of the giveaway
     * @param {string} userId - The user ID to add
     * @returns {Promise<boolean>} Whether the participant was successfully added
     */
    async addParticipant(messageId, userId) {
        try {
            const giveaway = this.giveaways.get(messageId);
            if (!giveaway || giveaway.ended) return false;

            // Check if user is already participating
            if (giveaway.participants.has(userId)) {
                return false; // Already participating
            }

            // Add to memory
            giveaway.participants.add(userId);

            // Add to database
            if (this.dbReady) {
                try {
                    await this.db.insert(this.schema.giveawayParticipants)
                        .values({
                            giveawayId: messageId,
                            userId: userId
                        });
                } catch (dbError) {
                    console.error(`[GIVEAWAY] Error adding participant ${userId} to database:`, dbError);
                    // Remove from memory if database operation failed
                    giveaway.participants.delete(userId);
                    return false;
                }
            }

            console.log(`[GIVEAWAY] Added participant ${userId} to giveaway ${messageId}`);
            return true;
        } catch (error) {
            console.error(`Error adding participant ${userId} to giveaway ${messageId}:`, error);
            return false;
        }
    }

    /**
     * Remove a participant from a giveaway
     * @param {string} messageId - The message ID of the giveaway
     * @param {string} userId - The user ID to remove
     * @returns {Promise<boolean>} Whether the participant was successfully removed
     */
    async removeParticipant(messageId, userId) {
        try {
            const giveaway = this.giveaways.get(messageId);
            if (!giveaway || giveaway.ended) return false;

            // Check if user is participating
            if (!giveaway.participants.has(userId)) {
                return false; // Not participating
            }

            // Remove from memory
            giveaway.participants.delete(userId);

            // Remove from database
            if (this.dbReady) {
                try {
                    await this.db.delete(this.schema.giveawayParticipants)
                        .where(and(
                            eq(this.schema.giveawayParticipants.giveawayId, messageId),
                            eq(this.schema.giveawayParticipants.userId, userId)
                        ));
                } catch (dbError) {
                    console.error(`[GIVEAWAY] Error removing participant ${userId} from database:`, dbError);
                    // Re-add to memory if database operation failed
                    giveaway.participants.add(userId);
                    return false;
                }
            }

            console.log(`[GIVEAWAY] Removed participant ${userId} from giveaway ${messageId}`);
            return true;
        } catch (error) {
            console.error(`Error removing participant ${userId} from giveaway ${messageId}:`, error);
            return false;
        }
    }
}

module.exports = GiveawayManager;
