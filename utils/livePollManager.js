const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');

// Import database and schema - we'll handle this dynamically
let db, livePolls, livePollOptions, livePollVotes, eq, and, desc, sql;

// Try to import database components - delayed initialization
let dbInitialized = false;

async function initializeDatabase() {
    if (dbInitialized) return true;
    
    try {
        // Try to import database components
        require('dotenv').config();
        
        // Check for MySQL database configuration
        const hasMySQL = process.env.DB_HOST || process.env.DB_USER || process.env.DB_NAME;
        const hasPostgreSQL = process.env.DATABASE_URL;
        
        if (!hasMySQL && !hasPostgreSQL) {
            console.log('⚠️ No database configuration found, using fallback mode');
            return false;
        }
        
        const dbModule = require('../server/db.js');
        db = dbModule.db;
        
        const schemaModule = require('../shared/schema.js');
        livePolls = schemaModule.livePolls;
        livePollOptions = schemaModule.livePollOptions;
        livePollVotes = schemaModule.livePollVotes;
        
        const drizzleORM = require('drizzle-orm');
        eq = drizzleORM.eq;
        and = drizzleORM.and;
        desc = drizzleORM.desc;
        sql = drizzleORM.sql;
        
        dbInitialized = true;
        console.log('✅ Database components loaded successfully for LivePollManager');
        return true;
    } catch (error) {
        console.error('❌ Error importing database components:', error.message);
        return false;
    }
}

// Initialize fallback functions
if (!dbInitialized) {
    db = { 
        insert: () => Promise.resolve([{ pollId: 'test-poll', passCode: 'TEST123' }]),
        select: () => Promise.resolve([]),
        update: () => Promise.resolve(),
        execute: () => Promise.resolve({ rows: [] })
    };
}

class LivePollManager {
    constructor(client = null) {
        this.client = client;
        this.pollCaches = new Map(); // Cache for active polls
        this.dbReady = false;
        this.db = null;
        this.drizzleDb = null;
        this.initializeDatabaseConnection();
    }

    // Initialize database connection and tables
    async initializeDatabaseConnection() {
        try {
            // First try to initialize database components
            const initialized = await initializeDatabase();
            
            if (initialized) {
                const { initializeGracefully } = require('../server/db.js');
                this.dbReady = await initializeGracefully();
                
                // Get the actual database instance
                if (this.dbReady) {
                    const dbModule = require('../server/db.js');
                    this.db = dbModule.pool;
                    this.drizzleDb = dbModule.db;
                    console.log('✅ Live poll database connection established');
                    
                    // Store database reference in global db variable for poll operations
                    if (!global.livePollDb) {
                        global.livePollDb = dbModule.db;
                    }
                } else {
                    console.log('⚠️ Live polls will use fallback mode (memory only)');
                }
            } else {
                this.dbReady = false;
                console.log('⚠️ Database components not available - using fallback mode');
            }
        } catch (error) {
            console.error('❌ Database initialization error:', error.message);
            this.dbReady = false;
            console.log('⚠️ Live polls will use fallback mode (memory only)');
            
            // If it's a connection error, retry after delay
            if (error.message.includes('Connection') || error.message.includes('timeout')) {
                console.log('⏳ Will retry database connection in 60 seconds...');
                setTimeout(() => {
                    this.initializeDatabaseConnection();
                }, 60000);
            }
        }
    }

    // Generate a unique poll ID
    generatePollId() {
        return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    }

    // Generate a random pass code
    generatePassCode() {
        return Math.random().toString(36).substring(2, 8).toUpperCase();
    }

    // Create a new live poll
    async createLivePoll({ question, options, creatorId, duration = null, allowMultipleVotes = false }) {
        try {
            const pollId = this.generatePollId();
            const passCode = this.generatePassCode();
            const expiresAt = duration ? new Date(Date.now() + duration) : null;

            const poll = {
                pollId,
                passCode,
                question,
                creatorId,
                isActive: true,
                allowMultipleVotes,
                expiresAt,
                createdAt: new Date()
            };

            // Create poll options
            const optionInserts = options.map((option, index) => ({
                pollId,
                optionText: option,
                optionIndex: index,
                voteCount: 0
            }));

            if (this.dbReady && (db || global.livePollDb)) {
                // Insert poll into database
                const dbInstance = db || global.livePollDb;
                await dbInstance.insert(livePolls).values(poll);
                await dbInstance.insert(livePollOptions).values(optionInserts);
                
                // Cache the poll
                this.pollCaches.set(pollId, {
                    ...poll,
                    options: optionInserts
                });
            } else {
                // Use in-memory storage
                this.pollCaches.set(pollId, {
                    ...poll,
                    options: optionInserts,
                    votes: [] // Store votes in memory
                });
            }

            return { pollId, passCode, poll };
        } catch (error) {
            console.error('Error creating live poll:', error);
            throw error;
        }
    }

    // Update poll with Discord message information
    async updatePollMessage(pollId, messageId, channelId) {
        try {
            if (this.dbReady && (db || global.livePollDb)) {
                const dbInstance = db || global.livePollDb;
                await dbInstance.update(livePolls)
                    .set({ messageId, channelId })
                    .where(eq(livePolls.pollId, pollId));
            }

            // Update cache
            if (this.pollCaches.has(pollId)) {
                this.pollCaches.get(pollId).messageId = messageId;
                this.pollCaches.get(pollId).channelId = channelId;
            }

            console.log(`[LIVE POLLS] Updated message info for poll ${pollId}: message ${messageId}, channel ${channelId}`);
        } catch (error) {
            console.error('Error updating poll message info:', error);
        }
    }

    // Get poll by ID or pass code
    async getPoll(identifier) {
        try {
            // Try to get from cache first
            if (this.pollCaches.has(identifier)) {
                return this.pollCaches.get(identifier);
            }

            // Check if any cached poll has this pass code
            for (const [pollId, pollData] of this.pollCaches.entries()) {
                if (pollData.passCode === identifier) {
                    return pollData;
                }
            }

            if (this.dbReady) {
                // Query database by poll ID or pass code  
                let poll = null;
                const dbInstance = db || global.livePollDb || this.drizzleDb;
                
                // First try by poll ID
                const pollById = await dbInstance.select()
                    .from(livePolls)
                    .where(eq(livePolls.pollId, identifier))
                    .limit(1);
                
                if (pollById.length > 0) {
                    poll = pollById[0];
                } else {
                    // If not found by poll ID, try by pass code
                    const pollByCode = await dbInstance.select()
                        .from(livePolls)
                        .where(eq(livePolls.passCode, identifier))
                        .limit(1);
                    
                    if (pollByCode.length > 0) {
                        poll = pollByCode[0];
                    }
                }

                if (!poll) return null;

                // Get poll options
                const options = await dbInstance.select()
                    .from(livePollOptions)
                    .where(eq(livePollOptions.pollId, poll.pollId))
                    .orderBy(livePollOptions.optionIndex);

                const pollData = { ...poll, options };
                
                // Check if poll has expired and update status
                if (pollData.expiresAt && new Date() > new Date(pollData.expiresAt) && pollData.isActive) {
                    console.log(`[DEBUG] Poll ${pollData.pollId} expired during retrieval, updating status...`);
                    
                    // Update database
                    await dbInstance.update(livePolls)
                        .set({ isActive: false })
                        .where(eq(livePolls.pollId, pollData.pollId));
                    
                    pollData.isActive = false;
                }
                
                // Cache the poll
                this.pollCaches.set(poll.pollId, pollData);
                
                return pollData;
            }

            return null;
        } catch (error) {
            console.error('Error getting poll:', error);
            return null;
        }
    }

    // Vote on a poll (wrapper method for button interactions)
    async vote(pollId, userId, optionIndex) {
        return await this.voteOnPoll({ pollId, userId, optionIndex });
    }

    // Vote on a poll
    async voteOnPoll({ pollId, userId, optionIndex }) {
        try {
            const poll = await this.getPoll(pollId);
            if (!poll || !poll.isActive) {
                return { success: false, message: 'Poll not found or not active' };
            }

            // Check if poll has expired
            if (poll.expiresAt && new Date() > new Date(poll.expiresAt)) {
                return { success: false, message: 'Poll has expired' };
            }

            // Check if option index is valid
            if (optionIndex < 0 || optionIndex >= poll.options.length) {
                return { success: false, message: 'Invalid option selected' };
            }

            // Check if user has already voted (if multiple votes not allowed)
            if (!poll.allowMultipleVotes) {
                if (this.dbReady && (db || global.livePollDb || this.drizzleDb)) {
                    const dbInstance = db || global.livePollDb || this.drizzleDb;
                    const existingVote = await dbInstance.select()
                        .from(livePollVotes)
                        .where(and(
                            eq(livePollVotes.pollId, pollId),
                            eq(livePollVotes.userId, userId)
                        ));

                    if (existingVote.length > 0) {
                        return { success: false, message: 'You have already voted on this poll' };
                    }
                } else {
                    // Check in-memory votes
                    const cachedPoll = this.pollCaches.get(pollId);
                    if (cachedPoll && cachedPoll.votes) {
                        const existingVote = cachedPoll.votes.find(vote => vote.userId === userId);
                        if (existingVote) {
                            return { success: false, message: 'You have already voted on this poll' };
                        }
                    }
                }
            }

            if (this.dbReady && (db || global.livePollDb || this.drizzleDb)) {
                // Record the vote in database
                const dbInstance = db || global.livePollDb || this.drizzleDb;
                await dbInstance.insert(livePollVotes).values({
                    pollId,
                    userId,
                    optionIndex
                });

                // Update vote count
                await dbInstance.update(livePollOptions)
                    .set({ voteCount: sql`${livePollOptions.voteCount} + 1` })
                    .where(and(
                        eq(livePollOptions.pollId, pollId),
                        eq(livePollOptions.optionIndex, optionIndex)
                    ));
            } else {
                // Record vote in memory
                const cachedPoll = this.pollCaches.get(pollId);
                if (cachedPoll) {
                    if (!cachedPoll.votes) cachedPoll.votes = [];
                    cachedPoll.votes.push({
                        userId,
                        optionIndex,
                        votedAt: new Date()
                    });
                }
            }

            // Update cache
            if (this.pollCaches.has(pollId)) {
                const cachedPoll = this.pollCaches.get(pollId);
                cachedPoll.options[optionIndex].voteCount++;
            }

            return { success: true, message: 'Vote recorded successfully' };
        } catch (error) {
            console.error('Error voting on poll:', error);
            return { success: false, message: 'Error recording vote' };
        }
    }

    // End a poll
    async endPoll(pollId, userId) {
        try {
            const poll = await this.getPoll(pollId);
            if (!poll) {
                return { success: false, message: 'Poll not found' };
            }

            if (poll.creatorId !== userId) {
                return { success: false, message: 'Only the poll creator can end this poll' };
            }

            // Get final results before ending
            const results = await this.getPollResults(pollId);

            // Update poll as inactive
            if (this.dbReady && (db || global.livePollDb || this.drizzleDb)) {
                const dbInstance = db || global.livePollDb || this.drizzleDb;
                await dbInstance.update(livePolls)
                    .set({ isActive: false })
                    .where(eq(livePolls.pollId, pollId));
            }

            // Update cache
            if (this.pollCaches.has(pollId)) {
                this.pollCaches.get(pollId).isActive = false;
            }

            // Create winning celebration message
            let celebrationMessage = 'Poll ended successfully';
            if (results && results.totalVotes > 0) {
                const winningInfo = this.createWinningMessage(results.poll, results.options, results.totalVotes);
                celebrationMessage = winningInfo.winnerText;
            }

            return { 
                success: true, 
                message: celebrationMessage,
                results: results,
                isEnded: true
            };
        } catch (error) {
            console.error('Error ending poll:', error);
            return { success: false, message: 'Error ending poll' };
        }
    }

    // Get poll results
    async getPollResults(pollId) {
        try {
            const poll = await this.getPoll(pollId);
            if (!poll) return null;

            // Check if poll has expired and update status if needed
            if (poll.expiresAt && new Date() > new Date(poll.expiresAt) && poll.isActive) {
                console.log(`[DEBUG] Poll ${pollId} has expired, updating status...`);
                
                // Update poll status to inactive
                if (this.dbReady && (db || global.livePollDb || this.drizzleDb)) {
                    const dbInstance = db || global.livePollDb || this.drizzleDb;
                    await dbInstance.update(livePolls)
                        .set({ isActive: false })
                        .where(eq(livePolls.pollId, pollId));
                }

                // Update cache
                if (this.pollCaches.has(pollId)) {
                    this.pollCaches.get(pollId).isActive = false;
                }
                
                // Update the poll object
                poll.isActive = false;
                console.log(`[DEBUG] Poll ${pollId} status updated to inactive`);
            }

            let options;
            
            if (this.dbReady && (db || global.livePollDb || this.drizzleDb)) {
                // Get updated vote counts from database
                const dbInstance = db || global.livePollDb || this.drizzleDb;
                options = await dbInstance.select()
                    .from(livePollOptions)
                    .where(eq(livePollOptions.pollId, pollId))
                    .orderBy(livePollOptions.optionIndex);
            } else {
                // Use cached data
                options = poll.options || [];
            }

            const totalVotes = options.reduce((sum, option) => sum + (option.voteCount || 0), 0);

            return {
                poll,
                options,
                totalVotes
            };
        } catch (error) {
            console.error('Error getting poll results:', error);
            return null;
        }
    }

    // Generate winning celebration message
    createWinningMessage(poll, options, totalVotes) {
        if (totalVotes === 0) {
            return {
                title: '🏁 Poll Ended - No Votes',
                description: `**${poll.question}**\n\nNo votes were cast for this poll.`,
                color: config.colors.warning
            };
        }

        // Find the winning option(s)
        const maxVotes = Math.max(...options.map(opt => opt.voteCount));
        const winners = options.filter(opt => opt.voteCount === maxVotes);
        
        const celebrationEmojis = ['🎉', '🏆', '✨', '🎊', '🥳', '🎈', '🌟'];
        const randomEmoji = celebrationEmojis[Math.floor(Math.random() * celebrationEmojis.length)];
        
        if (winners.length === 1) {
            // Single winner
            const winner = winners[0];
            const percentage = ((winner.voteCount / totalVotes) * 100).toFixed(1);
            
            return {
                title: `${randomEmoji} Congratulations! We Have a Winner! ${randomEmoji}`,
                description: `**${poll.question}**\n\n🏆 **"${winner.optionText}"** wins with **${winner.voteCount}** votes (${percentage}%)!\n\nThank you to everyone who participated in this poll!`,
                color: config.colors.success,
                winnerText: `🎊 Winner: **${winner.optionText}** with ${winner.voteCount} votes!`
            };
        } else {
            // Multiple winners (tie)
            const winnerNames = winners.map(w => `"${w.optionText}"`).join(', ');
            const percentage = ((maxVotes / totalVotes) * 100).toFixed(1);
            
            return {
                title: `${randomEmoji} It's a Tie! Multiple Winners! ${randomEmoji}`,
                description: `**${poll.question}**\n\n🏆 We have a ${winners.length}-way tie!\n**${winnerNames}** each received **${maxVotes}** votes (${percentage}%)!\n\nAmazing participation from everyone!`,
                color: config.colors.primary,
                winnerText: `🎊 Tie between: ${winnerNames} with ${maxVotes} votes each!`
            };
        }
    }

    // Create poll embed
    createPollEmbed(poll, options, totalVotes = 0, showResults = false, isWinningAnnouncement = false) {
        let embed;
        
        if (isWinningAnnouncement && !poll.isActive) {
            // Create special winning announcement embed
            const winningInfo = this.createWinningMessage(poll, options, totalVotes);
            embed = new EmbedBuilder()
                .setColor(winningInfo.color)
                .setTitle(winningInfo.title)
                .setDescription(winningInfo.description)
                .setTimestamp();
        } else {
            // Regular poll embed
            embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('📊 Live Poll')
                .setDescription(`**${poll.question}**`)
                .setTimestamp();
        }

        if (showResults) {
            const resultsText = options.map((option, index) => {
                const percentage = totalVotes > 0 ? ((option.voteCount / totalVotes) * 100).toFixed(1) : 0;
                const barLength = Math.round(percentage / 5);
                const bar = '█'.repeat(barLength) + '░'.repeat(20 - barLength);
                return `**${index + 1}.** ${option.optionText}\n${bar} ${option.voteCount} votes (${percentage}%)`;
            }).join('\n\n');

            embed.addFields(
                { name: 'Results', value: resultsText || 'No votes yet', inline: false },
                { name: 'Total Votes', value: totalVotes.toString(), inline: true },
                { name: 'Status', value: poll.isActive ? '🟢 Active' : '🔴 Ended', inline: true }
            );
        } else {
            const optionsText = options.map((option, index) => 
                `**${index + 1}.** ${option.optionText}`
            ).join('\n');

            embed.addFields(
                { name: 'Options', value: optionsText, inline: false },
                { name: 'Status', value: poll.isActive ? '🟢 Active' : '🔴 Ended', inline: true }
            );
        }

        if (poll.expiresAt) {
            embed.addFields({
                name: 'Expires',
                value: `<t:${Math.floor(new Date(poll.expiresAt).getTime() / 1000)}:R>`,
                inline: true
            });
        }

        return embed;
    }

    // Create vote buttons
    createVoteButtons(pollId, options) {
        const rows = [];
        const buttonsPerRow = 5;
        
        for (let i = 0; i < options.length; i += buttonsPerRow) {
            const row = new ActionRowBuilder();
            
            for (let j = i; j < Math.min(i + buttonsPerRow, options.length); j++) {
                row.addComponents(
                    new ButtonBuilder()
                        .setCustomId(`vote_${pollId}_${j}`)
                        .setLabel(`${j + 1}`)
                        .setStyle(ButtonStyle.Primary)
                );
            }
            
            rows.push(row);
        }

        return rows;
    }

    // Get user's polls
    async getUserPolls(userId, limit = 10) {
        try {
            const polls = await db.select()
                .from(livePolls)
                .where(eq(livePolls.creatorId, userId))
                .orderBy(desc(livePolls.createdAt))
                .limit(limit);

            return polls;
        } catch (error) {
            console.error('Error getting user polls:', error);
            return [];
        }
    }

    // Check for expired polls and update their status
    async checkExpiredPolls() {
        try {
            if (!this.dbReady || !(db || global.livePollDb || this.drizzleDb)) {
                console.log('[LIVE POLLS] Database not ready, skipping expiration check');
                return;
            }

            const dbInstance = db || global.livePollDb || this.drizzleDb;
            const now = new Date();

            // Add timeout wrapper for database operations
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Database operation timeout')), 10000); // 10 second timeout
            });

            // Find all active polls that have expired with timeout
            const expiredPolls = await Promise.race([
                dbInstance.select()
                    .from(livePolls)
                    .where(and(
                        eq(livePolls.isActive, true),
                        sql`${livePolls.expiresAt} IS NOT NULL AND ${livePolls.expiresAt} <= ${now}`
                    )),
                timeoutPromise
            ]);

            console.log(`[LIVE POLLS] Checking for expired polls. Found ${expiredPolls.length} expired polls.`);

            if (expiredPolls.length > 0) {
                // Update all expired polls to inactive
                for (const poll of expiredPolls) {
                    await dbInstance.update(livePolls)
                        .set({ isActive: false })
                        .where(eq(livePolls.pollId, poll.pollId));

                    // Update cache if exists
                    if (this.pollCaches.has(poll.pollId)) {
                        this.pollCaches.get(poll.pollId).isActive = false;
                    }

                    console.log(`[LIVE POLLS] Expired poll ${poll.pollId}: "${poll.question}"`);

                    // Update Discord message to show poll as ended
                    try {
                        if (poll.messageId && poll.channelId && this.client) {
                            const channel = await this.client.channels.fetch(poll.channelId);
                            if (channel) {
                                const message = await channel.messages.fetch(poll.messageId);
                                if (message) {
                                    // Get updated poll results with expired status
                                    const pollResults = await this.getPollResults(poll.pollId);
                                    if (pollResults) {
                                        // Show winning celebration for expired polls with votes
                                        const isWinningAnnouncement = pollResults.totalVotes > 0;
                                        const updatedEmbed = this.createPollEmbed(
                                            pollResults.poll, 
                                            pollResults.options, 
                                            pollResults.totalVotes, 
                                            true,
                                            isWinningAnnouncement
                                        );
                                        
                                        // Remove buttons for expired polls
                                        await message.edit({
                                            embeds: [updatedEmbed],
                                            components: []
                                        });
                                        
                                        // Send celebration message in channel if there were votes
                                        if (pollResults.totalVotes > 0) {
                                            const winningInfo = this.createWinningMessage(pollResults.poll, pollResults.options, pollResults.totalVotes);
                                            await channel.send(`⏰ **Poll Expired!** ${winningInfo.winnerText}`);
                                        }
                                        
                                        console.log(`[LIVE POLLS] Updated Discord message for expired poll ${poll.pollId}`);
                                    }
                                }
                            }
                        }
                    } catch (updateError) {
                        console.error(`[LIVE POLLS] Failed to update Discord message for poll ${poll.pollId}:`, updateError);
                    }
                }

                console.log(`[LIVE POLLS] Updated ${expiredPolls.length} expired polls to inactive status.`);
            }
        } catch (error) {
            console.error('[LIVE POLLS] Error checking expired polls:', error.message);
            
            // If it's a connection error, try to reinitialize database
            if (error.message.includes('Connection terminated') || error.message.includes('timeout')) {
                console.log('[LIVE POLLS] Connection issue detected, reinitializing database...');
                this.dbReady = false;
                
                // Try to reinitialize after a delay
                setTimeout(() => {
                    this.initializeDatabaseConnection();
                }, 30000); // Wait 30 seconds before retry
            }
        }
    }
}

module.exports = LivePollManager;