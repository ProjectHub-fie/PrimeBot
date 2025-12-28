const { EmbedBuilder } = require('discord.js');
const fs = require('fs');
const path = require('path');
const config = require('../config');
const ms = require('ms');

class PollManager {
    constructor(client) {
        this.client = client;
        this.polls = new Map();
        this.dataPath = path.join(__dirname, '../data/polls.json');
        
        // Ensure data directory exists
        const dataDir = path.join(__dirname, '../data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        
        this.loadPolls();
        
        // Start poll checking with a slight delay to ensure client is ready
        setTimeout(() => {
            this.startCheckingPolls();
        }, 5000);
    }
    
    /**
     * Load saved polls from the data file
     */
    loadPolls() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                for (const [messageId, poll] of Object.entries(data)) {
                    this.polls.set(messageId, poll);
                }
                console.log(`Loaded ${this.polls.size} polls from file.`);
            } else {
                // Create the file if it doesn't exist
                this.savePolls();
            }
        } catch (error) {
            console.error('Error loading polls:', error);
            this.polls = new Map();
        }
    }
    
    /**
     * Save polls to the data file
     */
    savePolls() {
        try {
            const data = {};
            for (const [messageId, poll] of this.polls.entries()) {
                data[messageId] = poll;
            }
            fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving polls:', error);
        }
    }
    
    /**
     * Start checking for ended polls at a regular interval
     */
    startCheckingPolls() {
        setInterval(() => {
            this.checkPolls();
        }, 10000); // Check every 10 seconds
        
        console.log('Poll checking system started.');
    }
    
    /**
     * Check for ended polls and process them
     */
    async checkPolls() {
        const now = Date.now();
        const endedPolls = [];
        
        console.log(`[POLLS] Checking for ended polls. Active polls: ${this.polls.size}`);
        
        // Log all active polls
        for (const [messageId, poll] of this.polls.entries()) {
            console.log(`[POLLS] Active poll ${messageId}: "${poll.question}", end time: ${new Date(poll.endTime).toISOString()}, current time: ${new Date(now).toISOString()}, ended: ${poll.ended}`);
            
            // Only process polls that are not yet ended and have reached their end time
            if (!poll.ended && poll.endTime <= now) {
                console.log(`[POLLS] Poll ${messageId} has ended, marking for processing`);
                endedPolls.push(messageId);
            }
        }
        
        if (endedPolls.length > 0) {
            console.log(`[POLLS] Found ${endedPolls.length} ended polls to process.`);
        } else {
            console.log(`[POLLS] No ended polls to process at this time.`);
        }
        
        for (const messageId of endedPolls) {
            try {
                const poll = this.polls.get(messageId);
                if (!poll) {
                    console.log(`[POLLS] Poll ${messageId} not found in map, skipping`);
                    continue;
                }
                
                console.log(`[POLLS] Processing ended poll: ${poll.question} (ID: ${messageId})`);
                const success = await this.endPoll(messageId);
                
                if (success) {
                    console.log(`[POLLS] Successfully ended poll ${messageId}`);
                    // Make sure to save the 'ended' status
                    this.savePolls();
                } else {
                    console.log(`[POLLS] Failed to end poll ${messageId}, will retry next cycle`);
                }
            } catch (error) {
                console.error(`[POLLS] Error ending poll ${messageId}:`, error);
            }
        }
    }
    
    /**
     * Create a new poll
     * @param {Object} options - Poll options
     * @returns {Promise<Object>} The sent message
     */
    async createPoll({ channelId, question, options, duration, userId }) {
        // Validate options (must have 2-10 options)
        if (!options || options.length < 2 || options.length > 10) {
            throw new Error('A poll must have between 2 and 10 options.');
        }
        
        const channel = await this.client.channels.fetch(channelId);
        if (!channel) {
            throw new Error('Channel not found.');
        }
        
        // Calculate end time from duration
        const durationMs = ms(duration);
        if (!durationMs) {
            throw new Error('Invalid duration. Please use a valid format like 1m, 1h, 1d.');
        }
        
        const endTime = Date.now() + durationMs;
        
        // Create the poll embed
        const optionsWithEmojis = options.map((option, index) => {
            const emoji = this.getOptionEmoji(index);
            return `${emoji} ${option}`;
        });
        
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle(`📊 Poll: ${question}`)
            .setDescription(optionsWithEmojis.join('\n\n'))
            .addFields(
                { name: 'Poll Duration', value: `Ends <t:${Math.floor(endTime / 1000)}:R>` }
            )
            .setFooter({ 
                text: `Poll created by ${userId ? (channel.guild.members.cache.get(userId)?.displayName || 'Unknown') : 'Unknown'}`, 
                iconURL: userId ? (channel.guild.members.cache.get(userId)?.user.displayAvatarURL({ dynamic: true }) || null) : null 
            })
            .setTimestamp();
        
        // Send the poll message
        const message = await channel.send({ embeds: [embed] });
        
        // Add reaction emojis for voting
        for (let i = 0; i < options.length; i++) {
            await message.react(this.getOptionEmoji(i));
        }
        
        // Save the poll data
        const pollData = {
            messageId: message.id,
            channelId,
            question,
            options,
            endTime,
            createdBy: userId,
            ended: false
        };
        
        this.polls.set(message.id, pollData);
        this.savePolls();
        
        return message;
    }
    
    /**
     * End a poll and display the results
     * @param {string} messageId - The message ID of the poll
     * @returns {Promise<boolean>} Whether the poll was successfully ended
     */
    async endPoll(messageId) {
        const poll = this.polls.get(messageId);
        if (!poll || poll.ended) {
            console.log(`[POLLS] Cannot end poll ${messageId}: poll not found or already ended`);
            return false;
        }
        
        try {
            console.log(`[POLLS] Ending poll ${messageId}: "${poll.question}"`);
            
            const channel = await this.client.channels.fetch(poll.channelId);
            if (!channel) {
                console.log(`[POLLS] Cannot end poll ${messageId}: channel not found`);
                throw new Error('Channel not found.');
            }
            
            const message = await channel.messages.fetch(messageId).catch((err) => {
                console.error(`[POLLS] Error fetching poll message: ${err.message}`);
                return null;
            });
            
            if (!message) {
                // Remove the poll if the message doesn't exist anymore
                console.log(`[POLLS] Poll message ${messageId} not found, removing from active polls`);
                this.polls.delete(messageId);
                this.savePolls();
                return false;
            }
            
            // Check if message has reactions manager
            if (!message || !message.reactions || typeof message.reactions.fetch !== 'function') {
                console.error(`[POLLS] Message ${messageId} does not have valid reactions manager`);
                // Try to get reactions manually
                if (!message.reactions || !message.reactions.cache) {
                    console.log(`[POLLS] Removing poll ${messageId} due to invalid message or reactions`);
                    this.polls.delete(messageId);
                    this.savePolls();
                    return false;
                }
                console.log(`[POLLS] Using cached reactions only for poll ${messageId}`);
            } else {
                // Ensure ALL reactions are completely fetched (Discord.js sometimes caches incomplete reactions)
                try {
                    await message.reactions.fetch();
                    console.log(`[POLLS] Fetched ${message.reactions.cache.size} reactions from poll message`);
                } catch (fetchError) {
                    console.error(`[POLLS] Error fetching reactions: ${fetchError.message}`);
                    // If reaction fetching fails, we'll work with what we have in cache
                    console.log(`[POLLS] Using cached reactions as fallback`);
                }
            }
            
            // Count votes
            const results = [];
            
            // Manually fetch all reactions with full collection of users
            for (let i = 0; i < poll.options.length; i++) {
                const emoji = this.getOptionEmoji(i);
                let reaction = message.reactions.cache.get(emoji);
                
                if (reaction) {
                    // Fetch ALL users who reacted to get accurate count (using fetchReactionUsers helper)
                    try {
                        console.log(`[POLLS] Fetching ALL users for reaction ${emoji}...`);
                        // Force a complete fetch of all reaction users
                        const reactionUsers = await this.fetchAllReactionUsers(reaction);
                        
                        // Get accurate count (exclude the bot)
                        const botId = this.client.user.id;
                        const userCount = reactionUsers.filter(user => user.id !== botId).size;
                        
                        console.log(`[POLLS] Option "${poll.options[i]}" (${emoji}) has ${userCount} votes (from complete fetch)`);
                        
                        results.push({
                            option: poll.options[i],
                            emoji,
                            votes: userCount
                        });
                    } catch (err) {
                        console.error(`[POLLS] Error fetching reaction users for ${emoji}: ${err.message}`);
                        // Fallback to basic count if full fetch fails
                        const count = reaction.count > 0 ? reaction.count - 1 : 0;
                        console.log(`[POLLS] Falling back to basic count: ${count} votes`);
                        
                        results.push({
                            option: poll.options[i],
                            emoji,
                            votes: count
                        });
                    }
                } else {
                    console.log(`[POLLS] No reaction found for option "${poll.options[i]}" (${emoji})`);
                    results.push({
                        option: poll.options[i],
                        emoji,
                        votes: 0
                    });
                }
            }
            
            // Sort by votes (highest first)
            results.sort((a, b) => b.votes - a.votes);
            
            // Calculate total votes
            const totalVotes = results.reduce((sum, result) => sum + result.votes, 0);
            console.log(`[POLLS] Total votes: ${totalVotes}`);
            
            // Calculate winners first (options with the highest votes)
            const highestVotes = results.length > 0 ? results[0].votes : 0;
            const winningResults = results.filter(result => result.votes === highestVotes && result.votes > 0);
            const winners = winningResults.map(result => result.option);
            
            console.log(`[POLLS] Identified winners: ${winners.join(', ')} with ${highestVotes} votes`);
            
            // Create results embed with enhanced winner display
            const resultLines = results.map((result, index) => {
                const percentage = totalVotes > 0 ? Math.round((result.votes / totalVotes) * 100) : 0;
                const progressBar = this.getProgressBar(percentage);
                
                // Add a crown emoji and make winners bold with gold color
                const isWinner = result.votes === highestVotes && result.votes > 0;
                
                // Enhanced winner formatting
                if (isWinner) {
                    return `👑 ${result.emoji} **${result.option}** 👑\n${progressBar} **${result.votes} votes (${percentage}%)**`;
                } else {
                    return `${result.emoji} **${result.option}**\n${progressBar} ${result.votes} votes (${percentage}%)`;
                }
            });
            
            console.log(`[POLLS] Winners: ${winners.length > 0 ? winners.join(', ') : 'None'} with ${highestVotes} votes`);
            
            // Create a winner announcement field
            let winnerField;
            
            if (totalVotes === 0) {
                winnerField = { name: 'No Votes', value: 'No votes were cast in this poll.' };
            } else if (winners.length === 0) {
                // This should rarely happen, but just in case
                winnerField = { name: 'No Winner', value: 'There was an issue determining the winner.' };
            } else if (winners.length === 1) {
                winnerField = { 
                    name: '🏆 Winner', 
                    value: `**${winners[0]}** with ${highestVotes} vote${highestVotes !== 1 ? 's' : ''}!` 
                };
            } else {
                winnerField = { 
                    name: '🏆 Tied Winners', 
                    value: `**${winners.join('** and **')}** with ${highestVotes} vote${highestVotes !== 1 ? 's' : ''} each!` 
                };
            }
            
            // Use special gold color for polls with winners, otherwise use primary color
            const embedColor = winners.length > 0 ? config.colors.Gold : config.colors.primary;
            
            const resultsEmbed = new EmbedBuilder()
                .setColor(embedColor)
                .setTitle(`📊 Poll Results: ${poll.question}`)
                .setDescription(resultLines.join('\n\n'))
                .addFields(
                    winnerField,
                    { name: '📊 Total Votes', value: `${totalVotes} vote${totalVotes !== 1 ? 's' : ''}` }
                )
                .setFooter({ 
                    text: `Poll ended • Results are final`, 
                    iconURL: null 
                })
                .setTimestamp();
            
            // Send the results
            console.log(`[POLLS] Sending poll results to channel ${channel.name}`);
            await channel.send({ embeds: [resultsEmbed] });
            
            // Mark the poll as ended
            poll.ended = true;
            this.polls.set(messageId, poll);
            this.savePolls();
            
            console.log(`[POLLS] Poll ${messageId} successfully ended`);
            return true;
        } catch (error) {
            console.error('[POLLS] Error ending poll:', error);
            return false;
        }
    }
    
    /**
     * Get the emoji for a poll option by index
     * @param {number} index - The option index
     * @returns {string} The emoji
     */
    getOptionEmoji(index) {
        const emojis = ['1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣', '🔟'];
        return emojis[index] || '❓';
    }
    
    /**
     * Get a progress bar for a percentage
     * @param {number} percentage - The percentage (0-100)
     * @returns {string} The progress bar
     */
    getProgressBar(percentage) {
        const filled = Math.round(percentage / 10);
        const empty = 10 - filled;
        
        return '█'.repeat(filled) + '░'.repeat(empty);
    }
    
    /**
     * Force end a poll early
     * @param {string} messageId - The message ID of the poll
     * @returns {Promise<boolean>} Whether the poll was successfully ended
     */
    async forceEndPoll(messageId) {
        console.log(`[POLLS] Force ending poll with ID: ${messageId}`);
        
        const poll = this.polls.get(messageId);
        if (!poll) {
            console.log(`[POLLS] Poll ${messageId} not found in active polls`);
            return false;
        }
        
        if (poll.ended) {
            console.log(`[POLLS] Poll ${messageId} is already ended`);
            return false;
        }
        
        console.log(`[POLLS] Found active poll to force end: "${poll.question}"`);
        const success = await this.endPoll(messageId);
        
        if (success) {
            console.log(`[POLLS] Successfully force-ended poll ${messageId}`);
        } else {
            console.log(`[POLLS] Failed to force-end poll ${messageId}`);
        }
        
        return success;
    }
    
    /**
     * Fetch all users who reacted with a specific reaction
     * This works around Discord API limitations by fetching users in batches
     * @param {MessageReaction} reaction - The reaction to fetch users for
     * @returns {Promise<Collection>} Collection of users who reacted
     */
    async fetchAllReactionUsers(reaction) {
        try {
            const { users } = reaction;
            let allUsers = users.cache.clone();
            let lastId = null;
            let hasMore = true;
            let fetchCount = 0;
            
            // Fetch users in batches of 100 until we get them all
            while (hasMore && fetchCount < 10) { // Limit to 10 fetches (1000 users) to prevent abuse
                fetchCount++;
                console.log(`[POLLS] Fetching reaction users batch ${fetchCount}, current size: ${allUsers.size}`);
                
                const options = { limit: 100 };
                if (lastId) options.after = lastId;
                
                const newUsers = await users.fetch(options);
                
                if (newUsers.size === 0) {
                    hasMore = false;
                    break;
                }
                
                allUsers = allUsers.concat(newUsers);
                lastId = newUsers.last().id;
                
                // If we got less than the requested limit, we've reached the end
                if (newUsers.size < 100) {
                    hasMore = false;
                }
            }
            
            console.log(`[POLLS] Completed reaction users fetch with ${allUsers.size} total users`);
            return allUsers;
        } catch (error) {
            console.error('[POLLS] Error fetching all reaction users:', error);
            // Return what we have in cache
            return reaction.users.cache;
        }
    }
}

module.exports = PollManager;