const fs = require('fs');
const path = require('path');
const { EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder } = require('discord.js');
const config = require('../config');

class CountingManager {
    constructor(client) {
        this.client = client;
        this.counting = new Map();
        this.dataPath = path.join(__dirname, '../data/counting.json');
        
        this.loadCounting();
    }
    
    /**
     * Load saved counting games from the data file
     */
    loadCounting() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                
                // Load each channel's counting data
                for (const [channelId, countData] of Object.entries(data)) {
                    this.counting.set(channelId, countData);
                }
                
                console.log(`Loaded counting data for ${this.counting.size} channels.`);
            } else {
                // Create an empty file if it doesn't exist
                this.saveCounting();
                console.log('Created empty counting data file.');
            }
        } catch (error) {
            console.error('Error loading counting data:', error);
            // Initialize empty map if loading fails
            this.counting = new Map();
        }
    }
    
    /**
     * Save counting data to file
     */
    saveCounting() {
        try {
            const data = {};
            
            // Convert Map to object for JSON storage
            for (const [channelId, countData] of this.counting.entries()) {
                data[channelId] = countData;
            }
            
            fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving counting data:', error);
        }
    }
    
    /**
     * Start a new counting game in a channel
     * @param {Object} options - Game options
     * @returns {Promise<Object>} The created game data
     */
    async startCountingGame({ channelId, startNumber = 1, goalNumber = 100 }) {
        try {
            // Validate inputs
            startNumber = parseInt(startNumber);
            goalNumber = parseInt(goalNumber);
            
            if (isNaN(startNumber) || isNaN(goalNumber)) {
                throw new Error('Start and goal numbers must be valid integers.');
            }
            
            if (startNumber >= goalNumber) {
                throw new Error('Start number must be lower than goal number.');
            }
            
            // Create new game data
            const countData = {
                currentNumber: startNumber - 1, // Initialize to one less so first valid number is startNumber
                goalNumber: goalNumber,
                startNumber: startNumber,
                lastUserId: null,
                highestNumber: startNumber - 1,
                failCount: 0,
                participants: {}
            };
            
            // Save the game
            this.counting.set(channelId, countData);
            this.saveCounting();
            
            // Get the channel
            const channel = await this.client.channels.fetch(channelId);
            if (!channel) {
                throw new Error('Could not find the channel.');
            }
            
            // Send the game start message
            const embed = this.createCountingEmbed(countData);
            await channel.send({ embeds: [embed] });
            
            return countData;
        } catch (error) {
            console.error('Error starting counting game:', error);
            throw error;
        }
    }
    
    /**
     * Process a message for counting game
     * @param {Message} message - The Discord message
     * @returns {Promise<boolean>} Whether the message was processed as a count
     */
    async processCountingMessage(message) {
        // Ignore bot messages
        if (message.author.bot) return false;
        
        // Check if this channel has a counting game
        const countData = this.counting.get(message.channel.id);
        if (!countData) return false;
        
        // Try to parse the message content as a number
        const content = message.content.trim();
        const number = parseInt(content);
        
        // If it's not a number, ignore
        if (isNaN(number)) return false;
        
        // Check if this is the next number in sequence
        const expectedNumber = countData.currentNumber + 1;
        
        // Check if the same user is counting twice in a row
        const isSameUser = message.author.id === countData.lastUserId;
        
        // If it's the correct number and not the same user
        if (number === expectedNumber && !isSameUser) {
            // Update the game state
            countData.currentNumber = number;
            countData.lastUserId = message.author.id;
            
            // Update highest number if applicable
            if (number > countData.highestNumber) {
                countData.highestNumber = number;
            }
            
            // Track participant stats
            if (!countData.participants[message.author.id]) {
                countData.participants[message.author.id] = 1;
            } else {
                countData.participants[message.author.id]++;
            }
            
            // Check if goal has been reached
            if (number === countData.goalNumber) {
                await this.handleGameWin(message.channel, countData);
                return true;
            }
            
            // Add a reaction to show it was correct
            try {
                await message.react('✅');
            } catch (error) {
                console.error('Error adding reaction:', error);
            }
            
            // Save the updated game state
            this.saveCounting();
            return true;
        } 
        // If it's wrong (wrong number or same user twice)
        else {
            try {
                // Add a reaction to show it was wrong
                await message.react('❌');
                
                // Increment fail count
                countData.failCount++;
                
                let failReason = '';
                if (isSameUser) {
                    failReason = `${message.author} counted twice in a row!`;
                } else {
                    failReason = `${message.author} counted ${number}, but the next number should be ${expectedNumber}!`;
                }
                
                // Send a fail message
                const failEmbed = new EmbedBuilder()
                    .setColor(config.colors.error)
                    .setTitle('Counting Failed!')
                    .setDescription(failReason)
                    .addFields(
                        { name: 'The count has been reset!', value: `The next number is **${countData.startNumber}**` }
                    );
                
                await message.channel.send({ embeds: [failEmbed] });
                
                // Reset the game
                countData.currentNumber = countData.startNumber - 1;
                countData.lastUserId = null;
                
                // Save the updated game state
                this.saveCounting();
                return true;
            } catch (error) {
                console.error('Error handling wrong count:', error);
                return false;
            }
        }
    }
    
    /**
     * Handle when players reach the goal number
     * @param {TextChannel} channel - The Discord channel
     * @param {Object} countData - The counting game data
     */
    async handleGameWin(channel, countData) {
        try {
            // Create participant list with most counts first
            const participants = Object.entries(countData.participants)
                .sort((a, b) => b[1] - a[1])
                .map(([userId, count], index) => {
                    return `${index + 1}. <@${userId}>: ${count} numbers`;
                })
                .join('\n');
            
            // Create win embed
            const winEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('🎉 Counting Goal Reached! 🎉')
                .setDescription(`You've successfully counted from **${countData.startNumber}** to **${countData.goalNumber}**!`)
                .addFields(
                    { 
                        name: 'Participants', 
                        value: participants || 'No participants' 
                    },
                    {
                        name: 'Failures',
                        value: `The count was reset ${countData.failCount} times.`
                    }
                );
            
            await channel.send({ embeds: [winEmbed] });
            
            // Reset the game with a higher goal
            const newGoal = countData.goalNumber * 2;
            countData.currentNumber = countData.startNumber - 1;
            countData.goalNumber = newGoal;
            countData.lastUserId = null;
            countData.highestNumber = countData.startNumber - 1;
            countData.failCount = 0;
            countData.participants = {};
            
            // Send a new game message
            const newGameEmbed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('New Counting Challenge')
                .setDescription(`Let's try to count from **${countData.startNumber}** to **${countData.goalNumber}**!`)
                .addFields(
                    { name: 'How to Play', value: 'Each person says the next number in sequence. No person can count twice in a row.' }
                );
            
            await channel.send({ embeds: [newGameEmbed] });
            
            // Save the updated game state
            this.saveCounting();
        } catch (error) {
            console.error('Error handling game win:', error);
        }
    }
    
    /**
     * Create an embed for the counting game
     * @param {Object} countData - The counting game data
     * @returns {EmbedBuilder} The game embed
     */
    createCountingEmbed(countData) {
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('Counting Game Started!')
            .setDescription(`Let's count from **${countData.startNumber}** to **${countData.goalNumber}**!`)
            .addFields(
                { name: 'How to Play', value: 'Each person says the next number in sequence. No person can count twice in a row.' },
                { name: 'Current Number', value: `${countData.currentNumber}` },
                { name: 'Next Number', value: `${countData.currentNumber + 1}` }
            );
        
        return embed;
    }
    
    /**
     * Get the current counting status for a channel
     * @param {string} channelId - Channel ID
     * @returns {Object|null} The counting data or null if not found
     */
    getCountingStatus(channelId) {
        return this.counting.get(channelId) || null;
    }
    
    /**
     * End a counting game in a channel
     * @param {string} channelId - Channel ID
     * @returns {boolean} Whether the game was ended successfully
     */
    endCountingGame(channelId) {
        if (this.counting.has(channelId)) {
            this.counting.delete(channelId);
            this.saveCounting();
            return true;
        }
        return false;
    }
    
    /**
     * Create a help embed for the counting game
     * @returns {EmbedBuilder} The help embed
     */
    createHelpEmbed() {
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('Counting Game Help')
            .setDescription('The counting game is a cooperative challenge where members count up from one number to another!')
            .addFields(
                { 
                    name: 'Commands', 
                    value: 
                        `\`$cstart [startNumber] [goalNumber]\` - Start a counting game\n` +
                        `\`$cstatus\` - Check the status of the current counting game\n` +
                        `\`$cend\` - End the current counting game\n` +
                        `\`$chelp\` - Show this help message` 
                },
                {
                    name: 'Rules',
                    value: 
                        `1. Each person must post the next number in sequence\n` +
                        `2. No person can count twice in a row\n` +
                        `3. If someone makes a mistake, the count resets` 
                },
                {
                    name: 'Example',
                    value: 'User A: 1\nUser B: 2\nUser C: 3\nUser A: 4'
                }
            );
        
        return embed;
    }
}

module.exports = CountingManager;