const { EmbedBuilder } = require('discord.js');
const fs = require('fs');
const path = require('path');
const config = require('../config');
const ms = require('ms');

class BirthdayManager {
    constructor(client) {
        this.client = client;
        this.birthdays = new Map();
        this.dataPath = path.join(__dirname, '../data/birthdays.json');
        
        // Track which embed style to use next (cycles through 0-3)
        this.currentEmbedIndex = 0;
        
        // Ensure data directory exists
        const dataDir = path.join(__dirname, '../data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        
        this.loadBirthdays();
        this.startCheckingBirthdays();
    }
    
    /**
     * Load saved birthdays from the data file
     */
    loadBirthdays() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                
                // Reset the Map
                this.birthdays.clear();
                
                // Process each guild's birthday data
                for (const [guildId, guildData] of Object.entries(data)) {
                    if (!this.birthdays.has(guildId)) {
                        this.birthdays.set(guildId, {
                            users: new Map(),
                            announcementChannel: guildData.announcementChannel || null,
                            role: guildData.role || null
                        });
                    }
                    
                    // Process users in this guild
                    if (guildData.users) {
                        for (const [userId, userData] of Object.entries(guildData.users)) {
                            const guildMap = this.birthdays.get(guildId);
                            guildMap.users.set(userId, userData);
                        }
                    }
                }
                
                console.log(`Loaded birthdays for ${this.birthdays.size} guilds.`);
            } else {
                // Create the file if it doesn't exist
                this.saveBirthdays();
            }
        } catch (error) {
            console.error('Error loading birthdays:', error);
            this.birthdays = new Map();
        }
    }
    
    /**
     * Save birthdays to the data file
     */
    saveBirthdays() {
        try {
            const data = {};
            
            // Convert the nested Map structure to a plain object for JSON serialization
            for (const [guildId, guildData] of this.birthdays.entries()) {
                data[guildId] = {
                    announcementChannel: guildData.announcementChannel,
                    role: guildData.role,
                    users: {}
                };
                
                for (const [userId, userData] of guildData.users.entries()) {
                    data[guildId].users[userId] = userData;
                }
            }
            
            fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving birthdays:', error);
        }
    }
    
    /**
     * Start checking for birthdays at a regular interval
     */
    startCheckingBirthdays() {
        // Check every hour
        setInterval(() => {
            this.checkBirthdays();
        }, 3600000); // 1 hour
        
        // Also check immediately on startup
        this.checkBirthdays();
        
        console.log('Birthday checking system started.');
    }
    
    /**
     * Check for birthdays and send celebration messages
     */
    async checkBirthdays() {
        const today = new Date();
        const month = today.getMonth() + 1; // JavaScript months are 0-indexed
        const day = today.getDate();
        const currentYear = today.getFullYear();
        const todayString = `${currentYear}-${month}-${day}`; // Format: YYYY-MM-DD
        
        console.log(`[BIRTHDAY] Checking for birthdays on ${todayString}`);
        
        // Loop through each guild
        for (const [guildId, guildData] of this.birthdays.entries()) {
            // Skip if no announcement channel is set
            if (!guildData.announcementChannel) continue;
            
            const guild = await this.client.guilds.fetch(guildId).catch(() => null);
            if (!guild) continue;
            
            const channel = await guild.channels.fetch(guildData.announcementChannel).catch(() => null);
            if (!channel) continue;
            
            // Find users with birthdays today that haven't been celebrated yet
            const birthdayUsers = [];
            const updatedUsers = new Map(); // Track users that need to be updated
            
            for (const [userId, userData] of guildData.users.entries()) {
                const birthMonth = userData.month;
                const birthDay = userData.day;
                
                if (birthMonth === month && birthDay === day) {
                    // Check if we already celebrated this birthday today
                    if (userData.lastCelebrated === todayString) {
                        console.log(`[BIRTHDAY] Already celebrated birthday for user ${userId} today`);
                        continue;
                    }
                    
                    const member = await guild.members.fetch(userId).catch(() => null);
                    if (member) {
                        console.log(`[BIRTHDAY] Found birthday for ${member.user.tag}`);
                        
                        birthdayUsers.push({
                            member,
                            age: userData.year ? currentYear - userData.year : null
                        });
                        
                        // Update the lastCelebrated date for this user
                        const updatedUserData = {...userData, lastCelebrated: todayString};
                        updatedUsers.set(userId, updatedUserData);
                        
                        // Assign birthday role if configured
                        if (guildData.role) {
                            const role = await guild.roles.fetch(guildData.role).catch(() => null);
                            if (role) {
                                await member.roles.add(role).catch(err => {
                                    console.error(`Failed to add birthday role to ${member.user.tag}:`, err);
                                });
                                
                                // Schedule role removal for tomorrow
                                setTimeout(async () => {
                                    const memberTomorrow = await guild.members.fetch(userId).catch(() => null);
                                    if (memberTomorrow) {
                                        await memberTomorrow.roles.remove(role).catch(err => {
                                            console.error(`Failed to remove birthday role from ${memberTomorrow.user.tag}:`, err);
                                        });
                                    }
                                }, 86400000); // 24 hours
                            }
                        }
                    }
                }
            }
            
            // Update user data for those with birthdays
            for (const [userId, updatedData] of updatedUsers.entries()) {
                guildData.users.set(userId, updatedData);
            }
            
            // Save changes if we updated any users
            if (updatedUsers.size > 0) {
                this.saveBirthdays();
            }
            
            // Send birthday celebration messages (only once per day per user)
            if (birthdayUsers.length > 0) {
                console.log(`[BIRTHDAY] Sending celebration for ${birthdayUsers.length} users`);
                await this.sendBirthdayCelebration(channel, birthdayUsers);
            }
        }
    }
    
    /**
     * Send a birthday celebration message
     * @param {TextChannel} channel - The channel to send the message to
     * @param {Array} users - Array of users with birthdays
     */
    async sendBirthdayCelebration(channel, users) {
        // Define the 4 sequential celebration embed styles
        const embedStyles = [
            // Style 1: Playful - Pink with cake
            {
                color: '#FF69B4', // Hot Pink
                title: '🎂 Happy Birthday Celebration! 🎉',
                image: 'https://i.imgur.com/KxoO5Ih.gif', // Cake gif
                quote: "May your birthday be filled with joy and surrounded by the people you love!"
            },
            // Style 2: Elegant - Blue with balloons
            {
                color: '#1E90FF', // Dodger Blue
                title: '🎈 Birthday Wishes! 🎁',
                image: 'https://i.imgur.com/VKgLOgY.gif', // Birthday balloons
                quote: "Another year, another adventure. Happy Birthday!"
            },
            // Style 3: Festive - Gold with confetti
            {
                color: '#FFD700', // Gold
                title: '✨ Celebrate Your Special Day! ✨',
                image: 'https://i.imgur.com/oDnVXdL.gif', // Birthday confetti
                quote: "Wishing you a day filled with happiness and a year filled with joy!"
            },
            // Style 4: Fun - Green with presents
            {
                color: '#32CD32', // Lime Green
                title: '🎁 Birthday Joy! 🥳',
                image: 'https://i.imgur.com/FrVGrVN.gif', // Birthday present
                quote: "Happy Birthday! May all your dreams come true!"
            }
        ];
        
        // Get the current style to use
        const currentStyle = embedStyles[this.currentEmbedIndex];
        
        // Log which style we're using
        console.log(`[BIRTHDAY] Using embed style #${this.currentEmbedIndex + 1}`);
        
        // Create the celebration embed
        const embed = new EmbedBuilder()
            .setColor(currentStyle.color)
            .setTitle(currentStyle.title)
            .setDescription(currentStyle.quote)
            .setTimestamp();
        
        // Add users to the embed
        for (const user of users) {
            const ageText = user.age ? `Turning ${user.age} today!` : '';
            embed.addFields({
                name: `Happy Birthday, ${user.member.displayName}! 🎈`,
                value: `${user.member} ${ageText}\nEveryone, wish them a happy birthday!`
            });
        }
        
        // Add the celebration image
        embed.setImage(currentStyle.image);
        
        // Send the celebration
        await channel.send({ 
            content: users.map(user => `Happy Birthday ${user.member}! 🎉`).join('\n'),
            embeds: [embed] 
        });
        
        console.log(`[BIRTHDAY] Sent celebration message with style #${this.currentEmbedIndex + 1}`);
        
        // Update the embed index for next time (cycle through 0-3)
        this.currentEmbedIndex = (this.currentEmbedIndex + 1) % 4;
        console.log(`[BIRTHDAY] Next celebration will use style #${this.currentEmbedIndex + 1}`);
    }
    
    /**
     * Set a user's birthday
     * @param {Object} options - Birthday options
     * @returns {Promise<boolean>} Whether the birthday was set successfully
     */
    async setBirthday({ guildId, userId, month, day, year = null }) {
        try {
            // Validate month and day
            if (month < 1 || month > 12) {
                throw new Error('Invalid month. Month must be between 1 and 12.');
            }
            
            // Check days based on month
            const daysInMonth = this.getDaysInMonth(month, year || new Date().getFullYear());
            if (day < 1 || day > daysInMonth) {
                throw new Error(`Invalid day. Day must be between 1 and ${daysInMonth} for the selected month.`);
            }
            
            // Validate year if provided
            if (year) {
                const currentYear = new Date().getFullYear();
                if (year < 1900 || year > currentYear) {
                    throw new Error(`Invalid year. Year must be between 1900 and ${currentYear}.`);
                }
            }
            
            // Initialize guild data if not exists
            if (!this.birthdays.has(guildId)) {
                this.birthdays.set(guildId, {
                    users: new Map(),
                    announcementChannel: null,
                    role: null
                });
            }
            
            const guildData = this.birthdays.get(guildId);
            
            // Set user's birthday
            guildData.users.set(userId, {
                month,
                day,
                year,
                lastCelebrated: null // Will be set when celebrated
            });
            
            this.saveBirthdays();
            return true;
        } catch (error) {
            console.error('Error setting birthday:', error);
            throw error;
        }
    }
    
    /**
     * Get days in a month
     * @param {number} month - Month (1-12)
     * @param {number} year - Year
     * @returns {number} Number of days in the month
     */
    getDaysInMonth(month, year) {
        return new Date(year, month, 0).getDate();
    }
    
    /**
     * Get a user's birthday
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @returns {Object|null} The birthday data or null if not set
     */
    getBirthday(guildId, userId) {
        const guildData = this.birthdays.get(guildId);
        if (!guildData) return null;
        
        return guildData.users.get(userId) || null;
    }
    
    /**
     * Remove a user's birthday
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @returns {boolean} Whether the birthday was removed successfully
     */
    removeBirthday(guildId, userId) {
        const guildData = this.birthdays.get(guildId);
        if (!guildData) return false;
        
        const deleted = guildData.users.delete(userId);
        if (deleted) {
            this.saveBirthdays();
        }
        
        return deleted;
    }
    
    /**
     * Set the birthday announcement channel for a guild
     * @param {string} guildId - Guild ID
     * @param {string} channelId - Channel ID
     * @returns {boolean} Whether the channel was set successfully
     */
    setAnnouncementChannel(guildId, channelId) {
        // Initialize guild data if not exists
        if (!this.birthdays.has(guildId)) {
            this.birthdays.set(guildId, {
                users: new Map(),
                announcementChannel: null,
                role: null
            });
        }
        
        const guildData = this.birthdays.get(guildId);
        guildData.announcementChannel = channelId;
        
        this.saveBirthdays();
        return true;
    }
    
    /**
     * Set the birthday role for a guild
     * @param {string} guildId - Guild ID
     * @param {string} roleId - Role ID
     * @returns {boolean} Whether the role was set successfully
     */
    setBirthdayRole(guildId, roleId) {
        // Initialize guild data if not exists
        if (!this.birthdays.has(guildId)) {
            this.birthdays.set(guildId, {
                users: new Map(),
                announcementChannel: null,
                role: null
            });
        }
        
        const guildData = this.birthdays.get(guildId);
        guildData.role = roleId;
        
        this.saveBirthdays();
        return true;
    }
    
    /**
     * Get all birthdays in a guild
     * @param {string} guildId - Guild ID
     * @returns {Map|null} Map of user birthdays or null if guild not found
     */
    getAllBirthdays(guildId) {
        const guildData = this.birthdays.get(guildId);
        if (!guildData) return null;
        
        return guildData.users;
    }
    
    /**
     * Get upcoming birthdays in a guild
     * @param {string} guildId - Guild ID
     * @param {number} limit - Maximum number of birthdays to return
     * @returns {Array} Array of upcoming birthdays sorted by date
     */
    getUpcomingBirthdays(guildId, limit = 10) {
        const guildData = this.birthdays.get(guildId);
        if (!guildData) return [];
        
        const today = new Date();
        const currentMonth = today.getMonth() + 1; // JavaScript months are 0-indexed
        const currentDay = today.getDate();
        
        // Convert birthdays to array for sorting
        const birthdays = [];
        
        for (const [userId, userData] of guildData.users.entries()) {
            // Calculate days until next birthday
            let nextBirthdayDays;
            
            // Birthday this year
            const birthdayThisYear = new Date(today.getFullYear(), userData.month - 1, userData.day);
            
            // Birthday next year
            const birthdayNextYear = new Date(today.getFullYear() + 1, userData.month - 1, userData.day);
            
            // If birthday has already passed this year, use next year
            if (birthdayThisYear < today) {
                nextBirthdayDays = Math.ceil((birthdayNextYear - today) / (1000 * 60 * 60 * 24));
            } else {
                nextBirthdayDays = Math.ceil((birthdayThisYear - today) / (1000 * 60 * 60 * 24));
            }
            
            birthdays.push({
                userId,
                month: userData.month,
                day: userData.day,
                year: userData.year,
                daysUntil: nextBirthdayDays
            });
        }
        
        // Sort by days until next birthday
        birthdays.sort((a, b) => a.daysUntil - b.daysUntil);
        
        // Return the upcoming birthdays, limited to the specified amount
        return birthdays.slice(0, limit);
    }
    
    /**
     * Format a date string from month and day
     * @param {number} month - Month (1-12)
     * @param {number} day - Day
     * @returns {string} Formatted date string
     */
    formatDate(month, day) {
        const months = [
            'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'
        ];
        
        return `${months[month - 1]} ${day}`;
    }
    
    /**
     * Get the birthday configuration for a guild
     * @param {string} guildId - Guild ID
     * @returns {Object} Guild birthday configuration
     */
    getGuildConfig(guildId) {
        const guildData = this.birthdays.get(guildId);
        if (!guildData) {
            return {
                announcementChannel: null,
                role: null,
                userCount: 0
            };
        }
        
        return {
            announcementChannel: guildData.announcementChannel,
            role: guildData.role,
            userCount: guildData.users.size
        };
    }
}

module.exports = BirthdayManager;