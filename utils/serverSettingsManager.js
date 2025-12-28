const { EmbedBuilder } = require('discord.js');
const fs = require('fs');
const path = require('path');
const config = require('../config');

/**
 * Manages server-specific settings and preferences
 */
class ServerSettingsManager {
    constructor(client) {
        this.client = client;
        this.serverSettings = new Map(); // Store server settings
        this.dataPath = path.join(__dirname, '../data/serverSettings.json');
        
        // Ensure data directory exists
        const dataDir = path.join(__dirname, '../data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        
        this.loadSettings();
    }
    
    /**
     * Load saved settings from the data file
     */
    loadSettings() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                
                for (const [guildId, guildSettings] of Object.entries(data)) {
                    this.serverSettings.set(guildId, guildSettings);
                }
                
                console.log(`Loaded settings for ${this.serverSettings.size} servers.`);
            } else {
                console.log('No server settings file found. Creating a new one.');
                this.saveSettings();
            }
        } catch (error) {
            console.error('Error loading server settings:', error);
            // Create a new settings file in case of corruption
            this.serverSettings = new Map();
            this.saveSettings();
        }
    }
    
    /**
     * Save settings to the data file
     */
    saveSettings() {
        try {
            // Convert Map to a plain object for JSON serialization
            const dataToSave = {};
            for (const [guildId, settings] of this.serverSettings.entries()) {
                dataToSave[guildId] = settings;
            }
            
            fs.writeFileSync(this.dataPath, JSON.stringify(dataToSave, null, 2), 'utf8');
            return true;
        } catch (error) {
            console.error('Error saving server settings:', error);
            return false;
        }
    }
    
    /**
     * Get settings for a specific guild
     * @param {string} guildId - Discord Guild ID
     * @returns {Object} Guild settings
     */
    getGuildSettings(guildId) {
        if (!this.serverSettings.has(guildId)) {
            // Initialize with default settings
            const defaultSettings = {
                receiveBroadcasts: true, // By default, servers receive broadcasts
                
                // Welcome system settings
                welcomeEnabled: false,
                welcomeChannelId: null,
                welcomeMessage: 'Welcome to the server, {member}! Enjoy your stay!',
                welcomeBannerUrl: config.welcome.bannerUrl || null,
                welcomeColor: config.colors.primary,
                
                // Direct message settings
                welcomeDmEnabled: config.welcome.sendDM,
                welcomeDmMessage: config.welcome.dmMessage || 'Hey {username}! Welcome to **{server}**!',
                
                // Welcome embed customization
                welcomeShowMemberCount: true,
                welcomeShowJoinDate: true,
                welcomeShowAccountAge: true,
                welcomeCustomTitle: null,
                welcomeCustomFooter: null,
                
                // Leveling system settings
                leveling: {
                    enabled: true,
                    levelUpChannelId: null,
                    xpMultiplier: 1.0,
                    xpCooldown: 60000 // Default 1 minute cooldown
                },
                
                // Auto-reaction settings
                autoReactions: {
                    enabled: false,
                    reactions: [] // Array of { trigger: 'word', emoji: '👍', caseSensitive: false }
                },
                
                // No-prefix mode settings
                noPrefixUsers: {}, // Map of user IDs to expiration timestamps
                
                // Add other default settings as needed
            };
            
            this.serverSettings.set(guildId, defaultSettings);
            this.saveSettings();
        }
        
        return this.serverSettings.get(guildId);
    }
    
    /**
     * Update a specific setting for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} setting - The setting name to update
     * @param {*} value - The new value
     * @returns {boolean} Whether the setting was successfully updated
     */
    updateGuildSetting(guildId, setting, value) {
        const guildSettings = this.getGuildSettings(guildId);
        
        if (guildSettings) {
            guildSettings[setting] = value;
            this.serverSettings.set(guildId, guildSettings);
            return this.saveSettings();
        }
        
        return false;
    }
    
    /**
     * Toggle broadcast reception for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} The new state (true = receiving, false = opted out)
     */
    toggleBroadcastReception(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        
        // Toggle the current value
        const newValue = !guildSettings.receiveBroadcasts;
        guildSettings.receiveBroadcasts = newValue;
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        this.saveSettings();
        
        return newValue;
    }
    
    /**
     * Enable no-prefix mode for a user
     * @param {string} guildId - Discord Guild ID
     * @param {string} userId - User ID to enable no-prefix mode for
     * @param {number} minutes - Duration in minutes (default: 10)
     * @returns {Object} Result with success status and message
     */
    enableNoPrefixMode(guildId, userId, minutes = 10) {
        if (!userId) return { success: false, message: "Invalid user" };
        if (minutes <= 0 || minutes > 60) return { success: false, message: "Duration must be between 1 and 60 minutes" };
        
        try {
            const guildSettings = this.getGuildSettings(guildId);
            
            // Ensure noPrefixUsers object exists
            if (!guildSettings.noPrefixUsers) {
                guildSettings.noPrefixUsers = {};
            }
            
            // Calculate expiration timestamp (current time + minutes)
            const expirationTime = Date.now() + (minutes * 60 * 1000);
            
            // Set the expiration time for this user
            guildSettings.noPrefixUsers[userId] = expirationTime;
            
            // Save the updated settings
            this.serverSettings.set(guildId, guildSettings);
            this.saveSettings();
            
            console.log(`[NO-PREFIX] Enabled no-prefix mode for user ${userId} in guild ${guildId} for ${minutes} minutes (expires at ${new Date(expirationTime)})`);
            
            return { 
                success: true, 
                message: `No-prefix mode enabled for ${minutes} minute${minutes !== 1 ? 's' : ''}`,
                expiresAt: expirationTime
            };
        } catch (error) {
            console.error(`[SERVER SETTINGS] Error enabling no-prefix mode for user ${userId} in guild ${guildId}:`, error);
            return { 
                success: false, 
                message: "An error occurred while enabling no-prefix mode." 
            };
        }
    }
    
    /**
     * Disable no-prefix mode for a user
     * @param {string} guildId - Discord Guild ID
     * @param {string} userId - User ID to disable no-prefix mode for
     * @returns {boolean} Whether no-prefix mode was successfully disabled
     */
    disableNoPrefixMode(guildId, userId) {
        if (!userId) return false;
        
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure noPrefixUsers object exists
        if (!guildSettings.noPrefixUsers) {
            guildSettings.noPrefixUsers = {};
            return false;
        }
        
        // Check if user has no-prefix mode enabled
        if (!guildSettings.noPrefixUsers[userId]) {
            return false;
        }
        
        // Remove the user from no-prefix mode
        delete guildSettings.noPrefixUsers[userId];
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        this.saveSettings();
        
        return true;
    }
    
    /**
     * Check if a user has no-prefix mode enabled
     * @param {string} guildId - Discord Guild ID
     * @param {string} userId - User ID to check
     * @returns {boolean} Whether the user has no-prefix mode enabled
     */
    hasNoPrefixMode(guildId, userId) {
        try {
            if (!guildId || !userId) {
                console.log(`[SERVER SETTINGS] Invalid parameters for hasNoPrefixMode: guildId=${guildId}, userId=${userId}`);
                return false;
            }
            
            const settings = this.getGuildSettings(guildId);
            
            // If noPrefixUsers doesn't exist or user doesn't have no-prefix mode enabled
            if (!settings.noPrefixUsers || !settings.noPrefixUsers[userId]) {
                return false;
            }
            
            // Check if no-prefix mode hasn't expired
            const now = Date.now();
            const expiresAt = settings.noPrefixUsers[userId];
            
            if (now > expiresAt) {
                // No-prefix mode has expired, clean it up
                console.log(`[NO-PREFIX] No-prefix mode expired for user ${userId} in guild ${guildId}`);
                delete settings.noPrefixUsers[userId];
                this.saveSettings();
                return false;
            }
            
            // User has active no-prefix mode (only log during command processing)
            return true;
        } catch (error) {
            console.error(`[SERVER SETTINGS] Error checking no-prefix mode for user ${userId} in guild ${guildId}:`, error);
            return false;
        }
    }
    
    /**
     * Get no-prefix mode expiration time for a user
     * @param {string} guildId - Discord Guild ID
     * @param {string} userId - User ID to check
     * @returns {number|null} Expiration timestamp or null if not enabled
     */
    getNoPrefixExpiration(guildId, userId) {
        if (!userId) return null;
        
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure noPrefixUsers object exists
        if (!guildSettings.noPrefixUsers) {
            return null;
        }
        
        // Get expiration time
        const expirationTime = guildSettings.noPrefixUsers[userId];
        if (!expirationTime) {
            return null;
        }
        
        // Check if expired
        const now = Date.now();
        if (now > expirationTime) {
            // No-prefix mode has expired, clean it up
            delete guildSettings.noPrefixUsers[userId];
            this.serverSettings.set(guildId, guildSettings);
            this.saveSettings();
            return null;
        }
        
        return expirationTime;
    }
    
    /**
     * Check if a guild has opted out of broadcasts
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} Whether the guild receives broadcasts
     */
    receivesBroadcasts(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        return guildSettings.receiveBroadcasts;
    }
    
    /**
     * Get a list of servers that have opted out of broadcasts
     * @returns {Array<string>} Array of guild IDs that have opted out
     */
    getOptedOutServers() {
        const optedOut = [];
        
        for (const [guildId, settings] of this.serverSettings.entries()) {
            if (!settings.receiveBroadcasts) {
                optedOut.push(guildId);
            }
        }
        
        return optedOut;
    }
    
    /**
     * Get count of servers that receive broadcasts
     * @returns {number} Count of servers accepting broadcasts
     */
    getBroadcastReceptionCount() {
        let count = 0;
        
        for (const settings of this.serverSettings.values()) {
            if (settings.receiveBroadcasts) {
                count++;
            }
        }
        
        // Add count for servers that haven't set preferences (they receive by default)
        const serversWithSettings = this.serverSettings.size;
        const totalServers = this.client.guilds.cache.size;
        const serversWithoutSettings = totalServers - serversWithSettings;
        
        return count + serversWithoutSettings;
    }

    /**
     * Check if welcome messages are enabled for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} Whether welcome messages are enabled
     */
    isWelcomeEnabled(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        return guildSettings.welcomeEnabled;
    }

    /**
     * Toggle welcome messages for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} The new state (true = enabled, false = disabled)
     */
    toggleWelcome(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        
        // Toggle the current value
        const newValue = !guildSettings.welcomeEnabled;
        guildSettings.welcomeEnabled = newValue;
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        this.saveSettings();
        
        return newValue;
    }

    /**
     * Toggle welcome DMs for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} The new state (true = enabled, false = disabled)
     */
    toggleWelcomeDm(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        
        // Toggle the current value
        const newValue = !guildSettings.welcomeDmEnabled;
        guildSettings.welcomeDmEnabled = newValue;
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        this.saveSettings();
        
        return newValue;
    }

    /**
     * Set welcome channel for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} channelId - Channel ID
     * @returns {boolean} Whether the channel was successfully set
     */
    setWelcomeChannel(guildId, channelId) {
        return this.updateGuildSetting(guildId, 'welcomeChannelId', channelId);
    }

    /**
     * Set welcome message for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} message - Welcome message
     * @returns {boolean} Whether the message was successfully set
     */
    setWelcomeMessage(guildId, message) {
        return this.updateGuildSetting(guildId, 'welcomeMessage', message);
    }

    /**
     * Set welcome DM message for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} message - Welcome DM message
     * @returns {boolean} Whether the message was successfully set
     */
    setWelcomeDmMessage(guildId, message) {
        return this.updateGuildSetting(guildId, 'welcomeDmMessage', message);
    }

    /**
     * Set welcome banner URL for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} url - Banner URL
     * @returns {boolean} Whether the URL was successfully set
     */
    setWelcomeBanner(guildId, url) {
        return this.updateGuildSetting(guildId, 'welcomeBannerUrl', url);
    }

    /**
     * Set welcome color for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} color - Color in hex format
     * @returns {boolean} Whether the color was successfully set
     */
    setWelcomeColor(guildId, color) {
        return this.updateGuildSetting(guildId, 'welcomeColor', color);
    }

    /**
     * Get welcome settings for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {Object} Welcome settings
     */
    getWelcomeSettings(guildId) {
        const settings = this.getGuildSettings(guildId);
        
        return {
            enabled: settings.welcomeEnabled,
            channelId: settings.welcomeChannelId,
            message: settings.welcomeMessage,
            bannerUrl: settings.welcomeBannerUrl,
            color: settings.welcomeColor,
            dmEnabled: settings.welcomeDmEnabled,
            dmMessage: settings.welcomeDmMessage,
            showMemberCount: settings.welcomeShowMemberCount,
            showJoinDate: settings.welcomeShowJoinDate,
            showAccountAge: settings.welcomeShowAccountAge,
            customTitle: settings.welcomeCustomTitle,
            customFooter: settings.welcomeCustomFooter
        };
    }

    /**
     * Toggle a welcome embed feature
     * @param {string} guildId - Discord Guild ID
     * @param {string} feature - Feature to toggle (welcomeShowMemberCount, welcomeShowJoinDate, welcomeShowAccountAge)
     * @returns {boolean} The new state
     */
    toggleWelcomeFeature(guildId, feature) {
        const validFeatures = [
            'welcomeShowMemberCount', 
            'welcomeShowJoinDate', 
            'welcomeShowAccountAge'
        ];
        
        if (!validFeatures.includes(feature)) {
            return false;
        }
        
        const settings = this.getGuildSettings(guildId);
        const newValue = !settings[feature];
        
        return this.updateGuildSetting(guildId, feature, newValue);
    }

    /**
     * Check if leveling is enabled for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} Whether leveling is enabled
     */
    isLevelingEnabled(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        return guildSettings.leveling?.enabled || false;
    }

    /**
     * Toggle leveling for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} The new state (true = enabled, false = disabled)
     */
    toggleLeveling(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure leveling object exists
        if (!guildSettings.leveling) {
            guildSettings.leveling = {
                enabled: false,
                levelUpChannelId: null,
                xpMultiplier: 1.0,
                xpCooldown: 60000 // Default 1 minute cooldown
            };
        }
        
        // Toggle the current value
        const newValue = !guildSettings.leveling.enabled;
        guildSettings.leveling.enabled = newValue;
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        this.saveSettings();
        
        return newValue;
    }

    /**
     * Set leveling channel for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} channelId - Channel ID for level-up announcements
     * @returns {boolean} Whether the channel was successfully set
     */
    setLevelingChannel(guildId, channelId) {
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure leveling object exists
        if (!guildSettings.leveling) {
            guildSettings.leveling = {
                enabled: true,
                levelUpChannelId: null,
                xpMultiplier: 1.0,
                xpCooldown: 60000
            };
        }
        
        // Update channel
        guildSettings.leveling.levelUpChannelId = channelId;
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        return this.saveSettings();
    }

    /**
     * Set XP multiplier for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {number} multiplier - XP multiplier (0.1-5.0)
     * @returns {boolean} Whether the multiplier was successfully set
     */
    setXpMultiplier(guildId, multiplier) {
        // Validate multiplier
        if (multiplier <= 0 || multiplier > 5) {
            return false;
        }
        
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure leveling object exists
        if (!guildSettings.leveling) {
            guildSettings.leveling = {
                enabled: true,
                levelUpChannelId: null,
                xpMultiplier: 1.0,
                xpCooldown: 60000
            };
        }
        
        // Update multiplier (limit to 2 decimal places)
        guildSettings.leveling.xpMultiplier = parseFloat(multiplier.toFixed(2));
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        return this.saveSettings();
    }

    /**
     * Set XP cooldown for a guild
     * @param {string} guildId - Discord Guild ID
     * @param {number} cooldownSeconds - Cooldown in seconds (5-300)
     * @returns {boolean} Whether the cooldown was successfully set
     */
    setXpCooldown(guildId, cooldownSeconds) {
        // Validate cooldown (between 5 seconds and 5 minutes)
        if (cooldownSeconds < 5 || cooldownSeconds > 300) {
            return false;
        }
        
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure leveling object exists
        if (!guildSettings.leveling) {
            guildSettings.leveling = {
                enabled: true,
                levelUpChannelId: null,
                xpMultiplier: 1.0,
                xpCooldown: 60000
            };
        }
        
        // Update cooldown (convert to milliseconds)
        guildSettings.leveling.xpCooldown = cooldownSeconds * 1000;
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        return this.saveSettings();
    }

    /**
     * Get leveling settings for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {Object} Leveling settings
     */
    getLevelingSettings(guildId) {
        const settings = this.getGuildSettings(guildId);
        
        // Ensure leveling object exists
        if (!settings.leveling) {
            settings.leveling = {
                enabled: true,
                levelUpChannelId: null,
                xpMultiplier: 1.0,
                xpCooldown: 60000 // Default 1 minute cooldown
            };
            
            // Save the default settings
            this.serverSettings.set(guildId, settings);
            this.saveSettings();
        }
        
        return settings.leveling;
    }

    /**
     * Add an auto-reaction trigger to a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} trigger - The trigger word or phrase
     * @param {string} emoji - The emoji to react with
     * @param {boolean} caseSensitive - Whether the trigger is case-sensitive
     * @returns {boolean} Whether the trigger was successfully added
     */
    addAutoReaction(guildId, trigger, emoji, caseSensitive = false) {
        if (!trigger || !emoji) return false;
        
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure autoReactions object exists and is enabled
        if (!guildSettings.autoReactions) {
            guildSettings.autoReactions = {
                enabled: true,
                reactions: []
            };
        }
        
        // Check if trigger already exists
        const existingIndex = guildSettings.autoReactions.reactions.findIndex(
            r => r.trigger.toLowerCase() === trigger.toLowerCase()
        );
        
        if (existingIndex !== -1) {
            // Update existing trigger
            guildSettings.autoReactions.reactions[existingIndex] = {
                trigger,
                emoji,
                caseSensitive
            };
        } else {
            // Add new trigger
            guildSettings.autoReactions.reactions.push({
                trigger,
                emoji,
                caseSensitive
            });
        }
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        return this.saveSettings();
    }

    /**
     * Remove an auto-reaction trigger from a guild
     * @param {string} guildId - Discord Guild ID
     * @param {string} trigger - The trigger word or phrase to remove
     * @returns {boolean} Whether the trigger was successfully removed
     */
    removeAutoReaction(guildId, trigger) {
        if (!trigger) return false;
        
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure autoReactions object exists
        if (!guildSettings.autoReactions || !guildSettings.autoReactions.reactions) {
            return false;
        }
        
        // Find and remove the trigger
        const initialLength = guildSettings.autoReactions.reactions.length;
        guildSettings.autoReactions.reactions = guildSettings.autoReactions.reactions.filter(
            r => r.trigger.toLowerCase() !== trigger.toLowerCase()
        );
        
        // Check if a trigger was removed
        if (guildSettings.autoReactions.reactions.length === initialLength) {
            return false;
        }
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        return this.saveSettings();
    }

    /**
     * Toggle auto-reactions for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {boolean} The new state (true = enabled, false = disabled)
     */
    toggleAutoReactions(guildId) {
        const guildSettings = this.getGuildSettings(guildId);
        
        // Ensure autoReactions object exists
        if (!guildSettings.autoReactions) {
            guildSettings.autoReactions = {
                enabled: true,
                reactions: []
            };
        } else {
            // Toggle the current value
            guildSettings.autoReactions.enabled = !guildSettings.autoReactions.enabled;
        }
        
        // Save the updated settings
        this.serverSettings.set(guildId, guildSettings);
        this.saveSettings();
        
        return guildSettings.autoReactions.enabled;
    }

    /**
     * Get auto-reactions for a guild
     * @param {string} guildId - Discord Guild ID
     * @returns {Object} Auto-reaction settings
     */
    getAutoReactions(guildId) {
        const settings = this.getGuildSettings(guildId);
        
        // Ensure autoReactions object exists
        if (!settings.autoReactions) {
            settings.autoReactions = {
                enabled: false,
                reactions: []
            };
            
            // Save the default settings
            this.serverSettings.set(guildId, settings);
            this.saveSettings();
        }
        
        return settings.autoReactions;
    }

    /**
     * Get triggered reactions for a message
     * @param {string} guildId - Discord Guild ID
     * @param {string} content - Message content
     * @returns {Array<string>} Array of emojis to react with
     */
    getTriggeredReactions(guildId, content) {
        if (!content) return [];
        
        const settings = this.getGuildSettings(guildId);
        
        // If auto-reactions are disabled or not configured
        if (!settings.autoReactions || !settings.autoReactions.enabled) {
            return [];
        }
        
        // Check each trigger against the message content
        const triggeredEmojis = [];
        
        for (const reaction of settings.autoReactions.reactions) {
            let messageContent = content;
            let trigger = reaction.trigger;
            
            // Handle case sensitivity
            if (!reaction.caseSensitive) {
                messageContent = messageContent.toLowerCase();
                trigger = trigger.toLowerCase();
            }
            
            // Check if message contains the trigger
            if (messageContent.includes(trigger)) {
                triggeredEmojis.push(reaction.emoji);
            }
        }
        
        return triggeredEmojis;
    }
}

module.exports = ServerSettingsManager;