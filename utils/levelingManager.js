/**
 * Database-based Leveling and Achievement Badge Manager for Discord bot
 * 
 * This module manages user levels, XP, and achievement badges
 * using MySQL database storage instead of JSON files.
 */

const { EmbedBuilder } = require('discord.js');
const { eq, and, desc, count } = require('drizzle-orm');
const fs = require('fs');
const path = require('path');
const config = require('../config');

class LevelingManager {
    constructor(client) {
        this.client = client;
        this.cooldowns = new Map(); // userId -> timestamp
        this.db = null;
        this.schema = null;
        this.dbReady = false;
        this.migrationComplete = false;
        
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
                console.log('✅ LevelingManager database connection established');
                
                // Perform migration from JSON to database
                await this.migrateFromJSON();
                
                console.log('✅ LevelingManager fully initialized and ready');
            } else {
                console.log('[LEVELING] Waiting for database to be ready...');
                // Retry after a short delay if database isn't ready yet
                setTimeout(() => this.initializeDatabase(), 1000);
            }
        } catch (error) {
            console.error('❌ LevelingManager database initialization failed:', error);
            console.error('[LEVELING] Stack trace:', error.stack);
            // Retry after a delay
            setTimeout(() => this.initializeDatabase(), 5000);
        }
    }

    /**
     * Migrate existing JSON data to the database
     */
    async migrateFromJSON() {
        if (!this.dbReady || this.migrationComplete) {
            return;
        }

        try {
            const jsonPath = path.join(__dirname, '../data/levels.json');
            
            if (!fs.existsSync(jsonPath)) {
                console.log('[LEVELING] No JSON data to migrate');
                this.migrationComplete = true;
                return;
            }

            console.log('[LEVELING] Starting migration from JSON to database...');
            const jsonData = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            
            let userCount = 0;
            let badgeCount = 0;
            
            // Prepare batch data for bulk insert
            const usersToInsert = [];
            const badgesToInsert = [];

            console.log('[LEVELING] Processing JSON data for bulk insert...');
            
            for (const [guildId, guildData] of Object.entries(jsonData)) {
                console.log(`[LEVELING] Processing guild ${guildId} with ${Object.keys(guildData).length} users`);
                
                for (const [userId, userData] of Object.entries(guildData)) {
                    try {
                        // Check if user already exists in database (batch check would be better but this is safer)
                        const existingUser = await this.db.select()
                            .from(this.schema.userLevels)
                            .where(and(
                                eq(this.schema.userLevels.guildId, guildId),
                                eq(this.schema.userLevels.userId, userId)
                            ))
                            .limit(1);

                        if (existingUser.length === 0) {
                            // Prepare user data for batch insert
                            usersToInsert.push({
                                guildId: guildId,
                                userId: userId,
                                xp: userData.xp || 0,
                                level: userData.level || 0,
                                messages: userData.messages || 0,
                                lastMessage: userData.lastMessage ? new Date(userData.lastMessage) : null,
                                createdAt: new Date(),
                                updatedAt: new Date()
                            });

                            // Prepare badges for batch insert
                            if (userData.badges && userData.badges.length > 0) {
                                for (const badge of userData.badges) {
                                    badgesToInsert.push({
                                        guildId: guildId,
                                        userId: userId,
                                        badgeId: badge.id,
                                        badgeName: badge.name,
                                        badgeEmoji: badge.emoji,
                                        badgeColor: badge.color,
                                        badgeDescription: badge.description,
                                        badgeType: badge.type,
                                        earnedAt: new Date(badge.earnedAt),
                                        createdAt: new Date()
                                    });
                                }
                            }
                        }
                        
                        // Process in smaller batches to avoid memory issues
                        if (usersToInsert.length >= 50) {
                            console.log(`[LEVELING] Inserting batch of ${usersToInsert.length} users...`);
                            await this.db.insert(this.schema.userLevels).values(usersToInsert);
                            userCount += usersToInsert.length;
                            usersToInsert.length = 0; // Clear array
                        }
                        
                        if (badgesToInsert.length >= 100) {
                            console.log(`[LEVELING] Inserting batch of ${badgesToInsert.length} badges...`);
                            await this.db.insert(this.schema.userBadges).values(badgesToInsert);
                            badgeCount += badgesToInsert.length;
                            badgesToInsert.length = 0; // Clear array
                        }
                        
                    } catch (error) {
                        console.error(`[LEVELING] Error processing user ${userId} in guild ${guildId}:`, error.message);
                        // Continue with next user instead of failing entire migration
                    }
                }
            }

            // Insert remaining users and badges
            if (usersToInsert.length > 0) {
                console.log(`[LEVELING] Inserting final batch of ${usersToInsert.length} users...`);
                await this.db.insert(this.schema.userLevels).values(usersToInsert);
                userCount += usersToInsert.length;
            }
            
            if (badgesToInsert.length > 0) {
                console.log(`[LEVELING] Inserting final batch of ${badgesToInsert.length} badges...`);
                await this.db.insert(this.schema.userBadges).values(badgesToInsert);
                badgeCount += badgesToInsert.length;
            }

            console.log(`[LEVELING] ✅ Migration complete! Migrated ${userCount} users and ${badgeCount} badges`);
            
            // Create backup of JSON file
            const backupPath = path.join(__dirname, '../data/levels.json.backup');
            fs.copyFileSync(jsonPath, backupPath);
            console.log(`[LEVELING] ✅ JSON backup created at ${backupPath}`);
            
            this.migrationComplete = true;
        } catch (error) {
            console.error('[LEVELING] Migration error:', error);
            console.error('[LEVELING] Stack trace:', error.stack);
            this.migrationComplete = false;
        }
    }

    /**
     * Process a message for XP gain
     * @param {Message} message - The Discord message
     */
    async processMessage(message) {
        // Ignore bot messages and DMs
        if (message.author.bot || !message.guild) return;
        
        // Wait for database to be ready
        if (!this.dbReady) return;
        
        // Get server settings
        const serverSettings = this.client.serverSettingsManager.getGuildSettings(message.guild.id);
        const levelingSettings = serverSettings.leveling || {
            enabled: false,
            xpMultiplier: 1.0,
            xpCooldown: 60000
        };
        
        // Check if leveling is enabled for this server
        if (!levelingSettings.enabled) return;
        
        // Ignore messages that are too short
        if (message.content.length < config.leveling.minMessageLength) return;
        
        // Check if the user is on cooldown
        const userId = message.author.id;
        const guildId = message.guild.id;
        const cooldownKey = `${guildId}-${userId}`;
        const now = Date.now();
        
        // Use server-specific cooldown
        const cooldownTime = levelingSettings.xpCooldown || config.leveling.xpCooldown;
        
        if (this.cooldowns.has(cooldownKey)) {
            const userCooldown = this.cooldowns.get(cooldownKey);
            if (now < userCooldown) {
                // User is on cooldown, don't award XP
                return;
            }
        }
        
        // Set cooldown using server settings
        this.cooldowns.set(cooldownKey, now + cooldownTime);
        
        // Award XP
        await this.awardXP(message, levelingSettings.xpMultiplier || 1.0);
    }

    /**
     * Award XP to a user for a message
     * @param {Message} message - The Discord message
     * @param {number} multiplier - Server-specific XP multiplier
     */
    async awardXP(message, multiplier = 1.0) {
        if (!this.dbReady) {
            console.log('[LEVELING] Database not ready, skipping XP award');
            return;
        }
        if (!this.db || !this.schema) {
            console.log('[LEVELING] Database or schema not initialized');
            return;
        }

        const guildId = message.guild.id;
        const userId = message.author.id;
        
        try {
            // Get or create user data
            let userData = await this.db.select()
                .from(this.schema.userLevels)
                .where(and(
                    eq(this.schema.userLevels.guildId, guildId),
                    eq(this.schema.userLevels.userId, userId)
                ))
                .limit(1);

            if (userData.length === 0) {
                // Create new user
                await this.db.insert(this.schema.userLevels).values({
                    guildId: guildId,
                    userId: userId,
                    xp: 0,
                    level: 0,
                    messages: 0,
                    lastMessage: new Date(),
                    createdAt: new Date(),
                    updatedAt: new Date()
                });

                userData = [{
                    xp: 0,
                    level: 0,
                    messages: 0,
                    lastMessage: new Date()
                }];
            }

            const user = userData[0];
            
            // Calculate XP to award with server multiplier
            const baseXP = config.leveling.xpPerMessage;
            const randomBonus = Math.floor(Math.random() * (config.leveling.maxRandomBonus + 1));
            const xpGain = Math.floor((baseXP + randomBonus) * multiplier);
            
            // Update user data
            const oldLevel = user.level;
            const newXP = user.xp + xpGain;
            const newMessages = user.messages + 1;
            
            // Calculate new level based on messages (not XP)
            const newLevel = this.calculateLevel(newMessages);
            
            // Update database
            await this.db.update(this.schema.userLevels)
                .set({
                    xp: newXP,
                    level: newLevel,
                    messages: newMessages,
                    lastMessage: new Date(),
                    updatedAt: new Date()
                })
                .where(and(
                    eq(this.schema.userLevels.guildId, guildId),
                    eq(this.schema.userLevels.userId, userId)
                ));
            
            // Check for level up
            if (newLevel > oldLevel) {
                // Level up!
                const updatedUserData = {
                    xp: newXP,
                    level: newLevel,
                    messages: newMessages,
                    lastMessage: new Date()
                };
                await this.handleLevelUp(message, updatedUserData, oldLevel, newLevel);
            }
            
        } catch (error) {
            console.error('[LEVELING] Error awarding XP:', error);
        }
    }

    /**
     * Calculate level based on messages
     * @param {number} messages - Number of messages sent
     * @returns {number} The calculated level
     */
    calculateLevel(messages) {
        // Start with 3 messages for level 1, then double for each subsequent level
        if (messages < 3) return 0;
        
        let level = 1;
        let requiredMessages = 3;
        
        while (messages >= requiredMessages) {
            level += 1;
            requiredMessages += 3 * Math.pow(2, level - 1);
        }
        
        return level - 1;
    }

    /**
     * Calculate messages needed for a specific level
     * @param {number} level - The level
     * @returns {number} Messages needed
     */
    calculateRequiredMessages(level) {
        if (level <= 0) return 0;
        if (level === 1) return 3;
        
        let totalRequired = 3; // Level 1 requires 3 messages
        
        for (let i = 2; i <= level; i++) {
            totalRequired += 3 * Math.pow(2, i - 1);
        }
        
        return totalRequired;
    }

    /**
     * Handle level up event
     * @param {Message} message - The Discord message that triggered the level up
     * @param {Object} userData - User data
     * @param {number} oldLevel - Previous level
     * @param {number} newLevel - New level
     */
    async handleLevelUp(message, userData, oldLevel, newLevel) {
        try {
            // Get the user
            const user = message.author;
            
            // Get server settings for leveling
            const guildId = message.guild.id;
            const serverSettings = this.client.serverSettingsManager.getGuildSettings(guildId);
            const levelingSettings = serverSettings.leveling || {
                enabled: true,
                levelUpChannelId: null,
                xpMultiplier: 1.0,
                xpCooldown: 60000,
                roleRewards: []
            };
            
            // Check for role rewards
            const roleReward = this.checkForRoleReward(newLevel, levelingSettings.roleRewards || []);
            if (roleReward) {
                await this.awardLevelRole(message, user, roleReward);
            }
            
            // Check for new badges
            const newBadges = await this.checkForNewBadges(guildId, user.id, oldLevel, newLevel);
            
            // Create level up embed
            const embed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('🎉 Level Up!')
                .setDescription(`Congratulations, **${user.displayName || user.username}**! You've reached **Level ${newLevel}**!`)
                .setThumbnail(user.displayAvatarURL({ dynamic: true }))
                .addFields(
                    { 
                        name: 'Progress', 
                        value: `Level ${oldLevel} → **Level ${newLevel}**` 
                    },
                    { 
                        name: 'Total XP', 
                        value: `${userData.xp} XP` 
                    }
                )
                .setFooter({ 
                    text: `Continue chatting to earn more XP!`,
                    iconURL: this.client.user.displayAvatarURL()
                })
                .setTimestamp();
            
            // Add badge information if new badges were earned
            if (newBadges.length > 0) {
                const badgeList = newBadges.map(badge => 
                    `${badge.badgeEmoji} **${badge.badgeName}** - ${badge.badgeDescription}`
                ).join('\n');
                
                embed.addFields({
                    name: '🏅 New Badge' + (newBadges.length > 1 ? 's' : '') + ' Earned!',
                    value: badgeList
                });
            }
            
            // Determine which channel to send the level up message to
            let targetChannel = message.channel;
            let useConfiguredChannel = false;
            
            // Check server-specific level up channel first
            if (levelingSettings.levelUpChannelId) {
                const serverLevelUpChannel = message.guild.channels.cache.get(levelingSettings.levelUpChannelId);
                if (serverLevelUpChannel) {
                    if (serverLevelUpChannel.permissionsFor(message.guild.members.me).has('SendMessages')) {
                        targetChannel = serverLevelUpChannel;
                        useConfiguredChannel = true;
                    }
                }
            }
            // Fall back to global config if no server-specific channel
            else if (config.leveling.levelUpChannelId && !useConfiguredChannel) {
                const globalLevelUpChannel = message.guild.channels.cache.get(config.leveling.levelUpChannelId);
                if (globalLevelUpChannel) {
                    if (globalLevelUpChannel.permissionsFor(message.guild.members.me).has('SendMessages')) {
                        targetChannel = globalLevelUpChannel;
                        useConfiguredChannel = true;
                    }
                }
            }
            
            // Send the level up message
            try {
                await targetChannel.send({ embeds: [embed] });
                console.log(`[LEVELING] Successfully sent level-up message to ${targetChannel.name}`);
            } catch (error) {
                console.error(`[LEVELING] Error sending level-up message:`, error.message);
                
                // Try to send to original channel if we failed to send to the configured channel
                if (useConfiguredChannel && message.channel.permissionsFor(message.guild.members.me).has('SendMessages')) {
                    try {
                        await message.channel.send({ embeds: [embed] });
                    } catch (fallbackError) {
                        console.error(`[LEVELING] Failed to send level-up message to fallback channel:`, fallbackError.message);
                    }
                }
            }
            
        } catch (error) {
            console.error('[LEVELING] Error handling level up:', error);
        }
    }

    /**
     * Check for new badges when a user levels up
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @param {number} oldLevel - Previous level
     * @param {number} newLevel - New level
     * @returns {Array} Array of new badges earned
     */
    async checkForNewBadges(guildId, userId, oldLevel, newLevel) {
        if (!this.dbReady) return [];

        const newBadges = [];
        
        try {
            // Check for level badges
            for (const badge of config.leveling.badges.levelBadges) {
                if (badge.level > oldLevel && badge.level <= newLevel) {
                    // Check if user already has this badge
                    const existingBadge = await this.db.select()
                        .from(this.schema.userBadges)
                        .where(and(
                            eq(this.schema.userBadges.guildId, guildId),
                            eq(this.schema.userBadges.userId, userId),
                            eq(this.schema.userBadges.badgeId, `level_${badge.level}`)
                        ))
                        .limit(1);

                    if (existingBadge.length === 0) {
                        // Award the badge
                        const badgeData = {
                            guildId: guildId,
                            userId: userId,
                            badgeId: `level_${badge.level}`,
                            badgeName: badge.name,
                            badgeEmoji: badge.emoji,
                            badgeColor: badge.color,
                            badgeDescription: badge.description,
                            badgeType: 'level',
                            earnedAt: new Date(),
                            createdAt: new Date()
                        };

                        await this.db.insert(this.schema.userBadges).values(badgeData);
                        newBadges.push(badgeData);
                    }
                }
            }
        } catch (error) {
            console.error('[LEVELING] Error checking for new badges:', error);
        }
        
        return newBadges;
    }

    /**
     * Check if user earned a role reward at this level
     * @param {number} level - The level reached
     * @param {Array} roleRewards - Array of role reward configurations
     * @returns {Object|null} Role reward object or null
     */
    checkForRoleReward(level, roleRewards) {
        return roleRewards.find(reward => reward.level === level) || null;
    }

    /**
     * Award a role to a user for reaching a level
     * @param {Message} message - The Discord message
     * @param {User} user - The user to award the role to
     * @param {Object} roleReward - Role reward configuration
     */
    async awardLevelRole(message, user, roleReward) {
        try {
            const member = await message.guild.members.fetch(user.id);
            const role = message.guild.roles.cache.get(roleReward.roleId);
            
            if (!role) {
                console.log(`[LEVELING] Role ${roleReward.roleId} not found for level ${roleReward.level}`);
                return;
            }
            
            if (member.roles.cache.has(roleReward.roleId)) {
                console.log(`[LEVELING] User ${user.tag} already has role ${role.name}`);
                return;
            }
            
            await member.roles.add(role);
            console.log(`[LEVELING] Awarded role ${role.name} to ${user.tag} for reaching level ${roleReward.level}`);
            
            // Send role reward notification
            const roleEmbed = new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('🎯 Role Reward!')
                .setDescription(`**${user.displayName || user.username}** has been awarded the **${role.name}** role for reaching Level ${roleReward.level}!`)
                .setThumbnail(user.displayAvatarURL({ dynamic: true }))
                .setTimestamp();
                
            await message.channel.send({ embeds: [roleEmbed] });
            
        } catch (error) {
            console.error('[LEVELING] Error awarding level role:', error);
        }
    }

    /**
     * Add a role reward for a specific level
     * @param {string} guildId - Guild ID
     * @param {number} level - Level requirement
     * @param {string} roleId - Role ID to award
     * @returns {boolean} Success status
     */
    addRoleReward(guildId, level, roleId) {
        try {
            const serverSettings = this.client.serverSettingsManager.getGuildSettings(guildId);
            if (!serverSettings.leveling) {
                serverSettings.leveling = { enabled: true, roleRewards: [] };
            }
            if (!serverSettings.leveling.roleRewards) {
                serverSettings.leveling.roleRewards = [];
            }
            
            // Check if role reward already exists for this level
            const existingReward = serverSettings.leveling.roleRewards.find(reward => reward.level === level);
            if (existingReward) {
                existingReward.roleId = roleId;
            } else {
                serverSettings.leveling.roleRewards.push({ level, roleId });
            }
            
            this.client.serverSettingsManager.saveSettings();
            return true;
        } catch (error) {
            console.error('[LEVELING] Error adding role reward:', error);
            return false;
        }
    }

    /**
     * Remove a role reward for a specific level
     * @param {string} guildId - Guild ID
     * @param {number} level - Level requirement
     * @returns {boolean} Success status
     */
    removeRoleReward(guildId, level) {
        try {
            const serverSettings = this.client.serverSettingsManager.getGuildSettings(guildId);
            if (!serverSettings.leveling || !serverSettings.leveling.roleRewards) {
                return false;
            }
            
            const index = serverSettings.leveling.roleRewards.findIndex(reward => reward.level === level);
            if (index !== -1) {
                serverSettings.leveling.roleRewards.splice(index, 1);
                this.client.serverSettingsManager.saveSettings();
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('[LEVELING] Error removing role reward:', error);
            return false;
        }
    }

    /**
     * Get all role rewards for a guild
     * @param {string} guildId - Guild ID
     * @returns {Array} Array of role rewards
     */
    getRoleRewards(guildId) {
        const serverSettings = this.client.serverSettingsManager.getGuildSettings(guildId);
        return serverSettings.leveling?.roleRewards || [];
    }

    /**
     * Award a badge to a user
     * @param {Object} options - Badge award options
     * @returns {Promise<Object>} Result of the operation
     */
    async awardBadge({ guildId, userId, badgeType, badgeId }) {
        if (!this.dbReady) {
            return { success: false, message: 'Database not ready' };
        }

        try {
            // Check if leveling is enabled for this server
            const serverSettings = this.client.serverSettingsManager.getGuildSettings(guildId);
            if (!serverSettings.leveling?.enabled) {
                return { success: false, message: 'Leveling is not enabled for this server' };
            }
            
            // Get badge data based on type and ID
            let badgeData = null;
            
            if (badgeType === 'achievement') {
                badgeData = config.leveling.badges.achievementBadges.find(b => b.id === badgeId);
            } else if (badgeType === 'special') {
                badgeData = config.leveling.badges.specialBadges.find(b => b.id === badgeId);
            }
            
            if (!badgeData) {
                return { success: false, message: 'Badge not found' };
            }
            
            // Check if the user already has this badge
            const existingBadge = await this.db.select()
                .from(this.schema.userBadges)
                .where(and(
                    eq(this.schema.userBadges.guildId, guildId),
                    eq(this.schema.userBadges.userId, userId),
                    eq(this.schema.userBadges.badgeId, badgeData.id),
                    eq(this.schema.userBadges.badgeType, badgeType)
                ))
                .limit(1);

            if (existingBadge.length > 0) {
                return { success: false, message: 'User already has this badge' };
            }

            // Ensure user exists in levels table
            let userLevel = await this.db.select()
                .from(this.schema.userLevels)
                .where(and(
                    eq(this.schema.userLevels.guildId, guildId),
                    eq(this.schema.userLevels.userId, userId)
                ))
                .limit(1);

            if (userLevel.length === 0) {
                // Create user if doesn't exist
                await this.db.insert(this.schema.userLevels).values({
                    guildId: guildId,
                    userId: userId,
                    xp: 0,
                    level: 0,
                    messages: 0,
                    lastMessage: new Date(),
                    createdAt: new Date(),
                    updatedAt: new Date()
                });
            }
            
            // Add the badge
            const newBadge = {
                guildId: guildId,
                userId: userId,
                badgeId: badgeData.id,
                badgeName: badgeData.name,
                badgeEmoji: badgeData.emoji,
                badgeColor: badgeData.color,
                badgeDescription: badgeData.description,
                badgeType: badgeType,
                earnedAt: new Date(),
                createdAt: new Date()
            };

            await this.db.insert(this.schema.userBadges).values(newBadge);
            
            return { 
                success: true, 
                message: 'Badge awarded successfully', 
                badge: newBadge 
            };
            
        } catch (error) {
            console.error('[LEVELING] Error awarding badge:', error);
            return { success: false, message: 'An error occurred' };
        }
    }

    /**
     * Revoke a badge from a user
     * @param {Object} options - Badge revoke options
     * @returns {Promise<Object>} Result of the operation
     */
    async revokeBadge({ guildId, userId, badgeType, badgeId }) {
        if (!this.dbReady) {
            return { success: false, message: 'Database not ready' };
        }

        try {
            // Check if leveling is enabled for this server
            const serverSettings = this.client.serverSettingsManager.getGuildSettings(guildId);
            if (!serverSettings.leveling?.enabled) {
                return { success: false, message: 'Leveling is not enabled for this server' };
            }
            
            // Remove the badge
            const result = await this.db.delete(this.schema.userBadges)
                .where(and(
                    eq(this.schema.userBadges.guildId, guildId),
                    eq(this.schema.userBadges.userId, userId),
                    eq(this.schema.userBadges.badgeId, badgeId),
                    eq(this.schema.userBadges.badgeType, badgeType)
                ));

            if (result.affectedRows > 0) {
                return { success: true, message: 'Badge revoked successfully' };
            } else {
                return { success: false, message: 'Badge not found' };
            }
            
        } catch (error) {
            console.error('[LEVELING] Error revoking badge:', error);
            return { success: false, message: 'An error occurred' };
        }
    }

    /**
     * Get user profile data
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @returns {Promise<Object|null>} User profile data or null
     */
    async getUserProfile(guildId, userId) {
        if (!this.dbReady) return null;

        try {
            // Get user data
            const userData = await this.db.select()
                .from(this.schema.userLevels)
                .where(and(
                    eq(this.schema.userLevels.guildId, guildId),
                    eq(this.schema.userLevels.userId, userId)
                ))
                .limit(1);

            if (userData.length === 0) return null;

            // Get user badges
            const badges = await this.db.select()
                .from(this.schema.userBadges)
                .where(and(
                    eq(this.schema.userBadges.guildId, guildId),
                    eq(this.schema.userBadges.userId, userId)
                ));

            return {
                ...userData[0],
                badges: badges
            };
        } catch (error) {
            console.error('[LEVELING] Error getting user profile:', error);
            return null;
        }
    }

    /**
     * Get leaderboard data
     * @param {string} guildId - Guild ID
     * @param {number} limit - Number of users to return
     * @returns {Promise<Array>} Leaderboard data
     */
    async getLeaderboard(guildId, limit = 100) {
        if (!this.dbReady) return [];

        try {
            const leaderboard = await this.db.select()
                .from(this.schema.userLevels)
                .where(eq(this.schema.userLevels.guildId, guildId))
                .orderBy(desc(this.schema.userLevels.level), desc(this.schema.userLevels.xp))
                .limit(limit);

            return leaderboard;
        } catch (error) {
            console.error('[LEVELING] Error getting leaderboard:', error);
            return [];
        }
    }

    /**
     * Create profile embed for a user
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @returns {Promise<Object|null>} Profile embed data
     */
    async createProfileEmbed(guildId, userId) {
        const profile = await this.getUserProfile(guildId, userId);
        if (!profile) return null;

        try {
            // Get user's rank position
            const leaderboard = await this.getLeaderboard(guildId, 1000);
            const userRank = leaderboard.findIndex(u => u.userId === userId) + 1;

            // Calculate progress to next level
            const currentLevel = profile.level;
            const nextLevel = currentLevel + 1;
            const currentLevelMessages = this.calculateRequiredMessages(currentLevel);
            const nextLevelMessages = this.calculateRequiredMessages(nextLevel);
            const messagesForCurrentLevel = nextLevelMessages - currentLevelMessages;
            const currentProgress = profile.messages - currentLevelMessages;
            const progressPercentage = Math.floor((currentProgress / messagesForCurrentLevel) * 100);

            // Create progress bar
            const progressBarLength = 20;
            const filledSquares = Math.floor((progressPercentage / 100) * progressBarLength);
            const emptySquares = progressBarLength - filledSquares;
            const progressBar = '█'.repeat(filledSquares) + '░'.repeat(emptySquares);

            // Get rank medal emoji
            let rankEmoji = '🏅';
            if (userRank === 1) rankEmoji = '🥇';
            else if (userRank === 2) rankEmoji = '🥈';
            else if (userRank === 3) rankEmoji = '🥉';
            else if (userRank <= 10) rankEmoji = '⭐';

            const embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('📊 User Profile')
                .addFields(
                    { 
                        name: `${rankEmoji} Server Rank`, 
                        value: `**#${userRank}** out of ${leaderboard.length}`, 
                        inline: true 
                    },
                    { 
                        name: '📊 Level', 
                        value: `**${profile.level}**`, 
                        inline: true 
                    },
                    { 
                        name: '✨ Total XP', 
                        value: `**${profile.xp.toLocaleString()}**`, 
                        inline: true 
                    },
                    { 
                        name: '💬 Messages', 
                        value: `**${profile.messages.toLocaleString()}**`, 
                        inline: true 
                    },
                    { 
                        name: '🎯 Next Level', 
                        value: `**${messagesForCurrentLevel - currentProgress}** messages`, 
                        inline: true 
                    },
                    { 
                        name: '📈 Progress', 
                        value: `**${progressPercentage}%**`, 
                        inline: true 
                    },
                    {
                        name: '▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬',
                        value: `\`${progressBar}\` ${currentProgress}/${messagesForCurrentLevel}`,
                        inline: false
                    }
                );

            if (profile.badges && profile.badges.length > 0) {
                const badgeDisplay = profile.badges
                    .slice(0, 10)
                    .map(badge => badge.badgeEmoji)
                    .join(' ');
                
                embed.addFields({
                    name: `🏆 Badges (${profile.badges.length})`,
                    value: badgeDisplay || 'None',
                    inline: false
                });
            }

            return { embed };
        } catch (error) {
            console.error('[LEVELING] Error creating profile embed:', error);
            return null;
        }
    }

    /**
     * Create badges embed for a user
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @returns {Promise<Object|null>} Badges embed data
     */
    async createBadgesEmbed(guildId, userId) {
        const profile = await this.getUserProfile(guildId, userId);
        if (!profile) return null;

        try {
            const embed = new EmbedBuilder()
                .setColor(config.colors.primary)
                .setTitle('User Badges');

            if (profile.badges.length > 0) {
                const badgeText = profile.badges.map(badge => 
                    `${badge.badgeEmoji} **${badge.badgeName}** - ${badge.badgeDescription}`
                ).join('\n');
                embed.setDescription(badgeText);
            } else {
                embed.setDescription('No badges earned yet.');
            }

            return { embed };
        } catch (error) {
            console.error('[LEVELING] Error creating badges embed:', error);
            return null;
        }
    }

    /**
     * Award XP directly to a user (admin function)
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @param {number} amount - Amount of XP to award
     * @returns {Promise<boolean>} Success status
     */
    async awardXPDirect(guildId, userId, amount) {
        if (!this.dbReady) return false;

        try {
            // Get or create user data
            let userData = await this.db.select()
                .from(this.schema.userLevels)
                .where(and(
                    eq(this.schema.userLevels.guildId, guildId),
                    eq(this.schema.userLevels.userId, userId)
                ))
                .limit(1);

            if (userData.length === 0) {
                // Create new user
                await this.db.insert(this.schema.userLevels).values({
                    guildId: guildId,
                    userId: userId,
                    xp: amount,
                    level: this.calculateLevel(0), // Start with 0 messages
                    messages: 0,
                    lastMessage: new Date(),
                    createdAt: new Date(),
                    updatedAt: new Date()
                });
            } else {
                // Update existing user
                const user = userData[0];
                const newXP = user.xp + amount;
                
                await this.db.update(this.schema.userLevels)
                    .set({
                        xp: newXP,
                        updatedAt: new Date()
                    })
                    .where(and(
                        eq(this.schema.userLevels.guildId, guildId),
                        eq(this.schema.userLevels.userId, userId)
                    ));
            }

            return true;
        } catch (error) {
            console.error('[LEVELING] Error awarding XP directly:', error);
            return false;
        }
    }

    /**
     * Reset user XP for the entire server (admin function)
     * @param {string} guildId - Guild ID
     * @returns {Promise<boolean>} Success status
     */
    async resetServerXP(guildId) {
        if (!this.dbReady) return false;

        try {
            // Delete all user levels and badges for this guild
            await this.db.delete(this.schema.userBadges)
                .where(eq(this.schema.userBadges.guildId, guildId));
            
            await this.db.delete(this.schema.userLevels)
                .where(eq(this.schema.userLevels.guildId, guildId));

            console.log(`[LEVELING] Reset all XP data for guild ${guildId}`);
            return true;
        } catch (error) {
            console.error('[LEVELING] Error resetting server XP:', error);
            return false;
        }
    }
}

module.exports = LevelingManager;