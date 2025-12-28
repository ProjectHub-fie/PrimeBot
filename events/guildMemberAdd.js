const { EmbedBuilder } = require('discord.js');
const config = require('../config');

module.exports = {
    name: 'guildMemberAdd',
    async execute(member, client) {
        try {
            // Check if server settings manager is available
            if (!client.serverSettingsManager) {
                console.warn('[WELCOME] Server settings manager not available, creating welcome functionality for all servers');
                
                // SERVER WELCOME MESSAGE - Welcome messages are now available in all servers by default
                await handleServerWelcome(member, null, client);
                
                // DM WELCOME MESSAGE
                if (config.welcome.sendDM) {
                    await handleDirectMessage(member, null, client);
                }
                
                return;
            }
            
            // Get server-specific settings
            const guildSettings = client.serverSettingsManager.getGuildSettings(member.guild.id);
            const welcomeSettings = client.serverSettingsManager.getWelcomeSettings(member.guild.id);
            
            console.log(`[WELCOME] Member joined ${member.guild.name} (${member.guild.id}), welcome enabled: ${welcomeSettings.enabled}`);
            
            // Skip if welcome is disabled for this server
            if (!welcomeSettings.enabled) {
                return;
            }
            
            // SERVER WELCOME MESSAGE
            await handleServerWelcome(member, welcomeSettings, client);
            
            // DM WELCOME MESSAGE
            if (welcomeSettings.dmEnabled) {
                await handleDirectMessage(member, welcomeSettings, client);
            }
            
        } catch (error) {
            console.error('[WELCOME] Error in guildMemberAdd event:', error.message);
            console.error(error.stack);
        }
    },
};

/**
 * Handle sending the welcome message in the server
 * @param {GuildMember} member - The member who joined
 * @param {Object} welcomeSettings - Server-specific welcome settings
 * @param {Client} client - Discord client
 */
async function handleServerWelcome(member, welcomeSettings, client) {
    try {
        // Get the welcome channel (either from settings, config, or find first available)
        let welcomeChannel;
        
        // Try to get from server-specific settings first
        if (welcomeSettings && welcomeSettings.channelId) {
            welcomeChannel = member.guild.channels.cache.get(welcomeSettings.channelId);
        } 
        // Fall back to global config
        else if (config.welcome.channelId) {
            welcomeChannel = member.guild.channels.cache.get(config.welcome.channelId);
        }

        // If no channel found from config, fall back to finding an appropriate channel
        if (!welcomeChannel) {
            // First try to find a channel specifically for welcomes
            welcomeChannel = member.guild.channels.cache.find(
                ch => ch.type === 0 && 
                (ch.name.includes('welcome') || ch.name.includes('general')) && 
                ch.permissionsFor(member.guild.members.me).has('SendMessages')
            );
            
            // If still no channel, find any text channel with proper permissions
            if (!welcomeChannel) {
                welcomeChannel = member.guild.channels.cache.find(
                    ch => ch.type === 0 && ch.permissionsFor(member.guild.members.me).has('SendMessages')
                );
            }
        }
        
        // Only proceed if a channel was found and we have permissions
        if (welcomeChannel && welcomeChannel.permissionsFor(member.guild.members.me).has('SendMessages')) {
            console.log(`[WELCOME] Found welcome channel for ${member.user.tag} in ${member.guild.name}: ${welcomeChannel.name}`);
            
            // Determine which settings to use (server-specific or global)
            const messageTemplate = welcomeSettings?.message || config.welcome.serverMessage;
            const bannerUrl = welcomeSettings?.bannerUrl || config.welcome.bannerUrl;
            const embedColor = welcomeSettings?.color || config.colors.primary;
            
            // Create welcome embed for server
            const welcomeEmbed = new EmbedBuilder()
                .setColor(embedColor)
                .setTitle(welcomeSettings?.customTitle || `Welcome to ${member.guild.name}!`)
                .setDescription(messageTemplate.replace('{member}', member))
                .setThumbnail(member.user.displayAvatarURL({ dynamic: true }));
                
            // Add fields if enabled (check server settings first, then default to showing all)
            const showAccountAge = welcomeSettings ? welcomeSettings.showAccountAge : true;
            const showJoinDate = welcomeSettings ? welcomeSettings.showJoinDate : true;
            const showMemberCount = welcomeSettings ? welcomeSettings.showMemberCount : true;
            
            if (showAccountAge) {
                welcomeEmbed.addFields({ 
                    name: '📅 Account Created', 
                    value: `<t:${Math.floor(member.user.createdTimestamp / 1000)}:R>`, 
                    inline: true 
                });
            }
            
            if (showJoinDate) {
                welcomeEmbed.addFields({ 
                    name: '📥 Joined Server', 
                    value: `<t:${Math.floor(member.joinedTimestamp / 1000)}:R>`, 
                    inline: true 
                });
            }
            
            if (showMemberCount) {
                welcomeEmbed.addFields({ 
                    name: '👥 Member Count', 
                    value: `${member.guild.memberCount}`, 
                    inline: true 
                });
            }
            
            // Set footer
            welcomeEmbed.setFooter({ 
                text: welcomeSettings?.customFooter || `User ID: ${member.user.id}` 
            }).setTimestamp();
            
            // Add banner image if defined
            if (bannerUrl) {
                welcomeEmbed.setImage(bannerUrl);
            }
            
            // Send welcome message to channel
            await welcomeChannel.send({ 
                content: `Welcome, ${member}! We hope you enjoy your stay in **${member.guild.name}**!`, 
                embeds: [welcomeEmbed] 
            }).catch(error => {
                console.error(`[WELCOME] Could not send welcome message in guild ${member.guild.name}:`, error.message);
            });
        } else {
            console.log(`[WELCOME] No suitable welcome channel found for ${member.user.tag} in ${member.guild.name}`);
        }
    } catch (error) {
        console.error(`[WELCOME] Error processing server welcome for ${member.user.tag}:`, error.message);
        console.error(error.stack);
    }
}

/**
 * Handle sending a direct message to the new member
 * @param {GuildMember} member - The member who joined
 * @param {Object} welcomeSettings - Server-specific welcome settings
 * @param {Client} client - Discord client
 */
async function handleDirectMessage(member, welcomeSettings, client) {
    try {
        // Determine which settings to use
        const messageTemplate = welcomeSettings?.dmMessage || config.welcome.dmMessage;
        const embedColor = welcomeSettings?.color || config.colors.primary;
        
        // Format the DM message
        const dmMessage = messageTemplate
            .replace('{username}', member.user.username)
            .replace('{server}', member.guild.name);
        
        // Create DM embed
        const dmEmbed = new EmbedBuilder()
            .setColor(embedColor)
            .setTitle(`Welcome to ${member.guild.name}!`)
            .setDescription(dmMessage)
            .setThumbnail(member.guild.iconURL({ dynamic: true }))
            .setFooter({ text: 'We\'re happy to have you here!' })
            .setTimestamp();
        
        // Add banner image if defined
        if (welcomeSettings?.bannerUrl) {
            dmEmbed.setImage(welcomeSettings.bannerUrl);
        }
        
        // Send DM to the new member
        await member.send({ embeds: [dmEmbed] }).catch(error => {
            console.log(`[WELCOME] Could not send DM to ${member.user.tag}: ${error.message}`);
        });
    } catch (error) {
        console.error(`[WELCOME] Error sending welcome DM to ${member.user.tag}:`, error.message);
        // Silently fail if DM fails - the user might have DMs disabled
    }
}
