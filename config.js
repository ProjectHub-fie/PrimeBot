module.exports = {
    // Bot version information
    version: '2.5.0',
    buildDate: '2025-05-29',
    
    // Bot configuration
    prefix: '$', // Command prefix for message commands
    website: 'https://primebot-online.vercel.app/',
    doc: 'https://primebot-online.vercel.app/docs.html',
    // Bot URLs
    supportServer: "https://discord.gg/gd7UNSfX86", // PrimeBot support server
  
    // Developer IDs (users who can access developer commands)
    developerIds: [
        "1310654136290639894", // Bot's client ID
        "1215935165909254195",  // Developer ID
        "1099412072094449814",  // Developer ID
        "1156234554613157968"   // Developer ID
    ],
    
    // Colors for embeds
    colors: {
        primary: '#5865F2', // Discord blurple color
        success: '#57F287', // Green color for success messages
        error: '#ED4245',   // Red color for error messages
        warning: '#FEE75C',  // Yellow color for warning messages
        Gold: "#FFD700",
        bronze: "#CD7F32",   // Bronze color for lower level badges
        silver: "#C0C0C0",   // Silver color for mid-level badges
        gold: "#FFD700",     // Gold color for high-level badges
        platinum: "#E5E4E2"  // Platinum color for highest level badges
    },
    
    // Welcome system configuration
    welcome: {
        // Default welcome message in server - can be customized
        serverMessage: 'Welcome to the server, {member}! Enjoy your stay!',
        
        // Welcome message sent via DM to new members
        dmMessage: 'Hey {username}! Welcome to **{server}**!\n\nWe\'re excited to have you join our community. If you have any questions, feel free to ask in the help channel.\n\nHere are a few things to check out:\n• Read the rules in the rules channel\n• Introduce yourself in the introductions channel\n• Get roles in the roles channel',
        
        // Default welcome channel ID (set to null to use the first available channel)
        channelId: null,
        
        // Whether to send a welcome DM to new members
        sendDM: true,
        
        // Additional welcome banner image URL (set to null for no image)
        bannerUrl: 'https://i.imgur.com/hxGEQJh.png',
        
        // Legacy support server ID - kept for backward compatibility
        // Welcome messages are now managed through server-specific settings
        supportServerId: "1317411980625313893" // AFK Devs server ID
    },
    
    // Giveaway settings
    giveaway: {
        defaultDuration: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
        reactionEmoji: '🎉', // Emoji used for giveaway reactions
        winnerCount: 1, // Default number of winners
        checkInterval: 10000, // Check for ended giveaways every 10 seconds
    },
    
    // Leveling system configuration
    leveling: {
        // Legacy support server ID - kept for backward compatibility
        // Leveling is now available in all servers and managed through server settings
        supportServerId: "1317411980625313893", // AFK Devs server ID
        
        // Channel where level-up messages are sent (null = the channel where message was sent)
        levelUpChannelId: null,
        
        // XP settings
        xpPerMessage: 15,       // Base XP per message
        xpCooldown: 60000,      // Cooldown between XP gains (1 minute)
        minMessageLength: 3,     // Minimum message length to earn XP
        maxRandomBonus: 10,     // Random bonus XP (0-10)
        
        // Level up formula: level = Math.floor(baseMultiplier * Math.sqrt(xp / baseMultiplier))
        baseMultiplier: 100,    // Affects XP curve
        
        // Badges configuration
        badges: {
            // Level-based badges
            levelBadges: [
                { level: 5, name: "Newcomer", emoji: "🔰", color: "bronze", description: "Reached level 5" },
                { level: 10, name: "Active Member", emoji: "⭐", color: "bronze", description: "Reached level 10" },
                { level: 15, name: "Dedicated", emoji: "🌟", color: "silver", description: "Reached level 15" },
                { level: 20, name: "Enthusiast", emoji: "💫", color: "silver", description: "Reached level 20" },
                { level: 30, name: "Expert", emoji: "🏆", color: "gold", description: "Reached level 30" },
                { level: 50, name: "Veteran", emoji: "👑", color: "gold", description: "Reached level 50" },
                { level: 75, name: "Legend", emoji: "🔮", color: "platinum", description: "Reached level 75" },
                { level: 100, name: "Community Hero", emoji: "⚡", color: "platinum", description: "Reached level 100" }
            ],
            
            // Achievement badges (manually awarded)
            achievementBadges: [
                { id: "helper", name: "Helpful Hand", emoji: "🤝", color: "primary", description: "Helped other members solve problems" },
                { id: "contributor", name: "Contributor", emoji: "🛠️", color: "success", description: "Contributed to community projects" },
                { id: "event", name: "Event Participant", emoji: "🎉", color: "warning", description: "Participated in community events" },
                { id: "creative", name: "Creative Mind", emoji: "🎨", color: "primary", description: "Shared creative content" },
                { id: "moderator", name: "Community Guardian", emoji: "🛡️", color: "error", description: "Helped maintain community standards" }
            ],
            
            // Special badges (rare, manually awarded)
            specialBadges: [
                { id: "founder", name: "Community Founder", emoji: "🏛️", color: "gold", description: "Founding member of the community" },
                { id: "innovator", name: "Innovator", emoji: "💡", color: "gold", description: "Introduced innovative ideas or projects" },
                { id: "patron", name: "Generous Patron", emoji: "💖", color: "gold", description: "Supported the community financially" }
            ]
        }
    },
    
    // Permission levels for commands
    permissions: {
        GIVEAWAY_CREATE: 'MANAGE_GUILD', // Permission needed to create giveaways
        GIVEAWAY_END: 'MANAGE_GUILD',    // Permission needed to end giveaways
        GIVEAWAY_REROLL: 'MANAGE_GUILD',  // Permission needed to reroll giveaways
        BADGES_AWARD: 'MANAGE_GUILD',    // Permission needed to award badges
        BADGES_REVOKE: 'MANAGE_GUILD'    // Permission needed to revoke badges
    }
};
