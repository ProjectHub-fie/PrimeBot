const { ActivityType } = require("discord.js");
const { logServerActivity } = require('../utils/logUtils');

module.exports = {
    name: "ready",
    once: true,
    execute(client) {
        console.log(`Logged in as ${client.user.tag}!`);

        // Giveaway checking will be started automatically by GiveawayManager after database initialization

        // Debug: List all registered slash commands
        console.log('\n===== SLASH COMMANDS DEBUG =====');
        console.log(`Commands collection size: ${client.commands.size}`);
        if (client.commands.size === 0) {
            console.log('WARNING: No commands are loaded in the collection!');
        } else {
            console.log('Registered commands:');
            client.commands.forEach((cmd, name) => {
                console.log(`- ${name}: ${cmd.data ? 'Has data' : 'No data'}, ${typeof cmd.execute === 'function' ? 'Has execute function' : 'No execute function'}`);
            });
        }
        console.log('=================================\n');

        // Set bot nickname for all guilds where possible (without detailed error logging)
        client.guilds.cache.forEach((guild) => {
            try {
                // Only attempt to set nickname if we have the right permissions
                if (guild.members?.me?.permissions?.has('ChangeNickname')) {
                    guild.members.me.setNickname("PrimeBot").catch(() => {
                        // Silent fail - this is not critical functionality
                    });
                }
            } catch (error) {
                // Ignore nickname errors - they're not critical
            }
        });

        // Set bot status
        const updateStatus = () => {
            const serverCount = client.guilds.cache.size;
            client.user.setPresence({
                activities: [
                    {
                        name: `${serverCount} servers | $help`,
                        type: ActivityType.Watching,
                    },
                ],
                status: "online",
            });
        };

        updateStatus();

        // Update activity every 5 minutes
        setInterval(updateStatus, 5 * 60 * 1000);

        console.log(
            `Bot is ready! Serving ${client.guilds.cache.size} servers.`,
        );
        
        // Log server names for debugging
        logServerActivity(`Bot is serving the following servers:`);
        client.guilds.cache.forEach(guild => {
            logServerActivity(`- ${guild.name} (ID: ${guild.id}, Members: ${guild.memberCount})`);
        });

        // Start live poll checking system
        if (client.livePollManager) {
            console.log('Poll checking system started.');
            setInterval(() => {
                client.livePollManager.checkExpiredPolls();
            }, 60000); // Check every minute
        }
    },
};
//
