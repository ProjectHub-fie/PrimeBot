/**
 * Connection enhancement module for the Discord bot
 * 
 * This module improves the bot's connection handling with Discord,
 * implementing better reconnection logic and handling various network issues.
 */

const { Client } = require('discord.js');
const { safeInterval, timeout, withRetry } = require('./utils/stabilityUtils');

/**
 * Enhance a Discord.js client with improved connection handling
 * @param {Client} client - The Discord.js client to enhance
 */
function enhanceConnection(client) {
    // Store original login method
    const originalLogin = client.login;
    
    // Replace with enhanced version
    client.login = async function(token) {
        return withRetry(
            () => originalLogin.call(this, token),
            {
                maxRetries: 5,
                delay: 5000,
                backoff: 1.5,
                errorFilter: (error) => {
                    // Don't retry invalid token errors
                    return !error.message || !error.message.includes('TOKEN_INVALID');
                }
            }
        );
    };
    
    // Add more robust reconnection handling
    client.on('disconnect', (event) => {
        console.warn(`Bot disconnected with code ${event.code}. Reason: ${event.reason}`);
        
        if (event.code === 4014) {
            console.error('Disconnect due to invalid intents. Please fix your intents configuration.');
        } else if ([4004, 4010, 4011, 4012, 4013].includes(event.code)) {
            console.error('Authentication error. Please check your bot token and permissions.');
        } else {
            console.log('Attempting to reconnect...');
            // Reconnect with exponential backoff
            setTimeout(() => {
                client.login(process.env.DISCORD_TOKEN).catch(console.error);
            }, 5000);
        }
    });
    
    // Monitor the WebSocket connection
    const wsMonitor = safeInterval(() => {
        if (client.ws.status === 0) {
            console.log('WebSocket connection is down, attempting to reconnect...');
            client.destroy();
            setTimeout(() => {
                client.login(process.env.DISCORD_TOKEN).catch(console.error);
            }, 5000);
        }
    }, 60000);
    wsMonitor.start();
    
    // Add heartbeat monitoring
    let lastHeartbeatAck = Date.now();
    
    client.ws.on('hello', () => {
        lastHeartbeatAck = Date.now();
    });
    
    client.ws.on('heartbeat', () => {
        lastHeartbeatAck = Date.now();
    });
    
    client.ws.on('heartbeatAck', () => {
        lastHeartbeatAck = Date.now();
    });
    
    // Check for stale connections
    const heartbeatMonitor = safeInterval(() => {
        const now = Date.now();
        if (now - lastHeartbeatAck > 3 * 60 * 1000) { // 3 minutes without heartbeat
            console.warn('No heartbeat received for 3 minutes, reconnecting...');
            client.destroy();
            setTimeout(() => {
                client.login(process.env.DISCORD_TOKEN).catch(console.error);
            }, 5000);
        }
    }, 60000);
    heartbeatMonitor.start();
    
    console.log('Enhanced Discord client with improved connection handling');
}

module.exports = enhanceConnection;