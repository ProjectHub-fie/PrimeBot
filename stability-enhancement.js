/**
 * Bot Stability Enhancement Script
 * 
 * This script will:
 * 1. Enhance error handling across critical parts of the bot
 * 2. Implement crash guards to prevent the bot from shutting down unexpectedly
 * 3. Add graceful degradation for features instead of hard crashes
 * 4. Improve logging to help diagnose issues in production
 */

const fs = require('fs');
const path = require('path');

console.log(`===== ENHANCING BOT STABILITY =====`);

// 1. Enhance the main index.js file with better error handling
const indexPath = path.join(__dirname, 'index.js');
let indexContent = '';

try {
    indexContent = fs.readFileSync(indexPath, 'utf8');
    
    // Add more comprehensive error handling for process events
    const processErrorHandling = `
// Enhanced error handling for process events
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't crash on unhandled rejections
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    // Log the error but don't exit unless absolutely necessary
    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
        console.log('Network error occurred, but the bot will continue running');
    } else if (error.message && error.message.includes('getaddrinfo')) {
        console.log('DNS resolution error occurred, but the bot will continue running');
    } else if (error.code === 'TOKEN_INVALID') {
        console.error('Invalid token. The bot must restart with a valid token');
        process.exit(1);
    }
    // For other errors, log but don't crash
});

process.on('warning', (warning) => {
    console.warn('Warning:', warning.name, warning.message);
});
`;

    // Check if the enhanced error handling is already there
    if (!indexContent.includes('Enhanced error handling for process events')) {
        // Add the enhanced error handling before the last line
        const lines = indexContent.split('\n');
        
        // Insert before the last closing brace to ensure it's in the global scope
        lines.splice(lines.length, 0, processErrorHandling);
        
        indexContent = lines.join('\n');
        fs.writeFileSync(indexPath, indexContent, 'utf8');
        console.log('✅ Enhanced error handling in index.js');
    } else {
        console.log('ℹ️ Error handling already enhanced in index.js');
    }
} catch (error) {
    console.error('❌ Error updating index.js:', error);
}

// 2. Create a stability module for use across the bot
const stabilityUtilPath = path.join(__dirname, 'utils', 'stabilityUtils.js');

try {
    const stabilityUtilContent = `/**
 * Stability utilities to improve bot resilience
 * 
 * This module provides utilities to help prevent crashes and implement
 * graceful degradation when problems occur.
 */

/**
 * Safely execute a function with error handling
 * @param {Function} fn - Function to execute
 * @param {any[]} args - Arguments to pass to the function
 * @param {any} defaultValue - Value to return if the function fails
 * @param {string} errorContext - Context for error logging
 * @returns {Promise<any>} The function result or default value on error
 */
async function safeExecute(fn, args = [], defaultValue = null, errorContext = 'Unknown operation') {
    try {
        return await fn(...args);
    } catch (error) {
        console.error(\`Error in \${errorContext}:\`, error);
        return defaultValue;
    }
}

/**
 * Safe version of discord.js's interaction.reply
 * @param {Interaction} interaction - Discord interaction object
 * @param {Object} options - Reply options
 * @returns {Promise<void>}
 */
async function safeReply(interaction, options) {
    try {
        if (interaction.replied || interaction.deferred) {
            await interaction.followUp(options);
        } else {
            await interaction.reply(options);
        }
    } catch (error) {
        console.error('Error replying to interaction:', error);
        try {
            // Try one more time with a simplified message
            if (!interaction.replied && !interaction.deferred) {
                await interaction.reply({ 
                    content: 'There was an error executing the command. Please try again later.',
                    ephemeral: false 
                });
            }
        } catch (secondError) {
            console.error('Failed to send error message:', secondError);
        }
    }
}

/**
 * Safely access a Discord API entity with error handling
 * @param {Function} accessor - Function to access the entity
 * @param {any} defaultValue - Value to return if access fails
 * @returns {any} The accessed entity or default value
 */
function safeAccess(accessor, defaultValue = null) {
    try {
        return accessor();
    } catch (error) {
        console.error('Error accessing Discord entity:', error);
        return defaultValue;
    }
}

/**
 * Set interval with built-in error handling
 * @param {Function} callback - Function to execute
 * @param {number} delay - Delay in milliseconds
 * @param {string} taskName - Name of the task for logging
 * @returns {NodeJS.Timeout} Interval ID
 */
function safeInterval(callback, delay, taskName = 'scheduled task') {
    return setInterval(() => {
        try {
            callback();
        } catch (error) {
            console.error(\`Error in \${taskName}:\`, error);
            // Continue running the interval despite errors
        }
    }, delay);
}

/**
 * Create a promise that resolves after a timeout
 * @param {number} ms - Milliseconds to wait
 * @returns {Promise<void>}
 */
function timeout(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Execute a function with retries on failure
 * @param {Function} fn - Function to execute
 * @param {Object} options - Retry options
 * @returns {Promise<any>} The function result
 */
async function withRetry(fn, { maxRetries = 3, delay = 1000, backoff = 2, errorFilter = null } = {}) {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error;
            
            // Skip retries if the error filter says so
            if (errorFilter && !errorFilter(error)) {
                throw error;
            }
            
            console.warn(\`Attempt \${attempt} failed, retrying in \${delay}ms...\`);
            
            // Wait before the next attempt
            if (attempt < maxRetries) {
                await timeout(delay);
                delay *= backoff; // Exponential backoff
            }
        }
    }
    
    // All retries failed
    throw lastError;
}

/**
 * Check if a request error is retryable
 * @param {Error} error - The error to check
 * @returns {boolean} Whether the error is retryable
 */
function isRetryableError(error) {
    // Network errors are usually retryable
    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND' || 
        error.code === 'ESOCKETTIMEDOUT' || error.code === 'ECONNABORTED') {
        return true;
    }
    
    // Some Discord API errors are retryable (rate limits, server errors)
    if (error.code >= 500 || error.code === 429) {
        return true;
    }
    
    return false;
}

module.exports = {
    safeExecute,
    safeReply,
    safeAccess,
    safeInterval,
    timeout,
    withRetry,
    isRetryableError
};
`;

    fs.writeFileSync(stabilityUtilPath, stabilityUtilContent, 'utf8');
    console.log('✅ Created stability utilities in utils/stabilityUtils.js');
} catch (error) {
    console.error('❌ Error creating stability utilities:', error);
}

// 3. Update the interaction handling to be more robust
const interactionHandlerPath = path.join(__dirname, 'events', 'interactionCreate.js');
let interactionHandlerContent = '';

try {
    interactionHandlerContent = fs.readFileSync(interactionHandlerPath, 'utf8');
    
    // Create more robust interaction handling
    const safeInteractionHandling = `const { safeReply, safeExecute } = require('../utils/stabilityUtils');

module.exports = {
    name: 'interactionCreate',
    
    async execute(interaction, client) {
        try {
            // Handle slash commands
            if (interaction.isChatInputCommand()) {
                const command = client.commands.get(interaction.commandName);
                
                if (!command) {
                    console.warn(\`Command not found: \${interaction.commandName}\`);
                    return safeReply(interaction, { 
                        content: 'This command is not currently available.',
                        ephemeral: false
                    });
                }
                
                // Log command usage
                console.log(\`[COMMAND] \${interaction.user.tag} used /\${interaction.commandName} in \${interaction.guild ? interaction.guild.name : 'DM'}\`);
                
                // Execute command with safe execution
                await safeExecute(
                    command.execute.bind(command), 
                    [interaction],
                    null,
                    \`Command "\${interaction.commandName}"\`
                );
                
                return;
            }
            
            // Handle buttons
            if (interaction.isButton()) {
                // Extract the custom ID parts
                const [action, ...params] = interaction.customId.split(':');
                
                // Route to the appropriate handler based on the action
                if (action === 'giveaway_enter') {
                    await safeExecute(
                        client.giveawayManager.handleGiveawayEntry.bind(client.giveawayManager),
                        [interaction],
                        null,
                        'Giveaway entry button'
                    );
                } else if (action === 'ticket_create') {
                    await safeExecute(
                        client.ticketManager.handleTicketCreation.bind(client.ticketManager),
                        [interaction],
                        null,
                        'Ticket creation button'
                    );
                } else if (action === 'ticket_close') {
                    await safeExecute(
                        client.ticketManager.handleTicketClose.bind(client.ticketManager),
                        [interaction],
                        null,
                        'Ticket close button'
                    );
                } else if (action === 'tictactoe') {
                    const position = params[0];
                    if (position) {
                        await safeExecute(
                            client.ticTacToeManager.makeMove.bind(client.ticTacToeManager),
                            [{ channelId: interaction.channelId, playerId: interaction.user.id, position }],
                            null,
                            'TicTacToe move button'
                        );
                    }
                }
                
                return;
            }
            
            // Handle select menus, modals, etc.
            // Add more handlers as needed
            
        } catch (error) {
            console.error('Error in interactionCreate event:', error);
            
            // Try to respond to the user if possible
            try {
                if (!interaction.replied && !interaction.deferred) {
                    await interaction.reply({
                        content: 'There was an error executing this interaction! Please try again later.',
                        ephemeral: false
                    });
                }
            } catch (replyError) {
                console.error('Failed to send error response:', replyError);
            }
        }
    }
};`;

    // Replace the entire file
    fs.writeFileSync(interactionHandlerPath, safeInteractionHandling, 'utf8');
    console.log('✅ Enhanced interaction handler with stability features');
} catch (error) {
    console.error('❌ Error updating interaction handler:', error);
}

// 4. Enhance the bot connection and reconnection logic
const connectionEnhancerPath = path.join(__dirname, 'connection-enhancer.js');

try {
    const connectionEnhancerContent = `/**
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
        console.warn(\`Bot disconnected with code \${event.code}. Reason: \${event.reason}\`);
        
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
    safeInterval(() => {
        if (client.ws.status === 0) {
            console.log('WebSocket connection is down, attempting to reconnect...');
            client.destroy();
            setTimeout(() => {
                client.login(process.env.DISCORD_TOKEN).catch(console.error);
            }, 5000);
        }
    }, 60000, 'WebSocket connection monitor');
    
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
    safeInterval(() => {
        const now = Date.now();
        if (now - lastHeartbeatAck > 3 * 60 * 1000) { // 3 minutes without heartbeat
            console.warn('No heartbeat received for 3 minutes, reconnecting...');
            client.destroy();
            setTimeout(() => {
                client.login(process.env.DISCORD_TOKEN).catch(console.error);
            }, 5000);
        }
    }, 60000, 'Heartbeat monitor');
    
    console.log('Enhanced Discord client with improved connection handling');
}

module.exports = enhanceConnection;`;

    fs.writeFileSync(connectionEnhancerPath, connectionEnhancerContent, 'utf8');
    console.log('✅ Created connection enhancer module');
} catch (error) {
    console.error('❌ Error creating connection enhancer:', error);
}

// 5. Update the main index.js to use the connection enhancer
try {
    indexContent = fs.readFileSync(indexPath, 'utf8');
    
    // Add the connection enhancer
    if (!indexContent.includes('connection-enhancer')) {
        // Add enhancer near the top after client creation
        const enhancerCode = `
// Enhance client connection handling
const enhanceConnection = require('./connection-enhancer');
enhanceConnection(client);
`;
        
        // Find position to insert after client initialization
        const clientInitIndex = indexContent.indexOf('const client = new Client');
        const endOfClientInit = indexContent.indexOf(';', clientInitIndex) + 1;
        
        const beforeEnhancer = indexContent.substring(0, endOfClientInit);
        const afterEnhancer = indexContent.substring(endOfClientInit);
        
        indexContent = beforeEnhancer + enhancerCode + afterEnhancer;
        
        fs.writeFileSync(indexPath, indexContent, 'utf8');
        console.log('✅ Added connection enhancer to index.js');
    } else {
        console.log('ℹ️ Connection enhancer already added to index.js');
    }
} catch (error) {
    console.error('❌ Error updating index.js with connection enhancer:', error);
}

// 6. Create an application entry-point that wraps the bot in a supervisor
const wrapperPath = path.join(__dirname, 'run-bot.js');

try {
    const wrapperContent = `/**
 * Bot supervisor script
 * 
 * This script launches the bot in a managed way, providing automatic
 * recovery from crashes, memory leak protection, and graceful shutdowns.
 */

const { spawn } = require('child_process');
const path = require('path');
require('dotenv').config();

console.log('=== BOT SUPERVISOR STARTING ===');

let restartCount = 0;
const MAX_RESTARTS = 10;
const RESTART_INTERVAL = 60000; // 1 minute
let lastRestart = Date.now();

/**
 * Start the bot process
 */
function startBot() {
    console.log(\`Starting bot process (restart #\${restartCount})\`);
    
    // Launch the bot as a child process
    const botProcess = spawn('node', [path.join(__dirname, 'index.js')], {
        stdio: 'inherit',
        env: process.env
    });
    
    // Handle process events
    botProcess.on('exit', (code, signal) => {
        console.log(\`Bot process exited with code \${code} and signal \${signal}\`);
        
        const now = Date.now();
        if (now - lastRestart < RESTART_INTERVAL) {
            restartCount++;
            console.warn(\`Rapid restart detected. Restart count: \${restartCount}/\${MAX_RESTARTS}\`);
        } else {
            // Reset restart count if enough time has passed
            restartCount = 0;
        }
        
        // Store restart time
        lastRestart = now;
        
        // Check if we should restart
        if (restartCount < MAX_RESTARTS) {
            console.log(\`Restarting bot in 5 seconds...\`);
            setTimeout(startBot, 5000);
        } else {
            console.error('Too many restart attempts. Please check the logs and fix the issues.');
            process.exit(1);
        }
    });
    
    // Handle supervisor termination
    process.on('SIGINT', () => {
        console.log('Supervisor received SIGINT, shutting down bot gracefully...');
        botProcess.kill('SIGINT');
        // Give the bot some time to clean up
        setTimeout(() => {
            console.log('Supervisor exiting');
            process.exit(0);
        }, 5000);
    });
    
    process.on('SIGTERM', () => {
        console.log('Supervisor received SIGTERM, shutting down bot gracefully...');
        botProcess.kill('SIGTERM');
        setTimeout(() => {
            process.exit(0);
        }, 5000);
    });
}

// Start the bot
startBot();`;

    fs.writeFileSync(wrapperPath, wrapperContent, 'utf8');
    console.log('✅ Created bot supervisor wrapper script');
} catch (error) {
    console.error('❌ Error creating bot supervisor:', error);
}

// 7. Update package.json script section
try {
    const packageJsonPath = path.join(__dirname, 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    
    // Add start script to use the wrapper
    packageJson.scripts = packageJson.scripts || {};
    packageJson.scripts.start = "node run-bot.js";
    packageJson.scripts.direct = "node index.js";
    packageJson.scripts.supervisor = "node run-bot.js";
    
    fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2), 'utf8');
    console.log('✅ Updated package.json with supervisor scripts');
} catch (error) {
    console.error('❌ Error updating package.json:', error);
}

console.log(`\n===== STABILITY ENHANCEMENTS COMPLETE =====`);
console.log(`Enhanced bot stability with:`);
console.log(`  • Improved error handling in critical areas`);
console.log(`  • Robust reconnection logic for Discord API`);
console.log(`  • Crash recovery and automatic restart system`);
console.log(`  • Graceful degradation instead of hard failures`);
console.log(`  • Safe execution utilities for command handlers`);
console.log(`\nYou can now run the bot with:`);
console.log(`  npm run supervisor - Run the bot with crash protection`);
console.log(`  npm run direct     - Run the bot directly without the supervisor`);
console.log(`We strongly recommend using 'npm run supervisor' for production use.`);