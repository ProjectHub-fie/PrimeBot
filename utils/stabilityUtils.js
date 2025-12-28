/**
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
        console.error(`Error in ${errorContext}:`, error);
        return defaultValue;
    }
}

/**
 * Safely reply to an interaction with error handling
 * @param {Interaction} interaction - The Discord interaction
 * @param {Object} replyOptions - Options for the reply
 * @returns {Promise<Message|void>} The reply message or void on error
 */
async function safeReply(interaction, replyOptions) {
    try {
        if (!interaction) return;
        
        // Check if the interaction can be replied to
        if (interaction.replied) {
            return await interaction.followUp(replyOptions).catch(() => null);
        } else if (interaction.deferred) {
            return await interaction.editReply(replyOptions).catch(() => null);
        } else {
            return await interaction.reply(replyOptions).catch(() => null);
        }
    } catch (error) {
        console.error('Error replying to interaction:', error);
        
        // Attempt a fallback reply if possible
        try {
            if (!interaction.replied && !interaction.deferred) {
                return await interaction.reply({ 
                    content: 'An error occurred while processing this command.',
                    ephemeral: true 
                }).catch(() => null);
            }
        } catch (fallbackError) {
            // Silent fail - we've done our best
        }
    }
}

/**
 * Safely access nested object properties
 * @param {Object} obj - The object to access
 * @param {string} path - Path to the property, dot-separated
 * @param {any} defaultValue - Value to return if the property is not found
 * @returns {any} The property value or default value
 */
function safeAccess(obj, path, defaultValue = null) {
    if (!obj || !path) return defaultValue;
    
    const keys = path.split('.');
    let result = obj;
    
    for (const key of keys) {
        if (result === null || result === undefined || typeof result !== 'object') {
            return defaultValue;
        }
        result = result[key];
    }
    
    return result !== undefined ? result : defaultValue;
}

/**
 * Creates a safer version of setInterval that doesn't stack
 * @param {Function} callback - Function to execute
 * @param {number} delay - Delay in milliseconds
 * @returns {Object} Interval controller with start/stop methods
 */
function safeInterval(callback, delay) {
    let intervalId = null;
    let running = false;
    
    const controller = {
        start: function() {
            if (intervalId) return;
            
            intervalId = setInterval(async () => {
                if (running) return; // Prevent overlap
                
                running = true;
                try {
                    await callback();
                } catch (error) {
                    console.error('Error in interval callback:', error);
                } finally {
                    running = false;
                }
            }, delay);
        },
        
        stop: function() {
            if (intervalId) {
                clearInterval(intervalId);
                intervalId = null;
            }
        },
        
        isRunning: function() {
            return intervalId !== null;
        }
    };
    
    return controller;
}

/**
 * Set a timeout that returns a promise
 * @param {number} ms - Milliseconds to wait
 * @returns {Promise<void>} Promise that resolves after the timeout
 */
function timeout(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Execute a function with automatic retries on failure
 * @param {Function} fn - The function to execute
 * @param {Object} options - Retry options
 * @returns {Promise<any>} The function result
 */
async function withRetry(fn, options = {}) {
    const { 
        maxRetries = 3, 
        initialDelay = 1000, 
        maxDelay = 10000,
        factor = 2,
        retryCondition = isRetryableError
    } = options;
    
    let attempt = 0;
    let delay = initialDelay;
    
    while (true) {
        try {
            return await fn();
        } catch (error) {
            attempt++;
            
            if (attempt >= maxRetries || !retryCondition(error)) {
                throw error;
            }
            
            console.warn(`Retry attempt ${attempt}/${maxRetries} after error:`, error);
            
            await timeout(delay);
            delay = Math.min(delay * factor, maxDelay);
        }
    }
}

/**
 * Determine if an error is retryable
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