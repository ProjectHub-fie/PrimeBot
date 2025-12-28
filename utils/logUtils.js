/**
 * Utility functions for better logging and debugging
 */

/**
 * Log a command execution with detailed information
 * @param {string} commandName - The name of the command
 * @param {Object} interaction - The interaction object
 */
function logCommandExecution(commandName, interaction) {
    console.log(`[COMMAND] ${commandName} executed by ${interaction.user.tag} (${interaction.user.id}) in ${interaction.guild ? interaction.guild.name : 'DM'}`);
}

/**
 * Log an error with detailed information
 * @param {string} context - Where the error occurred
 * @param {Error} error - The error object
 */
function logError(context, error) {
    console.error(`[ERROR] ${context}:`, error);
}

/**
 * Format uptime in a human-readable format
 * @param {number} uptime - The uptime in seconds
 * @returns {string} Formatted uptime string
 */
function formatUptime(uptime) {
    const seconds = Math.floor(uptime % 60);
    const minutes = Math.floor((uptime / 60) % 60);
    const hours = Math.floor((uptime / 3600) % 24);
    const days = Math.floor(uptime / 86400);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (seconds > 0) parts.push(`${seconds}s`);

    return parts.join(" ") || "0s";
}

/**
 * Log a server message for tracking interactions
 * @param {string} message - The message to log
 */
function logServerActivity(message) {
    console.log(`[SERVER] ${message}`);
}

module.exports = {
    logCommandExecution,
    logError,
    formatUptime,
    logServerActivity
};