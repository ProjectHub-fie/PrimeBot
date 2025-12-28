/**
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
    console.log(`Starting bot process (restart #${restartCount})`);
    
    // Launch the bot as a child process
    const botProcess = spawn('node', [path.join(__dirname, 'index.js')], {
        stdio: 'inherit',
        env: process.env
    });
    
    // Handle process events
    botProcess.on('exit', (code, signal) => {
        console.log(`Bot process exited with code ${code} and signal ${signal}`);
        
        const now = Date.now();
        if (now - lastRestart < RESTART_INTERVAL) {
            restartCount++;
            console.warn(`Rapid restart detected. Restart count: ${restartCount}/${MAX_RESTARTS}`);
        } else {
            // Reset restart count if enough time has passed
            restartCount = 0;
        }
        
        // Store restart time
        lastRestart = now;
        
        // Check if we should restart
        if (restartCount < MAX_RESTARTS) {
            console.log(`Restarting bot in 5 seconds...`);
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
startBot();