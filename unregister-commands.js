const { REST, Routes } = require('discord.js');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

// Make sure .env is loaded
const result = dotenv.config();
if (result.error) {
    console.error("Error loading .env file:", result.error);
    process.exit(1);
}

// Manually read from the .env file to be extra safe
let manualClientId = null;
let manualToken = null;

try {
    const envContent = fs.readFileSync('.env', 'utf8');
    const clientIdMatch = envContent.match(/CLIENT_ID=([^\s\r\n]+)/);
    const tokenMatch = envContent.match(/DISCORD_TOKEN=([^\s\r\n]+)/);
    
    if (clientIdMatch && clientIdMatch[1]) {
        manualClientId = clientIdMatch[1];
        console.log("Manually found CLIENT_ID:", manualClientId);
    }
    
    if (tokenMatch && tokenMatch[1]) {
        manualToken = tokenMatch[1];
        console.log("Manually found DISCORD_TOKEN: [HIDDEN]");
    }
} catch (err) {
    console.error("Error reading .env file manually:", err);
}

// Try to use environment variables first, then fall back to manual reading
const clientId = process.env.CLIENT_ID || manualClientId || '1356575287151951943'; // Hardcoded as last resort
const token = process.env.DISCORD_TOKEN || manualToken;

// Print environment variables to debug
console.log("Using CLIENT_ID:", clientId ? "✓ Found" : "✗ Missing");
console.log("Using DISCORD_TOKEN:", token ? "✓ Found" : "✗ Missing");

// Check if essential variables are present
if (!clientId) {
    console.error('CLIENT_ID is missing in .env file');
    process.exit(1);
}

if (!token) {
    console.error('DISCORD_TOKEN is missing in .env file');
    process.exit(1);
}

// Create a new REST instance
const rest = new REST({ version: '10' }).setToken(token);

// Function to unregister all global commands
async function unregisterGlobalCommands() {
    try {
        console.log('Started unregistering all application (/) commands globally...');

        // The PUT method is used to completely replace all commands in the guild with the new set
        // By passing an empty array, we're telling Discord to remove all commands
        await rest.put(
            Routes.applicationCommands(clientId),
            { body: [] },
        );

        console.log('Successfully unregistered all global application commands!');
    } catch (error) {
        console.error(error);
    }
}

// Execute the function
unregisterGlobalCommands();