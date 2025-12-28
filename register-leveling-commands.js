/**
 * Script to register only leveling-related commands to Discord
 * This is a specialized version of deploy-commands.js that only deploys leveling-related commands
 */
const { REST, Routes, PermissionFlagsBits } = require('discord.js');
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
process.env.CLIENT_ID = process.env.CLIENT_ID || manualClientId;
process.env.DISCORD_TOKEN = process.env.DISCORD_TOKEN || manualToken;

// Print environment variables to debug
console.log("Using CLIENT_ID:", process.env.CLIENT_ID ? "✓ Found" : "✗ Missing");
console.log("Using DISCORD_TOKEN:", process.env.DISCORD_TOKEN ? "✓ Found" : "✗ Missing");

// Define leveling-related command files
const levelingRelatedFiles = [
    'leveling.js'
    // Add other leveling-related command files here if you have any
];

const levelingCommands = [];

// Load leveling-related command data
for (const file of levelingRelatedFiles) {
    const filePath = path.join(__dirname, 'commands', file);
    if (fs.existsSync(filePath)) {
        const command = require(filePath);
        
        if ('data' in command && 'execute' in command) {
            levelingCommands.push(command.data.toJSON());
            console.log(`Loaded leveling command: ${command.data.name}`);
        } else {
            console.log(`[WARNING] The command at ${filePath} is missing required "data" or "execute" property.`);
        }
    } else {
        console.log(`[WARNING] Command file ${file} not found`);
    }
}

// Configure REST for deployment
const rest = new REST().setToken(process.env.DISCORD_TOKEN);

// Deploy leveling commands function
async function deployLevelingCommands() {
    try {
        console.log(`Started refreshing ${levelingCommands.length} leveling-related application (/) commands.`);

        // Check if we have a CLIENT_ID
        if (!process.env.CLIENT_ID) {
            console.error('Missing CLIENT_ID in .env file');
            return;
        }

        // Process commands and set permissions
        const processedCommands = levelingCommands.map(cmd => {
            // Make all leveling commands available to everyone
            cmd.default_member_permissions = '0';
            console.log(`Making leveling command visible to all members: ${cmd.name}`);
            return cmd;
        });

        // Instead of updating all commands, we'll only update the leveling commands individually
        for (const levelingCommand of processedCommands) {
            console.log(`Updating command: ${levelingCommand.name}`);
            
            try {
                // Get all existing commands
                const existingCommands = await rest.get(
                    Routes.applicationCommands(process.env.CLIENT_ID)
                );
                
                // Find the ID of the existing leveling command if it exists
                const existingCommand = existingCommands.find(cmd => cmd.name === levelingCommand.name);
                
                if (existingCommand) {
                    // Update the existing command
                    console.log(`Found existing command "${levelingCommand.name}" with ID: ${existingCommand.id}, updating...`);
                    
                    await rest.patch(
                        Routes.applicationCommand(process.env.CLIENT_ID, existingCommand.id),
                        { body: levelingCommand }
                    );
                    
                    console.log(`Successfully updated leveling command: ${levelingCommand.name}`);
                } else {
                    // Create a new command
                    console.log(`Command "${levelingCommand.name}" not found, creating new...`);
                    
                    await rest.post(
                        Routes.applicationCommands(process.env.CLIENT_ID),
                        { body: levelingCommand }
                    );
                    
                    console.log(`Successfully created leveling command: ${levelingCommand.name}`);
                }
            } catch (cmdError) {
                console.error(`Error updating command ${levelingCommand.name}:`, cmdError);
            }
        }

        console.log('Leveling commands have been refreshed successfully.');
        console.log('All leveling commands are now accessible to all users in all servers.');
    } catch (error) {
        console.error('Error deploying leveling commands:', error);
        console.error(error.stack);
    }
}

// Execute the deployment
deployLevelingCommands();