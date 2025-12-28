const { REST, Routes, PermissionFlagsBits } = require('discord.js');
const fs = require('fs');
const path = require('path');

// Directly read from .env file and set environment variables
try {
    const envFile = fs.readFileSync('.env', 'utf8');
    const envVars = envFile.split('\n');
    
    for (const line of envVars) {
        // Skip comments and empty lines
        if (line.startsWith('#') || line.trim() === '') continue;
        
        // Parse key-value pairs
        const match = line.match(/^([^=]+)=(.*)$/);
        if (match) {
            const key = match[1].trim();
            const value = match[2].trim();
            process.env[key] = value;
            console.log(`Set environment variable: ${key}`);
        }
    }
} catch (error) {
    console.error('Error loading .env file manually:', error.message);
}

// Verify environment variables
console.log("Environment variables loaded:");
console.log("CLIENT_ID:", process.env.CLIENT_ID || "Not found");
console.log("DISCORD_TOKEN:", process.env.DISCORD_TOKEN ? "Found (redacted)" : "Not found");

// Get command files
const commandsPath = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));

const commands = [];

// Load command data
for (const file of commandFiles) {
    const filePath = path.join(commandsPath, file);
    const command = require(filePath);
    
    if ('data' in command && 'execute' in command) {
        commands.push(command.data.toJSON());
        console.log(`Loaded command: ${command.data.name}`);
    } else {
        console.log(`[WARNING] The command at ${filePath} is missing required "data" or "execute" property.`);
    }
}

// Configure REST for deployment
const rest = new REST().setToken(process.env.DISCORD_TOKEN);

// Deploy commands function
async function deployCommands() {
    try {
        console.log(`Started refreshing ${commands.length} application (/) commands.`);

        // Check if we have a CLIENT_ID
        if (!process.env.CLIENT_ID) {
            console.error('Missing CLIENT_ID in .env file');
            return;
        }

        // Global deployment (for all servers the bot is in)
        // Process commands and set permissions
        const processedCommands = commands.map(cmd => {
            // Make all commands available to everyone (except echo which handles its own permissions)
            if (cmd.name !== 'echo') {
                // Set default_member_permissions to '0' (available to everyone)
                cmd.default_member_permissions = '0';
                console.log(`Making command visible to all members: ${cmd.name}`);
            } else {
                console.log(`Skipping permission update for command: ${cmd.name} (handled in command file)`);
            }
            
            return cmd;
        });

        const data = await rest.put(
            Routes.applicationCommands(process.env.CLIENT_ID),
            { body: processedCommands },
        );

        console.log(`Successfully reloaded ${data.length} application (/) commands.`);
        console.log(`All commands are now accessible to all users in all servers.`);
    } catch (error) {
        console.error('Error deploying commands:', error);
    }
}

// Execute the deployment
deployCommands();