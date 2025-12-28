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
process.env.CLIENT_ID = process.env.CLIENT_ID || manualClientId || '1356575287151951943';
process.env.DISCORD_TOKEN = process.env.DISCORD_TOKEN || manualToken;

// Print environment variables to debug
console.log("Using CLIENT_ID:", process.env.CLIENT_ID ? "✓ Found" : "✗ Missing");
console.log("Using DISCORD_TOKEN:", process.env.DISCORD_TOKEN ? "✓ Found" : "✗ Missing");

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