const { REST, Routes, PermissionFlagsBits } = require('discord.js');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { resolveDiscordToken } = require('./utils/tokenResolver');

// Load .env if it exists (Replit secrets are already in process.env)
dotenv.config();

// Try to read CLIENT_ID from .env file as a fallback
let manualClientId = null;
try {
    const envContent = fs.readFileSync('.env', 'utf8');
    const clientIdMatch = envContent.match(/CLIENT_ID=([^\s\r\n]+)/);
    if (clientIdMatch && clientIdMatch[1]) {
        manualClientId = clientIdMatch[1];
        console.log("Manually found CLIENT_ID:", manualClientId);
    }
} catch {
    // No .env file — rely on environment secrets
}

const manualToken = resolveDiscordToken();
process.env.DISCORD_TOKEN = manualToken || process.env.DISCORD_TOKEN;

// Derive the client ID from the token itself (most reliable)
function clientIdFromToken(token) {
    try {
        return Buffer.from(token.split('.')[0], 'base64').toString('utf8');
    } catch { return null; }
}
const derivedClientId = process.env.DISCORD_TOKEN ? clientIdFromToken(process.env.DISCORD_TOKEN) : null;
process.env.CLIENT_ID = derivedClientId || process.env.CLIENT_ID || process.env.DISCORD_CLIENT_ID || manualClientId;

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

        // Discord requires any existing "Entry Point" commands (e.g. Activities launch
        // commands, type 4) to be included in a bulk overwrite, or the request is rejected.
        const existingCommands = await rest.get(
            Routes.applicationCommands(process.env.CLIENT_ID),
        );
        const entryPointCommands = existingCommands.filter(cmd => cmd.type === 4);
        if (entryPointCommands.length > 0) {
            console.log(`Preserving ${entryPointCommands.length} Entry Point command(s) in bulk update.`);
        }

        const data = await rest.put(
            Routes.applicationCommands(process.env.CLIENT_ID),
            { body: [...processedCommands, ...entryPointCommands] },
        );

        console.log(`Successfully reloaded ${data.length} application (/) commands.`);
        console.log(`All commands are now accessible to all users in all servers.`);
    } catch (error) {
        console.error('Error deploying commands:', error);
    }
}

// Execute the deployment
deployCommands();