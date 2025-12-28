require('dotenv').config();
const { Client, GatewayIntentBits } = require('discord.js');

// Create a simple client with minimal intents
const client = new Client({
    intents: [GatewayIntentBits.Guilds]
});

// Log when we're ready
client.once('ready', () => {
    console.log(`Bot is ready! Logged in as ${client.user.tag}`);
    console.log(`Bot ID: ${client.user.id}`);
    console.log(`Bot is in ${client.guilds.cache.size} servers`);
    
    // List all servers the bot is in
    console.log('\nServers:');
    client.guilds.cache.forEach(guild => {
        console.log(`- ${guild.name} (${guild.id})`);
    });
    
    // Exit after successfully connecting
    console.log('\nTest successful! The token is valid.');
    setTimeout(() => {
        client.destroy();
        process.exit(0);
    }, 1000);
});

// Log any errors
client.on('error', error => {
    console.error('Discord client error:', error);
    process.exit(1);
});

// Log the token length and format (without revealing the actual token)
const token = process.env.DISCORD_TOKEN;
if (!token) {
    console.error('ERROR: No token found in .env file');
    process.exit(1);
}

console.log(`Token length: ${token.length}`);
console.log(`Token format check: ${token.includes('.')} (should be true)`);

// Attempt to login
console.log('Attempting to connect to Discord...');
client.login(token).catch(error => {
    console.error('Login failed:', error.message);
    process.exit(1);
});