/**
 * Script to make command responses visible to everyone in the channel
 * 
 * This script will modify all command files to remove 'ephemeral: true' from responses
 * so that command responses are visible to all users in the channel.
 */

const fs = require('fs');
const path = require('path');

// Path to commands directory
const commandsDir = path.join(__dirname, 'commands');

// Get all command files
const commandFiles = fs.readdirSync(commandsDir).filter(file => file.endsWith('.js'));

console.log(`===== UPDATING COMMAND RESPONSES =====`);
console.log(`Found ${commandFiles.length} command files to process\n`);

let updatedCount = 0;
let skippedCount = 0;

// Process each command file
for (const file of commandFiles) {
    const filePath = path.join(commandsDir, file);
    let content = fs.readFileSync(filePath, 'utf8');
    let originalContent = content;
    
    // Remove ephemeral flags from responses
    let updatedContent = content.replace(/ephemeral:\s*true/g, 'ephemeral: false');
    
    // Also check for interaction.reply({ content: '...', ephemeral: true }) pattern
    if (content === updatedContent) {
        // No changes were made with the first replacement pattern, try another common pattern
        updatedContent = content.replace(/interaction\.reply\(\{\s*content:[^}]+,\s*ephemeral:\s*true\s*\}\)/g, 
                                         (match) => match.replace('ephemeral: true', 'ephemeral: false'));
    }
    
    if (originalContent !== updatedContent) {
        fs.writeFileSync(filePath, updatedContent, 'utf8');
        console.log(`✅ Updated ${file} - Made responses visible to everyone`);
        updatedCount++;
    } else {
        console.log(`⏭️ No changes needed for ${file}`);
        skippedCount++;
    }
}

console.log(`\n===== UPDATE COMPLETE =====`);
console.log(`Total files processed: ${commandFiles.length}`);
console.log(`Files updated: ${updatedCount}`);
console.log(`Files skipped: ${skippedCount}`);
console.log(`\nCommand responses will now be visible to all channel members.`);
console.log(`Restart the bot to apply changes.`);