/**
 * Script to update all command files to be visible to everyone in servers
 * 
 * This script will modify all command files to remove or set the permission 
 * to '0' (available to everyone) except for the echo command which 
 * already handles its own permissions.
 */

const fs = require('fs');
const path = require('path');

// Path to commands directory
const commandsDir = path.join(__dirname, 'commands');

// Get all command files
const commandFiles = fs.readdirSync(commandsDir).filter(file => file.endsWith('.js'));

console.log(`===== UPDATING COMMAND VISIBILITY =====`);
console.log(`Found ${commandFiles.length} command files to process\n`);

let updatedCount = 0;
let skippedCount = 0;

// Process each command file
for (const file of commandFiles) {
    if (file === 'echo.js') {
        console.log(`⏩ Skipping echo.js (handles its own permissions)`);
        skippedCount++;
        continue;
    }
    
    const filePath = path.join(commandsDir, file);
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Remove any existing setDefaultMemberPermissions calls
    if (content.includes('.setDefaultMemberPermissions')) {
        // Replace with permissions set to 0 (everyone can use)
        content = content.replace(
            /.setDefaultMemberPermissions\([^)]+\)/g, 
            ''
        );
        
        fs.writeFileSync(filePath, content, 'utf8');
        console.log(`✅ Updated ${file} - Removed permission restrictions`);
        updatedCount++;
    } else {
        console.log(`⏭️ No permission changes needed for ${file}`);
        skippedCount++;
    }
}

console.log(`\n===== UPDATE COMPLETE =====`);
console.log(`Total files processed: ${commandFiles.length}`);
console.log(`Files updated: ${updatedCount}`);
console.log(`Files skipped: ${skippedCount}`);
console.log(`\nCommands will now be available to all server members when deployed.`);
console.log(`Run 'node deploy-commands.js' to update the bot commands.`);