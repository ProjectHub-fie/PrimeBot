/**
 * Script to update all command files with SendMessages permission
 * 
 * This script will modify all command files to add the SendMessages permission
 * except for the echo command which already handles its own permissions.
 */

const fs = require('fs');
const path = require('path');

// Path to the commands directory
const commandsPath = path.join(__dirname, 'commands');

// Get all command files
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));

console.log('===== UPDATING COMMAND PERMISSIONS =====');

for (const file of commandFiles) {
    // Skip the echo command - it has its own permission handling
    if (file === 'echo.js') {
        console.log(`SKIPPING: ${file} (Handles its own permissions)`);
        continue;
    }
    
    const filePath = path.join(commandsPath, file);
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Check if the file already imports PermissionFlagsBits
    const hasPermissionImport = content.includes('PermissionFlagsBits');
    
    // Add PermissionFlagsBits to imports if not already there
    if (!hasPermissionImport) {
        // Replace the first require line that imports from discord.js
        content = content.replace(
            /const \{([^}]*)\} = require\('discord\.js'\);/,
            "const {$1, PermissionFlagsBits} = require('discord.js');"
        );
    }
    
    // Check if setDefaultMemberPermissions is already set
    const hasSetDefaultMemberPermissions = content.includes('setDefaultMemberPermissions');
    
    if (!hasSetDefaultMemberPermissions) {
        // First remove any misplaced setDefaultMemberPermissions
        content = content.replace(/\.setDefaultMemberPermissions\(PermissionFlagsBits\.SendMessages\)/g, '');
        
        // Add setDefaultMemberPermissions right after the description, before any option definitions
        content = content.replace(
            /(\.setName\(['"].*['"]\)[^,]*\.setDescription\(['"].*['"]\))/,
            "$1\n        .setDefaultMemberPermissions(PermissionFlagsBits.SendMessages)"
        );
    }
    
    // Write the updated content back to the file
    fs.writeFileSync(filePath, content);
    console.log(`UPDATED: ${file} - Added SendMessages permission`);
}

console.log('===== COMMAND PERMISSIONS UPDATE COMPLETE =====');