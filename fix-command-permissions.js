/**
 * Script to fix permissions in command files
 * This will add setDefaultMemberPermissions('0') to all command files that don't have it
 */

const fs = require('fs');
const path = require('path');

// Path to the commands directory
const commandsPath = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));

console.log('===== FIXING SLASH COMMAND PERMISSIONS =====');

let fixedCount = 0;
let skippedCount = 0;

for (const file of commandFiles) {
    // Skip echo.js which should handle its own permissions
    if (file === 'echo.js') {
        console.log(`⏩ Skipping ${file} (handles its own permissions)`);
        skippedCount++;
        continue;
    }
    
    const filePath = path.join(commandsPath, file);
    
    try {
        // Read the file content
        let content = fs.readFileSync(filePath, 'utf8');
        
        // Check if setDefaultMemberPermissions is already present
        if (content.includes('.setDefaultMemberPermissions')) {
            console.log(`✓ Skipping ${file} (already has permissions set)`);
            skippedCount++;
            continue;
        }
        
        // Find where to insert the permissions
        // We want to add it after setDescription() but before any options
        const descriptionMatch = content.match(/\.setDescription\(['"`][^'"`]+['"`]\)/);
        
        if (!descriptionMatch) {
            console.log(`⚠️ Could not find setDescription in ${file}, skipping`);
            skippedCount++;
            continue;
        }
        
        const descriptionLine = descriptionMatch[0];
        const insertIndex = content.indexOf(descriptionLine) + descriptionLine.length;
        
        // Insert the permissions line
        const beforeInsert = content.substring(0, insertIndex);
        const afterInsert = content.substring(insertIndex);
        const newContent = beforeInsert + '\n\t\t.setDefaultMemberPermissions(\'0\')' + afterInsert;
        
        // Write the updated content back to the file
        fs.writeFileSync(filePath, newContent, 'utf8');
        
        console.log(`✅ Added permissions to ${file}`);
        fixedCount++;
        
    } catch (error) {
        console.error(`❌ Error processing ${file}:`, error.message);
        skippedCount++;
    }
}

console.log('\n===== PERMISSIONS FIX SUMMARY =====');
console.log(`Total files checked: ${commandFiles.length}`);
console.log(`Files fixed: ${fixedCount}`);
console.log(`Files skipped: ${skippedCount}`);
console.log('===== FIX COMPLETE =====');