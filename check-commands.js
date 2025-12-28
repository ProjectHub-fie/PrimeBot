/**
 * Script to check and identify issues with command loading
 */

const fs = require('fs');
const path = require('path');

// Path to the commands directory
const commandsPath = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));

console.log('===== COMMAND VALIDATION CHECK =====');
console.log(`Found ${commandFiles.length} command files\n`);

// Track valid and problematic commands
const validCommands = [];
const problematicCommands = [];

// Check each command file
for (const file of commandFiles) {
    const filePath = path.join(commandsPath, file);
    
    try {
        // Try to require the command
        const command = require(filePath);
        
        // Check if it has the required properties
        const hasData = 'data' in command;
        const hasExecute = 'execute' in command && typeof command.execute === 'function';
        
        if (hasData && hasExecute) {
            // Command is valid
            validCommands.push({
                file,
                name: command.data.name
            });
        } else {
            // Command is missing required properties
            problematicCommands.push({
                file,
                issues: [
                    !hasData ? 'Missing data property' : null,
                    !hasExecute ? 'Missing execute function' : null
                ].filter(Boolean)
            });
        }
    } catch (error) {
        // Command has a syntax error or other issue
        problematicCommands.push({
            file,
            issues: [`Failed to load: ${error.message}`]
        });
    }
}

// Output results
console.log('VALID COMMANDS:');
validCommands.forEach(cmd => {
    console.log(`✓ ${cmd.file} -> ${cmd.name}`);
});

if (problematicCommands.length > 0) {
    console.log('\nPROBLEMATIC COMMANDS:');
    problematicCommands.forEach(cmd => {
        console.log(`✗ ${cmd.file}:`);
        cmd.issues.forEach(issue => console.log(`  - ${issue}`));
    });
}

console.log('\n===== COMMAND STATUS SUMMARY =====');
console.log(`Total command files: ${commandFiles.length}`);
console.log(`Valid commands: ${validCommands.length}`);
console.log(`Problematic commands: ${problematicCommands.length}`);

// Look for any duplicated command names
const commandNames = validCommands.map(cmd => cmd.name);
const duplicateNames = commandNames.filter((name, index) => commandNames.indexOf(name) !== index);

if (duplicateNames.length > 0) {
    console.log('\n⚠️ DUPLICATE COMMAND NAMES:');
    duplicateNames.forEach(name => {
        const dupes = validCommands.filter(cmd => cmd.name === name);
        console.log(`Command "${name}" is defined in multiple files:`);
        dupes.forEach(cmd => console.log(`  - ${cmd.file}`));
    });
}

// List any SlashCommandBuilder issues
console.log('\nCHECKING SLASHCOMMANDBUILDER CONFIGURATIONS...');

for (const file of commandFiles) {
    const filePath = path.join(commandsPath, file);
    
    try {
        const command = require(filePath);
        
        // Skip if command doesn't have data
        if (!('data' in command)) continue;
        
        // Check for .setDefaultMemberPermissions positioning
        const commandSource = fs.readFileSync(filePath, 'utf8');
        const hasPermissionsProperty = commandSource.includes('.setDefaultMemberPermissions');
        
        if (hasPermissionsProperty && file !== 'echo.js') {
            // Check if it's correctly positioned
            const descriptionLineMatch = commandSource.match(/\.setDescription\([^)]+\)/);
            const permissionsLineMatch = commandSource.match(/\.setDefaultMemberPermissions\([^)]+\)/);
            
            if (descriptionLineMatch && permissionsLineMatch) {
                const descriptionIndex = commandSource.indexOf(descriptionLineMatch[0]);
                const permissionsIndex = commandSource.indexOf(permissionsLineMatch[0]);
                
                if (permissionsIndex < descriptionIndex) {
                    console.log(`⚠️ ${file}: setDefaultMemberPermissions is positioned before setDescription`);
                }
                
                // Check if positioned between add options
                const optionMatch = commandSource.match(/\.addStringOption|\.addChannelOption|\.addBooleanOption|\.addNumberOption|\.addRoleOption|\.addUserOption|\.addMentionableOption|\.addIntegerOption|\.addAttachmentOption/);
                
                if (optionMatch) {
                    const optionIndex = commandSource.indexOf(optionMatch[0]);
                    if (permissionsIndex > optionIndex) {
                        console.log(`⚠️ ${file}: setDefaultMemberPermissions is positioned after option definitions`);
                    }
                }
            }
        } else if (file !== 'echo.js') {
            console.log(`⚠️ ${file}: Missing setDefaultMemberPermissions`);
        }
        
    } catch (error) {
        // Skip files with errors, they were already reported
    }
}

console.log('\n===== CHECK COMPLETE =====');