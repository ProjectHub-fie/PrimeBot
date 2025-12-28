/**
 * Script to fix all slash command files with proper version information
 * 
 * This script will add config imports and version footers to all commands
 * that are missing them, ensuring complete consistency.
 */

const fs = require('fs');
const path = require('path');
const config = require('./config');

// Path to commands directory
const commandsDir = path.join(__dirname, 'commands');

// Get all command files
const commandFiles = fs.readdirSync(commandsDir).filter(file => file.endsWith('.js'));

console.log(`===== FIXING ALL COMMAND VERSIONS =====`);
console.log(`Processing ${commandFiles.length} command files`);
console.log(`Target Version: ${config.version} (${config.buildDate})\n`);

let fixedCount = 0;

// Process each command file
for (const file of commandFiles) {
    const filePath = path.join(commandsDir, file);
    
    try {
        // Read the file content
        let content = fs.readFileSync(filePath, 'utf8');
        let hasChanges = false;
        
        // Skip if file doesn't contain SlashCommandBuilder
        if (!content.includes('SlashCommandBuilder')) {
            console.log(`⏭️ Skipped ${file}: Not a slash command`);
            continue;
        }
        
        // Add config import if missing
        if (!content.includes("require('../config')")) {
            // Find the first require statement position
            const requireMatches = content.match(/const\s+{[^}]+}\s+=\s+require\(['"][^'"]+['"]\);/g);
            if (requireMatches && requireMatches.length > 0) {
                const lastRequire = requireMatches[requireMatches.length - 1];
                const insertPosition = content.indexOf(lastRequire) + lastRequire.length;
                content = content.slice(0, insertPosition) + 
                         `\nconst config = require('../config');` + 
                         content.slice(insertPosition);
                hasChanges = true;
            }
        }
        
        // Find all EmbedBuilder instances and add version footers where missing
        const embedBuilderPattern = /new EmbedBuilder\(\)/g;
        let embedMatches = [];
        let match;
        
        while ((match = embedBuilderPattern.exec(content)) !== null) {
            embedMatches.push(match.index);
        }
        
        // Process each embed from the end to avoid index shifting
        for (let i = embedMatches.length - 1; i >= 0; i--) {
            const embedStart = embedMatches[i];
            
            // Find the end of this embed (next semicolon or assignment)
            let embedEnd = content.indexOf(';', embedStart);
            if (embedEnd === -1) {
                embedEnd = content.length;
            }
            
            const embedContent = content.slice(embedStart, embedEnd);
            
            // Check if this embed already has a footer or version
            if (embedContent.includes('.setFooter(') || 
                embedContent.includes('Version') || 
                embedContent.includes('config.version')) {
                continue;
            }
            
            // Check if this embed has substantial content (title or description)
            if (!embedContent.includes('.setTitle(') && !embedContent.includes('.setDescription(')) {
                continue;
            }
            
            // Add version footer before the semicolon
            let footerAddition;
            if (embedContent.includes('.setTimestamp()')) {
                // Replace setTimestamp with footer + setTimestamp
                const newEmbedContent = embedContent.replace(
                    '.setTimestamp()',
                    `.setFooter({ text: 'Version ${config.version}' }).setTimestamp()`
                );
                content = content.slice(0, embedStart) + newEmbedContent + content.slice(embedEnd);
            } else {
                // Add footer at the end
                const insertPoint = embedEnd;
                footerAddition = `.setFooter({ text: 'Version ${config.version}' })`;
                content = content.slice(0, insertPoint) + footerAddition + content.slice(insertPoint);
            }
            
            hasChanges = true;
        }
        
        // Fix any hardcoded old versions
        const oldVersionPattern = /Version\s+\d+\.\d+\.\d+/g;
        content = content.replace(oldVersionPattern, (match) => {
            if (!match.includes(config.version)) {
                hasChanges = true;
                return `Version ${config.version}`;
            }
            return match;
        });
        
        // Write the updated content back to file
        if (hasChanges) {
            fs.writeFileSync(filePath, content, 'utf8');
            console.log(`✅ Fixed ${file}`);
            fixedCount++;
        } else {
            console.log(`✅ ${file}: Already up to date`);
        }
        
    } catch (error) {
        console.log(`❌ Error processing ${file}: ${error.message}`);
    }
}

console.log(`\n===== FIX COMPLETE =====`);
console.log(`Fixed ${fixedCount} command files`);
console.log(`All commands should now include version ${config.version}`);