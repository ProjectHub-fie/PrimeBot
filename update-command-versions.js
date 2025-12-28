/**
 * Script to update all slash command files with version information from config
 * 
 * This script will modify all command files to include version information
 * in their embed footers and ensure consistency across all commands.
 */

const fs = require('fs');
const path = require('path');
const config = require('./config');

// Path to commands directory
const commandsDir = path.join(__dirname, 'commands');

// Get all command files
const commandFiles = fs.readdirSync(commandsDir).filter(file => file.endsWith('.js'));

console.log(`===== UPDATING COMMAND VERSIONS =====`);
console.log(`Found ${commandFiles.length} command files to process`);
console.log(`Bot Version: ${config.version} (${config.buildDate})\n`);

let updatedCount = 0;

// Process each command file
for (const file of commandFiles) {
    const filePath = path.join(commandsDir, file);
    
    try {
        // Read the file content
        let content = fs.readFileSync(filePath, 'utf8');
        
        // Skip if file doesn't contain SlashCommandBuilder
        if (!content.includes('SlashCommandBuilder')) {
            console.log(`❌ Skipping ${file}: Not a slash command`);
            continue;
        }
        
        // Add config import if missing
        if (!content.includes("require('../config')")) {
            // Find the first require statement position
            const requireMatch = content.match(/const\s+{[^}]+}\s+=\s+require\(['"][^'"]+['"]\);/);
            if (requireMatch) {
                const insertPosition = content.indexOf(requireMatch[0]) + requireMatch[0].length;
                content = content.slice(0, insertPosition) + 
                         `\nconst config = require('../config');` + 
                         content.slice(insertPosition);
            } else {
                // Insert at the beginning after existing requires
                const lines = content.split('\n');
                let insertIndex = 0;
                for (let i = 0; i < lines.length; i++) {
                    if (lines[i].trim().startsWith('const') || lines[i].trim().startsWith('require')) {
                        insertIndex = i + 1;
                    } else if (lines[i].trim() === '') {
                        continue;
                    } else {
                        break;
                    }
                }
                lines.splice(insertIndex, 0, "const config = require('../config');");
                content = lines.join('\n');
            }
        }
        
        // Update embed footers to include version information
        // Pattern to match .setFooter({ text: 'something' }) or .setFooter({ text: 'something', iconURL: 'url' })
        const footerPattern = /\.setFooter\(\{\s*text:\s*['"`]([^'"`]*?)['"`](?:\s*,\s*iconURL:\s*[^}]+)?\s*\}\)/g;
        
        let hasFooterUpdates = false;
        content = content.replace(footerPattern, (match, footerText) => {
            // Don't update if it already contains version info
            if (footerText.includes('Version') || footerText.includes(config.version)) {
                return match;
            }
            
            hasFooterUpdates = true;
            
            // Extract iconURL if present
            const iconMatch = match.match(/iconURL:\s*([^}]+)/);
            const iconPart = iconMatch ? `, iconURL: ${iconMatch[1]}` : '';
            
            // Add version to footer text
            const newFooterText = `${footerText} • Version ${config.version}`;
            return `.setFooter({ text: '${newFooterText}'${iconPart} })`;
        });
        
        // For embeds without footers, add version footer
        // Look for embeds that end with .setTimestamp() but don't have .setFooter()
        const embedPattern = /(new EmbedBuilder\(\)[^;]*?)\.setTimestamp\(\)/g;
        content = content.replace(embedPattern, (match, embedContent) => {
            // Skip if this embed already has a footer
            if (embedContent.includes('.setFooter(')) {
                return match;
            }
            
            hasFooterUpdates = true;
            return `${embedContent}.setFooter({ text: 'Version ${config.version}', iconURL: this.client?.user?.displayAvatarURL() || client?.user?.displayAvatarURL() }).setTimestamp()`;
        });
        
        // Also handle embeds that don't have setTimestamp
        const embedPattern2 = /(new EmbedBuilder\(\)[^;]*?)(?=;|\n|$)/g;
        content = content.replace(embedPattern2, (match, embedContent) => {
            // Skip if this embed already has a footer or setTimestamp
            if (embedContent.includes('.setFooter(') || embedContent.includes('.setTimestamp()')) {
                return match;
            }
            
            // Only add footer to embeds that have substantial content
            if (embedContent.includes('.setTitle(') || embedContent.includes('.setDescription(')) {
                hasFooterUpdates = true;
                return `${embedContent}.setFooter({ text: 'Version ${config.version}' })`;
            }
            
            return match;
        });
        
        // Write the updated content back to file
        if (hasFooterUpdates || !content.includes("require('../config')")) {
            fs.writeFileSync(filePath, content, 'utf8');
            console.log(`✅ Updated ${file}`);
            updatedCount++;
        } else {
            console.log(`⏭️ Skipped ${file}: Already up to date`);
        }
        
    } catch (error) {
        console.log(`❌ Error processing ${file}: ${error.message}`);
    }
}

console.log(`\n===== UPDATE COMPLETE =====`);
console.log(`Updated ${updatedCount} command files`);
console.log(`All commands now include version ${config.version}`);