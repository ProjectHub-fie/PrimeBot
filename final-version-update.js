/**
 * Final script to ensure all commands have version information
 * Handles edge cases and different command structures
 */

const fs = require('fs');
const path = require('path');
const config = require('./config');

const commandsDir = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsDir).filter(file => file.endsWith('.js'));

const problematicFiles = [
    'counting.js', 'createticket.js', 'end.js', 'endgame.js', 
    'move.js', 'reroll.js', 'ticket.js', 'tictactoe.js', 'truthdare.js'
];

console.log(`===== FINAL VERSION UPDATE =====`);
console.log(`Targeting ${problematicFiles.length} remaining commands\n`);

for (const file of problematicFiles) {
    const filePath = path.join(commandsDir, file);
    
    try {
        let content = fs.readFileSync(filePath, 'utf8');
        let hasChanges = false;
        
        // Add version to any interaction.reply that uses embeds
        const replyEmbedPattern = /interaction\.reply\(\s*{\s*embeds:\s*\[([^\]]+)\]/g;
        content = content.replace(replyEmbedPattern, (match, embedContent) => {
            if (!embedContent.includes('setFooter') && embedContent.includes('EmbedBuilder')) {
                hasChanges = true;
                // Find the embed variable and add footer
                const embedVar = embedContent.trim();
                return match.replace(embedVar, `${embedVar}.setFooter({ text: 'Version ${config.version}' })`);
            }
            return match;
        });
        
        // Add version to any embeds that don't have footers
        const embedAssignPattern = /const\s+(\w+)\s*=\s*new\s+EmbedBuilder\(\)[^;]*;/g;
        content = content.replace(embedAssignPattern, (match, embedVar) => {
            if (!match.includes('setFooter') && (match.includes('setTitle') || match.includes('setDescription'))) {
                hasChanges = true;
                return match.replace(';', `.setFooter({ text: 'Version ${config.version}' });`);
            }
            return match;
        });
        
        // For simple commands without embeds, add version comment
        if (!content.includes('EmbedBuilder') && !content.includes('Version')) {
            // Add version comment at the top of execute function
            const executePattern = /(async execute\(interaction\) {)/;
            content = content.replace(executePattern, `$1\n        // Command version: ${config.version}`);
            hasChanges = true;
        }
        
        if (hasChanges) {
            fs.writeFileSync(filePath, content, 'utf8');
            console.log(`✅ Updated ${file}`);
        } else {
            console.log(`⏭️ No changes needed for ${file}`);
        }
        
    } catch (error) {
        console.log(`❌ Error processing ${file}: ${error.message}`);
    }
}

console.log(`\n===== FINAL UPDATE COMPLETE =====`);