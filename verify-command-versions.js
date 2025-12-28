/**
 * Script to verify all slash command files have proper version information
 * 
 * This script checks that all commands include version information consistently
 * and reports any issues found.
 */

const fs = require('fs');
const path = require('path');
const config = require('./config');

// Path to commands directory
const commandsDir = path.join(__dirname, 'commands');

// Get all command files
const commandFiles = fs.readdirSync(commandsDir).filter(file => file.endsWith('.js'));

console.log(`===== VERIFYING COMMAND VERSIONS =====`);
console.log(`Checking ${commandFiles.length} command files`);
console.log(`Expected Version: ${config.version} (${config.buildDate})\n`);

let validCount = 0;
let issueCount = 0;
const issues = [];

// Process each command file
for (const file of commandFiles) {
    const filePath = path.join(commandsDir, file);
    
    try {
        // Read the file content
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Skip if file doesn't contain SlashCommandBuilder
        if (!content.includes('SlashCommandBuilder')) {
            console.log(`⏭️ Skipped ${file}: Not a slash command`);
            continue;
        }
        
        const fileIssues = [];
        
        // Check if config is imported
        if (!content.includes("require('../config')")) {
            fileIssues.push('Missing config import');
        }
        
        // Check if version is referenced
        if (!content.includes('config.version') && !content.includes(config.version)) {
            fileIssues.push('Version not referenced in code');
        }
        
        // Check for version in footers
        const hasVersionFooter = content.includes(`Version ${config.version}`) || 
                                content.includes('config.version');
        
        if (!hasVersionFooter) {
            fileIssues.push('Version not found in embed footers');
        }
        
        // Check for hardcoded old versions
        const oldVersionPattern = /Version\s+\d+\.\d+\.\d+/g;
        const versionMatches = content.match(oldVersionPattern);
        if (versionMatches) {
            for (const match of versionMatches) {
                if (!match.includes(config.version) && !match.includes('config.version')) {
                    fileIssues.push(`Hardcoded version found: ${match}`);
                }
            }
        }
        
        if (fileIssues.length === 0) {
            console.log(`✅ ${file}: All checks passed`);
            validCount++;
        } else {
            console.log(`❌ ${file}: ${fileIssues.join(', ')}`);
            issues.push({ file, issues: fileIssues });
            issueCount++;
        }
        
    } catch (error) {
        console.log(`❌ Error processing ${file}: ${error.message}`);
        issues.push({ file, issues: [`Error: ${error.message}`] });
        issueCount++;
    }
}

console.log(`\n===== VERIFICATION COMPLETE =====`);
console.log(`✅ Valid commands: ${validCount}`);
console.log(`❌ Commands with issues: ${issueCount}`);

if (issues.length > 0) {
    console.log(`\n===== DETAILED ISSUES =====`);
    issues.forEach(({ file, issues }) => {
        console.log(`\n${file}:`);
        issues.forEach(issue => console.log(`  • ${issue}`));
    });
}

console.log(`\n✅ Verification complete for version ${config.version}`);