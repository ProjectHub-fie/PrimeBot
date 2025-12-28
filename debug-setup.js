/**
 * Debug setup script for Discord bot
 * 
 * This script sets up proper debug configuration for the bot.
 * It uses the debug npm package to provide flexible debug logging.
 */

const fs = require('fs');
const path = require('path');

console.log(`===== SETTING UP DEBUG CONFIGURATION =====`);

// 1. Add script to package.json
const packageJsonPath = path.join(__dirname, 'package.json');
let packageJson;

try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    
    // Add debug scripts
    packageJson.scripts = packageJson.scripts || {};
    packageJson.scripts.start = "node index.js";
    packageJson.scripts.debug = "DEBUG=bot:* node index.js";
    packageJson.scripts.debugall = "DEBUG=* node index.js";
    
    // Write updated package.json
    fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2), 'utf8');
    console.log('✅ Updated package.json with debug scripts');
} catch (error) {
    console.error('❌ Error updating package.json:', error);
}

// 2. Update .env with DEBUG settings
const envPath = path.join(__dirname, '.env');
let envContent = '';

try {
    if (fs.existsSync(envPath)) {
        envContent = fs.readFileSync(envPath, 'utf8');
    }
    
    // Check if DEBUG is already set
    if (!envContent.includes('DEBUG=')) {
        // Add DEBUG environment variable
        envContent += '\n# Debug settings (uncomment to enable)\n# DEBUG=bot:*\n';
        fs.writeFileSync(envPath, envContent, 'utf8');
        console.log('✅ Added DEBUG configuration to .env file');
    } else {
        console.log('ℹ️ DEBUG configuration already exists in .env file');
    }
} catch (error) {
    console.error('❌ Error updating .env file:', error);
}

// 3. Create debug utility
const debugUtilPath = path.join(__dirname, 'utils', 'debugUtils.js');

try {
    const debugUtilContent = `/**
 * Debug utilities for the Discord bot
 * 
 * This module provides convenience functions for debugging using the debug package.
 */

const debug = {
    main: require('debug')('bot:main'),
    commands: require('debug')('bot:commands'),
    events: require('debug')('bot:events'),
    utils: require('debug')('bot:utils'),
    website: require('debug')('bot:website'),
    error: require('debug')('bot:error')
};

// Set error to also output to stderr
debug.error.log = console.error.bind(console);

/**
 * Log a message with the appropriate debug namespace
 * @param {string} namespace - Debug namespace (main, commands, events, utils, website, error)
 * @param {string} message - Message to log
 * @param {any} [data] - Optional data to log
 */
function log(namespace, message, data) {
    if (debug[namespace]) {
        if (data) {
            debug[namespace](message, data);
        } else {
            debug[namespace](message);
        }
    }
}

module.exports = {
    debug,
    log
};
`;

    fs.writeFileSync(debugUtilPath, debugUtilContent, 'utf8');
    console.log('✅ Created debug utilities in utils/debugUtils.js');
} catch (error) {
    console.error('❌ Error creating debug utilities:', error);
}

// 4. Fix website error logging
const websiteJsPath = path.join(__dirname, 'website.js');
let websiteJs = '';

try {
    if (fs.existsSync(websiteJsPath)) {
        websiteJs = fs.readFileSync(websiteJsPath, 'utf8');
        
        // Add debug import
        if (!websiteJs.includes('debugUtils')) {
            websiteJs = "const { log } = require('./utils/debugUtils');\n" + websiteJs;
            
            // Add error handling for bot info
            websiteJs = websiteJs.replace(
                'app.use((req, res, next) => {',
                'app.use((req, res, next) => {\n    try {'
            );
            
            websiteJs = websiteJs.replace(
                '    next();',
                '    } catch (error) {\n        log(\'error\', \'Error setting up bot info middleware:\', error);\n        res.locals.botInfo = {\n            name: \'AFK Devs Bot\',\n            prefix: \'/\',\n            servers: \'Offline\',\n            commands: [],\n            uptime: \'Offline\'\n        };\n    }\n    next();'
            );
            
            // Fix API endpoint
            websiteJs = websiteJs.replace(
                'app.get(\'/api/botinfo\', (req, res) => {',
                'app.get(\'/api/botinfo\', (req, res) => {\n    try {'
            );
            
            websiteJs = websiteJs.replace(
                '    res.json(res.locals.botInfo);',
                '        res.json(res.locals.botInfo);\n    } catch (error) {\n        log(\'error\', \'Error serving bot info API:\', error);\n        res.json({\n            name: \'AFK Devs Bot\',\n            prefix: \'/\',\n            servers: \'Offline\',\n            commands: [],\n            uptime: \'Offline\'\n        });\n    }'
            );
            
            fs.writeFileSync(websiteJsPath, websiteJs, 'utf8');
            console.log('✅ Updated website.js with improved error handling');
        } else {
            console.log('ℹ️ Debug utilities already added to website.js');
        }
    }
} catch (error) {
    console.error('❌ Error updating website.js:', error);
}

console.log(`\n===== DEBUG SETUP COMPLETE =====`);
console.log(`You can now run the bot with debug logging enabled using:`);
console.log(`  npm run debug    - Show bot-related logs only`);
console.log(`  npm run debugall - Show all debug logs`);
console.log(`Or set the DEBUG environment variable in .env to control logging.`);