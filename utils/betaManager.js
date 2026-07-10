const fs = require('fs');
const path = require('path');
const config = require('../config');

const DATA_PATH = path.join(__dirname, '../data/betaSettings.json');

const dataDir = path.join(__dirname, '../data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

let betaSettings = {};

function load() {
    try {
        if (fs.existsSync(DATA_PATH)) {
            betaSettings = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
        } else {
            save();
        }
    } catch {
        betaSettings = {};
        save();
    }
}

function save() {
    try {
        fs.writeFileSync(DATA_PATH, JSON.stringify(betaSettings, null, 2), 'utf8');
        return true;
    } catch {
        return false;
    }
}

load();

/**
 * Is this guild on the developer-approved beta access list?
 */
function isAllowed(guildId) {
    return Array.isArray(config.betaServers) && config.betaServers.includes(guildId);
}

/**
 * Has this guild's owner opted in to beta?
 */
function isEnabled(guildId) {
    return !!(betaSettings[guildId] && betaSettings[guildId].enabled);
}

/**
 * Enable beta for a guild.  Returns false if not on allowed list.
 */
function enable(guildId) {
    if (!isAllowed(guildId)) return false;
    betaSettings[guildId] = { enabled: true };
    save();
    return true;
}

/**
 * Disable beta for a guild.
 */
function disable(guildId) {
    if (betaSettings[guildId]) {
        betaSettings[guildId].enabled = false;
        save();
    }
    return true;
}

/**
 * Is a specific command name currently gated as a beta feature?
 */
function isBetaFeature(commandName) {
    return Array.isArray(config.betaFeatures) && config.betaFeatures.includes(commandName);
}

/**
 * Can this guild access beta features right now?
 */
function canAccess(guildId) {
    return isAllowed(guildId) && isEnabled(guildId);
}

module.exports = { isAllowed, isEnabled, enable, disable, isBetaFeature, canAccess };
