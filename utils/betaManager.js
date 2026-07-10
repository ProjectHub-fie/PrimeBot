const config = require('../config');
const { db } = require('../server/db');
const { betaSettings } = require('../shared/schema');
const { eq } = require('drizzle-orm');

/**
 * Is this guild on the developer-approved beta access list? (sync — config only)
 */
function isAllowed(guildId) {
    return Array.isArray(config.betaServers) && config.betaServers.includes(guildId);
}

/**
 * Has this guild's owner opted in to beta? (async — DB)
 */
async function isEnabled(guildId) {
    try {
        const rows = await db
            .select()
            .from(betaSettings)
            .where(eq(betaSettings.guildId, guildId))
            .limit(1);
        return rows.length > 0 && rows[0].enabled === true;
    } catch (err) {
        console.error('[BETA] isEnabled DB error:', err.message);
        return false;
    }
}

/**
 * Enable beta for a guild. Returns false if not on allowed list. (async — DB)
 */
async function enable(guildId) {
    if (!isAllowed(guildId)) return false;
    try {
        await db
            .insert(betaSettings)
            .values({ guildId, enabled: true, updatedAt: new Date() })
            .onConflictDoUpdate({
                target: betaSettings.guildId,
                set: { enabled: true, updatedAt: new Date() },
            });
        return true;
    } catch (err) {
        console.error('[BETA] enable DB error:', err.message);
        return false;
    }
}

/**
 * Disable beta for a guild. (async — DB)
 */
async function disable(guildId) {
    try {
        await db
            .insert(betaSettings)
            .values({ guildId, enabled: false, updatedAt: new Date() })
            .onConflictDoUpdate({
                target: betaSettings.guildId,
                set: { enabled: false, updatedAt: new Date() },
            });
        return true;
    } catch (err) {
        console.error('[BETA] disable DB error:', err.message);
        return false;
    }
}

/**
 * Is a specific command name currently gated as a beta feature? (sync — config only)
 */
function isBetaFeature(commandName) {
    return Array.isArray(config.betaFeatures) && config.betaFeatures.includes(commandName);
}

/**
 * Can this guild access beta features right now? (async — DB)
 */
async function canAccess(guildId) {
    return isAllowed(guildId) && await isEnabled(guildId);
}

module.exports = { isAllowed, isEnabled, enable, disable, isBetaFeature, canAccess };
