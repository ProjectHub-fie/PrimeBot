const config = require('../config');
const { db } = require('../server/db');
const { betaSettings } = require('../shared/schema');
const { eq } = require('drizzle-orm');

/**
 * Is this guild on the developer-approved beta access list? (async — DB)
 * Falls back to config.betaServers as a seed list.
 */
async function isAllowed(guildId) {
    // Always allow servers listed in config as a hard-coded fallback
    if (Array.isArray(config.betaServers) && config.betaServers.includes(guildId)) return true;
    try {
        const rows = await db
            .select()
            .from(betaSettings)
            .where(eq(betaSettings.guildId, guildId))
            .limit(1);
        return rows.length > 0 && rows[0].allowed === true;
    } catch (err) {
        console.error('[BETA] isAllowed DB error:', err.message);
        return false;
    }
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
 * Add a guild to the beta allowed list. (async — DB, bot owner only)
 */
async function allowServer(guildId) {
    try {
        await db
            .insert(betaSettings)
            .values({ guildId, allowed: true, enabled: false, updatedAt: new Date() })
            .onConflictDoUpdate({
                target: betaSettings.guildId,
                set: { allowed: true, updatedAt: new Date() },
            });
        return true;
    } catch (err) {
        console.error('[BETA] allowServer DB error:', err.message);
        return false;
    }
}

/**
 * Remove a guild from the beta allowed list. (async — DB, bot owner only)
 */
async function denyServer(guildId) {
    try {
        await db
            .insert(betaSettings)
            .values({ guildId, allowed: false, enabled: false, updatedAt: new Date() })
            .onConflictDoUpdate({
                target: betaSettings.guildId,
                set: { allowed: false, enabled: false, updatedAt: new Date() },
            });
        return true;
    } catch (err) {
        console.error('[BETA] denyServer DB error:', err.message);
        return false;
    }
}

/**
 * Return all guilds currently on the allowed list. (async — DB)
 */
async function listAllowedServers() {
    try {
        const rows = await db
            .select()
            .from(betaSettings)
            .where(eq(betaSettings.allowed, true));
        return rows;
    } catch (err) {
        console.error('[BETA] listAllowedServers DB error:', err.message);
        return [];
    }
}

/**
 * Enable beta for a guild. Returns false if not on allowed list. (async — DB)
 */
async function enable(guildId) {
    if (!(await isAllowed(guildId))) return false;
    try {
        await db
            .insert(betaSettings)
            .values({ guildId, enabled: true, allowed: true, updatedAt: new Date() })
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
    return (await isAllowed(guildId)) && (await isEnabled(guildId));
}

module.exports = { isAllowed, isEnabled, enable, disable, isBetaFeature, canAccess, allowServer, denyServer, listAllowedServers };
