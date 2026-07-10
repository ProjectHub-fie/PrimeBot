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
        const allowed = rows.length > 0 && rows[0].allowed === true;
        return allowed;
    } catch (err) {
        console.error('[BETA] isAllowed DB error:', err.message);
        // On DB error, fall back to config seed list (already checked above) and return false
        // but expose the error for diagnostics via lastError
        module.exports._lastError = err;
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
        const enabled = rows.length > 0 && rows[0].enabled === true;
        return enabled;
    } catch (err) {
        console.error('[BETA] isEnabled DB error:', err.message);
        module.exports._lastError = err;
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
    try {
        const allowed = await isAllowed(guildId);
        const enabled = await isEnabled(guildId);
        return allowed && enabled;
    } catch (err) {
        console.error('[BETA] canAccess error:', err?.message || err);
        module.exports._lastError = err;
        return false;
    }
}

// Diagnostic: test DB connectivity and beta tables
async function checkDbHealth() {
    try {
        // Try a lightweight query against betaSettings
        const rows = await db.select().from(betaSettings).limit(1);
        return { ok: true };
    } catch (err) {
        return { ok: false, error: err.message || String(err) };
    }
}

module.exports = { isAllowed, isEnabled, enable, disable, isBetaFeature, canAccess, allowServer, denyServer, listAllowedServers, checkDbHealth, _lastError: null };
