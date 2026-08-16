const config = require('../config');
const { betaDb, betaPool } = require('../server/betaDb');
const { betaSettings } = require('../shared/schema');
const { eq } = require('drizzle-orm');

// Self-create the beta_settings table on the beta pool (mirrors every other
// settings manager — automod/events/live giveaways self-create their tables).
// drizzle never runs DDL, so without this the table only exists if migration
// 0002 + 0003 were applied manually to the BETA_DATABASE_URL. If the table is
// missing, isAllowed/isEnabled throw and return false, so an approved+enabled
// beta server gets treated as non-beta (locked overlay / 403 beta_required)
// on the dashboard.
const ENSURE_BETA_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS beta_settings (
        guild_id   VARCHAR(50) PRIMARY KEY,
        enabled    BOOLEAN NOT NULL DEFAULT FALSE,
        allowed    BOOLEAN NOT NULL DEFAULT FALSE,
        updated_at TIMESTAMP DEFAULT NOW()
    );
`;

let _tableEnsured = false;
async function ensureBetaTable() {
    if (_tableEnsured) return;
    try {
        await betaPool.query(ENSURE_BETA_TABLE_SQL);
        _tableEnsured = true;
    } catch (err) {
        console.error('[BETA] ensureBetaTable failed:', err.message);
    }
}

/**
 * Is this guild on the developer-approved beta access list? (async — DB)
 * Falls back to config.betaServers as a seed list.
 */
async function isAllowed(guildId) {
    // Always allow servers listed in config as a hard-coded fallback
    if (Array.isArray(config.betaServers) && config.betaServers.includes(guildId)) return true;
    await ensureBetaTable();
    try {
        const rows = await betaDb
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
    await ensureBetaTable();
    try {
        const rows = await betaDb
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
        await betaDb
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
        await betaDb
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
        const rows = await betaDb
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
        await betaDb
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
        await betaDb
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
