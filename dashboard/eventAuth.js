/**
 * Event Management authorization middleware.
 *
 * Every Event Management API endpoint is server-side authorized — hiding a
 * dashboard button is never sufficient. Two guards are layered on top of the
 * existing `requireAuth` + `requireGuildAdmin` (which already prove the caller
 * manages the guild and that the bot is present):
 *
 *   • requireEventPermission(perm) — allows the server owner, administrators,
 *     and members holding the guild's configured event-manager role with the
 *     requested granular permission. Resolves the caller's Discord roles once
 *     per request and caches the event policy for a short TTL.
 *   • requireEventOwnership — for a specific event, ensures `:id` belongs to the
 *     authenticated guild (cross-guild isolation / IDOR protection).
 *
 * Degrades safely: any error resolving roles denies access rather than widening
 * it, and the cache is invalidated whenever the policy changes.
 */

const discord = require('./discord');
const repo = require('../server/eventMgmtRepo');
const { EVENT_PERMISSION_KEYS, normalizeEventPermissions } = require('../shared/eventConstants');

// guildId -> { at, ownerId, managerRoleId, permissions, guildIds }
const _policyCache = new Map();
const POLICY_TTL_MS = 30_000;

function ownerBypass(userGuild) {
    return !!(userGuild && userGuild.owner);
}

function clearEventPolicyCache(guildId) {
    if (guildId) _policyCache.delete(String(guildId));
    else _policyCache.clear();
}

/**
 * Load the guild-wide event policy. The manager role + permissions are the same
 * for every event in a guild, so we read them from any event that configures
 * one (or fall back to the most recently updated event). This is one bounded
 * query per ~30s per guild — never per request.
 */
async function loadGuildPolicy(guildId) {
    const id = String(guildId);
    const cached = _policyCache.get(id);
    if (cached && Date.now() - cached.at < POLICY_TTL_MS) return cached;
    let managerRoleId = null;
    let permissions = [];
    try {
        const { events } = await repo.getGuildEvents(guildId, { limit: 100, sort: 'updated' });
        for (const ev of events) {
            if (ev.eventManagerRoleId) {
                managerRoleId = ev.eventManagerRoleId;
                permissions = normalizeEventPermissions(ev.eventPermissions);
                break;
            }
        }
    } catch (err) {
        console.error('[EVENT AUTH] policy load failed:', err.message);
    }
    const policy = { at: Date.now(), managerRoleId, permissions };
    _policyCache.set(id, policy);
    return policy;
}

function isGuildAdmin(req) {
    // Server owner, or an administrator/manage-server member. `requireGuildAdmin`
    // always runs first and has already verified manage-guild access, so when the
    // permission bitfield is unavailable we treat the caller as an admin.
    if (req.guild && req.guild.userIsOwner) return true;
    const perms = req.session && req.session.userGuildPermissions;
    if (perms == null) return true;
    return discord.canManageGuild(perms);
}

/**
 * Is the caller allowed the requested permission?
 */
async function isEventManager(req, permission) {
    const guildId = req.guild.id;
    const policy = await loadGuildPolicy(guildId);
    if (!policy.managerRoleId) return false;
    if (Array.isArray(policy.permissions) && policy.permissions.length
        && !policy.permissions.includes(permission)) {
        return false;
    }
    const roles = await discord.getGuildMemberRoles(guildId, req.user.id);
    return roles.includes(policy.managerRoleId);
}

/**
 * Middleware factory: require a granular event permission. The server owner and
 * administrators always pass; an event manager must hold the configured role and
 * have the permission enabled.
 */
function requireEventPermission(permission) {
    if (!EVENT_PERMISSION_KEYS.includes(permission)) {
        throw new Error(`Unknown event permission: ${permission}`);
    }
    return async (req, res, next) => {
        try {
            if (isGuildAdmin(req)) return next();
            const allowed = await isEventManager(req, permission).catch((err) => {
                console.error('[EVENT AUTH] isEventManager failed:', err.message);
                return false;
            });
            if (!allowed) {
                return res.status(403).json({ error: 'You do not have permission to manage events in this server.', reason: 'event_permission_required' });
            }
            next();
        } catch (err) {
            console.error('[EVENT AUTH] requireEventPermission error:', err.message);
            return res.status(500).json({ error: 'Failed to verify event permissions.' });
        }
    };
}

/**
 * Middleware: ensure the `:id` event belongs to the authenticated guild. Sets
 * `req.event` for downstream handlers (IDOR / cross-guild protection).
 */
async function requireEventOwnership(req, res, next) {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid event id.' });
        const event = await repo.getEvent(id);
        if (!event || String(event.guildId) !== String(req.guild.id)) {
            return res.status(404).json({ error: 'Event not found.' });
        }
        req.event = event;
        next();
    } catch (err) {
        console.error('[EVENT AUTH] requireEventOwnership error:', err.message);
        return res.status(500).json({ error: 'Failed to load the event.' });
    }
}

module.exports = {
    requireEventPermission,
    requireEventOwnership,
    clearEventPolicyCache,
    loadGuildPolicy,
    isEventManager,
    isGuildAdmin,
};
