const { PermissionFlagsBits } = require('discord.js');
const botRoles = require('./botRoles');

/**
 * Ticket claim permission helpers.
 *
 * Permission hierarchy (recommended in the claim spec):
 *   owner/developer  — can claim, unclaim anyone, force-unclaim, transfer;
 *   admin/ticket managers — can claim, unclaim anyone (force), transfer;
 *   support staff       — can claim unclaimed tickets, unclaim their own tickets;
 *   normal users        — no claim management.

 * "Support staff" is derived from the existing panel supportRoleIds (the same
 * roles that can see/ticket channels). Discord Administrator always counts as
 * support. The bot-role service (utils/botRoles.js) adds developer/owner
 * as the ultimate override. All DB lookups degrade safely — a DB failure never
 * widens access.

 * No role IDs are hard-coded here: the panel's supportRoleIds (the existing
 * ticket permission config) and the bot's staff-role service (bot_roles table)
 *
 * Every helper is async (botRoles.getRole may touch the community DB).
 */

function _isAdmin(member) {
    return Boolean(
        member &&
        member.permissions &&
        member.permissions.has(PermissionFlagsBits.Administrator)
    );
}

/** Is the member a configured support-role holder for this panel?? */
function _isSupportRole(member, panel) {
    const roles = Array.isArray(panel && panel.supportRoleIds) ? panel.supportRoleIds : [];
    if (roles.length === 0) return false;
    if (!member) return false;
    const cache = member.roles?.cache || member.roles || null;
    if (!cache || typeof cache.has !== 'function') return false;
    return roles.some(r => cache.has(r));
}

/** Is this user a bot-role manager (developer+ / owner)? Async DB-backed. */
async function _isManager(userId) {
    if (!userId) return false;
    try {
        return await botRoles.canBypassFeatureGates(userId);
    } catch (err) {
        // A bot_roles DB outage must never widen access; degrade to false.
        console.error('[TICKET CLAIM] canBypassFeatureGates error:', err.message);
        return false;
    }
}

/**
 * Support-staff gate shared by every claim action. A member counts when they
 * hold a panel support role, are a Discord Administrator, or hold a bot
 * role of developer+ (owner/developer). Normal users never pass.
 */
async function canManageTicket(guild, member, panel) {
    if (_isAdmin(member)) return true;
    if (_isSupportRole(member, panel)) return true;
    const userId = member && member.id ? member.id : (guild && member && member.user ? member.user.id : null);
    if (userId) return await _isManager(userId);
    return false;
}

/** May this member claim a ticket?? (unclaimed + support + not the ticket owner.). */
async function canClaimTicket(guild, member, panel, instance) {
    if (instance && instance.status && instance.status !== 'open') return false;
    if (instance && instance.claimedBy) return false; // already claimed
    if (instance && member && String(member.id) === String(instance.userId)) return false; // ticket author can't claim
    return await canManageTicket(guild, member, panel);
}

/**
 * May this member unclaim a ticket??
 *   - The current claimer always can.

 *   - Admin / ticket managers (incl. developer/owner) can force-unclaim.

 *   - A regular staff member cannot unclaim someone else's claim.

 * Returns { allowed, reason } so callers can surface a friendly message.

 */
async function canUnclaimTicket(guild, member, panel, instance) {
    if (instance && instance.status && instance.status !== 'open') return { allowed: false, reason: 'ticket_closed' };
    const userId = member && member.id ? String(member.id) : '';
    const isClaimer = Boolean(instance && instance.claimedBy && String(instance.claimedBy) === userId);
    if (isClaimer) return { allowed: true };
    if (!userId) return { allowed: false, reason: 'not_authorized' };
    const force = await _isForceOverride(guild, member, panel);
    if (force) return { allowed: true, force: true };
    return { allowed: false, reason: 'claim_other' };
}

/** May this member transfer/override a claim? Admin/ticket managers + bot managers. */
async function _isForceOverride(guild, member, panel) {
    if (_isAdmin(member)) return true;
    const userId = member && member.id ? member.id : null;
    if (userId) return await _isManager(userId);
    return false;
}

/**
 * May this member transfer the claim from `fromStaffId` to `toStaffId`??
 *   - The current claimer can transfer when allowed (always under soft claim).
 *   - Admin/ticket managers can force-transfer.

 *   - `toStaffId` must be a different user, and when provided the manager
 *     checks the target member holds support perms guild-side (via
 *     canManageTicket on the target members). The permission check for the
 *     target is done by the caller only when a target member can be resolved.
 */
async function canTransferTicketClaim(guild, member, panel, instance, toStaffId = null) {
    if (instance && instance.status && instance.status !== 'open') return { allowed: false, reason: 'ticket_closed' };
    const userId = member && member.id ? String(member.id) : '';
    const isClaimer = Boolean(instance && instance.claimedBy && String(instance.claimedBy) === userId);
    if (isClaimer) return { allowed: true };
    if (!userId) return { allowed: false, reason: 'not_authorized' };
    const force = await _isForceOverride(guild, member, panel);
    if (!force) return { allowed: false, reason: 'claim_other' };
    if (toStaffId && String(toStaffId) === userId) return { allowed: false, reason: 'self_transfer' };
    return { allowed: true, force: true };
}

module.exports = {
    canManageTicket,
    canClaimTicket,
    canUnclaimTicket,
    canTransferTicketClaim,
};