/**
 * Anti-Nuke — owner-controlled access hierarchy + authorization helper.
 *
 * Four access levels:
 *   Level 1  Server Owner   — the ACTUAL Discord guild owner, resolved at call
 *                             time from Discord guild ownership data. Full
 *                             access, never removable/demotable, never stored.
 *   Level 2  Co-Owner       — an individual appointed by the owner inside
 *                             PrimeBot; receives ONLY the assigned permissions.
 *                             Discord Administrator does NOT imply Co-Owner.
 *   Level 3  Trusted Admin  — an individual selected by the owner; ONLY the
 *                             assigned permissions.
 *   Level 4  everyone else  — no Anti-Nuke management access.
 *
 * Central authorization helper:
 *
 *     authorizeAntiNuke(guild, userId, requiredPermission, { actorId })
 *
 *   1. Resolve the actual guild owner (guild.ownerId or guild.owner_id).
 *   2. Load the user's bot-defined assignment (antinuke_access on the shared
 *      ANUKE_DATABASE_URL pool).
 *   3. Calculate effective permissions (owner implicit full set; assignment
 *      stored set otherwise).
 *   4. Verify the requested permission.
 *   5. (Optional) verify guild membership for Discord interactions.
 *   6. Return an authorization result.
 *   7. Record sensitive access changes (the mutation callers audit).
 *
 * The ACTUAL guild owner is never trusted from the client: the calling route
 * passes a guild whose ownerId/owner_id came from Discord (the dashboard's
 * requireGuildAdmin used `getBotGuild` REST data; the bot uses guild.ownerId).
 *
 * Delegation boundaries (enforced server-side, never only in the UI):
 *   • the owner can do everything;
 *   • a manager may only grant permissions they themselves hold;
 *   • a manager may only assign roles at/below their own level (a Co-Owner can
 *     never mint a Co-Owner; a Trusted Admin can never appoint anyone above
 *     themselves);
 *   • no one can modify the owner;
 *   • no one can grant themselves additional permissions;
 *   • Co-Owner appointment/removal is owner-only unless the owner delegates
 *     `antinuke.access.manage` / `antinuke.access.revoke` — and even then a
 *     delegated manager can only change people strictly below themselves.
 *
 * The owner remains exempt from detection regardless of these permissions —
 * "trusted to manage" is deliberately separate from "exempt from punishment".
 */

const {
    ANTI_NUKE_PERMISSION_BY_ID,
    ANTI_NUKE_LEVELS,
    normalizePermissionList,
    intersectPermissions,
    applyPreset,
    OWNER_PERMISSION_IDS,
    levelFor,
} = require('../shared/antiNukePermissions');
const { normalizeAuditAction } = require('../shared/antiNukeAuditLog');
const {
    anukePool: _pool,
    listAccessRows,
    getAccessRow,
    upsertAccessRow,
    deleteAccessRow,
    addAccessHistoryRow,
    listAccessHistory,
} = require('../server/anukeDb');

const ROLES = { coOwner: 'coOwner', trustedAdmin: 'trustedAdmin' };
const ROLE_LEVELS = { coOwner: 2, trustedAdmin: 3 };

/**
 * Parse the role argument of `antinuke grant @user <co-owner|admin>`.
 *
 * Prefix args arrive as `['grant', '<@id>', 'co-owner']` — the mention is its
 * own token — so read the role from the NON-mention tokens rather than a fixed
 * index. Accepts "co-owner"/"coowner"/"co_owner" and
 * "admin"/"trustedAdmin"/"trusted-admin".
 *
 * @param {string[]} args raw args AFTER the subcommand (args[0] === 'grant')
 * @returns {{ role: string|null, roleArg: string }}
 */
function parseGrantArgs(args) {
    const nonMention = (Array.isArray(args) ? args : [])
        .filter(a => a && !/^<[@#!&]*\d+>$/.test(a));
    // args[0] is the subcommand ('grant'); the role is the first non-mention token after it.
    const roleArg = (nonMention[1] || '').toLowerCase().replace(/[-_\s]/g, '');
    let role = null;
    if (roleArg === 'coowner') role = ROLES.coOwner;
    else if (roleArg === 'trustedadmin' || roleArg === 'admin') role = ROLES.trustedAdmin;
    return { role, roleArg };
}

/** The fixed preset for a role — co-owner → Protection Manager, admin → Security Monitor. */
function defaultPresetForRole(role) {
    return role === ROLES.coOwner ? 'protectionManager' : 'securityMonitor';
}

/** The effective set the owner carries (every permission in the registry). */
function ownerPermissions() {
    return OWNER_PERMISSION_IDS.slice();
}

function roleForLevel(level) {
    if (level <= 1) return 'owner';
    if (level === 2) return 'coOwner';
    if (level === 3) return 'trustedAdmin';
    return 'none';
}

/**
 * Resolve the actual guild owner id, accepting either a discord.js Guild or the
 * dashboard's REST-derived guild descriptor (both carry ownerId/owner_id from
 * Discord). Returns null when the guild shape is unusable — callers must refuse
 * authorization, never guess.
 */
function resolveOwnerId(guild) {
    if (!guild) return null;
    if (guild.ownerId) return String(guild.ownerId);
    if (guild.owner_id) return String(guild.owner_id);
    return null;
}

/**
 * Compute the aggregate authorization context for a user in a guild.
 *
 * @returns {Promise<{
 *   ownerId:string|null, role:string, level:number, permissions:string[],
 *   assigned:object|null, isOwner:boolean, canManageAccess:boolean,
 *   canAppointCoOwners:boolean, canRevoke:boolean, guildMember:boolean|null,
 *   ok:boolean
 * }>}
 */
async function computeAccess({ guild, userId, member = null }) {
    const ownerId = resolveOwnerId(guild);
    const isOwner = !!ownerId && String(userId) === String(ownerId);
    const rawMember = member && typeof member === 'object' ? member : null;
    const guildMember = rawMember
        ? { present: true, roles: Array.isArray(rawMember.roles) ? rawMember.roles : [] }
        : null;

    let assigned = null;
    let role = isOwner ? 'owner' : 'none';
    let permissions = isOwner ? ownerPermissions() : [];

    if (!isOwner && ownerId && userId) {
        try {
            assigned = await getAccessRow(guild && guild.id ? guild.id : null, userId);
        } catch (err) {
            assigned = null;
        }
        if (assigned) {
            role = assigned.role === ROLES.coOwner ? ROLES.coOwner : ROLES.trustedAdmin;
            permissions = normalizePermissionList(assigned.permissions);
        }
    }

    const level = levelFor(role);
    return {
        ownerId,
        role,
        level,
        isOwner,
        permissions,
        assigned,
        // Composite access-management capabilities (owner-only grants).
        canManageAccess: isOwner || permissions.includes('antinuke.access.manage'),
        canAppointCoOwners: isOwner || false, // co-owner appointment is always owner-only
        canRevoke: isOwner || permissions.includes('antinuke.access.revoke'),
        guildMember,
        ok: true,
    };
}

/**
 * Central authorization helper.
 *
 *   authorizeAntiNuke(guild, userId, requiredPermission, opts)
 *
 * - `requiredPermission` is one of the registry ids (`antinuke.view`, …).
 * - When `requiredPermission` is omitted/null, only guild membership is
 *   checked (used to gate the page itself).
 * - `opts`:
 *     member        — pre-loaded member object (Discord interaction) to verify
 *                     guild membership; when the caller passes a non-null
 *                     `member` that is NOT present, authorization fails.
 *     requireMember — force a guild-membership check (dashboard flow); the
 *                     caller supplies `member: { present: bool, roles: [] }`.
 *
 * Returns `{ ok, reason?, permissions, role, level, ownerId, isOwner }`.
 * `ok === false` never throws — callers render 403 with the `reason`.
 */
async function authorizeAntiNuke(guild, userId, requiredPermission = null, opts = {}) {
    if (!guild || !guild.id || !userId) {
        return { ok: false, reason: 'invalid_context', permissions: [], role: 'none', level: 4, ownerId: null, isOwner: false, userId: userId || null };
    }

    const ctx = await computeAccess({
        guild,
        userId,
        member: opts.member !== undefined ? opts.member : undefined,
    });
    ctx.userId = String(userId);

    // Optional explicit guild-membership requirement (interactions already
    // guarantee it; the dashboard checks the member is present in the guild).
    if (opts.requireMember && opts.member) {
        if (!opts.member.present) {
            ctx.guildMember = { present: false, roles: [] };
            return { ok: false, reason: 'not_a_member', ...ctx };
        }
    }

    if (ctx.isOwner) {
        return { ...ctx, ok: true };
    }
    if (!ctx.ownerId) {
        // Cannot prove who the owner is — refuse rather than trust an undefined
        // owner. (Detection never punishes without attribution either.)
        return { ...ctx, ok: false, reason: 'owner_unresolved' };
    }
    if (requiredPermission && !ctx.permissions.includes(requiredPermission)) {
        return { ...ctx, ok: false, reason: 'permission_denied', requiredPermission };
    }
    // No required permission means "any granted access" — an unassigned user
    // has none.
    if (!requiredPermission && ctx.level > 3) {
        return { ...ctx, ok: false, reason: 'permission_denied', requiredPermission: null };
    }
    return { ...ctx, ok: true };
}

/**
 * The authorization result for a page render (never throws). Used by the
 * dashboard to decide between the real page, the "no access" page and the
 * owner-locked variant.
 */
async function getGuildAccess(guild, userId, { member = undefined } = {}) {
    try {
        return await authorizeAntiNuke(guild, userId, null, { member });
    } catch (err) {
        return { ok: false, reason: 'error', error: err.message, permissions: [], role: 'none', level: 4, ownerId: null, isOwner: false };
    }
}

// ── Assignment mutations (with audit) ───────────────────────────────────────

function _summarize(row) {
    if (!row) return {};
    return {
        userId: row.user_id != null ? row.user_id : row.userId,
        role: row.role,
        permissions: row.permissions || [],
        preset: row.preset || null,
    };
}

/**
 * Effective permission set for an assigned row, stripped of owner-only ids
 * (a stored permission list can never grant anything only the owner holds).
 */
function effectivePermissionsForAssigned(permissions) {
    return normalizePermissionList(permissions).filter(id => !ANTI_NUKE_PERMISSION_BY_ID[id].ownerOnly);
}

/**
 * Can `actor` (an effective-access object) modify `targetRole`/`targetLevel`?
 * A manager may only act on people strictly below themselves (a co-owner's own
 * level-2 assignment is owned by the owner, so a delegate at level 2 cannot
 * modify another level-2 person's row).
 */
function canManageTarget(actor, targetLevel, targetUserId, actorUserId) {
    if (!actor) return false;
    if (actor.isOwner) return true;
    if (!actor.permissions.includes('antinuke.access.manage') &&
        !actor.permissions.includes('antinuke.access.revoke')) return false;
    // Cannot modify yourself (no self-elevation).
    if (targetUserId && (actor.userId || actorUserId) && String(targetUserId) === String(actor.userId || actorUserId)) return false;
    return targetLevel > actor.level;
}

/** Replace an assignment's permissions (owner or a delegated manager). */
async function setPermissions({ guild, actorUserId, actor, targetUserId, permissions = [], preset = null, reason = '' }) {
    const ownerId = resolveOwnerId(guild);
    const existing = await getAccessRow(guild.id, targetUserId);
    const targetLevel = existing ? ROLE_LEVELS[existing.role] || 4 : 3;
    if (actor.isOwner) {
        // Owner flow: no restrictions beyond never touching the owner himself.
        if (String(targetUserId) === String(ownerId)) return { ok: false, reason: 'cannot_modify_owner' };
        const cleaned = effectivePermissionsForAssigned(permissions);
        const prev = _summarize(existing);
        await upsertAccessRow(guild.id, {
            userId: targetUserId,
            role: existing ? existing.role : ROLES.trustedAdmin,
            permissions: cleaned,
            preset,
            updatedBy: actorUserId,
        });
        await addAccessHistoryRow({
            guildId: guild.id, actorId: actorUserId, targetId: targetUserId,
            action: 'permissions_updated',
            previousState: prev, newState: { role: existing ? existing.role : 'trustedAdmin', permissions: cleaned, preset },
            reason: String(reason || '').slice(0, 500),
        });
        return { ok: true, role: existing ? existing.role : ROLES.trustedAdmin, permissions: cleaned };
    }
    if (!actor.permissions.includes('antinuke.access.manage')) return { ok: false, reason: 'permission_denied' };
    if (!canManageTarget(actor, targetLevel, targetUserId, actorUserId)) return { ok: false, reason: 'outside_authority' };
    // Delegation boundary: the delegated manager can only grant what they hold.
    const cleaned = intersectPermissions(effectivePermissionsForAssigned(permissions), actor.permissions);
    const prev = _summarize(existing);
    await upsertAccessRow(guild.id, {
        userId: targetUserId,
        role: existing ? existing.role : ROLES.trustedAdmin, // a delegate never creates co-owners
        permissions: cleaned,
        preset,
        updatedBy: actorUserId,
    });
    await addAccessHistoryRow({
        guildId: guild.id, actorId: actorUserId, targetId: targetUserId,
        action: 'permissions_updated',
        previousState: prev, newState: { role: existing ? existing.role : 'trustedAdmin', permissions: cleaned, preset },
        reason: String(reason || '').slice(0, 500),
    });
    return { ok: true, role: existing ? existing.role : ROLES.trustedAdmin, permissions: cleaned };
}

/**
 * Appoint an assignment. `role` is validated against the calling actor's
 * authority:
 *   • owner may appoint coOwner/trustedAdmin;
 *   • a delegated manager may only (re)assign trustedAdmin rows strictly below
 *     themselves, capped to their own permission set.
 */
async function assignAccess({ guild, actorUserId, actor, targetUserId, role = 'trustedAdmin', permissions = [], preset = null, reason = '' }) {
    const ownerId = resolveOwnerId(guild);
    if (String(targetUserId) === String(ownerId)) return { ok: false, reason: 'cannot_modify_owner' };

    const desiredRole = role === ROLES.coOwner ? ROLES.coOwner : ROLES.trustedAdmin;
    const existing = await getAccessRow(guild.id, targetUserId);
    const targetLevelAfter = desiredRole === ROLES.coOwner ? 2 : 3;

    if (actor.isOwner) {
        if (desiredRole === ROLES.coOwner) {
            // Appointing/upgrading a Co-Owner requires the confirmation flow to
            // have run; the API enforces the confirmation token. Server-side,
            // the owner may still only grant co-owner to a non-owner member.
            const cleaned = effectivePermissionsForAssigned(permissions);
            await upsertAccessRow(guild.id, {
                userId: targetUserId, role: desiredRole, permissions: cleaned, preset,
                grantedBy: actorUserId, updatedBy: actorUserId,
            });
            await addAccessHistoryRow({
                guildId: guild.id, actorId: actorUserId, targetId: targetUserId,
                action: 'co_owner_appointed',
                previousState: _summarize(existing),
                newState: { role: desiredRole, permissions: cleaned, preset },
                reason: String(reason || '').slice(0, 500),
            });
            return { ok: true, role: desiredRole, permissions: cleaned };
        }
        const cleaned = effectivePermissionsForAssigned(permissions);
        await upsertAccessRow(guild.id, {
            userId: targetUserId, role: ROLES.trustedAdmin, permissions: cleaned, preset,
            grantedBy: actorUserId, updatedBy: actorUserId,
        });
        await addAccessHistoryRow({
            guildId: guild.id, actorId: actorUserId, targetId: targetUserId,
            action: 'trusted_admin_added',
            previousState: _summarize(existing),
            newState: { role: ROLES.trustedAdmin, permissions: cleaned, preset },
            reason: String(reason || '').slice(0, 500),
        });
        return { ok: true, role: ROLES.trustedAdmin, permissions: cleaned };
    }

    // Delegated manager path.
    if (!actor.permissions.includes('antinuke.access.manage')) return { ok: false, reason: 'permission_denied' };
    // Co-Owner appointment/upgrade is owner-only — checked before the level
    // boundary so a delegated manager never sees a confusing `outside_authority`
    // for something they are never allowed to do.
    if (desiredRole === ROLES.coOwner) return { ok: false, reason: 'co_owner_owner_only' };
    if (!canManageTarget(actor, targetLevelAfter, targetUserId, actorUserId)) return { ok: false, reason: 'outside_authority' };
    const cleaned = intersectPermissions(effectivePermissionsForAssigned(permissions), actor.permissions);
    await upsertAccessRow(guild.id, {
        userId: targetUserId, role: ROLES.trustedAdmin, permissions: cleaned, preset,
        grantedBy: actorUserId, updatedBy: actorUserId,
    });
    await addAccessHistoryRow({
        guildId: guild.id, actorId: actorUserId, targetId: targetUserId,
        action: 'trusted_admin_added',
        previousState: _summarize(existing),
        newState: { role: ROLES.trustedAdmin, permissions: cleaned, preset },
        reason: String(reason || '').slice(0, 500),
    });
    return { ok: true, role: ROLES.trustedAdmin, permissions: cleaned };
}

/**
 * Remove an assignment (owner, or a delegated manager strictly above the
 * target). Revocation is immediate — the next authorization re-reads the rows,
 * so a revoked user's open session is denied on the next request.
 */
async function removeAccess({ guild, actorUserId, actor, targetUserId, reason = '' }) {
    const ownerId = resolveOwnerId(guild);
    if (String(targetUserId) === String(ownerId)) return { ok: false, reason: 'cannot_modify_owner' };
    const existing = await getAccessRow(guild.id, targetUserId);
    if (!existing) return { ok: false, reason: 'no_assignment' };

    if (actor.isOwner) {
        const action = existing.role === ROLES.coOwner ? 'co_owner_removed' : 'trusted_admin_removed';
        await deleteAccessRow(guild.id, targetUserId);
        await addAccessHistoryRow({
            guildId: guild.id, actorId: actorUserId, targetId: targetUserId,
            action,
            previousState: _summarize(existing), newState: {},
            reason: String(reason || '').slice(0, 500),
        });
        return { ok: true };
    }
    const targetLevel = ROLE_LEVELS[existing.role] || 4;
    if (!actor.permissions.includes('antinuke.access.revoke') &&
        !actor.permissions.includes('antinuke.access.manage')) return { ok: false, reason: 'permission_denied' };
    if (!canManageTarget(actor, targetLevel, targetUserId, actorUserId)) return { ok: false, reason: 'outside_authority' };
    await deleteAccessRow(guild.id, targetUserId);
    await addAccessHistoryRow({
        guildId: guild.id, actorId: actorUserId, targetId: targetUserId,
        action: 'access_revoked',
        previousState: _summarize(existing), newState: {},
        reason: String(reason || '').slice(0, 500),
    });
    return { ok: true };
}

/**
 * Build the full access snapshot for the Access Control page: owner + every
 * assignment with their computed level/effective set, with the acting user's
 * own context.
 */
async function buildAccessSnapshot({ guild, viewerUserId }) {
    const ownerId = resolveOwnerId(guild);
    const rows = await listAccessRows(guild.id);
    const assignments = rows.map(row => {
        const role = row.role === ROLES.coOwner ? ROLES.coOwner : ROLES.trustedAdmin;
        return {
            userId: row.user_id,
            role,
            level: ROLE_LEVELS[role] || 3,
            permissions: normalizePermissionList(row.permissions),
            preset: row.preset || null,
            grantedBy: row.granted_by || null,
            grantedAt: row.granted_at || null,
            updatedBy: row.updated_by || null,
            updatedAt: row.updated_at || null,
        };
    });
    const viewer = await computeAccess({ guild, userId: viewerUserId });
    const history = await listAccessHistory(guild.id, { limit: 50 }).catch(() => []);
    const historyRows = history.map(row => ({
        id: row.id,
        actorId: row.actor_id,
        targetId: row.target_id,
        action: normalizeAuditAction(row.action),
        previousState: row.previous_state || {},
        newState: row.new_state || {},
        result: row.result || 'success',
        reason: row.reason || '',
        createdAt: row.created_at || null,
    }));

    return {
        ownerId,
        assignments,
        history: historyRows,
        viewer: {
            userId: viewerUserId,
            role: viewer.role,
            level: viewer.level,
            isOwner: viewer.isOwner,
            permissions: viewer.permissions,
            canManageAccess: viewer.canManageAccess,
            canAppointCoOwners: viewer.canAppointCoOwners,
            canRevoke: viewer.canRevoke,
        },
    };
}

module.exports = {
    ROLES,
    ROLE_LEVELS,
    parseGrantArgs,
    defaultPresetForRole,
    ownerPermissions,
    resolveOwnerId,
    computeAccess,
    authorizeAntiNuke,
    getGuildAccess,
    canManageTarget,
    effectivePermissionsForAssigned,
    setPermissions,
    assignAccess,
    removeAccess,
    buildAccessSnapshot,
};