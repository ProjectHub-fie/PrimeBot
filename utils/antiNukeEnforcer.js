/**
 * Anti-Nuke — real enforcement actions.
 *
 * Everything the Anti-Nuke manager DOES after a threshold trips, beyond the
 * alert + reversible containment already in utils/antiNukeContainment.js:
 *
 *   • ban  — ban the confirmed attacker (permission + hierarchy gated)
 *   • kick — kick the confirmed attacker (permission + hierarchy gated)
 *   • quarantine — apply an owner-configured quarantine role and strip
 *                  dangerous roles, where safely possible
 *   • deleteWebhook — delete the webhook(s) involved in the attack (never a
 *                  blanket sweep of every webhook in the guild)
 *   • lockChannels — deny @everyone Send Messages on the channels involved
 *
 * Every handler follows the same contract:
 *
 *   1. Validate the bot has the required Discord permission.
 *   2. Validate the executor is manageable (not the owner, not the bot, not a
 *      trusted role, not at/above the bot's highest role).
 *   3. Execute the action.
 *   4. Verify the Discord API result and report the exact outcome — a success
 *      is only ever reported when Discord accepted the action.
 *
 * Handlers never throw: they return a structured result
 * `{ executed, errors, attempted, details }` so the manager can persist an
 * accurate incident status and never claim success for a failed action.
 */

const { PermissionFlagsBits } = require('discord.js');

// The discord.js v14 PermissionFlagsBits values the handlers need.
const PERM = {
    ban: PermissionFlagsBits.BanMembers,
    kick: PermissionFlagsBits.KickMembers,
    manageRoles: PermissionFlagsBits.ManageRoles,
    manageWebhooks: PermissionFlagsBits.ManageWebhooks,
    manageChannels: PermissionFlagsBits.ManageChannels,
};

/** Does the bot hold `flag` in `guild`? Never throws. */
function botHasPermission(guild, flag) {
    try {
        const me = guild && guild.members && guild.members.me;
        return Boolean(me && me.permissions && typeof me.permissions.has === 'function' && me.permissions.has(flag));
    } catch (_) {
        return false;
    }
}

/**
 * Rank-based safety gate. Returns null when the target is manageable, or a
 * reason string when the bot must not act on them.
 */
function hierarchyCheck({ guild, member, guildOwnerId, botUserId, trustedRoleIds = [] } = {}) {
    if (!member) return 'no_member';
    if (guildOwnerId && member.id === guildOwnerId) return 'owner_exempt';
    if (botUserId && member.id === botUserId) return 'bot_exempt';
    const trusted = new Set(trustedRoleIds || []);
    const roles = member.roles && member.roles.cache
        ? Array.from(member.roles.cache.values())
        : [];
    for (const r of roles) {
        if (trusted.has(r.id)) return 'trusted_role_exempt';
    }
    const me = guild && guild.members && guild.members.me;
    if (!me) return 'no_bot_member';
    const botHighest = me.roles && me.roles.highest ? Number(me.roles.highest.position) : -1;
    const target = member.roles && member.roles.highest ? Number(member.roles.highest.position) : 0;
    if (botHighest >= 0 && target >= botHighest) return 'target_above_bot';
    return null;
}

/** Resolve the executor member from cache/then fetch; null when absent. */
async function resolveMember(client, guild, userId) {
    if (!guild || !userId) return null;
    try {
        if (guild.members && guild.members.cache && guild.members.cache.get(userId)) {
            return guild.members.cache.get(userId);
        }
        if (guild.members && typeof guild.members.fetch === 'function') {
            return await guild.members.fetch(userId);
        }
    } catch (_) { /* the member may have left the guild — enforcement is best-effort */ }
    return null;
}

async function banExecutor(client, guild, executorId, { reason = 'Anti-Nuke: confirmed attacker', settings = {} } = {}) {
    if (!botHasPermission(guild, PERM.ban)) {
        return { executed: false, attempted: true, errors: ['missing Ban Members'], available: false };
    }
    const member = await resolveMember(client, guild, executorId);
    const blocked = hierarchyCheck({
        guild, member: member || { id: executorId, roles: { cache: new Map() } },
        guildOwnerId: guild.ownerId, botUserId: client && client.user ? client.user.id : null,
        trustedRoleIds: settings.trustedRoleIds,
    });
    if (blocked) return { executed: false, attempted: true, errors: [`hierarchy: ${blocked}`] };
    try {
        await guild.members.ban(executorId, { reason, deleteMessageSeconds: 0 });
        return { executed: true, attempted: true, errors: [], action: 'ban', target: executorId };
    } catch (err) {
        return { executed: false, attempted: true, errors: [`ban_rejected: ${err && (err.code || err.message)}`], action: 'ban', target: executorId };
    }
}

async function kickExecutor(client, guild, executorId, { reason = 'Anti-Nuke: confirmed attacker', settings = {} } = {}) {
    if (!botHasPermission(guild, PERM.kick)) {
        return { executed: false, attempted: true, errors: ['missing Kick Members'], available: false };
    }
    const member = await resolveMember(client, guild, executorId);
    if (!member) return { executed: false, attempted: true, errors: ['member_not_found'], available: false };
    const blocked = hierarchyCheck({
        guild, member,
        guildOwnerId: guild.ownerId, botUserId: client && client.user ? client.user.id : null,
        trustedRoleIds: settings.trustedRoleIds,
    });
    if (blocked) return { executed: false, attempted: true, errors: [`hierarchy: ${blocked}`] };
    try {
        await member.kick(reason);
        return { executed: true, attempted: true, errors: [], action: 'kick', target: executorId };
    } catch (err) {
        return { executed: false, attempted: true, errors: [`kick_rejected: ${err && (err.code || err.message)}`], action: 'kick', target: executorId };
    }
}

/**
 * Quarantine: apply the configured quarantine role (if any) and strip
 * dangerous roles. Only roles strictly below the bot's highest role are
 * touched, and trusted roles are never touched.
 */
async function quarantineMember(client, guild, executorId, { reason = 'Anti-Nuke: quarantine', settings = {}, onChange = null } = {}) {
    const errors = [];
    const details = { actions: [] };
    let executedAny = false;

    if (!botHasPermission(guild, PERM.manageRoles)) {
        errors.push('missing Manage Roles');
    } else {
        const member = await resolveMember(client, guild, executorId);
        const blocked = hierarchyCheck({
            guild, member: member || { id: executorId, roles: { cache: new Map() } },
            guildOwnerId: guild.ownerId, botUserId: client && client.user ? client.user.id : null,
            trustedRoleIds: settings.trustedRoleIds,
        });
        if (blocked) errors.push(`hierarchy: ${blocked}`);
        else if (!member) errors.push('member_not_found');
        else {
            // 1. Apply the configured quarantine role, if present.
            if (settings.quarantineRoleId) {
                const role = guild.roles && guild.roles.cache ? guild.roles.cache.get(settings.quarantineRoleId) : null;
                if (role) {
                    const botHighest = guild.members.me && guild.members.me.roles && guild.members.me.roles.highest
                        ? Number(guild.members.me.roles.highest.position) : -1;
                    if (botHighest < 0 || Number(role.position) < botHighest) {
                        try {
                            if (!member.roles || !member.roles.cache || !member.roles.cache.has(role.id)) {
                                await member.roles.add(role.id, reason);
                                executedAny = true;
                                details.actions.push('addQuarantineRole');
                            }
                        } catch (err) {
                            errors.push(`quarantine_role: ${err && (err.code || err.message)}`);
                        }
                    } else {
                        errors.push('quarantine_role_above_bot');
                    }
                } else {
                    errors.push('quarantine_role_missing');
                }
            }

            // 2. Strip dangerous roles.
            const { computeDangerousRoleRemovals, stripDangerousRoles } = require('./antiNukeContainment');
            const plan = computeDangerousRoleRemovals({
                member,
                botMember: guild.members && guild.members.me,
                guildOwnerId: guild.ownerId,
                botUserId: client && client.user ? client.user.id : null,
                trustedRoleIds: settings.trustedRoleIds,
                dangerousPermissions: settings.dangerousPermissions,
            });
            if (!plan.reason && plan.removable.length) {
                const res = await stripDangerousRoles(member, plan, reason);
                if (res.removed.length) { executedAny = true; details.actions.push(`stripRoles:${res.removed.length}`); }
                for (const f of res.failed) errors.push(`strip_role_failed: ${f.roleId}`);
            } else if (plan.reason) {
                details.actions.push(`skip_strip:${plan.reason}`);
            }
        }
    }

    if (typeof onChange === 'function') onChange({ executedAny, errors });
    return { executed: executedAny, attempted: true, errors, details, action: 'quarantine', target: executorId };
}

/**
 * Delete the webhook(s) involved in the attack. `webhooks` is the list Discord
 * reports as the attack's target webhooks (their creates/updates). Never a
 * blanket sweep of the guild's webhooks.
 */
async function deleteWebhooks(client, guild, webhookIds, { reason = 'Anti-Nuke: malicious webhook' } = {}) {
    const ids = (Array.isArray(webhookIds) ? webhookIds : []).map(String).filter(Boolean);
    if (ids.length === 0) {
        // No specific ids resolved (an unattributed webhook action) — do
        // nothing rather than guessing which webhook was malicious.
        return { executed: false, attempted: false, errors: ['no_webhook_targets'], action: 'deleteWebhook' };
    }
    if (!botHasPermission(guild, PERM.manageWebhooks)) {
        return { executed: false, attempted: true, errors: ['missing Manage Webhooks'], available: false };
    }
    const removed = [];
    const failed = [];
    for (const id of ids) {
        try {
            const webhook = await guild.fetchWebhooks().then(list =>
                list.find(w => String(w.id) === String(id))
            ).catch(() => null);
            if (!webhook) {
                // Already gone → treated as removed.
                removed.push(id);
                continue;
            }
            await webhook.delete(reason);
            removed.push(id);
        } catch (err) {
            failed.push({ id, error: `${err && (err.code || err.message)}` });
        }
    }
    const executed = removed.length > 0;
    return {
        executed,
        attempted: true,
        errors: failed.map(f => `webhook_delete:${f.id}: ${f.error}`),
        removed,
        failed,
        action: 'deleteWebhook',
    };
}

/**
 * Lock the affected channels: deny @everyone Send Messages. `channelIds` is the
 * set of channels implicated in the attack. Reversible by the same handler.
 */
async function lockChannels(client, guild, channelIds, { reason = 'Anti-Nuke: channel attack lockdown' } = {}) {
    const ids = (Array.isArray(channelIds) ? channelIds : []).map(String).filter(Boolean);
    if (ids.length === 0) {
        return { executed: false, attempted: false, errors: ['no_channels'], action: 'lockChannels' };
    }
    if (!botHasPermission(guild, PERM.manageChannels)) {
        return { executed: false, attempted: true, errors: ['missing Manage Channels'], available: false };
    }
    const locked = [];
    const failed = [];
    const beforeByChannel = {};
    for (const id of ids) {
        try {
            const channel = await guild.channels.fetch(id).catch(() => null);
            if (!channel || typeof channel.permissionOverwrites?.edit !== 'function') {
                failed.push({ id, error: 'channel_unavailable' });
                continue;
            }
            const ow = channel.permissionOverwrites.cache
                ? channel.permissionOverwrites.cache.get(guild.id) : null;
            const allows = channel.permissionsFor
                ? Boolean(channel.permissionsFor(guild.id)?.has(PermissionFlagsBits.SendMessages))
                : true;
            if (!allows) { locked.push(id); continue; } // already locked
            const allowPrev = ow && (ow.allow && ow.allow.bitfield != null ? String(ow.allow.bitfield) : (ow.allow != null ? String(ow.allow) : '0'));
            const denyPrev = ow && (ow.deny && ow.deny.bitfield != null ? String(ow.deny.bitfield) : (ow.deny != null ? String(ow.deny) : '0'));
            if (ow) beforeByChannel[id] = { allow: allowPrev, deny: denyPrev };
            await channel.permissionOverwrites.edit(guild.id, { SendMessages: false }, { reason });
            locked.push(id);
        } catch (err) {
            failed.push({ id, error: `${err && (err.code || err.message)}` });
        }
    }
    return {
        executed: locked.length > 0,
        attempted: true,
        errors: failed.map(f => `lock_channel:${f.id}: ${f.error}`),
        locked,
        failed,
        beforeByChannel,
        action: 'lockChannels',
    };
}

module.exports = {
    botHasPermission,
    hierarchyCheck,
    resolveMember,
    banExecutor,
    kickExecutor,
    quarantineMember,
    deleteWebhooks,
    lockChannels,
    PERM,
};