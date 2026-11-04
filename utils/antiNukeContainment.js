/**
 * Anti-Nuke — alerts, safe containment and reversible lockdown.
 *
 * This module holds the three things Anti-Nuke does *after* a threshold trips:
 *
 *   1. Alert embeds — a premium "PRIMEBOT SECURITY ALERT" embed with an
 *      event-specific colour, never pinging @everyone/@here.
 *   2. Dangerous-role containment — remove only the roles that actually grant
 *      the configured dangerous permissions, only when the executor is
 *      confidently identified, only when the bot outranks the role, and never
 *      the server owner / the bot itself / a trusted role.
 *   3. Reversible lockdown — raise the verification level and (optionally)
 *      deny CreateInstantInvite for @everyone on channels that currently allow
 *      it, recording every change so it can be restored — and refusing to
 *      restore over a change an administrator made after the lockdown started.
 *
 * Every Discord-touching function is written to never throw: a containment
 * failure must degrade to "alert only", never crash the event handler. The
 * planning helpers (`computeDangerousRoleRemovals`, `planInvitePause`) are pure
 * over their inputs so the safety rules are unit-testable without a gateway.
 */

const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const { DANGEROUS_PERMISSION_BY_KEY } = require('./antiNukeRules');

// Event-specific colours (spec: critical red, high orange, medium yellow,
// protected green, informational blue).
const SEVERITY_COLORS = {
    critical: 0xED4245,
    high: 0xE67E22,
    medium: 0xFEE75C,
    protected: 0x57F287,
    info: 0x5865F2,
};

function severityColor(severity) {
    return SEVERITY_COLORS[String(severity || '').toLowerCase()] || SEVERITY_COLORS.info;
}

// ── Permission catalogue ────────────────────────────────────────────────────

// The permissions each protection module needs, with the human label shown on
// the dashboard's permission-validation step.
const REQUIRED_PERMISSIONS = [
    { key: 'ViewAuditLog',    label: 'View Audit Log',   flag: PermissionFlagsBits.ViewAuditLog,    neededFor: 'All modules (attribution)' },
    { key: 'ManageRoles',     label: 'Manage Roles',     flag: PermissionFlagsBits.ManageRoles,     neededFor: 'Role + permission containment' },
    { key: 'ManageChannels',  label: 'Manage Channels',  flag: PermissionFlagsBits.ManageChannels,  neededFor: 'Lockdown' },
    { key: 'BanMembers',      label: 'Ban Members',      flag: PermissionFlagsBits.BanMembers,      neededFor: 'Mass-ban response' },
    { key: 'ManageGuild',     label: 'Manage Server',    flag: PermissionFlagsBits.ManageGuild,     neededFor: 'Lockdown (verification level)' },
    { key: 'ManageWebhooks',  label: 'Manage Webhooks',  flag: PermissionFlagsBits.ManageWebhooks,  neededFor: 'Webhook protection' },
];

/**
 * Check the bot's permissions in a guild. Returns one entry per required
 * permission with `{ key, label, neededFor, available }`, plus an overall
 * `ok` flag. Never throws — a guild with no resolved bot member reports every
 * permission as unavailable rather than pretending protection works.
 */
function validateBotPermissions(guild) {
    const me = guild && guild.members && guild.members.me;
    const perms = me && me.permissions;
    const checks = REQUIRED_PERMISSIONS.map(p => {
        let available = false;
        try {
            available = Boolean(perms && typeof perms.has === 'function' && perms.has(p.flag));
        } catch (_) { available = false; }
        return { key: p.key, label: p.label, neededFor: p.neededFor, available };
    });
    const missing = checks.filter(c => !c.available).map(c => c.key);
    return { ok: missing.length === 0, checks, missing };
}

// ── Alert embeds ────────────────────────────────────────────────────────────

/**
 * Same check as `validateBotPermissions`, but from a raw permission bitfield
 * (the dashboard computes one from the bot's roles via REST, since it has no
 * gateway member object). `bitfield` may be a BigInt, a numeric string, or null
 * (→ everything unavailable).
 */
function validatePermissionsFromBitfield(bitfield) {
    let bits = null;
    try {
        if (bitfield != null) bits = BigInt(bitfield);
    } catch (_) { bits = null; }
    const checks = REQUIRED_PERMISSIONS.map(p => {
        let available = false;
        if (bits != null) {
            try { available = (bits & BigInt(p.flag)) === BigInt(p.flag); } catch (_) { available = false; }
        }
        return { key: p.key, label: p.label, neededFor: p.neededFor, available };
    });
    const missing = checks.filter(c => !c.available).map(c => c.key);
    return { ok: missing.length === 0, checks, missing };
}

/**
 * Build the premium security-alert embed. Pure (no Discord calls), so it is
 * unit-testable. `fields` are the incident-specific rows; the standard rows
 * (responsible user, actions detected, window, response, server, time) are
 * appended by the caller through `extraFields`.
 *
 * @param {object} p
 * @param {string} p.title        e.g. "Potential Nuke Attempt Detected"
 * @param {string} p.threatLabel  e.g. "Mass Channel Deletion"
 * @param {string} p.severity
 * @param {string} [p.executorLabel]  mention/label of the responsible user, or a reason
 * @param {string} [p.actionSummary]  e.g. "4 channel deletions"
 * @param {string} [p.windowLabel]    e.g. "10 seconds"
 * @param {string} [p.responseLabel]  e.g. "Dry-run / Containment"
 * @param {string} [p.guildName]
 * @param {Array}  [p.extraFields]
 * @param {boolean}[p.dryRun]
 */
function buildSecurityAlertEmbed(p = {}) {
    const color = severityColor(p.severity);
    const embed = new EmbedBuilder()
        .setColor(color)
        .setTitle('🛡️ PRIMEBOT SECURITY ALERT')
        .setDescription(p.title || 'Potential Nuke Attempt Detected')
        .setTimestamp();

    if (p.threatLabel) embed.addFields({ name: 'Threat type', value: String(p.threatLabel), inline: true });
    if (p.severity) embed.addFields({ name: 'Severity', value: String(p.severity).toUpperCase(), inline: true });
    if (p.executorLabel) embed.addFields({ name: 'Responsible user', value: String(p.executorLabel).slice(0, 1000), inline: false });
    if (p.actionSummary) embed.addFields({ name: 'Actions detected', value: String(p.actionSummary).slice(0, 1000), inline: true });
    if (p.windowLabel) embed.addFields({ name: 'Detection window', value: String(p.windowLabel), inline: true });
    if (p.responseLabel) embed.addFields({ name: 'Protection response', value: String(p.responseLabel).slice(0, 1000), inline: false });
    if (Array.isArray(p.extraFields)) {
        for (const f of p.extraFields) {
            if (f && f.name && f.value) embed.addFields({ name: String(f.name), value: String(f.value).slice(0, 1000), inline: !!f.inline });
        }
    }
    if (p.guildName) embed.addFields({ name: 'Server', value: String(p.guildName), inline: true });

    embed.setFooter({ text: p.dryRun ? 'PrimeBot Security System · DRY RUN' : 'PrimeBot Security System' });
    return embed;
}

// ── Dangerous-role containment ──────────────────────────────────────────────

/** The permission keys (from the catalog) that a role currently grants. */
function dangerousPermissionsOnRole(role, dangerousKeys) {
    // No configured dangerous permissions means "strip nothing" — NOT "strip
    // every catalog permission". Containment is opt-in, so an empty list is a
    // valid (alert-only) configuration and must never widen to the full catalog.
    const keys = Array.isArray(dangerousKeys) ? dangerousKeys : [];
    const hit = [];
    for (const key of keys) {
        const meta = DANGEROUS_PERMISSION_BY_KEY[key];
        if (!meta) continue;
        try {
            if (role.permissions && typeof role.permissions.has === 'function' && role.permissions.has(meta.flag)) {
                hit.push(key);
            }
        } catch (_) { /* a role without resolved permissions is skipped */ }
    }
    return hit;
}

/**
 * Decide which of `member`'s roles may be removed as containment. Pure over the
 * passed objects (no API calls), so the safety rules are directly testable.
 *
 * Safety rules applied, in order:
 *   • never the server owner, never the bot itself
 *   • never a role in trustedRoleIds
 *   • never @everyone (unremovable)
 *   • never an integration-managed role
 *   • never a role at/above the bot's highest role (would 50013)
 *   • only roles that actually grant a configured dangerous permission
 *
 * @returns {{ removable: Array, skipped: Array, reason: string|null }}
 */
function computeDangerousRoleRemovals({ member, botMember, guildOwnerId, botUserId, trustedRoleIds = [], dangerousPermissions = [] } = {}) {
    if (!member) return { removable: [], skipped: [], reason: 'no_member' };
    if (guildOwnerId && member.id === guildOwnerId) return { removable: [], skipped: [], reason: 'owner_exempt' };
    if (botUserId && member.id === botUserId) return { removable: [], skipped: [], reason: 'bot_exempt' };

    const trusted = new Set(trustedRoleIds);
    const botHighest = botMember && botMember.roles && botMember.roles.highest
        ? botMember.roles.highest.position
        : (botMember && botMember.roles && Array.isArray(botMember.roles.cache)
            ? Math.max(-1, ...botMember.roles.cache.map(r => r.position || 0))
            : -1);

    const removable = [];
    const skipped = [];
    const roles = member.roles && member.roles.cache
        ? Array.from(member.roles.cache.values())
        : [];

    for (const role of roles) {
        if (!role || role.id === (member.guild && member.guild.id)) continue; // @everyone
        const hits = dangerousPermissionsOnRole(role, dangerousPermissions);
        if (hits.length === 0) continue; // unrelated role — never touch it
        if (trusted.has(role.id)) { skipped.push({ roleId: role.id, name: role.name, reason: 'trusted_role', permissions: hits }); continue; }
        if (role.managed) { skipped.push({ roleId: role.id, name: role.name, reason: 'managed_role', permissions: hits }); continue; }
        if (typeof role.position === 'number' && botHighest >= 0 && role.position >= botHighest) {
            skipped.push({ roleId: role.id, name: role.name, reason: 'above_bot', permissions: hits });
            continue;
        }
        removable.push({ roleId: role.id, name: role.name, permissions: hits });
    }
    return { removable, skipped, reason: null };
}

/**
 * Remove the computed dangerous roles from the member. Returns a structured
 * result; never throws.
 */
async function stripDangerousRoles(member, plan, reason = 'Anti-Nuke containment') {
    const result = { removed: [], failed: [], skipped: plan && plan.skipped ? plan.skipped : [] };
    if (!member || !plan || !plan.removable || plan.removable.length === 0) return result;
    for (const item of plan.removable) {
        try {
            await member.roles.remove(item.roleId, reason);
            result.removed.push(item);
        } catch (err) {
            result.failed.push({ ...item, error: err.message });
        }
    }
    return result;
}

// ── Lockdown ────────────────────────────────────────────────────────────────

const VERIFICATION_LEVELS = { none: 0, low: 1, medium: 2, high: 3, veryHigh: 4 };
const MAX_LOCKDOWN_CHANNELS = 50;

/**
 * Read the allow/deny bits from a PermissionOverwrites object. discord.js v14
 * exposes them as a `Permissions` instance (`.bitfield`); tolerate a plain
 * `{ allow, deny }` object too. Returns `{ allow, deny }` as BigInt.
 */
function overwriteBits(ow) {
    if (!ow) return { allow: 0n, deny: 0n };
    try {
        const allow = ow.allow && ow.allow.bitfield != null ? ow.allow.bitfield : (ow.allow != null ? ow.allow : 0n);
        const deny = ow.deny && ow.deny.bitfield != null ? ow.deny.bitfield : (ow.deny != null ? ow.deny : 0n);
        return { allow: BigInt(allow), deny: BigInt(deny) };
    } catch (_) {
        return { allow: 0n, deny: 0n };
    }
}

/**
 * Plan the invite-pause changes for lockdown. Returns the channels whose
 * @everyone overwrite currently allows CreateInstantInvite and the overwrite to
 * apply, capped at `MAX_LOCKDOWN_CHANNELS` so a lockdown never fans out into an
 * unbounded burst of API calls.
 *
 * Pure over the passed guild (reads caches only, no API calls).
 */
function planInvitePause(guild) {
    const changes = [];
    if (!guild || !guild.channels || !guild.channels.cache) return changes;
    for (const channel of guild.channels.cache.values()) {
        if (changes.length >= MAX_LOCKDOWN_CHANNELS) break;
        try {
            // Only channels that currently allow @everyone to create invites.
            const everyone = channel.permissionOverwrites && channel.permissionOverwrites.cache
                ? channel.permissionOverwrites.cache.get(guild.id)
                : null;
            const allows = channel.permissionsFor
                ? channel.permissionsFor(guild.id) && channel.permissionsFor(guild.id).has(PermissionFlagsBits.CreateInstantInvite)
                : true;
            if (!allows) continue;
            const bits = overwriteBits(everyone);
            changes.push({
                channelId: channel.id,
                before: everyone ? { allow: String(bits.allow), deny: String(bits.deny) } : null,
            });
        } catch (_) { /* skip a channel we cannot read */ }
    }
    return changes;
}

/**
 * Apply lockdown. Saves the previous verification level and the invite
 * overwrites it changes, then raises the verification level and (when
 * configured) denies CreateInstantInvite for @everyone on the planned channels.
 *
 * @returns {Promise<object>} the lockdown record (also persisted by the caller)
 */
async function applyLockdown(guild, { settings, reason = 'Anti-Nuke lockdown', startedBy = null } = {}) {
    const lockCfg = (settings && settings.lockdown) || {};
    const record = {
        active: true,
        startedAt: new Date().toISOString(),
        reason,
        startedBy,
        verificationLevelBefore: null,
        verificationLevelAfter: null,
        inviteChanges: [],
        pausedInvites: false,
        warnings: [],
    };
    if (!guild) return { ...record, active: false, warnings: ['no_guild'] };

    // 1. Verification level (reversible, saved).
    try {
        const before = typeof guild.verificationLevel === 'number' ? guild.verificationLevel : null;
        const target = VERIFICATION_LEVELS[lockCfg.verificationLevel] != null
            ? VERIFICATION_LEVELS[lockCfg.verificationLevel]
            : VERIFICATION_LEVELS.high;
        record.verificationLevelBefore = before;
        if (before !== target) {
            await guild.setVerificationLevel(target, reason);
            record.verificationLevelAfter = target;
        } else {
            record.verificationLevelAfter = before;
        }
    } catch (err) {
        record.warnings.push(`verification_level: ${err.message}`);
    }

    // 2. Pause invites where supported (bounded + recorded).
    if (lockCfg.pauseInvites !== false) {
        const plan = planInvitePause(guild);
        for (const change of plan) {
            try {
                const channel = guild.channels.cache.get(change.channelId);
                if (!channel || typeof channel.permissionOverwrites?.edit !== 'function') continue;
                await channel.permissionOverwrites.edit(guild.id, { CreateInstantInvite: false }, { reason });
                record.inviteChanges.push(change);
            } catch (err) {
                record.warnings.push(`invite_pause:${change.channelId}: ${err.message}`);
            }
        }
        record.pausedInvites = record.inviteChanges.length > 0;
    }

    return record;
}

/**
 * Restore a lockdown. Reverts the verification level and each invite overwrite
 * that lockdown changed — but only when the current state still matches what
 * lockdown applied, so an administrator's later change is never clobbered.
 *
 * @returns {Promise<{ restored: object, warnings: string[] }>}
 */
async function restoreLockdown(guild, record, { reason = 'Anti-Nuke lockdown lifted' } = {}) {
    const warnings = [];
    const restored = { verificationLevel: false, invites: 0, skippedInvites: [] };
    if (!guild || !record) return { restored, warnings: ['no_guild_or_record'] };

    // Verification level: only revert if it is still what lockdown set.
    try {
        if (record.verificationLevelAfter != null && record.verificationLevelBefore != null) {
            const current = typeof guild.verificationLevel === 'number' ? guild.verificationLevel : null;
            if (current === record.verificationLevelAfter) {
                await guild.setVerificationLevel(record.verificationLevelBefore, reason);
                restored.verificationLevel = true;
            } else {
                warnings.push('verification_level_changed_by_admin');
            }
        }
    } catch (err) {
        warnings.push(`verification_level: ${err.message}`);
    }

    // Invite overwrites: only revert the channels we changed, and only when the
    // overwrite still matches what we applied.
    for (const change of record.inviteChanges || []) {
        try {
            const channel = guild.channels.cache.get(change.channelId);
            if (!channel || typeof channel.permissionOverwrites?.edit !== 'function') {
                warnings.push(`invite_restore_missing_channel:${change.channelId}`);
                continue;
            }
            const ow = channel.permissionOverwrites.cache.get(guild.id);
            const current = overwriteBits(ow);
            const stillDenied = (current.deny & PermissionFlagsBits.CreateInstantInvite) === PermissionFlagsBits.CreateInstantInvite;
            if (!stillDenied) { restored.skippedInvites.push(change.channelId); continue; }
            if (change.before) {
                await channel.permissionOverwrites.edit(guild.id, {
                    allow: BigInt(change.before.allow),
                    deny: BigInt(change.before.deny),
                }, { reason });
            } else {
                await channel.permissionOverwrites.edit(guild.id, { CreateInstantInvite: null }, { reason });
            }
            restored.invites++;
        } catch (err) {
            warnings.push(`invite_restore:${change.channelId}: ${err.message}`);
        }
    }

    return { restored, warnings };
}

module.exports = {
    SEVERITY_COLORS,
    severityColor,
    REQUIRED_PERMISSIONS,
    validateBotPermissions,
    validatePermissionsFromBitfield,
    buildSecurityAlertEmbed,
    dangerousPermissionsOnRole,
    computeDangerousRoleRemovals,
    stripDangerousRoles,
    VERIFICATION_LEVELS,
    planInvitePause,
    applyLockdown,
    restoreLockdown,
    MAX_LOCKDOWN_CHANNELS,
};
