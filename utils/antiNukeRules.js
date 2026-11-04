/**
 * Anti-Nuke protection — per-guild configuration + detection catalog.
 *
 * Anti-Nuke watches the *destructive administrative* actions a compromised or
 * malicious moderator can perform (mass channel/role deletion, mass bans/kicks,
 * webhook and bot additions, permission rewrites) and — when a threshold trips —
 * alerts the owner and applies reversible containment.
 *
 * It is deliberately conservative: it never punishes the server owner, the bot
 * itself, trusted users/roles, or anyone whose responsibility could not be
 * established from the audit log, and it never bans/kicks a moderator
 * automatically.
 *
 * Everything in this file is pure (catalog + normalizers + merge helpers) so it
 * can be unit-tested without a database or a Discord client. The stateful
 * executor lives in utils/antiNukeManager.js, the audit-log correlation in
 * utils/antiNukeAudit.js, the sliding-window detector in
 * utils/antiNukeDetector.js and the containment/lockdown actions in
 * utils/antiNukeContainment.js.
 */

// ── Protection modules ──────────────────────────────────────────────────────
//
// Seven independent protection modules, each owning one or more watched actions.
// `key` is stable and used by the dashboard section rail + the settings
// normalizer; `iconName` is an SVG icon from dashboard/public/js/icons.js.
const NUKE_MODULES = [
    { key: 'channel',    label: 'Channel Protection',  iconName: 'hash',      description: 'Mass channel/category deletion or creation and unauthorized channel edits.' },
    { key: 'role',       label: 'Role Protection',     iconName: 'role',      description: 'Mass role deletion/creation and dangerous role permission changes.' },
    { key: 'member',     label: 'Member Protection',   iconName: 'users',     description: 'Mass bans, kicks and role changes across members.' },
    { key: 'webhook',    label: 'Webhook Protection',  iconName: 'link',      description: 'Webhook creation, deletion and modification.' },
    { key: 'bot',        label: 'Bot Protection',      iconName: 'robot',     description: 'Bots added by untrusted users and bot permission escalation.' },
    { key: 'server',     label: 'Server Protection',   iconName: 'settings',  description: 'Sensitive server settings (name, icon, verification level).' },
    { key: 'permission', label: 'Permission Protection', iconName: 'key',     description: 'Administrator and Manage-* permission grants.' },
];
const NUKE_MODULE_KEYS = NUKE_MODULES.map(m => m.key);
const NUKE_MODULE_BY_KEY = Object.fromEntries(NUKE_MODULES.map(m => [m.key, m]));

// ── Watched actions (the single source of truth) ────────────────────────────
//
// `auditEvent` is the discord.js AuditLogEvent name the detector correlates
// against. `targetType` is an optional filter applied to the correlated audit
// entry (e.g. only count ChannelDelete entries whose target was a category).
// `permission` marks a permission-protection action (granted via a role
// assignment or role update).
const NUKE_ACTIONS = [
    // ── Channel protection ──────────────────────────────────────────────────
    {
        key: 'channelDelete',
        module: 'channel',
        label: 'Channel deletions',
        icon: '🗑️',
        iconName: 'trash',
        auditEvent: 'ChannelDelete',
        description: 'Text/voice channels deleted in bulk.',
        threshold: 3,
        seconds: 10,
        severity: 'critical',
    },
    {
        key: 'channelCreate',
        module: 'channel',
        label: 'Channel creations',
        icon: '➕',
        iconName: 'plus',
        auditEvent: 'ChannelCreate',
        description: 'Channels created in bulk (often spam channels).',
        threshold: 5,
        seconds: 10,
        severity: 'high',
    },
    {
        key: 'channelUpdate',
        module: 'channel',
        label: 'Channel updates',
        icon: 'pencil',
        iconName: 'pencil',
        auditEvent: 'ChannelUpdate',
        description: 'Channels renamed or reconfigured unexpectedly.',
        threshold: 5,
        seconds: 15,
        severity: 'medium',
    },
    {
        key: 'categoryDelete',
        module: 'channel',
        label: 'Category deletions',
        icon: 'trash',
        iconName: 'trash',
        auditEvent: 'ChannelDelete',
        targetType: 4, // ChannelType.GuildCategory — deleting a category deletes its channels
        description: 'Categories deleted in bulk (removes every channel inside).',
        threshold: 2,
        seconds: 10,
        severity: 'critical',
    },
    // ── Role protection ─────────────────────────────────────────────────────
    {
        key: 'roleDelete',
        module: 'role',
        label: 'Role deletions',
        icon: '🗑️',
        iconName: 'trash',
        auditEvent: 'RoleDelete',
        description: 'Roles deleted in bulk.',
        threshold: 3,
        seconds: 10,
        severity: 'critical',
    },
    {
        key: 'roleCreate',
        module: 'role',
        label: 'Role creations',
        icon: '➕',
        iconName: 'plus',
        auditEvent: 'RoleCreate',
        description: 'Roles created in bulk.',
        threshold: 5,
        seconds: 10,
        severity: 'medium',
    },
    {
        key: 'rolePermissionUpdate',
        module: 'role',
        label: 'Role permission changes',
        icon: 'key',
        iconName: 'key',
        auditEvent: 'RoleUpdate',
        description: 'Role permission bits changed (privilege escalation).',
        threshold: 3,
        seconds: 15,
        severity: 'high',
    },
    // ── Member protection ───────────────────────────────────────────────────
    {
        key: 'memberBan',
        module: 'member',
        label: 'Mass bans',
        icon: '🔨',
        iconName: 'ban',
        auditEvent: 'MemberBanAdd',
        description: 'Members banned in bulk.',
        threshold: 5,
        seconds: 10,
        severity: 'critical',
    },
    {
        key: 'memberKick',
        module: 'member',
        label: 'Mass kicks',
        icon: '👢',
        iconName: 'userX',
        auditEvent: 'MemberKick',
        description: 'Members kicked in bulk.',
        threshold: 5,
        seconds: 10,
        severity: 'critical',
    },
    {
        key: 'memberRoleUpdate',
        module: 'member',
        label: 'Mass role changes',
        icon: '🎭',
        iconName: 'role',
        auditEvent: 'MemberRoleUpdate',
        description: 'Roles added/removed across many members in bulk (privilege escalation).',
        threshold: 10,
        seconds: 20,
        severity: 'high',
    },
    // ── Webhook protection ──────────────────────────────────────────────────
    {
        key: 'webhookCreate',
        module: 'webhook',
        label: 'Webhook creation',
        icon: '🔗',
        iconName: 'link',
        auditEvent: 'WebhookCreate',
        description: 'Webhooks created (often used to spam or exfiltrate).',
        threshold: 2,
        seconds: 30,
        severity: 'high',
    },
    {
        key: 'webhookDelete',
        module: 'webhook',
        label: 'Webhook deletion',
        icon: '🔗',
        iconName: 'linkOff',
        auditEvent: 'WebhookDelete',
        description: 'Webhooks deleted in bulk.',
        threshold: 3,
        seconds: 30,
        severity: 'medium',
    },
    {
        key: 'webhookUpdate',
        module: 'webhook',
        label: 'Webhook changes',
        icon: 'pencil',
        iconName: 'pencil',
        auditEvent: 'WebhookUpdate',
        description: 'Existing webhooks renamed or retargeted.',
        threshold: 3,
        seconds: 30,
        severity: 'medium',
    },
    // ── Bot protection ──────────────────────────────────────────────────────
    {
        key: 'botAdd',
        module: 'bot',
        label: 'Bot additions',
        icon: '🤖',
        iconName: 'robot',
        auditEvent: 'BotAdd',
        description: 'Bots added to the server by a non-owner.',
        threshold: 1,
        seconds: 60,
        severity: 'high',
    },
    {
        key: 'botPermissionEscalation',
        module: 'bot',
        label: 'Bot permission escalation',
        icon: 'key',
        iconName: 'key',
        auditEvent: 'MemberRoleUpdate',
        description: 'A bot member was granted a dangerous role/permission.',
        threshold: 1,
        seconds: 60,
        severity: 'high',
    },
    // ── Server protection ───────────────────────────────────────────────────
    {
        key: 'guildUpdate',
        module: 'server',
        label: 'Server setting changes',
        icon: '⚙️',
        iconName: 'settings',
        auditEvent: 'GuildUpdate',
        description: 'Server settings (name, icon, verification) changed unexpectedly.',
        threshold: 2,
        seconds: 30,
        severity: 'medium',
    },
    // ── Permission protection ───────────────────────────────────────────────
    {
        key: 'permissionUpdate',
        module: 'channel',
        label: 'Permission overwrites',
        icon: '🔑',
        iconName: 'key',
        auditEvent: 'ChannelOverwriteUpdate',
        description: 'Channel permission overwrites changed in bulk.',
        threshold: 5,
        seconds: 10,
        severity: 'high',
    },
    {
        key: 'adminGrant',
        module: 'permission',
        label: 'Administrator grants',
        icon: '👑',
        iconName: 'shieldAlert',
        auditEvent: 'MemberRoleUpdate',
        permission: 'Administrator',
        description: 'The Administrator permission was granted to a member.',
        threshold: 1,
        seconds: 30,
        severity: 'critical',
    },
    {
        key: 'dangerousPermissionGrant',
        module: 'permission',
        label: 'Dangerous permission grants',
        icon: '🔑',
        iconName: 'key',
        auditEvent: 'RoleUpdate',
        permission: 'dangerous',
        description: 'Ban/Kick/Manage-Webhooks style permissions granted to a role.',
        threshold: 2,
        seconds: 30,
        severity: 'high',
    },
    {
        key: 'manageGuildGrant',
        module: 'permission',
        label: 'Manage Server grants',
        icon: '🔑',
        iconName: 'key',
        auditEvent: 'RoleUpdate',
        permission: 'ManageGuild',
        description: 'The Manage Server permission was granted.',
        threshold: 1,
        seconds: 30,
        severity: 'high',
    },
    {
        key: 'manageRolesGrant',
        module: 'permission',
        label: 'Manage Roles grants',
        icon: '🔑',
        iconName: 'key',
        auditEvent: 'RoleUpdate',
        permission: 'ManageRoles',
        description: 'The Manage Roles permission was granted.',
        threshold: 1,
        seconds: 30,
        severity: 'high',
    },
    {
        key: 'manageChannelsGrant',
        module: 'permission',
        label: 'Manage Channels grants',
        icon: '🔑',
        iconName: 'key',
        auditEvent: 'RoleUpdate',
        permission: 'ManageChannels',
        description: 'The Manage Channels permission was granted.',
        threshold: 1,
        seconds: 30,
        severity: 'high',
    },
];
const NUKE_ACTION_KEYS = NUKE_ACTIONS.map(a => a.key);
const NUKE_ACTION_BY_KEY = Object.fromEntries(NUKE_ACTIONS.map(a => [a.key, a]));

/** Watched actions belonging to one protection module. */
function actionsForModule(moduleKey) {
    return NUKE_ACTIONS.filter(a => a.module === moduleKey);
}

// ── Response catalog ────────────────────────────────────────────────────────
//
// Every response is an alert or reversible containment — none of them punish a
// member automatically. `dangerous: true` marks the responses that change
// server/member state (the dashboard asks for confirmation before enabling
// them, and the executor applies them only when the executor is confidently
// identified).
const NUKE_RESPONSES = [
    { key: 'alertOwner',   label: 'Alert the server owner',    iconName: 'send',      description: 'DM the owner with the offending action and the responsible user.' },
    { key: 'alertChannel', label: 'Post to the alert channel', iconName: 'megaphone', description: 'Post a high-priority embed to the configured alert channel.' },
    { key: 'removeRoles',  label: 'Strip dangerous roles',     iconName: 'key',       dangerous: true, description: 'Remove Administrator / Manage-* roles from the responsible user where safely possible.' },
    { key: 'lockdown',     label: 'Server lockdown',           iconName: 'lock',      dangerous: true, description: 'Raise the verification level and pause new invites while the incident is reviewed.' },
    { key: 'manualReview', label: 'Flag for manual review',    iconName: 'eye',       description: 'Record the incident as needing a human decision (no automatic containment).' },
    { key: 'logOnly',      label: 'Log only (no containment)', iconName: 'scroll',    description: 'Record the incident and take no other action.' },
];
const NUKE_RESPONSE_KEYS = NUKE_RESPONSES.map(r => r.key);
const NUKE_RESPONSE_BY_KEY = Object.fromEntries(NUKE_RESPONSES.map(r => [r.key, r]));

const DEFAULT_NUKE_RESPONSES = ['alertOwner', 'alertChannel', 'logOnly'];

// ── Dangerous permissions ───────────────────────────────────────────────────
//
// The permissions considered dangerous for containment + permission-grant
// detection. Admins can narrow this list from the dashboard (they cannot widen
// it past this catalog, so the bot never strips an unexpected permission).
const DANGEROUS_PERMISSIONS = [
    { key: 'Administrator',  label: 'Administrator',   flag: 8n,         default: true },
    { key: 'ManageGuild',    label: 'Manage Server',   flag: 32n,        default: true },
    { key: 'ManageRoles',    label: 'Manage Roles',    flag: 268435456n, default: true },
    { key: 'ManageChannels', label: 'Manage Channels', flag: 16n,        default: true },
    { key: 'ManageWebhooks', label: 'Manage Webhooks', flag: 536870912n, default: false },
    { key: 'BanMembers',     label: 'Ban Members',     flag: 4n,         default: false },
    { key: 'KickMembers',    label: 'Kick Members',    flag: 2n,         default: false },
];
const DANGEROUS_PERMISSION_KEYS = DANGEROUS_PERMISSIONS.map(p => p.key);
const DANGEROUS_PERMISSION_BY_KEY = Object.fromEntries(DANGEROUS_PERMISSIONS.map(p => [p.key, p]));

// ── Default configuration ───────────────────────────────────────────────────

/**
 * Default Anti-Nuke configuration. Safe by default: disabled until an admin
 * opts in, and dry-run until they explicitly turn it off.
 */
function defaultAntiNukeSettings() {
    const watched = {};
    for (const a of NUKE_ACTIONS) {
        watched[a.key] = {
            enabled: a.severity === 'critical' || a.severity === 'high',
            threshold: a.threshold,
            seconds: a.seconds,
        };
    }
    return {
        enabled: false,
        alertChannelId: null,
        responses: DEFAULT_NUKE_RESPONSES.slice(),
        // Users/roles that are never treated as a threat (e.g. the rest of the
        // staff team). The server owner is ALWAYS exempt, regardless of config.
        trustedUserIds: [],
        trustedRoleIds: [],
        watched,
        // Reversible-containment + lockdown configuration.
        dangerousPermissions: DANGEROUS_PERMISSIONS.filter(p => p.default).map(p => p.key),
        lockdown: {
            enabled: true,
            verificationLevel: 'high',
            pauseInvites: true,
        },
        responseCooldownSeconds: 30,
        dryRun: true,
        updatedAt: null,
    };
}

// ── Normalizers ─────────────────────────────────────────────────────────────

function _int(v, fallback, { min = 1, max = 1000 } = {}) {
    const n = Number(v);
    if (!Number.isFinite(n)) return fallback;
    const i = Math.floor(n);
    return i >= min && i <= max ? i : fallback;
}

function _idList(v) {
    if (!Array.isArray(v)) return [];
    // Trusted user/role ids are ALWAYS Discord snowflakes (15-22 digits, the
    // same bound utils/resolveUserId.js uses). Only strings are accepted: a
    // JSON number would be parsed as a double and lose precision past 2^53, so
    // `222222222222222222` would silently become `222222222222222200`.
    return Array.from(new Set(
        v.filter(x => typeof x === 'string').map(x => x.trim()).filter(x => /^\d{15,22}$/.test(x)),
    )).slice(0, 100);
}

/**
 * Normalize a raw Anti-Nuke config (from the DB row or an API patch) into the
 * canonical shape. Unknown action keys are dropped; thresholds are clamped;
 * trusted ids are validated; unknown responses are rejected.
 */
function normalizeAntiNukeSettings(raw = {}) {
    const base = defaultAntiNukeSettings();
    const src = raw && typeof raw === 'object' ? raw : {};
    const watched = {};
    for (const action of NUKE_ACTIONS) {
        const incoming = src.watched && src.watched[action.key];
        const prev = base.watched[action.key];
        watched[action.key] = {
            enabled: incoming && 'enabled' in incoming ? incoming.enabled !== false : prev.enabled,
            threshold: _int(incoming && incoming.threshold, prev.threshold, { min: 1, max: 100 }),
            seconds: _int(incoming && incoming.seconds, prev.seconds, { min: 1, max: 3600 }),
        };
    }
    const responses = Array.isArray(src.responses)
        ? src.responses.filter(r => NUKE_RESPONSE_BY_KEY[r])
        : base.responses.slice();

    // Dangerous permissions: only keys from the catalog are accepted. The list
    // may be EMPTY — containment is opt-in and an admin may choose to strip
    // nothing (e.g. an alert-only setup), so this is never forced back to a
    // default. `containment` treats an empty list as "nothing to strip".
    const dpIn = Array.isArray(src.dangerousPermissions)
        ? Array.from(new Set(src.dangerousPermissions.filter(p => DANGEROUS_PERMISSION_KEYS.includes(p))))
        : base.dangerousPermissions.slice();
    const dangerousPermissions = dpIn;

    const lockSrc = (src.lockdown && typeof src.lockdown === 'object') ? src.lockdown : {};
    const lockdown = {
        enabled: lockSrc.enabled !== undefined ? lockSrc.enabled !== false : base.lockdown.enabled,
        verificationLevel: ['none', 'low', 'medium', 'high', 'veryHigh'].includes(lockSrc.verificationLevel)
            ? lockSrc.verificationLevel
            : base.lockdown.verificationLevel,
        pauseInvites: lockSrc.pauseInvites !== undefined ? lockSrc.pauseInvites !== false : base.lockdown.pauseInvites,
    };

    return {
        enabled: src.enabled === true,
        alertChannelId: src.alertChannelId ? String(src.alertChannelId) : null,
        responses: responses.length ? Array.from(new Set(responses)) : base.responses.slice(),
        trustedUserIds: _idList(src.trustedUserIds),
        trustedRoleIds: _idList(src.trustedRoleIds),
        watched,
        dangerousPermissions,
        lockdown,
        responseCooldownSeconds: _int(src.responseCooldownSeconds, base.responseCooldownSeconds, { min: 0, max: 3600 }),
        dryRun: src.dryRun !== false,
        updatedAt: src.updatedAt || null,
    };
}

// ── Trust + threshold helpers ───────────────────────────────────────────────

/**
 * Is `userId` exempt from Anti-Nuke? The server owner always is. Trusted users
 * and members holding a trusted role are exempt too. Never throws.
 */
function isTrusted({ userId, roleIds = [], guildOwnerId, settings } = {}) {
    if (!userId) return true;
    if (guildOwnerId && userId === guildOwnerId) return true;
    const s = settings || {};
    if (Array.isArray(s.trustedUserIds) && s.trustedUserIds.includes(userId)) return true;
    if (Array.isArray(s.trustedRoleIds) && s.trustedRoleIds.length
        && roleIds.some(r => s.trustedRoleIds.includes(r))) return true;
    return false;
}

/**
 * Evaluate a burst of audit-log actions against the watched thresholds.
 * `counts` is `{ actionKey: [{ ts, userId }] }`; the caller owns the windows
 * (in-memory, never persisted). Returns the list of tripped actions.
 */
function evaluateBurst(counts, settings, now = Date.now()) {
    const tripped = [];
    const s = settings || {};
    for (const action of NUKE_ACTIONS) {
        const watch = s.watched && s.watched[action.key];
        if (!watch || watch.enabled === false) continue;
        const entries = Array.isArray(counts[action.key]) ? counts[action.key] : [];
        const windowMs = watch.seconds * 1000;
        const recent = entries.filter(e => now - e.ts < windowMs);
        if (recent.length >= watch.threshold) {
            tripped.push({
                action: action.key,
                label: action.label,
                module: action.module,
                severity: action.severity,
                count: recent.length,
                threshold: watch.threshold,
                seconds: watch.seconds,
                userId: recent[recent.length - 1].userId || null,
            });
        }
    }
    return tripped;
}

/**
 * Resolve the effective watched config for one action, falling back to the
 * catalog defaults when the guild has no override. Used by the detector so an
 * action added to the catalog after a guild saved its config still has sane
 * bounds.
 */
function watchFor(settings, actionKey) {
    const action = NUKE_ACTION_BY_KEY[actionKey];
    if (!action) return null;
    const w = settings && settings.watched && settings.watched[actionKey];
    return {
        enabled: w ? w.enabled !== false : (action.severity === 'critical' || action.severity === 'high'),
        threshold: w && w.threshold ? w.threshold : action.threshold,
        seconds: w && w.seconds ? w.seconds : action.seconds,
    };
}

module.exports = {
    NUKE_MODULES,
    NUKE_MODULE_KEYS,
    NUKE_MODULE_BY_KEY,
    actionsForModule,
    NUKE_ACTIONS,
    NUKE_ACTION_KEYS,
    NUKE_ACTION_BY_KEY,
    NUKE_RESPONSES,
    NUKE_RESPONSE_KEYS,
    NUKE_RESPONSE_BY_KEY,
    DEFAULT_NUKE_RESPONSES,
    DANGEROUS_PERMISSIONS,
    DANGEROUS_PERMISSION_KEYS,
    DANGEROUS_PERMISSION_BY_KEY,
    defaultAntiNukeSettings,
    normalizeAntiNukeSettings,
    isTrusted,
    evaluateBurst,
    watchFor,
};
