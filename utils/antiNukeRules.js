/**
 * Anti-Nuke protection — per-guild configuration + detection catalog.
 *
 * Anti-Nuke watches the *destructive administrative* actions a compromised or
 * malicious moderator can perform (mass channel/role deletion, mass bans/kicks,
 * webhook and bot additions, permission rewrites) and alerts the server owner.
 * It is deliberately conservative: it never punishes anyone automatically, and
 * it never touches the server owner.
 *
 * ── Status ──────────────────────────────────────────────────────────────────
 * This module is the *data + configuration* layer. The dashboard tab is marked
 * `upcoming: true`, so the page renders the "Coming Soon……" overlay for every
 * server and the write endpoints are guarded by `requireUpcoming` (403 for
 * ordinary users; developer/owner bot roles bypass the gate so the feature can
 * be exercised). Nothing here is wired into Discord's audit-log events yet —
 * the detection executor lives behind the upcoming gate so shipping it cannot
 * surprise a guild with automatic moderation.
 *
 * Everything in this file is pure (catalog + normalizers + a merge helper) so it
 * can be unit-tested without a database or a Discord client.
 */

// Every dangerous action Anti-Nuke can watch. `auditEvent` is the discord.js
// AuditLogEvent name the future executor will subscribe to; it is recorded here
// so the catalog stays the single source of truth.
const NUKE_ACTIONS = [
    {
        key: 'channelDelete',
        label: 'Channel deletions',
        icon: '🗑️',
        iconName: 'trash',
        auditEvent: 'ChannelDelete',
        description: 'Channels deleted in bulk.',
        threshold: 3,
        seconds: 10,
        severity: 'critical',
    },
    {
        key: 'channelCreate',
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
        key: 'roleDelete',
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
        key: 'memberBan',
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
        key: 'webhookCreate',
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
        key: 'botAdd',
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
        key: 'permissionUpdate',
        label: 'Permission changes',
        icon: '🔑',
        iconName: 'key',
        auditEvent: 'ChannelOverwriteUpdate',
        description: 'Channel permission overwrites changed in bulk.',
        threshold: 5,
        seconds: 10,
        severity: 'high',
    },
    {
        key: 'guildUpdate',
        label: 'Server setting changes',
        icon: '⚙️',
        iconName: 'settings',
        auditEvent: 'GuildUpdate',
        description: 'Server settings (name, icon, verification) changed unexpectedly.',
        threshold: 2,
        seconds: 30,
        severity: 'medium',
    },
    {
        key: 'memberRoleUpdate',
        label: 'Mass role changes',
        icon: '🎭',
        iconName: 'role',
        auditEvent: 'MemberRoleUpdate',
        description: 'Roles added/removed across many members in bulk (privilege escalation).',
        threshold: 10,
        seconds: 20,
        severity: 'high',
    },
];
const NUKE_ACTION_KEYS = NUKE_ACTIONS.map(a => a.key);
const NUKE_ACTION_BY_KEY = Object.fromEntries(NUKE_ACTIONS.map(a => [a.key, a]));

// Response actions Anti-Nuke can take when a threshold trips. All of them are
// alerts/containment — none of them punish a member automatically.
const NUKE_RESPONSES = [
    { key: 'alertOwner',   label: 'Alert the server owner',      iconName: 'send',        description: 'DM the owner with the offending action and the responsible user.' },
    { key: 'alertChannel', label: 'Post to the alert channel',   iconName: 'megaphone',   description: 'Post a high-priority embed to the configured alert channel.' },
    { key: 'removeRoles',  label: 'Strip dangerous roles',       iconName: 'key',         description: 'Remove Administrator / Manage-* roles from the responsible user where safely possible.' },
    { key: 'lockdown',     label: 'Server lockdown',             iconName: 'lock',        description: 'Raise the verification level and pause new invites while the incident is reviewed.' },
    { key: 'logOnly',      label: 'Log only (no containment)',   iconName: 'scroll',      description: 'Record the incident and take no other action.' },
];
const NUKE_RESPONSE_KEYS = NUKE_RESPONSES.map(r => r.key);
const NUKE_RESPONSE_BY_KEY = Object.fromEntries(NUKE_RESPONSES.map(r => [r.key, r]));

const DEFAULT_NUKE_RESPONSES = ['alertOwner', 'alertChannel', 'logOnly'];

/** Default Anti-Nuke configuration (disabled until an admin opts in). */
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
        dryRun: true,
        updatedAt: null,
    };
}

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
 * canonical shape. Unknown action keys are dropped; thresholds are clamped.
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
    return {
        enabled: src.enabled === true,
        alertChannelId: src.alertChannelId ? String(src.alertChannelId) : null,
        responses: responses.length ? Array.from(new Set(responses)) : base.responses.slice(),
        trustedUserIds: _idList(src.trustedUserIds),
        trustedRoleIds: _idList(src.trustedRoleIds),
        watched,
        dryRun: src.dryRun !== false,
        updatedAt: src.updatedAt || null,
    };
}

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

module.exports = {
    NUKE_ACTIONS,
    NUKE_ACTION_KEYS,
    NUKE_ACTION_BY_KEY,
    NUKE_RESPONSES,
    NUKE_RESPONSE_KEYS,
    NUKE_RESPONSE_BY_KEY,
    DEFAULT_NUKE_RESPONSES,
    defaultAntiNukeSettings,
    normalizeAntiNukeSettings,
    isTrusted,
    evaluateBurst,
};
