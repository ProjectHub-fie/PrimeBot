/**
 * Anti-Nuke — centralized permission registry, presets and access-level
 * metadata.
 *
 * SINGLE SOURCE OF TRUTH for bot-defined Anti-Nuke access control. The server
 * authorization helper (utils/antiNukeAccess.js), the dashboard (render +
 * client), the Discord command and the tests all read from this catalog so a
 * permission id can never mean different things in two places.
 *
 * Four access levels:
 *   Level 1  the ACTUAL Discord guild owner (unrestricted, never removable)
 *   Level 2  bot-defined Co-Owner  (appointed by the owner; only assigned
 *            permissions — NOT granted by Discord Administrator status)
 *   Level 3  Trusted Admin (an individual member picked by the owner; only
 *            assigned permissions)
 *   Level 4  every other member (no Anti-Nuke management access by default —
 *            Discord Administrator/Moderator does not grant anything here)
 *
 * The owner is resolved server-side from Discord guild ownership data
 * (guild.ownerId / REST owner_id) — never from a client-supplied value.
 */

// ── The registry ────────────────────────────────────────────────────────────
//
// `group` maps into the Access Control UI sections; `ownerOnly` marks
// permissions that may never be delegated to a Co-Owner/Trusted Admin;
// `delegatable` marks permissions a manager may pass on within their own
// authority (a user can never receive a permission they do not already hold).
const ANTI_NUKE_PERMISSIONS = [
    // ── Dashboard Access ────────────────────────────────────────────────────
    {
        id: 'antinuke.view',
        label: 'View Anti-Nuke',
        description: 'View the Anti-Nuke dashboard and live protection status.',
        group: 'dashboard',
    },
    {
        id: 'antinuke.setup',
        label: 'Setup & resume',
        description: 'Run, resume and retry the Automatic and Manual setup wizards.',
        group: 'dashboard',
    },

    // ── Setup Management ────────────────────────────────────────────────────
    {
        id: 'antinuke.config',
        label: 'General configuration',
        description: 'Modify the general Anti-Nuke configuration (enable, alert channel, dry-run, lockdown policy).',
        group: 'setup',
        delegatable: true,
    },
    {
        id: 'antinuke.rules',
        label: 'Protection rules',
        description: 'Enable, disable and configure the watched detection rules and thresholds.',
        group: 'setup',
        delegatable: true,
    },
    {
        id: 'antinuke.raid.manage',
        label: 'Anti-Raid',
        description: 'Configure the Anti-Raid guard (join thresholds, account-age cutoff, automatic lockdown).',
        group: 'setup',
        delegatable: true,
    },
    {
        id: 'antinuke.health.view',
        label: 'Health & readiness',
        description: 'View the Anti-Nuke health scan and readiness diagnostics.',
        group: 'logs',
    },
    {
        id: 'antinuke.trusted.view',
        label: 'View trusted list',
        description: 'View the trusted users and roles.',
        group: 'setup',
    },
    {
        id: 'antinuke.trusted.manage',
        label: 'Manage trusted list',
        description: 'Add and remove trusted users and roles.',
        group: 'setup',
        delegatable: true,
    },

    // ── Response Management ─────────────────────────────────────────────────
    {
        id: 'antinuke.responses',
        label: 'Automated responses',
        description: 'Configure the automated protection responses and reaction plan.',
        group: 'responses',
        delegatable: true,
    },

    // ── Incident Management ─────────────────────────────────────────────────
    {
        id: 'antinuke.incidents.view',
        label: 'View incidents',
        description: 'View detected security incidents and the response taken.',
        group: 'incidents',
    },
    {
        id: 'antinuke.incidents.manage',
        label: 'Manage incidents',
        description: 'Review, resolve and manage security incidents.',
        group: 'incidents',
        delegatable: true,
    },
    {
        id: 'antinuke.incidents.export',
        label: 'Export incidents',
        description: 'Export the detected security incidents (JSON).',
        group: 'incidents',
    },

    // ── Backups ─────────────────────────────────────────────────────────────
    {
        id: 'antinuke.backup.view',
        label: 'View backups',
        description: 'View the Anti-Nuke configuration snapshots (roles, channels, settings).',
        group: 'backups',
    },
    {
        id: 'antinuke.backup.create',
        label: 'Create backups',
        description: 'Capture a new configuration snapshot.',
        group: 'backups',
        delegatable: true,
    },
    {
        id: 'antinuke.backup.restore',
        label: 'Restore backups',
        description: 'Restore roles, channels or settings from a snapshot (inside the bot\'s authority).',
        group: 'backups',
        delegatable: true,
        sensitive: true,
    },

    // ── Emergency Controls ──────────────────────────────────────────────────
    {
        id: 'antinuke.lockdown',
        label: 'Emergency lockdown',
        description: 'Trigger an emergency lockdown.',
        group: 'emergency',
        sensitive: true,
        delegatable: true,
    },
    {
        id: 'antinuke.recovery',
        label: 'Lockdown recovery',
        description: 'Restore protection after a lockdown.',
        group: 'emergency',
        sensitive: true,
        delegatable: true,
    },

    // ── Logs and Monitoring ─────────────────────────────────────────────────
    {
        id: 'antinuke.logs',
        label: 'Audit logs',
        description: 'View the Anti-Nuke activity and access-change audit trail.',
        group: 'logs',
    },

    // ── Access Control ──────────────────────────────────────────────────────
    // These ARE delegatable: the owner may grant a Co-Owner/Trusted Admin
    // limited access-management authority. The owner-only *actions* (appointing
    // a Co-Owner, touching the owner) are enforced as role/action rules in
    // utils/antiNukeAccess (canAppointCoOwners / cannot_modify_owner), not as
    // `ownerOnly` permission flags — that keeps them delegatable while making
    // the boundary unforgeable server-side.
    {
        id: 'antinuke.access.view',
        label: 'View access',
        description: 'View the delegated access assignments.',
        group: 'access',
    },
    {
        id: 'antinuke.access.manage',
        label: 'Manage access',
        description: 'Assign and modify delegated permissions within the manager\'s own authority.',
        group: 'access',
        delegatable: true,
        sensitive: true,
    },
    {
        id: 'antinuke.access.revoke',
        label: 'Revoke access',
        description: 'Revoke delegated access within the manager\'s own authority.',
        group: 'access',
        delegatable: true,
        sensitive: true,
    },
];

/** Stable index maps */
const ANTI_NUKE_PERMISSION_BY_ID = Object.fromEntries(ANTI_NUKE_PERMISSIONS.map(p => [p.id, p]));
const ANTI_NUKE_PERMISSION_GROUPS = ['dashboard', 'setup', 'responses', 'incidents', 'backups', 'emergency', 'logs', 'access'];

const ANTI_NUKE_GROUP_LABELS = {
    dashboard: 'Dashboard Access',
    setup: 'Setup Management',
    responses: 'Response Management',
    incidents: 'Incident Management',
    backups: 'Backups',
    emergency: 'Emergency Controls',
    logs: 'Logs and Monitoring',
    access: 'Access Control',
};

function permissionGroupLabel(group) {
    return ANTI_NUKE_GROUP_LABELS[group] || group;
}

function listPermissionsForGroup(group) {
    return ANTI_NUKE_PERMISSIONS.filter(p => p.group === group);
}

// ── Access levels ───────────────────────────────────────────────────────────

const ANTI_NUKE_LEVELS = {
    owner: { level: 1, label: 'Server Owner' },
    coOwner: { level: 2, label: 'Co-Owner' },
    trustedAdmin: { level: 3, label: 'Trusted Admin' },
    none: { level: 4, label: 'No Access' },
};

function levelFor(role) {
    return ANTI_NUKE_LEVELS[role] ? ANTI_NUKE_LEVELS[role].level : 4;
}

// ── Presets ─────────────────────────────────────────────────────────────────
//
// `ownerOnly` permissions are never included in a preset — the owner alone
// holds them. A preset applied by a manager is intersected with the manager's
// own effective set so a delegated manager can never grant what they do not
// hold (enforced both here and server-side).
const ANTI_NUKE_PRESETS = [
    {
        key: 'viewer',
        label: 'Viewer',
        description: 'Read-only. View the dashboard, protection status, incidents and logs.',
        permissions: ['antinuke.view', 'antinuke.incidents.view', 'antinuke.logs', 'antinuke.trusted.view'],
    },
    {
        key: 'securityMonitor',
        label: 'Security Monitor',
        description: 'Watches detection and incident activity. Read-only.',
        permissions: [
            'antinuke.view', 'antinuke.trusted.view', 'antinuke.incidents.view',
            'antinuke.logs', 'antinuke.responses',
        ],
    },
    {
        key: 'protectionManager',
        label: 'Protection Manager',
        description: 'Configures detection rules, thresholds, trusted lists and responses.',
        permissions: [
            'antinuke.view', 'antinuke.setup', 'antinuke.config', 'antinuke.rules',
            'antinuke.trusted.view', 'antinuke.trusted.manage', 'antinuke.responses',
            'antinuke.incidents.view', 'antinuke.logs',
        ],
    },
    {
        key: 'incidentManager',
        label: 'Incident Manager',
        description: 'Reviews and manages security incidents.',
        permissions: [
            'antinuke.view', 'antinuke.incidents.view', 'antinuke.incidents.manage',
            'antinuke.logs', 'antinuke.responses',
        ],
    },
    {
        key: 'emergencyResponder',
        label: 'Emergency Responder',
        description: 'Can trigger lockdown and recovery in an emergency. No configuration access.',
        permissions: [
            'antinuke.view', 'antinuke.incidents.view', 'antinuke.logs',
            'antinuke.lockdown', 'antinuke.recovery',
        ],
    },
    {
        key: 'custom',
        label: 'Custom',
        description: 'Manually selected permissions.',
        permissions: [],
    },
];

const ANTI_NUKE_PRESET_BY_KEY = Object.fromEntries(ANTI_NUKE_PRESETS.map(p => [p.key, p]));

/** Validate/coerce a raw permission list to a unique set of known ids. */
function normalizePermissionList(list) {
    return Array.from(new Set(
        (Array.isArray(list) ? list : [])
            .filter(id => typeof id === 'string' && ANTI_NUKE_PERMISSION_BY_ID[id]),
    ));
}

/**
 * Intersect a permission list with a manager's own effective set — the strict
 * delegation boundary. Presets do the same (see applyPreset).
 */
function intersectPermissions(list, authority) {
    const allowed = new Set(normalizePermissionList(authority));
    return normalizePermissionList(list).filter(id => allowed.has(id));
}

/** A preset's permissions, already stripped of owner-only ids. */
function presetPermissions(key) {
    const preset = ANTI_NUKE_PRESET_BY_KEY[key];
    if (!preset) return [];
    return ANTI_NUKE_PERMISSIONS
        .filter(p => preset.permissions.includes(p.id) && !p.ownerOnly)
        .map(p => p.id);
}

/** Apply a preset, capped to a manager's authority (empty = unlimited/owner). */
function applyPreset(key, authorityPermissions = null) {
    const perms = presetPermissions(key);
    if (authorityPermissions === null) return perms; // the owner — full preset
    return intersectPermissions(perms, authorityPermissions);
}

// ── The owner's implicit set ────────────────────────────────────────────────
const ALL_ANTI_NUKE_PERMISSION_IDS = ANTI_NUKE_PERMISSIONS.map(p => p.id);
const OWNER_PERMISSION_IDS = ALL_ANTI_NUKE_PERMISSION_IDS.slice();

// ── Convenience aggregate ───────────────────────────────────────────────────

function antiNukePermissionCatalog() {
    return {
        permissions: ANTI_NUKE_PERMISSIONS,
        groups: ANTI_NUKE_GROUPS_FOR_UI(),
        presets: ANTI_NUKE_PRESETS,
        levels: ANTI_NUKE_LEVELS,
    };
}

/** Grouped view for the permission matrix UI. */
function ANTI_NUKE_GROUPS_FOR_UI() {
    return ANTI_NUKE_PERMISSION_GROUPS.map(group => ({
        key: group,
        label: ANTI_NUKE_GROUP_LABELS[group],
        permissions: listPermissionsForGroup(group),
    }));
}

module.exports = {
    ANTI_NUKE_PERMISSIONS,
    ANTI_NUKE_PERMISSION_BY_ID,
    ANTI_NUKE_PERMISSION_GROUPS,
    ANTI_NUKE_GROUP_LABELS,
    ANTI_NUKE_LEVELS,
    ANTI_NUKE_PRESETS,
    ANTI_NUKE_PRESET_BY_KEY,
    ALL_ANTI_NUKE_PERMISSION_IDS,
    OWNER_PERMISSION_IDS,
    permissionGroupLabel,
    listPermissionsForGroup,
    normalizePermissionList,
    intersectPermissions,
    presetPermissions,
    applyPreset,
    levelFor,
    antiNukePermissionCatalog,
};