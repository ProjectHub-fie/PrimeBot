/**
 * Anti-Nuke — audit-log action catalog.
 *
 * The `antinuke_access_history` table stores one row per sensitive access /
 * setup change. The action strings here are the stable identifiers shared by
 * the server authorization helper, the dashboard API and the Discord command.
 *
 * Audit rows are append-only: no endpoint ever deletes or rewrites them.
 */

const ANTI_NUKE_AUDIT_ACTIONS = [
    'co_owner_appointed',
    'co_owner_removed',
    'trusted_admin_added',
    'trusted_admin_removed',
    'permissions_updated',
    'preset_applied',
    'access_revoked',
    'setup_started',
    'setup_step',
    'setup_completed',
    'setup_failed',
    'setup_reset',
    'setup_resumed',
    'protection_changed',
    'lockdown_engaged',
    'lockdown_restored',
];

const ANTI_NUKE_AUDIT_ACTION_SET = new Set(ANTI_NUKE_AUDIT_ACTIONS);

function normalizeAuditAction(action) {
    return ANTI_NUKE_AUDIT_ACTION_SET.has(action) ? action : 'permissions_updated';
}

module.exports = {
    ANTI_NUKE_AUDIT_ACTIONS,
    ANTI_NUKE_AUDIT_ACTION_SET,
    normalizeAuditAction,
};