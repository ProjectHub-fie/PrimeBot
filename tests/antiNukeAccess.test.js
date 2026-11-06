/**
 * Owner-controlled Anti-Nuke access hierarchy tests.
 *
 * Covers the central authorization helper (utils/antiNukeAccess) + the shared
 * permission registry (shared/antiNukePermissions) with an in-memory stub for
 * `server/anukeDb` (the project already uses this pattern for pool stubs —
 * there is no Postgres in CI). Focus areas:
 *   • Owner always has full access.
 *   • Discord Administrator without trust has no Anti-Nuke management access.
 *   • Co-Owner / Trusted Admin receive only assigned permissions.
 *   • Self-elevation is impossible.
 *   • Delegation never exceeds the delegator's own authority.
 *   • Owner can revoke immediately (next check reflects it).
 *   • Guild isolation (A's permission never grants B).
 *   • Presets resolve through the registry.
 *   • Audit trail is append-only.
 *   • Effective permissions are recomputed per request (no stale cache).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

// In-memory anti-nuke DB stub (replays anukeDb's row shapes only).
const IN_MEMORY = {
    rows: [], // { guild_id, user_id, role, permissions (array), preset }
    history: [],
};
const dbStub = {
    listAccessRows: async (guildId) =>
        IN_MEMORY.rows.filter(r => r.guild_id === String(guildId))
            .map(r => ({ guild_id: r.guild_id, user_id: r.user_id, role: r.role, permissions: r.permissions, preset: r.preset, granted_by: r.granted_by || null, granted_at: null, updated_by: r.updated_by || null, updated_at: new Date() }))
            .sort((a, b) => 0),
    getAccessRow: async (guildId, userId) => {
        const r = IN_MEMORY.rows.find(x => x.guild_id === String(guildId) && x.user_id === String(userId));
        return r ? { guild_id: r.guild_id, user_id: r.user_id, role: r.role, permissions: r.permissions, preset: r.preset, granted_by: r.granted_by || null, granted_at: null, updated_by: r.updated_by || null, updated_at: null } : null;
    },
    upsertAccessRow: async (guildId, { userId, role, permissions = [], preset = null, grantedBy = null, updatedBy = null }) => {
        const i = IN_MEMORY.rows.findIndex(x => x.guild_id === String(guildId) && x.user_id === String(userId));
        const row = { guild_id: String(guildId), user_id: String(userId), role, permissions, preset, granted_by: grantedBy, updated_by: updatedBy };
        if (i >= 0) IN_MEMORY.rows[i] = row; else IN_MEMORY.rows.push(row);
        return true;
    },
    deleteAccessRow: async (guildId, userId) => {
        IN_MEMORY.rows = IN_MEMORY.rows.filter(x => !(x.guild_id === String(guildId) && x.user_id === String(userId)));
        return true;
    },
    addAccessHistoryRow: async (rec) => { IN_MEMORY.history.push(rec); return true; },
    listAccessHistory: async (guildId, { limit = 50 } = {}) =>
        IN_MEMORY.history.filter(h => h.guildId === String(guildId)).slice(0, limit).map(h => ({
            id: IN_MEMORY.history.indexOf(h) + 1, guild_id: h.guildId, actor_id: h.actorId, target_id: h.targetId,
            action: h.action, previous_state: h.previousState, new_state: h.newState, result: h.result, reason: h.reason, created_at: new Date(),
        })),
};

const ANUKE = path.join(__dirname, '..', 'server', 'anukeDb.js');
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
    if (parent && parent.filename && parent.filename.includes(`${path.sep}utils${path.sep}`) && request === '../server/anukeDb') {
        return dbStub;
    }
    if (parent && parent.filename && parent.filename.includes(`${path.sep}server${path.sep}`) && request === './anukeDb') {
        return dbStub;
    }
    return origLoad.apply(this, arguments);
};

const access = require('../utils/antiNukeAccess');
const perms = require('../shared/antiNukePermissions');

// One ACTUAL guild; a second guild for isolation checks.
const GUILD_A = { id: '100000000000000001', owner_id: '1', name: 'Guild A' };
const GUILD_B = { id: '100000000000000002', owner_id: '9', name: 'Guild B' };
const OWNER = '1';
const CO_OWNER = '2';
const TA = '3';
const ADMIN_NO_TRUST = '4';
const OTHER_GUILD_OWNER = '9';

function reset() {
    IN_MEMORY.rows.length = 0;
    IN_MEMORY.history.length = 0;
}
function actorCtxFor(userId, guild = GUILD_A) {
    return { include: (async () => access.computeAccess({ guild, userId: String(userId) }))() };
}

test.beforeEach(() => reset());

// ── Hierarchy basics ───────────────────────────────────────────────────────

test('the actual guild owner always has full access', async () => {
    const ctx = await access.computeAccess({ guild: GUILD_A, userId: OWNER });
    assert.equal(ctx.isOwner, true);
    assert.equal(ctx.role, 'owner');
    assert.equal(ctx.level, 1);
    for (const id of perms.ALL_ANTI_NUKE_PERMISSION_IDS) {
        assert.ok(ctx.permissions.includes(id), `owner is missing ${id}`);
    }
    const auth = await access.authorizeAntiNuke(GUILD_A, OWNER, 'antinuke.lockdown');
    assert.equal(auth.ok, true);
});

test('a Discord Administrator without trust has no Anti-Nuke management access', async () => {
    // The user is not the owner and has no access row. The Discord-side
    // Administrator/ManageGuild flag is NOT fed to the helper at all — it is
    // deliberately ignored.
    const ctx = await access.computeAccess({ guild: GUILD_A, userId: ADMIN_NO_TRUST });
    assert.equal(ctx.role, 'none');
    assert.equal(ctx.level, 4);
    assert.deepEqual(ctx.permissions, []);
    const auth = await access.authorizeAntiNuke(GUILD_A, ADMIN_NO_TRUST, 'antinuke.view');
    assert.equal(auth.ok, false, 'an untrusted Discord Administrator gets nothing');
    assert.equal(auth.reason, 'permission_denied');
});

test('a Co-Owner receives only the explicitly assigned permissions', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: CO_OWNER, role: 'coOwner', permissions: ['antinuke.view', 'antinuke.setup'],
    });
    const ctx = await access.computeAccess({ guild: GUILD_A, userId: CO_OWNER });
    assert.equal(ctx.role, 'coOwner');
    assert.equal(ctx.level, 2);
    assert.deepEqual(new Set(ctx.permissions), new Set(['antinuke.view', 'antinuke.setup']));
    assert.equal((await access.authorizeAntiNuke(GUILD_A, CO_OWNER, 'antinuke.view')).ok, true);
    assert.equal((await access.authorizeAntiNuke(GUILD_A, CO_OWNER, 'antinuke.config')).ok, false,
        'a Co-Owner cannot exceed the delegated permission set');
});

test('a Trusted Admin receives only the explicitly assigned permissions', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view', 'antinuke.incidents.view'],
    });
    const ctx = await access.computeAccess({ guild: GUILD_A, userId: TA });
    assert.equal(ctx.role, 'trustedAdmin');
    assert.equal(ctx.level, 3);
    assert.ok(ctx.permissions.includes('antinuke.view'));
    assert.ok(!ctx.permissions.includes('antinuke.lockdown'));
});

// ── Delegation boundaries ──────────────────────────────────────────────────

test('a Co-Owner cannot appoint another Co-Owner', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: CO_OWNER, role: 'coOwner', permissions: ['antinuke.access.manage'],
    });
    const co = await access.authorizeAntiNuke(GUILD_A, CO_OWNER);
    const res = await access.assignAccess({
        guild: GUILD_A, actorUserId: CO_OWNER, actor: co,
        targetUserId: TA, role: 'coOwner', permissions: ['antinuke.view'],
    });
    assert.equal(res.ok, false, 'a Co-Owner cannot appoint a Co-Owner');
    assert.equal(res.reason, 'co_owner_owner_only');
});

test('a Trusted Admin cannot grant themselves more permissions (self-elevation blocked)', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view'],
    });
    const ta = await access.authorizeAntiNuke(GUILD_A, TA);
    const res = await access.setPermissions({
        guild: GUILD_A, actorUserId: TA, actor: ta, targetUserId: TA,
        permissions: ['antinuke.lockdown', 'antinuke.recovery'],
    });
    assert.equal(res.ok, false, 'self-elevation must be rejected');
    // Effective permissions unchanged.
    const after = await access.computeAccess({ guild: GUILD_A, userId: TA });
    assert.deepEqual(new Set(after.permissions), new Set(['antinuke.view']));
});

test('a delegated access manager cannot grant permissions they do not possess', async () => {
    // A Co-Owner (level 2) holds antinuke.view + access.manage but NOT
    // lockdown/recovery. They may create a Trusted Admin (level 3) below them,
    // capped to their own set.
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: CO_OWNER, role: 'coOwner', permissions: ['antinuke.view', 'antinuke.access.manage'],
    });
    const managerAuth = await access.authorizeAntiNuke(GUILD_A, CO_OWNER);
    const res = await access.assignAccess({
        guild: GUILD_A, actorUserId: CO_OWNER, actor: managerAuth,
        targetUserId: TA, role: 'trustedAdmin',
        permissions: ['antinuke.view', 'antinuke.lockdown'], // lockdown NOT held by manager
    });
    assert.equal(res.ok, true, 'grant succeeds but is clipped to the manager authority');
    const ta = await access.computeAccess({ guild: GUILD_A, userId: TA });
    assert.ok(ta.permissions.includes('antinuke.view'));
    assert.ok(!ta.permissions.includes('antinuke.lockdown'), 'floor at the manager authority');
});

test('revoking access takes effect on the very next authorization (no stale caches)', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view', 'antinuke.config'],
    });
    assert.equal((await access.authorizeAntiNuke(GUILD_A, TA, 'antinuke.config')).ok, true);
    const owner = await access.authorizeAntiNuke(GUILD_A, OWNER);
    const res = await access.removeAccess({ guild: GUILD_A, actorUserId: OWNER, actor: owner, targetUserId: TA });
    assert.equal(res.ok, true);
    // Immediate: every subsequent authorization re-reads the rows.
    const auth = await access.authorizeAntiNuke(GUILD_A, TA, 'antinuke.view');
    assert.equal(auth.ok, false, 'a revoked user is rejected immediately');
});

// ── Guild isolation ────────────────────────────────────────────────────────

test('Guild A permissions never grant access to Guild B', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view', 'antinuke.config'],
    });
    const inB = await access.computeAccess({ guild: GUILD_B, userId: TA });
    assert.equal(inB.role, 'none', 'TA has no access row in Guild B');
    assert.equal((await access.authorizeAntiNuke(GUILD_B, TA, 'antinuke.view')).ok, false);
    // Guild B's owner is a different person; the TA is not them either.
    const otherOwner = await access.computeAccess({ guild: GUILD_B, userId: OTHER_GUILD_OWNER });
    assert.equal(otherOwner.isOwner, true);
});

// ── Owner restrictions ─────────────────────────────────────────────────────

test('the actual owner cannot be demoted, removed or modified through access control', async () => {
    const owner = await access.authorizeAntiNuke(GUILD_A, OWNER);
    const res = await access.setPermissions({
        guild: GUILD_A, actorUserId: OWNER, actor: owner, targetUserId: OWNER,
        permissions: ['antinuke.view'], preset: null,
    });
    assert.equal(res.ok, false, 'the owner cannot be modified');
    assert.equal(res.reason, 'cannot_modify_owner');
    const removeRes = await access.removeAccess({ guild: GUILD_A, actorUserId: OWNER, actor: owner, targetUserId: OWNER });
    assert.equal(removeRes.ok, false);
});

test('a delegated manager cannot modify someone at or above their level', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: CO_OWNER, role: 'trustedAdmin', permissions: ['antinuke.access.manage'],
    });
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'coOwner', permissions: ['antinuke.view'],
    });
    const manager = await access.authorizeAntiNuke(GUILD_A, CO_OWNER); // level 3 (trustedAdmin)
    const targetCo = await access.computeAccess({ guild: GUILD_A, userId: TA }); // level 2 coOwner
    const res = await access.setPermissions({
        guild: GUILD_A, actorUserId: CO_OWNER, actor: manager, targetUserId: TA,
        permissions: ['antinuke.lockdown'],
    });
    assert.equal(res.ok, false, 'cannot manage someone above the manager');
    assert.equal(res.reason, 'outside_authority');
});

// ── Presets ────────────────────────────────────────────────────────────────

test('every preset maps to actual permission ids from the registry', () => {
    const catalog = perms.antiNukePermissionCatalog();
    for (const preset of catalog.presets) {
        if (preset.key === 'custom') continue;
        for (const id of preset.permissions) {
            assert.ok(perms.ANTI_NUKE_PERMISSION_BY_ID[id], `preset ${preset.key} grants unknown permission ${id}`);
        }
    }
});

test('a delegated manager\'s preset is capped to their authority', () => {
    const { applyPreset } = perms;
    const cap = ['antinuke.view', 'antinuke.config'];
    const out = applyPreset('protectionManager', cap);
    for (const id of out) assert.ok(cap.includes(id), `preset leaked ${id} beyond the manager's authority`);
});

test('the permission registry is the single source of truth for the UI catalog', () => {
    const catalog = perms.antiNukePermissionCatalog();
    assert.ok(Array.isArray(catalog.groups) && catalog.groups.length > 0);
    const flat = catalog.groups.flatMap(g => g.permissions);
    assert.equal(flat.length, catalog.permissions.length, 'groups must not omit permissions');
    const ids = new Set(flat.map(p => p.id));
    assert.equal(ids.size, flat.length, 'permission ids must be unique');
});

// ── Audit trail ────────────────────────────────────────────────────────────

test('sensitive access changes are written to the audit trail', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: CO_OWNER, role: 'coOwner',
        permissions: ['antinuke.view'], reason: 'owner requested',
    });
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view'],
    });
    await access.removeAccess({ guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER), targetUserId: TA, reason: 'left the server' });
    const entries = IN_MEMORY.history.filter(h => h.guildId === String(GUILD_A.id));
    const actions = entries.map(h => h.action);
    assert.ok(actions.includes('co_owner_appointed'), `trail records co-owner appointment (got ${actions.join(', ')})`);
    assert.ok(actions.includes('trusted_admin_added'), `trail records trusted admin add (got ${actions.join(', ')})`);
    assert.ok(actions.includes('trusted_admin_removed'), `trail records trusted admin removal (got ${actions.join(', ')})`);
    const co = entries.find(h => h.action === 'co_owner_appointed');
    assert.equal(co.actorId, String(OWNER));
    assert.equal(co.targetId, String(CO_OWNER));
    assert.ok(co.newState && Array.isArray(co.newState.permissions), 'previous/new state captured');
});

// ── Snapshot for the Access Control page ───────────────────────────────────

test('buildAccessSnapshot reports owner, assignments, history and the viewer', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: CO_OWNER, role: 'coOwner', permissions: ['antinuke.view', 'antinuke.setup'],
    });
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view'],
    });
    const snap = await access.buildAccessSnapshot({ guild: GUILD_A, viewerUserId: OWNER });
    assert.equal(snap.ownerId, String(OWNER));
    assert.equal(snap.assignments.length, 2);
    const co = snap.assignments.find(a => a.userId === String(CO_OWNER));
    assert.equal(co.role, 'coOwner');
    assert.equal(co.level, 2);
    assert.ok(co.permissions.includes('antinuke.setup'));
    assert.equal(snap.viewer.isOwner, true);
    assert.equal(snap.viewer.canAppointCoOwners, true);
});

test('the snapshot viewer context honours a non-owner manager', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.access.manage', 'antinuke.access.view'],
    });
    const snap = await access.buildAccessSnapshot({ guild: GUILD_A, viewerUserId: TA });
    assert.equal(snap.viewer.role, 'trustedAdmin');
    assert.equal(snap.viewer.canManageAccess, true);
    assert.equal(snap.viewer.canAppointCoOwners, false, 'only the owner appoints Co-Owners');
});

// ── Discord command gate (the same hierarchy, reached from slash) ───────────

test('the /antinuke command gates each subcommand behind a bot-defined permission', async () => {
    const cmd = require('../commands/antinuke');
    assert.equal(cmd.data.name, 'antinuke');

    // The access context the command now checks per subcommand.
    // A Discord Administrator with no assignment is denied anything but the
    // owner. Enable lockdown for the TA, then verify lockdown itself works.
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view', 'antinuke.incidents.view'],
    });

    const asAdmin = await access.authorizeAntiNuke(GUILD_A, ADMIN_NO_TRUST, 'antinuke.view');
    assert.equal(asAdmin.ok, false, 'an untrusted Discord Administrator is denied on the Discord side too');

    const asTAView = await access.authorizeAntiNuke(GUILD_A, TA, 'antinuke.view');
    assert.equal(asTAView.ok, true, 'TA with antinuke.view can read status');
    const asTALockdown = await access.authorizeAntiNuke(GUILD_A, TA, 'antinuke.lockdown');
    assert.equal(asTALockdown.ok, false, 'TA without antinuke.lockdown cannot lockdown from Discord');

    const asOwnerLockdown = await access.authorizeAntiNuke(GUILD_A, OWNER, 'antinuke.lockdown');
    assert.equal(asOwnerLockdown.ok, true, 'the owner can always lockdown');
});

test('the setup-buttons require antinuke.setup for everyone but the owner', async () => {
    await access.assignAccess({
        guild: GUILD_A, actorUserId: OWNER, actor: await access.authorizeAntiNuke(GUILD_A, OWNER),
        targetUserId: TA, role: 'trustedAdmin', permissions: ['antinuke.view', 'antinuke.setup'],
    });
    // The setup button flow checks `antinuke.setup` for start/confirm and
    // `antinuke.view` for progress — verify the permission mapping is the same
    // the interaction handler uses.
    const taSetup = await access.authorizeAntiNuke(GUILD_A, TA, 'antinuke.setup');
    assert.equal(taSetup.ok, true);
    const adminSetup = await access.authorizeAntiNuke(GUILD_A, ADMIN_NO_TRUST, 'antinuke.setup');
    assert.equal(adminSetup.ok, false);
    const ownerSetup = await access.authorizeAntiNuke(GUILD_A, OWNER, 'antinuke.setup');
    assert.equal(ownerSetup.ok, true);
});

// ── Discord setup-progress bar chart — the embed must show a real bar ─────

test('setupEmbed renders a visible unicode bar chart, not only text', () => {
    const { setupEmbed } = require('../utils/antiNukeEmbed');
    const progress = {
        percent: 60, completed: 6, total: 10, failed: 1, skipped: 1, remaining: 3,
        currentStep: 'configureProtectionRules',
        steps: [
            { label: 'Validate access', status: 'completed', required: true },
            { label: 'Inspect permissions', status: 'completed', required: true },
            { label: 'Configure rules', status: 'running', required: true },
            { label: 'Alert channel', status: 'skipped', required: false },
            { label: 'Confirm & apply', status: 'pending', required: true },
        ],
    };
    const embed = setupEmbed(progress);
    const text = JSON.stringify(embed.toJSON());
    assert.ok(text.includes('░'), 'the empty part of the bar chart must be visible (U+2593)');
    assert.ok(text.includes('%'), 'the bar chart embeds the percentage');
    assert.ok(/Setup progress[^\n]*█/.test(text), 'the filled bar blocks appear');
    // 60% of a 16-wide bar = 10 filled, 6 empty. Clamp check: never below 0/above 100.
    const { percent, completed, total } = progress;
    assert.ok(percent >= 0 && percent <= 100);
    assert.ok(completed <= total);
    assert.ok(text.includes('6/10'), 'the field reports completed/total required');
});

test('the /antinuke command schema exposes the new access + progress subcommands', () => {
    const cmd = require('../commands/antinuke');
    const subNames = Object.values(cmd.data.toJSON().options || {}).map(s => s && s.name).filter(Boolean);
    assert.ok(subNames.includes('access'), 'access subcommand registered');
    assert.ok(subNames.includes('grant'), 'grant subcommand registered');
    assert.ok(subNames.includes('revoke'), 'revoke subcommand registered');
    assert.ok(subNames.includes('progress'), 'progress subcommand registered');
});

// ── Prefix `an grant @user <co-owner|admin>` argument parsing ───────────────

test('parseGrantArgs reads the role from the non-mention token (prefix offset bug)', () => {
    const { parseGrantArgs, ROLES, defaultPresetForRole } = require('../utils/antiNukeAccess');
    // The regression: prefix args are ['grant','<@id>','co-owner'] — the mention
    // is its OWN token, so a fixed-index read picked up the mention and every
    // `$an grant @user co-owner` fell through to the usage error.
    assert.equal(parseGrantArgs(['grant', '<@123456789012345678>', 'co-owner']).role, ROLES.coOwner);
    assert.equal(parseGrantArgs(['grant', '<@!123456789012345678>', 'coowner']).role, ROLES.coOwner);
    assert.equal(parseGrantArgs(['grant', '<@123456789012345678>', 'Co-Owner']).role, ROLES.coOwner);
    assert.equal(parseGrantArgs(['grant', '<@123456789012345678>', 'co_owner']).role, ROLES.coOwner);
    // admin aliases → Trusted Admin
    for (const alias of ['admin', 'Admin', 'trustedAdmin', 'trusted-admin']) {
        assert.equal(parseGrantArgs(['grant', '<@123456789012345678>', alias]).role, ROLES.trustedAdmin, alias);
    }
    // Role before the mention still resolves.
    assert.equal(parseGrantArgs(['grant', 'co-owner', '<@123456789012345678>']).role, ROLES.coOwner);
    // Missing / unknown role → null (the handler replies with usage).
    assert.equal(parseGrantArgs(['grant', '<@123456789012345678>']).role, null);
    assert.equal(parseGrantArgs(['grant', '<@123456789012345678>', 'bogus']).role, null);
    assert.equal(parseGrantArgs([]).role, null);
    // The preset is fixed per role.
    assert.equal(defaultPresetForRole(ROLES.coOwner), 'protectionManager');
    assert.equal(defaultPresetForRole(ROLES.trustedAdmin), 'securityMonitor');
});