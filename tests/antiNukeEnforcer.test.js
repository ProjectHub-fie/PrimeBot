/**
 * Anti-Nuke real enforcement engine tests.
 *
 * Covers utils/antiNukeEnforcer.js: the actual ban / kick / quarantine /
 * delete-webhook / lock-channel actions the old detection-only implementation
 * never executed, plus the per-action response mapping and dry-run OFF default
 * that make those actions reachable. All guild/member objects are pure stubs —
 * no Discord API is touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    responsesForAction,
    defaultAntiNukeSettings,
    normalizeAntiNukeSettings,
    DEFAULT_NUKE_RESPONSES,
    DEFAULT_ACTION_RESPONSES,
    NUKE_RESPONSES,
    ENFORCED_RESPONSE_KEYS,
} = require('../utils/antiNukeRules');

const {
    botHasPermission,
    hierarchyCheck,
    banExecutor,
    kickExecutor,
    quarantineMember,
    deleteWebhooks,
    lockChannels,
} = require('../utils/antiNukeEnforcer');

// ── Stub helpers ────────────────────────────────────────────────────────────

function stubRole(id, position, permissions = []) {
    return {
        id,
        position,
        permissions: {
            has: (flag) => permissions.includes(flag),
        },
    };
}

function stubMember({ id = '999', guild = null, roles = [], highestPos = 0 } = {}) {
    const rolesCache = new Map(roles.map(r => [r.id, r]));
    return {
        id,
        roles: {
            cache: rolesCache,
            highest: highestPos !== undefined ? { position: highestPos } : null,
            add: async (roleId) => { actions.push(`addRole:${roleId}`); },
        },
        kick: async () => { actions.push('kick'); },
    };
}

let actions = [];

function resetActions() { actions = []; }

const PERM = require('discord.js').PermissionFlagsBits;

function stubGuild({ botHighest = 10, ownerId = 'owner', permissions = [], roles = [], overrides = {} } = {}) {
    const roleMap = new Map(roles.map(r => [r.id, r]));
    const me = {
        id: 'bot',
        roles: {
            highest: { position: botHighest },
        },
        permissions: {
            has: (flag) => permissions.includes(flag),
        },
    };
    const membersCache = new Map();
    return {
        id: 'guild1',
        ownerId,
        members: {
            me,
            cache: membersCache,
            fetch: async (id) => {
                if (overrides.fetchMember && overrides.fetchMember(id)) return overrides.fetchMember(id);
                const m = membersCache.get(String(id));
                if (m) return m;
                throw new Error('Unknown Member');
            },
        },
        roles: { cache: roleMap },
        channels: { cache: new Map() },
        fetchWebhooks: async () => ({ find: () => null }),
        ...overrides.simple,
    };
}

// ── Response mapping ────────────────────────────────────────────────────────

test('every catalog action has an explicit per-action response map', () => {
    const { NUKE_ACTIONS } = require('../utils/antiNukeRules');
    for (const a of NUKE_ACTIONS) {
        assert.ok(DEFAULT_ACTION_RESPONSES[a.key], `${a.key} must have a default response map`);
        assert.ok(DEFAULT_ACTION_RESPONSES[a.key].length > 0, `${a.key} default responses non-empty`);
        for (const r of DEFAULT_ACTION_RESPONSES[a.key]) {
            assert.ok(NUKE_RESPONSES.some(x => x.key === r), `${a.key} -> ${r} is a known response`);
        }
    }
    // Punishments are never on by default in the per-action maps that could
    // assign them to ordinary (moderation) actions.
    assert.ok(!DEFAULT_ACTION_RESPONSES.memberBan.includes('ban'), 'a mass-ban attack does not self-punish with another ban by default');
    assert.ok(DEFAULT_ACTION_RESPONSES.webhookCreate.includes('deleteWebhook'), 'webhook attack deletes the malicious webhook by default');
});

test('responsesForAction: per-action override wins; admin global list next; catalog default last', () => {
    const settings = normalizeAntiNukeSettings({
        responses: ['alertOwner'],
        actionResponses: { channelDelete: ['alertChannel', 'lockChannels'] },
    });
    assert.deepEqual(responsesForAction(settings, 'channelDelete'), ['alertChannel', 'lockChannels']);
    assert.deepEqual(responsesForAction(settings, 'memberBan'), ['alertOwner'], 'global responses used when no per-action map');

    const defaults = normalizeAntiNukeSettings({ responses: [] });
    assert.deepEqual(responsesForAction(defaults, 'channelDelete'), DEFAULT_ACTION_RESPONSES.channelDelete);
    // Both stock default lists fall through to the catalog: the new default
    // (every response except log-only) so a fresh config gets the curated
    // per-action plan, and the legacy alert-only list so an existing guild that
    // never customised responses keeps its per-action enforcement.
    const newStock = normalizeAntiNukeSettings({ responses: DEFAULT_NUKE_RESPONSES });
    assert.deepEqual(responsesForAction(newStock, 'memberBan'), DEFAULT_ACTION_RESPONSES.memberBan);
    const legacyStock = normalizeAntiNukeSettings({ responses: ['alertOwner', 'alertChannel', 'logOnly'] });
    assert.deepEqual(responsesForAction(legacyStock, 'memberBan'), DEFAULT_ACTION_RESPONSES.memberBan);
    // Unknown action keys fall back to the default response list.
    assert.deepEqual(responsesForAction(defaults, 'doesNotExist'), DEFAULT_NUKE_RESPONSES);
});

test('new guilds default dry-run OFF with every response (except log-only) pre-checked; punishments stay opt-in per rule', () => {
    const d = defaultAntiNukeSettings();
    assert.equal(d.dryRun, false, 'new configs enforce for real');
    assert.deepEqual(d.responses, DEFAULT_NUKE_RESPONSES,
        'response configuration checks every response except log-only by default');
    assert.ok(!d.responses.includes('logOnly'), 'log-only is never on by default');
    // The *effective* plan for a default config comes from the per-action
    // catalog, which still excludes permanent punishment for the rules where a
    // mass-punish would self-inflict (e.g. memberBan never bans by default).
    assert.ok(!DEFAULT_ACTION_RESPONSES.memberBan.includes('ban'),
        'a mass-ban attack does not self-punish with another ban by default');
    assert.deepEqual(responsesForAction(d, 'memberBan'), DEFAULT_ACTION_RESPONSES.memberBan);
    // Even with dry-run off and punishments in the *effective* set, a rule can
    // only punish when the admin opted into it for that rule.
    const n = normalizeAntiNukeSettings({ responses: ['ban', 'kick', 'alertOwner'] });
    assert.equal(n.dryRun, false);
    assert.deepEqual(n.responses, ['ban', 'kick', 'alertOwner']);
});

test('enforced response keys exist in the catalog and exclude pure-alert keys', () => {
    assert.ok(ENFORCED_RESPONSE_KEYS.includes('ban'));
    assert.ok(ENFORCED_RESPONSE_KEYS.includes('kick'));
    assert.ok(ENFORCED_RESPONSE_KEYS.includes('quarantine'));
    assert.ok(ENFORCED_RESPONSE_KEYS.includes('deleteWebhook'));
    assert.ok(ENFORCED_RESPONSE_KEYS.includes('lockChannels'));
    assert.ok(!ENFORCED_RESPONSE_KEYS.includes('alertOwner'));
    assert.ok(!ENFORCED_RESPONSE_KEYS.includes('logOnly'));
});

// ── Hierarchy + permission gates ────────────────────────────────────────────

test('hierarchyCheck blocks owner, bot and trusted roles, and above-bot targets', async () => {
    const trusted = ['role-trusted'];
    const base = { guild: { members: { me: { roles: { highest: { position: 10 } } } } }, guildOwnerId: 'owner', botUserId: 'bot', trustedRoleIds: trusted };

    assert.equal(hierarchyCheck({ ...base, member: { id: 'owner', roles: { cache: new Map() } } }), 'owner_exempt');
    assert.equal(hierarchyCheck({ ...base, member: { id: 'bot', roles: { cache: new Map() } } }), 'bot_exempt');
    assert.equal(hierarchyCheck({ ...base, member: { id: 'u', roles: { cache: new Map([[trusted[0], stubRole(trusted[0], 5)]]) } } }), 'trusted_role_exempt');
    assert.equal(hierarchyCheck({ ...base, member: { id: 'u', roles: { cache: new Map([['r', stubRole('r', 12)]]) } } }), null, 'highest not set on the stub reports as manageable in this test shape');
    const above = { ...base, member: { id: 'u', roles: { cache: new Map([['r', stubRole('r', 12)]]), highest: { position: 12 } } } };
    assert.equal(hierarchyCheck(above), 'target_above_bot');
    assert.equal(hierarchyCheck({ ...base, member: { id: 'u', roles: { cache: new Map([['r', stubRole('r', 3)]]) } } }), null);
    assert.equal(hierarchyCheck({ ...base, member: null }), 'no_member');
});

test('botHasPermission validates the bot member permission set', async () => {
    const guild = stubGuild({ permissions: [PERM.BanMembers] });
    assert.equal(botHasPermission(guild, PERM.BanMembers), true);
    assert.equal(botHasPermission(guild, PERM.KickMembers), false);
    const noMe = { members: { me: null } };
    assert.equal(botHasPermission(noMe, PERM.BanMembers), false);
});

// ── Ban ─────────────────────────────────────────────────────────────────────

test('banExecutor reports precisely: missing permission, hierarchy block, success, API rejection', async () => {
    resetActions();

    const noPerm = stubGuild({ permissions: [] });
    const r1 = await banExecutor({}, noPerm, 'attacker');
    assert.equal(r1.executed, false);
    assert.ok(r1.errors.some(e => e.includes('missing Ban Members')));

    const blocked = stubGuild({ permissions: [PERM.BanMembers] });
    const ownerGuild = stubGuild({ permissions: [PERM.BanMembers], overrides: { fetchMember: (id) => (id === 'owner' ? { id: 'owner', roles: { cache: new Map() } } : null) } });
    const r2 = await banExecutor({ user: { id: 'bot' } }, ownerGuild, 'owner');
    assert.equal(r2.executed, false);
    assert.ok(r2.errors.some(e => e.includes('hierarchy: owner_exempt')));

    const successGuild = stubGuild({ permissions: [PERM.BanMembers] });
    successGuild.members.ban = async () => { actions.push('ban'); };
    const r3 = await banExecutor({ user: { id: 'bot' } }, successGuild, 'attacker', { settings: {} });
    assert.equal(r3.executed, true);
    assert.deepEqual(actions, ['ban']);

    const rejectGuild = stubGuild({ permissions: [PERM.BanMembers] });
    rejectGuild.members.ban = async () => { throw Object.assign(new Error('50013'), { code: 50013 }); };
    const r4 = await banExecutor({ user: { id: 'bot' } }, rejectGuild, 'attacker', { settings: {} });
    assert.equal(r4.executed, false);
    assert.ok(r4.errors.some(e => e.includes('ban_rejected: 50013')));
});

// ── Kick ────────────────────────────────────────────────────────────────────

test('kickExecutor reports missing permission and executes when allowed', async () => {
    resetActions();
    const noPerm = stubGuild({ permissions: [PERM.BanMembers] });
    const r1 = await kickExecutor({}, noPerm, 'attacker');
    assert.equal(r1.executed, false);
    assert.ok(r1.errors.some(e => e.includes('missing Kick Members')));

    const kickMembers = stubGuild({ permissions: [PERM.KickMembers] });
    kickMembers.members.ban = async () => {};
    kickMembers.members.cache.set('attacker', { id: 'attacker', roles: { cache: new Map() }, kick: async () => { actions.push('kick'); } });
    const r2 = await kickExecutor({ user: { id: 'bot' } }, kickMembers, 'attacker');
    assert.equal(r2.executed, true);
    assert.deepEqual(actions, ['kick']);
});

// ── Quarantine ──────────────────────────────────────────────────────────────

test('quarantine applies the configured quarantine role + strips dangerous roles', async () => {
    resetActions();
    const { PermissionFlagsBits } = require('discord.js');
    const dangerousMode = {
        Administrator: PermissionFlagsBits.Administrator,
    };
    const badRole = stubRole('admin-role', 9, [PermissionFlagsBits.Administrator]);
    const safeRole = stubRole('safe-role', 3, [PermissionFlagsBits.SendMessages]);
    const member = {
        id: 'attacker',
        roles: {
            cache: new Map([['admin-role', badRole], ['safe-role', safeRole]]),
            highest: { position: 9 },
            add: async (roleId) => { actions.push(`addRole:${roleId}`); },
            remove: async (roleId) => { actions.push(`removeRole:${roleId}`); },
        },
    };
    const guild = stubGuild({
        permissions: [PermissionFlagsBits.ManageRoles],
        botHighest: 12,
        roles: [badRole, safeRole],
    });
    guild.members.cache.set('attacker', member);
    guild.members.fetch = async () => member;
    // Compute dangerous removals requires a member overlord structure.
    const quarantineRole = stubRole('1000000000000011000', 4);
    guild.roles.cache.set('1000000000000011000', quarantineRole);

    const settings = normalizeAntiNukeSettings({
        quarantineRoleId: '1000000000000011000',
        dangerousPermissions: ['Administrator'],
    });
    const res = await quarantineMember({ user: { id: 'bot' } }, guild, 'attacker', { settings });
    assert.equal(res.executed, true);
    assert.ok(res.details.actions.includes('addQuarantineRole'));
    assert.ok(actions.some(a => a.startsWith('addRole:1000000000000011000')));
    assert.ok(actions.some(a => a.startsWith('removeRole:admin-role')));
});

// ── Webhooks ────────────────────────────────────────────────────────────────

test('deleteWebhooks removes only the targeted webhooks and requires Manage Webhooks', async () => {
    resetActions();
    const noPerm = stubGuild({ permissions: [] });
    const r1 = await deleteWebhooks({}, noPerm, ['111', '222']);
    assert.equal(r1.executed, false);
    assert.ok(r1.errors.some(e => e.includes('missing Manage Webhooks')));

    const withPerm = stubGuild({ permissions: [PERM.ManageWebhooks] });
    const webhooks = [
        { id: '111', delete: async () => { actions.push('del:111'); } },
        { id: '222', delete: async () => { throw Object.assign(new Error('10003'), { code: 10003 }); } },
    ];
    withPerm.fetchWebhooks = async () => ({ find: (fn) => webhooks.find(fn) });
    const r2 = await deleteWebhooks({}, withPerm, ['111', '222']);
    assert.equal(r2.executed, true);
    assert.deepEqual(actions, ['del:111']);
    assert.deepEqual(r2.removed, ['111']);
    assert.equal(r2.failed.length, 1);

    // No specific ids → never a blanket sweep.
    const r3 = await deleteWebhooks({}, withPerm, []);
    assert.equal(r3.executed, false);
    assert.ok(r3.errors.includes('no_webhook_targets'));
    assert.deepEqual(actions, ['del:111'], 'no additional deletions');
});

// ── Lock channels ───────────────────────────────────────────────────────────

test('lockChannels denies Send Messages on the affected channels and records before-state', async () => {
    resetActions();
    const withPerm = stubGuild({ permissions: [PERM.ManageChannels] });
    const channel = {
        id: 'channel-1',
        permissionOverwrites: {
            cache: new Map([[withPerm.id, { allow: { bitfield: 0n }, deny: { bitfield: 0n } }]]),
            edit: async (id, patch) => { actions.push(`lock:${id}:${JSON.stringify(patch)}`); },
        },
        permissionsFor: () => ({ has: () => true }),
    };
    withPerm.channels.fetch = async () => channel;
    const res = await lockChannels({}, withPerm, ['channel-1']);
    assert.equal(res.executed, true);
    assert.ok(actions.some(a => a.startsWith('lock:guild1:')));
    assert.deepEqual(res.locked, ['channel-1']);
    assert.ok(res.beforeByChannel['channel-1'], 'before-state recorded for recovery');
});
// ── Manager integration: _respond executes the enforcer ───────────────────

test('manager _respond executes ban enforcement and records action_executed when dry-run OFF', async () => {
    const anukeDb = require('../server/anukeDb');
    const originalClaim = anukeDb.claimDedupKey;
    const originalQuery = anukeDb.anukePool.query;

    // Stub the module-level dedup + DB so the manager stays DB-free.
    anukeDb.claimDedupKey = async () => true;
    anukeDb.anukePool.query = async () => ({ rows: [] });
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    anukeDb.claimDedupKey = originalClaim;
    anukeDb.anukePool.query = originalQuery;

    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    mgr.detector = { tryConsumeCooldown: () => true };

    const banned = [];
    const attacker = { id: 'attacker', user: { tag: 'attacker#0000' } };
    attacker.ban = async (opts) => { banned.push(opts); };
    attacker.roles = { cache: new Map(), highest: { position: 1 } };
    const guild = {
        id: 'g1',
        ownerId: 'owner',
        members: {
            me: { id: 'bot', permissions: { has: () => true }, roles: { highest: { position: 10 } } },
            fetch: async (id) => (String(id) === 'attacker' ? attacker : null),
            cache: new Map(),
            ban: async (id) => { banned.push({ id }); },
        },
        roles: { cache: new Map() },
        channels: { cache: new Map() },
    };

    let recorded = null;
    let alerted = null;
    mgr._fetchMember = async () => attacker;
    mgr._alert = async (a) => { alerted = a; };
    mgr._recordIncident = async (inc) => { recorded = inc; };
    mgr._emit = async () => {};
    mgr._saveLockdown = async () => {};

    const settings = normalizeAntiNukeSettings({
        dryRun: false,
        actionResponses: { memberBan: ['ban', 'removeRoles', 'alertOwner'] },
        trustedRoleIds: [],
    });

    const verdict = { tripped: true, count: 3, threshold: 3, seconds: 10 };
    const res = await mgr._respond({
        guild, settings,
        action: { key: 'memberBan', label: 'Mass Ban', module: 'member', severity: 'critical' },
        watch: { threshold: 3, seconds: 10 },
        executorId: 'attacker', executorName: 'attacker#0000',
        attribution: 'audit_log', verdict, details: { summary: '3 bans' },
    });

    assert.equal(banned.length, 1, 'ban enforcer ran on the confirmed attacker');
    assert.equal(res.handled, true);
    assert.equal(res.responseResult.status, 'action_executed');
    assert.ok(res.responseResult.executed.includes('ban'));
    assert.ok(res.responseResult.taken.includes('ban'));
    assert.equal(recorded.status, 'action_executed');
    assert.equal(recorded.dryRun, false);
    assert.equal(alerted.status, 'action_executed');
});

test('manager _respond dry-run OFF with alert-only responses never punishes', async () => {
    const anukeDb = require('../server/anukeDb');
    const originalClaim = anukeDb.claimDedupKey;
    anukeDb.claimDedupKey = async () => true;
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    anukeDb.claimDedupKey = originalClaim;

    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    mgr.detector = { tryConsumeCooldown: () => true };
    const guild = { id: 'g2', ownerId: 'owner', members: { me: { id: 'bot', permissions: { has: () => true }, roles: { highest: { position: 10 } } }, fetch: async () => null, cache: new Map() }, roles: { cache: new Map() }, channels: { cache: new Map() } };

    let recorded = null;
    let alerted = null;
    mgr._fetchMember = async () => null;
    mgr._alert = async (a) => { alerted = a; };
    mgr._recordIncident = async (inc) => { recorded = inc; };
    mgr._emit = async () => {};
    mgr._saveLockdown = async () => {};

    const settings = normalizeAntiNukeSettings({ dryRun: false, responses: ['alertOwner'], actionResponses: {} });
    const verdict = { tripped: true, count: 3, threshold: 3, seconds: 10 };
    const res = await mgr._respond({
        guild, settings,
        action: { key: 'memberBan', label: 'Mass Ban', module: 'member', severity: 'critical' },
        watch: { threshold: 3, seconds: 10 },
        executorId: 'u1', executorName: 'u1', attribution: 'audit_log', verdict, details: {},
    });
    assert.equal(res.handled, true);
    assert.equal(res.responseResult.status, 'detected');
    assert.ok(!res.responseResult.executed.includes('ban'), 'no punishment for alert-only config');
});

test('manager _respond dry-run ON detects + logs, never enforces', async () => {
    const anukeDb = require('../server/anukeDb');
    const originalClaim = anukeDb.claimDedupKey;
    anukeDb.claimDedupKey = async () => true;
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    anukeDb.claimDedupKey = originalClaim;

    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    mgr.detector = { tryConsumeCooldown: () => true };
    const guild = { id: 'g3', ownerId: 'owner', members: { me: { id: 'bot', permissions: { has: () => true }, roles: { highest: { position: 10 } } }, fetch: async () => null, cache: new Map() }, roles: { cache: new Map() }, channels: { cache: new Map() } };

    let recorded = null;
    let alerted = null;
    mgr._fetchMember = async () => null;
    mgr._alert = async (a) => { alerted = a; };
    mgr._recordIncident = async (inc) => { recorded = inc; };
    mgr._emit = async () => {};
    mgr._saveLockdown = async () => {};

    const settings = normalizeAntiNukeSettings({ dryRun: true, actionResponses: { memberBan: ['ban'] } });
    const verdict = { tripped: true, count: 3, threshold: 3, seconds: 10 };
    const res = await mgr._respond({
        guild, settings,
        action: { key: 'memberBan', label: 'Mass Ban', module: 'member', severity: 'critical' },
        watch: { threshold: 3, seconds: 10 },
        executorId: 'u1', executorName: 'u1', attribution: 'audit_log', verdict, details: {},
    });
    assert.equal(res.reason, 'dry_run');
    assert.equal(res.responseResult.status, 'dry_run');
    assert.equal(recorded.status, 'dry_run');
    assert.equal(recorded.dryRun, true);
});

// ── Audit-entry dedup: composite key (auditEntryId + actionKey) ────────────

test('processEvent does NOT suppress distinct rules that share one audit entry', async () => {
    const anukeDb = require('../server/anukeDb');
    const originalClaim = anukeDb.claimDedupKey;
    anukeDb.claimDedupKey = async () => true;
    anukeDb.anukePool.query = async () => ({ rows: [] });
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    anukeDb.claimDedupKey = originalClaim;
    anukeDb.anukePool.query = async () => ({ rows: [] });

    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    mgr.detector = { tryConsumeCooldown: () => true, record: () => ({ count: 1, tripped: true, threshold: 1, seconds: 10 }) };
    const guild = {
        id: 'g', ownerId: 'owner',
        members: { me: { id: 'bot', permissions: { has: () => true }, roles: { highest: { position: 10 } } }, fetch: async () => null, cache: new Map() },
        roles: { cache: new Map() }, channels: { cache: new Map() },
    };
    mgr._fetchMember = async () => ({ id: 'attacker', user: { tag: 'attacker#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    mgr._alert = async () => {};
    mgr._recordIncident = async () => {};
    mgr._emit = async () => {};
    mgr._saveLockdown = async () => {};

    const settings = normalizeAntiNukeSettings({
        enabled: true, dryRun: false,
        actionResponses: {
            rolePermissionUpdate: ['alertOwner'],
            dangerousPermissionGrant: ['alertOwner'],
            adminGrant: ['alertOwner'],
            memberRoleUpdate: ['alertOwner'],
        },
    });
    mgr._cache.set('g', settings);
    const before = mgr._seenEventIds.size;

    // One RoleUpdate+Administrator entry watching TWO distinct actions (both
    // threshold-tripped). Both MUST be evaluated, not deduped against each other.
    const r1 = await mgr.processEvent({
        guild, actionKey: 'rolePermissionUpdate',
        knownExecutorId: 'attacker',
        details: { auditEntryId: 'A900', targetId: 'role1', summary: 'x' },
    });
    const r2 = await mgr.processEvent({
        guild, actionKey: 'dangerousPermissionGrant',
        knownExecutorId: 'attacker',
        details: { auditEntryId: 'A900', targetId: 'role1', summary: 'x' },
    });
    assert.notEqual(r1.reason, 'duplicate_event', 'first rule evaluated, not suppressed');
    assert.notEqual(r2.reason, 'duplicate_event', 'second rule evaluated, not suppressed');

    // Same entry + same action → still deduped (blocks a duplicate delivery).
    const r3 = await mgr.processEvent({
        guild, actionKey: 'rolePermissionUpdate',
        knownExecutorId: 'attacker',
        details: { auditEntryId: 'A900', targetId: 'role1', summary: 'x' },
    });
    assert.equal(r3.reason, 'duplicate_event', 'same entry + same action is a duplicate');
    assert.ok(before <= mgr._seenEventIds.size);
    mgr._seenEventIds.clear();
});

test('processEvent records staged diagnostics through enforcement for a confirmed attack', async () => {
    const anukeDb = require('../server/anukeDb');
    const originalClaim = anukeDb.claimDedupKey;
    anukeDb.claimDedupKey = async () => true;
    anukeDb.anukePool.query = async () => ({ rows: [] });
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    anukeDb.claimDedupKey = originalClaim;
    anukeDb.anukePool.query = async () => ({ rows: [] });

    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    mgr.detector = { tryConsumeCooldown: () => true, record: () => ({ count: 1, tripped: true, threshold: 1, seconds: 10 }) };
    const guild = {
        id: 'g2', ownerId: 'owner',
        members: { me: { id: 'bot', permissions: { has: () => true }, roles: { highest: { position: 10 } } }, fetch: async () => null, cache: new Map() },
        roles: { cache: new Map() }, channels: { cache: new Map() },
    };
    mgr._fetchMember = async () => ({ id: 'attacker', user: { tag: 'attacker#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    let recorded = null;
    mgr._alert = async () => {};
    mgr._recordIncident = async (inc) => { recorded = inc; };
    mgr._emit = async () => {};
    mgr._saveLockdown = async () => {};

    const settings = normalizeAntiNukeSettings({ enabled: true, dryRun: false, actionResponses: { memberBan: ['alertOwner'] } });
    mgr._cache.set('g2', settings);

    const res = await mgr.processEvent({
        guild, actionKey: 'memberBan', knownExecutorId: 'attacker',
        details: { auditEntryId: 'A901', summary: '1 ban' },
    });
    assert.equal(res.handled, true);
    assert.ok(recorded, 'incident recorded');
    const stages = recorded.responseResult.stages || [];
    const keys = stages.map(s => s.key);
    assert.ok(keys.includes('event_received'), 'stage event_received recorded');
    assert.ok(keys.includes('action_mapped'), 'stage action_mapped recorded');
    assert.ok(keys.includes('enabled_check'), 'stage enabled_check recorded');
    assert.ok(keys.includes('rule_check'), 'stage rule_check recorded');
    assert.ok(keys.includes('attribution'), 'stage attribution recorded');
    assert.ok(keys.includes('trust_check'), 'stage trust_check recorded');
    assert.ok(keys.includes('threshold'), 'stage threshold recorded');
    assert.ok(keys.includes('response_plan'), 'stage response_plan recorded');
    assert.ok(keys.includes('hierarchy'), 'stage hierarchy recorded');
    assert.ok(keys.includes('final'), 'stage final recorded');
    assert.equal(recorded.status, 'detected');
    mgr._seenEventIds.clear();
});
