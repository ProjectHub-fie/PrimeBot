// Anti-Nuke protection system — unit tests.
//
// Everything here is pure / in-memory: the rule catalog, the sliding-window
// detector, the trust + burst evaluation, the audit-entry → action mapping, the
// setup-wizard progress maths and the alert-embed builder. No DB, no gateway,
// no Discord calls — the same modules the bot and the dashboard both use.

const test = require('node:test');
const assert = require('node:assert/strict');

const rules = require('../utils/antiNukeRules');
const { AntiNukeDetector, SlidingWindow } = require('../utils/antiNukeDetector');
const setup = require('../utils/antiNukeSetup');
const { validatePermissionsFromBitfield, validateBotPermissions, buildSecurityAlertEmbed, severityColor, SEVERITY_COLORS } = require('../utils/antiNukeContainment');
const entry = require('../utils/antiNukeEntry');
const audit = require('../utils/antiNukeAudit');

// ── Catalog integrity ───────────────────────────────────────────────────────

test('the rule catalog is coherent: unique keys, valid modules and responses', () => {
    assert.ok(rules.NUKE_ACTIONS.length >= 20, 'the catalog covers every protection module');
    const keys = rules.NUKE_ACTIONS.map(a => a.key);
    assert.equal(new Set(keys).size, keys.length, 'action keys must be unique');
    const moduleKeys = new Set(rules.NUKE_MODULE_KEYS);
    for (const a of rules.NUKE_ACTIONS) {
        assert.ok(moduleKeys.has(a.module), `${a.key} references an unknown module ${a.module}`);
        assert.ok(a.threshold >= 1 && a.seconds >= 1, `${a.key} needs a sane threshold/window`);
        assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(a.severity), `${a.key} severity`);
    }
    const responseKeys = rules.NUKE_RESPONSES.map(r => r.key);
    assert.equal(new Set(responseKeys).size, responseKeys.length, 'response keys must be unique');
});

test('every protection module named in the task has at least one action', () => {
    for (const module of ['channel', 'role', 'member', 'webhook', 'bot', 'server', 'permission']) {
        assert.ok(rules.actionsForModule(module).length > 0, `module ${module} has no actions`);
    }
});

// ── Settings normalization ──────────────────────────────────────────────────

test('default settings enable every action but stay in dry-run with alert-only responses', () => {
    const s = rules.defaultAntiNukeSettings();
    assert.equal(s.enabled, false, 'Anti-Nuke is opt-in');
    assert.equal(s.dryRun, true, 'dry-run is the safe default');
    assert.ok(s.responses.includes('alertOwner'), 'the owner is alerted by default');
    assert.ok(!s.responses.includes('lockdown'), 'destructive responses are not on by default');
    assert.equal(Object.keys(s.watched).length, rules.NUKE_ACTIONS.length, 'every action has a watch entry');
});

test('normalization clamps bad input and never drops an action from the catalog', () => {
    const s = rules.normalizeAntiNukeSettings({
        watched: { channelDelete: { enabled: false, threshold: 9999, seconds: -5 } },
        responses: ['alertOwner', 'nonsense'],
        dangerousPermissions: ['Administrator', 'Bogus'],
        lockdown: { verificationLevel: 'nonsense' },
    });
    assert.equal(s.watched.channelDelete.enabled, false);
    assert.ok(s.watched.channelDelete.threshold <= 100, 'threshold is clamped');
    assert.ok(s.watched.channelDelete.seconds >= 1, 'window is clamped');
    assert.deepEqual(s.responses, ['alertOwner'], 'unknown responses are dropped');
    assert.deepEqual(s.dangerousPermissions, ['Administrator'], 'unknown permissions are dropped');
    assert.ok(['none', 'low', 'medium', 'high', 'veryHigh'].includes(s.lockdown.verificationLevel));
    assert.ok(s.watched.roleDelete, 'actions absent from the input are still present');
});

test('an empty dangerous-permission list is allowed (containment is opt-in)', () => {
    const s = rules.normalizeAntiNukeSettings({ dangerousPermissions: ['Bogus'] });
    assert.deepEqual(s.dangerousPermissions, [], 'unknown keys are dropped and the list stays empty');
    const s2 = rules.normalizeAntiNukeSettings({ dangerousPermissions: [] });
    assert.deepEqual(s2.dangerousPermissions, [], 'clearing the list is honoured, not forced back to a default');
    // An omitted key still falls back to the catalog default.
    const s3 = rules.normalizeAntiNukeSettings({});
    assert.ok(s3.dangerousPermissions.length > 0, 'the default keeps a sensible starting set');
});

// ── Trust ───────────────────────────────────────────────────────────────────

test('the owner, trusted users and trusted roles are trusted; others are not', () => {
    const settings = rules.normalizeAntiNukeSettings({
        trustedUserIds: ['111111111111111111'],
        trustedRoleIds: ['222222222222222222'],
    });
    assert.equal(rules.isTrusted({ userId: '999', guildOwnerId: '999', settings }), true, 'owner is always exempt');
    assert.equal(rules.isTrusted({ userId: '111111111111111111', guildOwnerId: '999', settings }), true, 'trusted user');
    assert.equal(rules.isTrusted({ userId: '333', roleIds: ['222222222222222222'], guildOwnerId: '999', settings }), true, 'trusted role');
    assert.equal(rules.isTrusted({ userId: '333', roleIds: ['444'], guildOwnerId: '999', settings }), false, 'an ordinary member is not trusted');
    assert.equal(rules.isTrusted({ userId: null, settings }), true, 'an unknown executor is never punished');
});

test('an administrator is NOT trusted automatically', () => {
    const settings = rules.defaultAntiNukeSettings();
    assert.equal(rules.isTrusted({ userId: '555', roleIds: ['admin-role'], guildOwnerId: '999', settings }), false);
});

// ── Sliding-window detector ─────────────────────────────────────────────────

test('the detector trips only once the threshold is reached inside the window', () => {
    const d = new AntiNukeDetector();
    const base = { guildId: 'g', actionKey: 'channelDelete', executorId: 'u', threshold: 3, seconds: 10 };
    assert.equal(d.record({ ...base, ts: 1000 }).tripped, false);
    assert.equal(d.record({ ...base, ts: 2000 }).tripped, false);
    assert.equal(d.record({ ...base, ts: 3000 }).tripped, true, 'third action in the window trips');
});

test('actions from different executors are never counted together', () => {
    const d = new AntiNukeDetector();
    const base = { guildId: 'g', actionKey: 'roleDelete', threshold: 2, seconds: 10 };
    d.record({ ...base, executorId: 'a', ts: 1000 });
    const other = d.record({ ...base, executorId: 'b', ts: 1000 });
    assert.equal(other.count, 1, 'a second executor starts their own window');
    assert.equal(other.tripped, false);
});

test('a sliding window forgets entries older than its length', () => {
    const d = new AntiNukeDetector();
    const base = { guildId: 'g', actionKey: 'memberBan', executorId: 'u', threshold: 3, seconds: 10 };
    d.record({ ...base, ts: 0 });
    d.record({ ...base, ts: 1000 });
    // 20s later the first two have aged out.
    const r = d.record({ ...base, ts: 21000 });
    assert.equal(r.count, 1);
    assert.equal(r.tripped, false);
});

test('the detector enforces the response cooldown per guild+action', () => {
    const d = new AntiNukeDetector();
    assert.equal(d.tryConsumeCooldown('g', 'channelDelete', 30, 1000), true, 'the first response is allowed');
    assert.equal(d.tryConsumeCooldown('g', 'channelDelete', 30, 2000), false, 'a second response inside the cooldown is blocked');
    assert.equal(d.tryConsumeCooldown('g', 'channelDelete', 30, 32000), true, 'the cooldown expires');
    assert.equal(d.tryConsumeCooldown('g', 'roleDelete', 30, 32000), true, 'other actions are unaffected');
    assert.equal(d.tryConsumeCooldown('g', 'roleDelete', 0, 32000), true, 'a zero cooldown always allows');
});

test('the detector is bounded — it never grows without limit', () => {
    const d = new AntiNukeDetector({ maxWindows: 50 });
    for (let i = 0; i < 500; i++) {
        d.record({ guildId: 'g', actionKey: 'channelDelete', executorId: `u${i}`, threshold: 3, seconds: 10, ts: i });
    }
    assert.ok(d.windows.size <= 50, `window map must stay bounded, got ${d.windows.size}`);
});

test('a SlidingWindow caps its own entry list', () => {
    const w = new SlidingWindow({ seconds: 100, maxEntries: 5 });
    for (let i = 0; i < 50; i++) w.add(i);
    assert.ok(w.count(1000) <= 5, 'entries per window are capped');
});

// ── evaluateBurst ───────────────────────────────────────────────────────────

test('evaluateBurst reports each tripped action with its window metadata', () => {
    const settings = rules.normalizeAntiNukeSettings({});
    const now = Date.now();
    const counts = {
        channelDelete: [{ ts: now - 5000, userId: 'u' }, { ts: now - 4000, userId: 'u' }, { ts: now - 3000, userId: 'u' }, { ts: now - 2000, userId: 'u' }],
    };
    const tripped = rules.evaluateBurst(counts, settings, now);
    const channel = tripped.find(t => t.action === 'channelDelete');
    assert.ok(channel, 'a 4-in-10s channel burst must trip the default threshold of 3');
    assert.equal(channel.count, 4);
    assert.equal(channel.threshold, 3);
    assert.equal(channel.userId, 'u');
});

test('evaluateBurst ignores actions outside the window and disabled rules', () => {
    const settings = rules.normalizeAntiNukeSettings({ watched: { channelDelete: { enabled: false } } });
    const now = Date.now();
    const counts = { channelDelete: Array.from({ length: 10 }, (_, i) => ({ ts: now - 60000 - i, userId: 'u' })) };
    assert.equal(rules.evaluateBurst(counts, settings, now).length, 0, 'disabled + stale actions never trip');
});

test('watchFor falls back to the catalog default for an action with no override', () => {
    const settings = rules.normalizeAntiNukeSettings({});
    const w = rules.watchFor(settings, 'channelDelete');
    assert.equal(w.threshold, rules.NUKE_ACTION_BY_KEY.channelDelete.threshold);
    assert.equal(rules.watchFor(settings, 'not-an-action'), null);
});

// ── Audit-entry → action mapping ────────────────────────────────────────────

test('a channel-delete audit entry maps to the channelDelete action', () => {
    // The catalog keys actions by the AuditLogEvent NAME ("ChannelDelete").
    const matched = entry.evaluateAuditEntry({ action: 'ChannelDelete', targetId: '123', executorId: 'u' }, { id: 'g' });
    assert.ok(matched.some(m => m.actionKey === 'channelDelete'), 'ChannelDelete must map to channelDelete');
});

test('evaluateAuditEntry never emits an action key outside the catalog', () => {
    const keys = new Set(rules.NUKE_ACTION_KEYS);
    for (const action of ['ChannelCreate', 'ChannelDelete', 'RoleCreate', 'RoleDelete', 'RoleUpdate', 'MemberBanAdd', 'GuildUpdate', 'BotAdd', 'WebhookCreate', 'nonsense']) {
        for (const m of entry.evaluateAuditEntry({ action, targetId: '1', executorId: 'u' }, { id: 'g' })) {
            assert.ok(keys.has(m.actionKey), `${action} produced unknown action ${m.actionKey}`);
        }
    }
});

test('every catalog audit event is reachable through the entry mapper', () => {
    for (const action of rules.NUKE_ACTIONS) {
        const candidates = entry.actionsForAuditEvent(action.auditEvent);
        assert.ok(candidates.includes(action.key), `${action.key} is not indexed under ${action.auditEvent}`);
    }
});

test('a role-update that grants Administrator is detected as a privilege escalation', () => {
    const ADMIN = 0x8n;
    const matched = entry.evaluateAuditEntry({
        action: 'RoleUpdate',
        targetId: 'role',
        executorId: 'u',
        changes: [{ key: 'permissions', old: 0n, new: ADMIN }],
    }, { id: 'g' });
    assert.ok(matched.some(m => m.actionKey === 'adminGrant' || m.actionKey === 'rolePermissionUpdate'),
        'an Administrator grant must map to a permission-escalation action');
});

test('entryGrantsPermission reads a permission grant from an audit change', () => {
    const ADMIN = 0x8n;
    const granted = entry.entryGrantsPermission({
        action: 'RoleUpdate',
        changes: [{ key: 'permissions', old: 0n, new: ADMIN }],
    }, 'Administrator');
    assert.equal(granted, true, 'a newly granted Administrator bit is detected');
    const notGranted = entry.entryGrantsPermission({
        action: 'RoleUpdate',
        changes: [{ key: 'permissions', old: ADMIN, new: ADMIN }],
    }, 'Administrator');
    assert.equal(notGranted, false, 'an unchanged bit is not a grant');
    const dangerous = entry.entryGrantsPermission({
        action: 'RoleUpdate',
        changes: [{ key: 'permissions', old: 0n, new: ADMIN }],
    }, 'dangerous');
    assert.equal(dangerous, true, 'the "dangerous" pseudo-key matches any configured dangerous permission');
});

// ── Audit correlation helpers ───────────────────────────────────────────────

test('matchAuditEntry only matches an entry with the right type, target and a fresh timestamp', () => {
    const now = Date.now();
    const TYPE = 12; // arbitrary numeric AuditLogEvent
    const entries = [
        { id: 'a', action: TYPE, targetId: '111', executorId: 'u', createdTimestamp: now - 500 },
        { id: 'b', action: TYPE, targetId: '222', executorId: 'u', createdTimestamp: now - 500 },
        { id: 'c', action: TYPE, targetId: '111', executorId: 'u', createdTimestamp: now - 600000 },
        { id: 'd', action: 99, targetId: '111', executorId: 'u', createdTimestamp: now - 500 },
    ];
    const hit = audit.matchAuditEntry(entries, { type: TYPE, targetId: '111', now, maxAgeMs: 5000 });
    assert.ok(hit && hit.id === 'a', 'the freshest matching entry wins');
    assert.equal(audit.matchAuditEntry(entries, { type: TYPE, targetId: '333', now }), null, 'a different target never matches');
    assert.equal(audit.matchAuditEntry(entries, { type: 77, targetId: '111', now }), null, 'a type no entry carries never matches');
});

test('matchAuditEntry refuses to attribute an entry with no executor', () => {
    const now = Date.now();
    const entries = [{ id: 'a', action: 12, targetId: '111', executorId: null, createdTimestamp: now - 500 }];
    assert.equal(audit.matchAuditEntry(entries, { type: 12, targetId: '111', now }), null,
        'an unattributable entry is never used');
});

test('the dedup key is stable for the same audit entry and distinct across entries', () => {
    const k1 = audit.dedupeKey({ id: 'a' });
    const k2 = audit.dedupeKey({ id: 'a' });
    const k3 = audit.dedupeKey({ id: 'b' });
    assert.equal(k1, k2);
    assert.notEqual(k1, k3);
});

// ── Setup wizard progress ───────────────────────────────────────────────────

test('progress is derived from real step state, never a timer', () => {
    let state = setup.normalizeSetupState({ method: 'automatic' });
    let p = setup.computeProgress('automatic', state);
    assert.equal(p.percent, 0);
    assert.equal(p.completed, 0);
    assert.ok(p.total > 0);

    state = setup.applyStep(state, 'inspection', { status: 'completed' });
    p = setup.computeProgress('automatic', state);
    assert.equal(p.completed, 1);
    assert.equal(p.percent, Math.round((1 / p.total) * 100));
});

test('failed and skipped steps never count as completed', () => {
    let state = setup.normalizeSetupState({ method: 'automatic' });
    state = setup.applyStep(state, 'inspection', { status: 'failed', error: 'boom' });
    state = setup.applyStep(state, 'permissions', { status: 'skipped' });
    const p = setup.computeProgress('automatic', state);
    assert.equal(p.completed, 0);
    assert.equal(p.failed, 1);
    assert.equal(p.skipped, 1);
    assert.equal(setup.isComplete('automatic', state), false);
});

test('setup only counts as complete when every required step succeeded', () => {
    let state = setup.normalizeSetupState({ method: 'automatic' });
    for (const step of setup.AUTOMATIC_STEPS) {
        state = setup.applyStep(state, step.key, { status: 'completed' });
    }
    const p = setup.computeProgress('automatic', state);
    assert.equal(p.percent, 100);
    assert.equal(setup.isComplete('automatic', state), true);
});

test('an optional section does not change the manual-setup percentage', () => {
    let withOptional = setup.normalizeSetupState({ method: 'manual' });
    let withoutOptional = setup.normalizeSetupState({ method: 'manual' });
    withOptional = setup.applyStep(withOptional, 'general', { status: 'completed' });
    withoutOptional = setup.applyStep(withoutOptional, 'general', { status: 'completed' });
    withOptional = setup.applyStep(withOptional, 'trust', { status: 'skipped' }); // optional
    const a = setup.computeProgress('manual', withOptional);
    const b = setup.computeProgress('manual', withoutOptional);
    assert.equal(a.percent, b.percent, 'a skipped optional section must not move the bar');
    assert.equal(a.total, b.total, 'optional steps are excluded from the denominator');
});

test('setup state survives a serialize/parse round trip (resume after refresh)', () => {
    let state = setup.normalizeSetupState({ method: 'manual' });
    state = setup.applyStep(state, 'general', { status: 'completed' });
    state = setup.applyStep(state, 'channel', { status: 'failed', error: 'no perms' });
    const roundTripped = setup.normalizeSetupState(JSON.parse(JSON.stringify(state)));
    const p = setup.computeProgress('manual', roundTripped);
    assert.equal(p.completed, 1);
    assert.equal(p.failed, 1);
    assert.equal(roundTripped.steps.channel.error, 'no perms', 'the failure detail survives');
});

test('diffRecommended reports what automatic setup would change', () => {
    const current = { enabled: false, dryRun: true, alertChannelId: null, watched: {} };
    const recommended = require('../utils/antiNukeSetupRunner').recommendedConfig();
    const diff = setup.diffRecommended(current, recommended);
    assert.ok(diff.some(d => d.field === 'enabled'), 'enabling protection is a reported change');
    assert.ok(diff.some(d => d.field.startsWith('watched.')), 'threshold changes are reported');
});

// ── Permission validation ───────────────────────────────────────────────────

test('permission validation reports missing permissions honestly', () => {
    const none = validatePermissionsFromBitfield(0n);
    assert.equal(none.ok, false);
    assert.ok(none.missing.length > 0, 'a zero bitfield has everything missing');
    const all = validatePermissionsFromBitfield(0xFFFFFFFFFFFFFn);
    assert.equal(all.ok, true, 'a full bitfield passes every check');
    for (const c of all.checks) assert.equal(c.available, true);
});

test('validateBotPermissions degrades safely when the bot member is unknown', () => {
    const report = validateBotPermissions({ members: {} });
    assert.equal(report.ok, false);
    assert.ok(Array.isArray(report.checks));
});

// ── Alert embeds ────────────────────────────────────────────────────────────

test('the security alert embed carries the required fields and never pings @everyone', () => {
    const embed = buildSecurityAlertEmbed({
        title: 'Potential Nuke Attempt Detected',
        severity: 'critical',
        threatLabel: 'Mass Channel Deletion',
        executorLabel: '<@123456789012345678> (Moderator)',
        actionSummary: '4 channel deletions',
        windowLabel: '10 seconds',
        responseLabel: 'Dry-run / Containment',
        guildName: 'Example Server',
        dryRun: true,
    });
    const json = typeof embed.toJSON === 'function' ? embed.toJSON() : embed;
    const flat = JSON.stringify(json);
    assert.ok(flat.includes('Mass Channel Deletion'));
    assert.ok(flat.includes('123456789012345678'), 'the executor is named');
    assert.ok(flat.includes('4 channel deletions'), 'the action summary is present');
    assert.ok(flat.includes('DRY RUN'), 'the dry-run state is disclosed');
    assert.ok(!flat.includes('@everyone'), 'never mention @everyone');
    assert.ok(!flat.includes('@here'), 'never mention @here');
});

test('severity colours are event-specific and complete', () => {
    for (const sev of ['critical', 'high', 'medium', 'protected', 'info']) {
        assert.ok(SEVERITY_COLORS[sev] != null, `${sev} needs a colour`);
        assert.ok(typeof severityColor(sev) === 'number');
    }
    assert.notEqual(severityColor('critical'), severityColor('info'));
    assert.equal(severityColor('nonsense'), SEVERITY_COLORS.info, 'an unknown severity falls back to informational');
});

// ── Dangerous-role containment safety rules ─────────────────────────────────

const {
    dangerousPermissionsOnRole, computeDangerousRoleRemovals, stripDangerousRoles,
} = require('../utils/antiNukeContainment');

function role(id, name, { admin = false, position = 1, managed = false, grants = [] } = {}) {
    return {
        id, name, position, managed,
        permissions: { has: (flag) => admin || grants.includes(flag) },
    };
}

function memberWith(id, roles) {
    return { id, roles: { cache: new Map(roles.map(r => [r.id, r])) } };
}

test('containment never touches the owner or the bot itself', () => {
    const owner = memberWith('owner', [role('r1', 'Admin', { admin: true })]);
    const plan = computeDangerousRoleRemovals({ member: owner, guildOwnerId: 'owner', botUserId: 'bot', botMember: { roles: { highest: { position: 50 } } } });
    assert.equal(plan.reason, 'owner_exempt');
    assert.equal(plan.removable.length, 0);

    const bot = memberWith('bot', [role('r1', 'Admin', { admin: true })]);
    const plan2 = computeDangerousRoleRemovals({ member: bot, guildOwnerId: 'owner', botUserId: 'bot', botMember: { roles: { highest: { position: 50 } } } });
    assert.equal(plan2.reason, 'bot_exempt');
});

test('containment only targets roles that grant a configured dangerous permission', () => {
    const ADMIN = 0x8n;
    const member = memberWith('u', [
        role('admin', 'Admin', { admin: true }),
        role('neutral', 'Members', {}),
        role('mod', 'Moderator', { grants: [ADMIN] }),
    ]);
    const plan = computeDangerousRoleRemovals({
        member, guildOwnerId: 'owner', botUserId: 'bot',
        botMember: { roles: { highest: { position: 50 } } },
        dangerousPermissions: ['Administrator'],
    });
    const ids = plan.removable.map(r => r.roleId);
    assert.ok(ids.includes('admin'), 'the admin role is removable');
    assert.ok(ids.includes('mod'), 'a role granting Administrator is removable');
    assert.ok(!ids.includes('neutral'), 'an unrelated role is never touched');
});

test('containment never attempts a role at or above the bot highest role', () => {
    const member = memberWith('u', [role('high', 'High', { admin: true, position: 60 })]);
    const plan = computeDangerousRoleRemovals({
        member, guildOwnerId: 'owner', botUserId: 'bot',
        botMember: { roles: { highest: { position: 50 } } },
        dangerousPermissions: ['Administrator'],
    });
    assert.equal(plan.removable.length, 0);
    assert.equal(plan.skipped[0].reason, 'above_bot');
});

test('containment skips trusted roles and managed (integration) roles', () => {
    const member = memberWith('u', [
        role('trusted', 'Trusted', { admin: true }),
        role('managed', 'Bot Role', { admin: true, managed: true }),
    ]);
    const plan = computeDangerousRoleRemovals({
        member, guildOwnerId: 'owner', botUserId: 'bot',
        botMember: { roles: { highest: { position: 50 } } },
        trustedRoleIds: ['trusted'],
        dangerousPermissions: ['Administrator'],
    });
    assert.equal(plan.removable.length, 0);
    const reasons = plan.skipped.map(s => s.reason).sort();
    assert.deepEqual(reasons, ['managed_role', 'trusted_role']);
});

test('stripDangerousRoles removes only the planned roles and reports failures', async () => {
    const removed = [];
    const member = {
        roles: {
            remove: async (id) => {
                if (id === 'bad') throw new Error('missing permissions');
                removed.push(id);
            },
        },
    };
    const res = await stripDangerousRoles(member, { removable: [{ roleId: 'good' }, { roleId: 'bad' }], skipped: [] });
    assert.deepEqual(removed, ['good']);
    assert.equal(res.removed.length, 1);
    assert.equal(res.failed.length, 1);
    assert.match(res.failed[0].error, /missing permissions/);
});

test('dangerousPermissionsOnRole reports the exact permissions a role grants', () => {
    const ADMIN = 0x8n;
    const hits = dangerousPermissionsOnRole(role('r', 'Admin', { grants: [ADMIN] }), ['Administrator']);
    assert.deepEqual(hits, ['Administrator']);
    assert.deepEqual(dangerousPermissionsOnRole(role('n', 'Neutral', {}), ['Administrator']), []);
});

test('an empty dangerous-permission list strips NOTHING (never widens to the catalog)', () => {
    const ADMIN = 0x8n;
    // A role that would match the catalog default must NOT match an empty list —
    // otherwise "alert only" silently becomes full containment.
    assert.deepEqual(dangerousPermissionsOnRole(role('r', 'Admin', { grants: [ADMIN] }), []), []);
    const plan = computeDangerousRoleRemovals({
        member: memberWith('m1', [role('r', 'Admin', { grants: [ADMIN] })]),
        botMember: { roles: { highest: { position: 50 } } },
        guildOwnerId: 'owner', botUserId: 'bot',
        trustedRoleIds: [],
        dangerousPermissions: [],
    });
    assert.deepEqual(plan.removable, [], 'nothing is removable when no permissions are configured');
    assert.equal(plan.reason, null, 'this is a valid configuration, not an error');
});

// ── Lockdown: reversible, never clobbers a later admin change ───────────────

const {
    applyLockdown, restoreLockdown, planInvitePause, VERIFICATION_LEVELS,
} = require('../utils/antiNukeContainment');

function lockdownGuild({ verificationLevel = 0 } = {}) {
    const state = { verificationLevel };
    const overwrites = new Map();
    const mkChannel = (id) => ({
        id, type: 0,
        permissionOverwrites: {
            cache: { get: () => overwrites.get(id) },
            edit: async (_gid, perms) => {
                const cur = overwrites.get(id) || { allow: 0n, deny: 0n };
                const next = { ...cur };
                if (perms.CreateInstantInvite === false) next.deny = cur.deny | 0x1n;
                else if (perms.CreateInstantInvite === null) next.deny = cur.deny & ~0x1n;
                if (perms.allow !== undefined) next.allow = BigInt(perms.allow);
                if (perms.deny !== undefined) next.deny = BigInt(perms.deny);
                overwrites.set(id, next);
            },
        },
        permissionsFor: () => ({ has: () => true }),
    });
    const cache = new Map([['c1', mkChannel('c1')], ['c2', mkChannel('c2')]]);
    return {
        id: 'g', ownerId: 'o', memberCount: 3,
        get verificationLevel() { return state.verificationLevel; },
        setVerificationLevel: async (v) => { state.verificationLevel = v; },
        channels: { cache, fetch: async (id) => cache.get(id) || null },
        roles: { cache: new Map() }, members: { me: { roles: { highest: { position: 50 } } } },
        _state: state, _overwrites: overwrites,
    };
}

test('lockdown raises verification, pauses invites, and is fully reversible', async () => {
    const guild = lockdownGuild({ verificationLevel: 0 });
    const settings = { lockdown: { enabled: true, verificationLevel: 'high', pauseInvites: true } };

    const record = await applyLockdown(guild, { settings, reason: 'test' });
    assert.equal(record.active, true);
    assert.equal(record.verificationLevelBefore, 0);
    assert.equal(record.verificationLevelAfter, VERIFICATION_LEVELS.high);
    assert.equal(record.inviteChanges.length, 2, 'both invite-allowing channels are paused');
    assert.equal(record.pausedInvites, true);
    assert.equal(guild._state.verificationLevel, VERIFICATION_LEVELS.high);
    assert.equal((guild._overwrites.get('c1').deny & 0x1n), 0x1n);

    const { restored, warnings } = await restoreLockdown(guild, record, { reason: 'lift' });
    assert.deepEqual(warnings, []);
    assert.equal(restored.verificationLevel, true);
    assert.equal(restored.invites, 2);
    assert.equal(guild._state.verificationLevel, 0, 'verification level is restored');
    assert.equal((guild._overwrites.get('c1').deny & 0x1n), 0n, 'invite deny bit is cleared');
});

test('lockdown restore never clobbers a change an administrator made after lockdown', async () => {
    const guild = lockdownGuild({ verificationLevel: 0 });
    const settings = { lockdown: { enabled: true, verificationLevel: 'high', pauseInvites: true } };
    const record = await applyLockdown(guild, { settings, reason: 'test' });

    // Admin raises the verification level further while the lockdown is active.
    await guild.setVerificationLevel(VERIFICATION_LEVELS.veryHigh);

    const { restored, warnings } = await restoreLockdown(guild, record, { reason: 'lift' });
    assert.equal(restored.verificationLevel, false, 'the admin change is preserved, not reverted');
    assert.equal(guild._state.verificationLevel, VERIFICATION_LEVELS.veryHigh);
    assert.ok(warnings.includes('verification_level_changed_by_admin'));
});

test('lockdown never fans out past the channel cap', () => {
    const guild = lockdownGuild();
    // Add far more invite-allowing channels than the cap.
    for (let i = 0; i < 200; i++) {
        guild.channels.cache.set('x' + i, {
            id: 'x' + i, type: 0,
            permissionOverwrites: { cache: { get: () => null } },
            permissionsFor: () => ({ has: () => true }),
        });
    }
    const plan = planInvitePause(guild);
    assert.equal(plan.length, 50, 'the plan is capped so a lockdown cannot burst the API');
});

// ── Alert-channel resolution (live guild AND dashboard REST shim) ────────────

const { resolveAlertChannel, ALERT_CHANNEL_CANDIDATES } = require('../utils/antiNukeSetupRunner');

function restShimGuild(channels) {
    const map = new Map(channels.map(c => [String(c.id), c]));
    return {
        id: 'g',
        channels: {
            cache: {
                find: (fn) => { for (const v of map.values()) if (fn(v)) return v; return undefined; },
                get: (id) => map.get(String(id)) || null,
            },
            fetch: async (id) => map.get(String(id)) || null,
        },
        members: { me: { permissions: { has: () => true } } },
    };
}

test('alert channel resolves from a dashboard REST shim (descriptors have no .send)', async () => {
    // The dashboard has no gateway client: its guild shim exposes plain channel
    // descriptors. The resolver must still find #security-logs, otherwise the
    // wizard could never complete from the dashboard.
    const guild = restShimGuild([
        { id: '1', name: 'general', type: 0 },
        { id: '2', name: 'security-logs', type: 0 },
    ]);
    const res = await resolveAlertChannel(guild, null);
    assert.equal(res.channelId, '2');
    assert.equal(res.source, 'matched');
});

test('alert channel honours an existing configured channel id', async () => {
    const guild = restShimGuild([{ id: '7', name: 'ops', type: 0 }]);
    const res = await resolveAlertChannel(guild, '7');
    assert.equal(res.channelId, '7');
    assert.equal(res.source, 'existing');
});

test('alert channel reports "none" honestly when no candidate exists', async () => {
    const guild = restShimGuild([{ id: '1', name: 'general', type: 0 }]);
    const res = await resolveAlertChannel(guild, null);
    assert.equal(res.channelId, null);
    assert.equal(res.source, 'none');
    assert.ok(ALERT_CHANNEL_CANDIDATES.includes('security-logs'));
});

// ── Manager surface (no DB) ─────────────────────────────────────────────────

test('the manager never throws when the database is unavailable', async () => {
    delete process.env.ANUKE_DATABASE_URL;
    delete process.env.DATABASE_URL;
    const AntiNukeManager = require('../utils/antiNukeManager');
    const m = new AntiNukeManager({ client: null });
    // These all degrade to a safe no-op / empty result.
    assert.equal(m.isEnabled('g'), false);
    const res = await m.processEvent({ guild: { id: 'g', ownerId: 'o', members: { me: null } }, actionKey: 'channelDelete', knownExecutorId: 'u' });
    assert.equal(res.handled, false);
    if (typeof m.stop === 'function') m.stop();
});
