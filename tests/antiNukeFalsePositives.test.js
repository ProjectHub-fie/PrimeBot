/**
 * Anti-Nuke false-positive regression tests.
 *
 * The task: ordinary role-management and legitimate moderation must NOT
 * trigger Anti-Nuke reports, role removal, or punishment, while genuine
 * unauthorized destructive activity remains protected.
 *
 * These tests pin the classification + threshold behaviour that previously
 * produced false positives:
 *
 *   1. A member receiving a role (single) → no report.
 *   2. An admin assigning a role to a member (single) → no punishment.
 *   3. An admin removing a role from a member (single) → no report.
 *   4. An admin banning a member legitimately → no punishment.
 *   5. An admin kicking a member legitimately → no punishment.
 *   6. Unauthorized member deleting many roles → protection activates.
 *   7. Unauthorized member creating a dangerous permission on a role → Role
 *      Guard evaluates and responds (the rolePermissionUpdate guard + the
 *      dangerous/manage-* grant rules).
 *   8. Unauthorized member rapidly banning members → ban protection evaluates.
 *   9. An audit entry belonging to another event is never misattributed.
 *  10. A delayed audit entry is retried safely and only matched when fresh.
 *  11. Duplicate delivery across handlers/nodes → no duplicate punishment.
 *  12. Existing legitimate-attack protection is preserved.
 *
 * The manager tests mount the REAL AntiNukeManager with the DB pool stubbed
 * out (no Postgres in CI), following the existing enforcer-test pattern.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');

const rules = require('../utils/antiNukeRules');
const entry = require('../utils/antiNukeEntry');
const audit = require('../utils/antiNukeAudit');
const { AntiNukeDetector } = require('../utils/antiNukeDetector');

const ADMIN_FLAG = 0x8n; // PermissionFlagsBits.Administrator

// ── Pure classification + threshold tests (no manager/DB) ───────────────────

test('a member receiving a single role is never mapped to a destructive action', () => {
    // A normal MemberRoleUpdate that adds ONE non-dangerous role.
    const matched = entry.evaluateAuditEntry({
        action: 'MemberRoleUpdate',
        targetId: 'member1',
        executorId: 'mod',
        changes: [{ key: '$add', new: [{ id: 'role1' }] }],
    }, {
        id: 'g',
        roles: { cache: new Map([[ 'role1', { id: 'role1', permissions: { has: (f) => f === ADMIN_FLAG ? false : false, bitfield: 0n } } ]]) },
    });
    // No role edge matched as a single assignment; if memberRoleUpdate or
    // adminGrant IS present it must remain below its (now raised) threshold.
    const dangerKeys = matched.map(m => m.actionKey);
    assert.ok(!dangerKeys.includes('adminGrant'), 'a single role assignment is not adminGrant');
    assert.ok(!dangerKeys.includes('botPermissionEscalation'), 'a single non-dangerous assignment is not a bot escalation');
});

test('a single dangerous-role grant does not trip the detector (raised threshold)', () => {
    const det = new AntiNukeDetector();
    // One grant of a role that grants Administrator.
    let r = det.record({ guildId: 'g', actionKey: 'adminGrant', executorId: 'mod', threshold: rules.NUKE_ACTION_BY_KEY.adminGrant.threshold, seconds: rules.NUKE_ACTION_BY_KEY.adminGrant.seconds, ts: Date.now() });
    assert.equal(r.tripped, false, 'a single Administrator-role grant stays below threshold');
    r = det.record({ guildId: 'g', actionKey: 'botPermissionEscalation', executorId: 'mod', threshold: rules.NUKE_ACTION_BY_KEY.botPermissionEscalation.threshold, seconds: rules.NUKE_ACTION_BY_KEY.botPermissionEscalation.seconds, ts: Date.now() + 1000 });
    assert.equal(r.tripped, false, 'a single dangerous-role grant stays below threshold');
});

test('an unauthorized actor granting Administrator several times in a window still trips', () => {
    const det = new AntiNukeDetector();
    const thr = rules.NUKE_ACTION_BY_KEY.adminGrant.threshold; // 3
    const sec = rules.NUKE_ACTION_BY_KEY.adminGrant.seconds;   // 60
    const base = Date.now();
    let tripped = false;
    for (let i = 0; i < thr; i++) {
        tripped = det.record({ guildId: 'g', actionKey: 'adminGrant', executorId: 'attacker', threshold: thr, seconds: sec, ts: base + i * 1000 }).tripped;
    }
    assert.equal(tripped, true, 'repeated Administrator grants trip the raised threshold');
});

test('cosmetic role updates never count as role-permission changes', () => {
    // A RoleUpdate that only renamed/hoisted the role (no permission change).
    const matched = entry.evaluateAuditEntry({
        action: 'RoleUpdate',
        targetId: 'role1',
        executorId: 'mod',
        changes: [{ key: 'name', old: 'Old', new: 'New' }],   // no permissions key
    }, { id: 'g' });
    assert.ok(!matched.some(m => m.actionKey === 'rolePermissionUpdate'),
        'a cosmetic (non-permission) role update is NOT a permission change');
    assert.ok(!matched.some(m => m.actionKey === 'dangerousPermissionGrant'), 'no dangerous grant');
});

test('a real permission change on a role still maps to the permission guard', () => {
    const matched = entry.evaluateAuditEntry({
        action: 'RoleUpdate',
        targetId: 'role1',
        executorId: 'mod',
        changes: [{ key: 'permissions', old: 0n, new: ADMIN_FLAG }],
    }, { id: 'g' });
    assert.ok(matched.some(m => m.actionKey === 'rolePermissionUpdate'),
        'a real permission change maps to rolePermissionUpdate');
    assert.ok(matched.some(m => m.actionKey === 'dangerousPermissionGrant'),
        'a real Administrator grant maps to the dangerous-permission grant');
});

test('entryHasPermissionChange distinguishes cosmetic from real permission edits', () => {
    assert.equal(entry.entryHasPermissionChange({ action: 'RoleUpdate', changes: [{ key: 'name', old: 'a', new: 'b' }] }), false);
    assert.equal(entry.entryHasPermissionChange({ action: 'RoleUpdate', changes: [{ key: 'permissions', old: 0n, new: ADMIN_FLAG }] }), true);
    assert.equal(entry.entryHasPermissionChange({ action: 'RoleUpdate', changes: [{ key: 'permissions', old: ADMIN_FLAG, new: ADMIN_FLAG }] }), false, 'an unchanged bitfield is not a change');
    assert.equal(entry.entryHasPermissionChange({ action: 'RoleUpdate', changes: [] }), false);
});

// ── Audit-log misattribution / delayed-entry / safety ───────────────────────

test('an audit entry belonging to another target is never misattributed', () => {
    const now = Date.now();
    const TYPE = 11; // channel delete-like numeric
    const entries = [
        { id: 'x', action: TYPE, targetId: 'victim', executorId: 'attacker', createdTimestamp: now - 300 },
        { id: 'y', action: TYPE, targetId: 'other',  executorId: 'attacker', createdTimestamp: now - 300 },
    ];
    const hit = audit.matchAuditEntry(entries, { type: TYPE, targetId: 'victim', now, maxAgeMs: 5000 });
    assert.equal(hit && hit.id, 'x', 'only the entry whose target matches is selected');
    assert.equal(audit.matchAuditEntry(entries, { type: TYPE, targetId: 'nope', now, maxAgeMs: 5000 }), null,
        'a target mismatch never matches');
});

test('a delayed audit entry is only matched once it is fresh enough, and stale ones are rejected', () => {
    const now = Date.now();
    const TYPE = 12;
    const stale = audit.matchAuditEntry([
        { id: 's', action: TYPE, targetId: 't', executorId: 'u', createdTimestamp: now - 600000 },
    ], { type: TYPE, targetId: 't', now, maxAgeMs: 5000 });
    assert.equal(stale, null, 'an entry created long before the event is unrelated (stale)');
    const fresh = audit.matchAuditEntry([
        { id: 'f', action: TYPE, targetId: 't', executorId: 'u', createdTimestamp: now - 200 },
    ], { type: TYPE, targetId: 't', now, maxAgeMs: 5000 });
    assert.ok(fresh && fresh.executorId === 'u', 'a fresh matching entry is accepted');
    // A future-dated entry is impossible.
    assert.equal(audit.matchAuditEntry([
        { id: 'z', action: TYPE, targetId: 't', executorId: 'u', createdTimestamp: now + 60000 },
    ], { type: TYPE, targetId: 't', now, maxAgeMs: 5000 }), null, 'a future entry is rejected');
});

test('a delayed audit entry is retried: fetch returns nothing first, then the entry appears', async () => {
    const { correlateAuditEntry, DEFAULT_DELAY_MS } = audit;
    // Simulate Discord writing the entry a beat late with a first empty read.
    let call = 0;
    const guild = {
        fetchAuditLogs: async () => {
            call++;
            if (call === 1) return { entries: new Map() }; // empty — entry not written yet
            return entryResults();
        },
    };
    // helper returns a map with one matching fresh entry
    function entryResults() {
        const e = { id: 'later', action: 12, targetId: 't1', executorId: 'u1', createdTimestamp: Date.now() - 100 };
        const m = new Map(); m.set(e.id, e); return { entries: m };
    }
    const res = await correlateAuditEntry(guild, { auditEvent: 12, targetId: 't1', delayMs: 0, maxAgeMs: 5000 });
    assert.equal(res.ok, true, 'a delayed entry is found on retry');
    assert.equal(res.executorId, 'u1');
    assert.ok(call >= 2, 'retried after the first empty read');
});

test('an entry whose executor is missing is never used to attribute', () => {
    const now = Date.now();
    const hit = audit.matchAuditEntry([
        { id: 'n', action: 12, targetId: 't1', executorId: null, createdTimestamp: now - 100 },
    ], { type: 12, targetId: 't1', now, maxAgeMs: 5000 });
    assert.equal(hit, null, 'an entry with no executor cannot attribute anyone');
});

test('the dedup key prevents the same entry from being consumed twice', () => {
    const { dedupeKey } = audit;
    const e = { id: 'a1', action: 12, targetId: 't1', executorId: 'u1' };
    assert.equal(dedupeKey(e), dedupeKey({ id: 'a1', action: 12, targetId: 't1', executorId: 'u1' }));
    assert.notEqual(dedupeKey(e), dedupeKey({ id: 'a2', action: 12, targetId: 't1', executorId: 'u1' }));
});

// ── Manager-level: legitimate actions never punished, attacks still caught ──

// A real manager with the DB stubbed. `claimDedupKey` returns true (single
// node claims everything), the incident recorder is a no-op, detection uses the
// real AntiNukeDetector so thresholds are exercised for real.
function makeManager({ detector } = {}) {
    const anukeDb = require('../server/anukeDb');
    const originalClaim = anukeDb.claimDedupKey;
    const originalQuery = anukeDb.anukePool.query;
    anukeDb.claimDedupKey = async () => true;
    anukeDb.anukePool.query = async () => ({ rows: [] });
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    // Restore the module-level stubs for the NEXT manager construction.
    anukeDb.claimDedupKey = originalClaim;
    anukeDb.anukePool.query = originalQuery;

    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    if (detector) mgr.detector = detector;
    return { mgr, anukeDb };
}

function stubGuild({ ownerId = 'owner', roles = new Map(), mePos = 10 } = {}) {
    return {
        id: 'guild1',
        ownerId,
        name: 'Guild',
        members: {
            me: { id: 'bot', permissions: { has: () => true }, roles: { highest: { position: mePos } } },
            cache: new Map(),
            fetch: async () => null,
        },
        roles: { cache: roles },
        channels: { cache: new Map() },
    };
}

function normalSettings() {
    return rules.normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        actionResponses: {
            memberRoleUpdate: ['alertOwner'],
            adminGrant: ['alertOwner'],
            botPermissionEscalation: ['alertOwner'],
            rolePermissionUpdate: ['alertOwner'],
            dangerousPermissionGrant: ['alertOwner'],
            manageRolesGrant: ['alertOwner'],
            memberBan: ['alertOwner'],
            memberKick: ['alertOwner'],
            roleDelete: ['alertOwner', 'quarantine'],
        },
    });
}

test('NO false positive: a member receiving a role via an ordinary assignment', async () => {
    const { mgr } = makeManager();
    const guild = stubGuild();
    const settings = normalSettings();
    mgr._cache.set(guild.id, settings);
    mgr._fetchMember = async () => ({ id: 'mod', user: { tag: 'mod#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    let incident = null;
    mgr._alert = async () => { throw new Error('must not alert'); };
    mgr._recordIncident = async (i) => { incident = i; };

    const res = await mgr.processEvent({
        guild, actionKey: 'memberRoleUpdate', knownExecutorId: 'mod',
        details: { auditEntryId: 'fp1', targetId: 'memberA', summary: 'one role added' },
    });
    // memberRoleUpdate threshold is 10 — one role assignment never trips.
    assert.equal(res.handled, false);
    assert.equal(res.reason, 'below_threshold');
    assert.equal(incident, null, 'no incident recorded for a single role assignment');
    mgr._seenEventIds.clear();
});

test('NO false positive: an admin assigning a single role is not punished', async () => {
    const { mgr } = makeManager();
    const guild = stubGuild();
    const settings = normalSettings();
    mgr._cache.set(guild.id, settings);
    mgr._fetchMember = async () => ({ id: 'mod', user: { tag: 'mod#0' }, roles: { cache: new Map(), highest: { position: 2 } } });
    let alerted = 0;
    let incident = null;
    mgr._alert = async (a) => { alerted++; if (!a.dryRun) throw new Error('punishment alert must not fire'); };
    mgr._recordIncident = async (i) => { if (i.status !== 'ignored_trusted_user') incident = i; };

    // Single MemberRoleUpdate → memberRoleUpdate (threshold 10).
    const res = await mgr.processEvent({
        guild, actionKey: 'memberRoleUpdate', knownExecutorId: 'mod',
        details: { auditEntryId: 'fp2', targetId: 'memberA', summary: 'admin assigns a role' },
    });
    assert.equal(res.handled, false);
    assert.equal(res.reason, 'below_threshold');
    assert.equal(alerted, 0, 'no alert');
    assert.equal(incident, null, 'no incident');

    // Single adminRole assignment → adminGrant (threshold 3) stays below.
    const res2 = await mgr.processEvent({
        guild, actionKey: 'adminGrant', knownExecutorId: 'mod',
        details: { auditEntryId: 'fp2b', targetId: 'memberA', summary: 'admin grants Administrator role once' },
    });
    assert.equal(res2.handled, false, 'a single Administrator-role grant is below the raised threshold');
    assert.equal(alerted, 0, 'still no alert/punishment');
    mgr._seenEventIds.clear();
});

test('NO false positive: an admin removing a role normally is not a report', async () => {
    const { mgr } = makeManager();
    const guild = stubGuild();
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'mod', user: { tag: 'mod#0' }, roles: { cache: new Map(), highest: { position: 2 } } });
    let incident = null;
    mgr._alert = async () => { throw new Error('must not alert'); };
    mgr._recordIncident = async (i) => { if (i.status !== 'ignored_trusted_user') incident = i; };

    const res = await mgr.processEvent({
        guild, actionKey: 'memberRoleUpdate', knownExecutorId: 'mod',
        details: { auditEntryId: 'fp3', targetId: 'memberA', summary: 'role removed' },
    });
    assert.equal(res.handled, false);
    assert.equal(res.reason, 'below_threshold');
    assert.equal(incident, null, 'no nuke incident for a single role removal');
    mgr._seenEventIds.clear();
});

test('NO false positive: a legitimate single ban by an admin is not punished', async () => {
    const { mgr } = makeManager();
    const guild = stubGuild();
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'mod', user: { tag: 'mod#0' }, roles: { cache: new Map(), highest: { position: 2 } } });
    let incident = null;
    mgr._alert = async () => { throw new Error('must not alert'); };
    mgr._recordIncident = async (i) => { if (i.status !== 'ignored_trusted_user') incident = i; };

    const res = await mgr.processEvent({
        guild, actionKey: 'memberBan', knownExecutorId: 'mod',
        details: { auditEntryId: 'fp4', targetId: 'rogue', summary: 'ban a spammer' },
    });
    assert.equal(res.handled, false);
    assert.equal(res.reason, 'below_threshold');
    assert.equal(incident, null, 'a single legitimate ban never raised a report');
    mgr._seenEventIds.clear();
});

test('NO false positive: a legitimate single kick by an admin is not punished', async () => {
    const { mgr } = makeManager();
    const guild = stubGuild();
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'mod', user: { tag: 'mod#0' }, roles: { cache: new Map(), highest: { position: 2 } } });
    let incident = null;
    mgr._alert = async () => { throw new Error('must not alert'); };
    mgr._recordIncident = async (i) => { if (i.status !== 'ignored_trusted_user') incident = i; };

    const res = await mgr.processEvent({
        guild, actionKey: 'memberKick', knownExecutorId: 'mod',
        details: { auditEntryId: 'fp5', targetId: 'rogue', summary: 'kick a troublemaker' },
    });
    assert.equal(res.handled, false);
    assert.equal(res.reason, 'below_threshold');
    assert.equal(incident, null);
    mgr._seenEventIds.clear();
});

test('PROTECTION: unauthorized role deletion activates after the threshold', async () => {
    const det = new AntiNukeDetector();
    const { mgr } = makeManager({ detector: det });
    const guild = stubGuild();
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'attacker', user: { tag: 'att#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    let alerted = 0;
    let incident = null;
    mgr._alert = async () => { alerted++; };
    mgr._recordIncident = async (i) => { incident = i; };

    const thr = rules.NUKE_ACTION_BY_KEY.roleDelete.threshold; // 3
    let res;
    for (let i = 0; i < thr; i++) {
        res = await mgr.processEvent({
            guild, actionKey: 'roleDelete', knownExecutorId: 'attacker',
            details: { auditEntryId: `del${i}`, targetId: `role_${i}`, summary: 'mass role deletion' },
        });
    }
    assert.equal(res.handled, true, 'the role-deletion burst activates protection');
    assert.ok(alerted > 0, 'the attack triggers an alert');
    assert.ok(incident, 'an incident is recorded for the confirmed attack');
    mgr._seenEventIds.clear();
});

test('PROTECTION: unauthorized dangerous permission creation on a role is evaluated', async () => {
    const det = new AntiNukeDetector();
    const { mgr } = makeManager({ detector: det });
    const guild = stubGuild();
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'attacker', user: { tag: 'att#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    let alerted = 0;
    let incident = null;
    mgr._alert = async () => { alerted++; };
    mgr._recordIncident = async (i) => { incident = i; };

    // dangerousPermissionGrant threshold is 2 — a ROLE being granted a
    // dangerous permission bit twice by an unauthorized actor trips.
    const thr = rules.NUKE_ACTION_BY_KEY.dangerousPermissionGrant.threshold;
    let res;
    for (let i = 0; i < thr; i++) {
        res = await mgr.processEvent({
            guild, actionKey: 'dangerousPermissionGrant', knownExecutorId: 'attacker',
            details: { auditEntryId: `perm${i}`, targetId: `role_r${i}`, summary: 'dangerous permission created' },
        });
    }
    assert.equal(res.handled, true, 'dangerous-permission creation activates protection');
    assert.ok(alerted > 0, 'the attack is alerted');
    assert.ok(incident, 'an incident is recorded');
    mgr._seenEventIds.clear();
});

test('PROTECTION: unauthorized rapid bans evaluate the configured threshold', async () => {
    const det = new AntiNukeDetector();
    const { mgr } = makeManager({ detector: det });
    const guild = stubGuild();
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'attacker', user: { tag: 'att#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    let alerted = 0;
    let incident = null;
    mgr._alert = async () => { alerted++; };
    mgr._recordIncident = async (i) => { incident = i; };

    const thr = rules.NUKE_ACTION_BY_KEY.memberBan.threshold; // 5
    let res;
    for (let i = 0; i < thr; i++) {
        res = await mgr.processEvent({
            guild, actionKey: 'memberBan', knownExecutorId: 'attacker',
            details: { auditEntryId: `ban${i}`, targetId: `m${i}`, summary: 'rapid mass ban' },
        });
    }
    assert.equal(res.handled, true, 'rapid bans activate ban protection');
    assert.ok(alerted > 0, 'the attack is alerted');
    assert.ok(incident, 'an incident is recorded');
    mgr._seenEventIds.clear();
});

test('PROTECTION: the owner is never punished even when a threshold trips', async () => {
    const det = new AntiNukeDetector();
    const { mgr } = makeManager({ detector: det });
    const guild = stubGuild({ ownerId: 'owner' });
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'owner', user: { tag: 'owner#0' }, roles: { cache: new Map(), highest: { position: 0 } } });
    let incident = null;
    mgr._alert = async (a) => { throw new Error('owner must never be alerted'); };
    mgr._recordIncident = async (i) => { incident = i; };

    const thr = rules.NUKE_ACTION_BY_KEY.roleDelete.threshold;
    for (let i = 0; i < thr; i++) {
        await mgr.processEvent({
            guild, actionKey: 'roleDelete', knownExecutorId: 'owner',
            details: { auditEntryId: `o${i}`, targetId: `r${i}`, summary: 'owner cleanup' },
        });
    }
    // Owner is always exempt → no response, no alert, an "ignored trusted user"
    // record at most.
    assert.equal(incident && incident.status, 'ignored_trusted_user');
    mgr._seenEventIds.clear();
});

// ── Multi-node duplicate safety ─────────────────────────────────────────────

test('NO duplicate punishment: the same event claimed by another node is skipped', async () => {
    const anukeDb = require('../server/anukeDb');
    // ClaimDedupKey returns false the FIRST time (as if another node already
    // claimed this (guild, action, executor, window)) → the responder stands down.
    let first = true;
    anukeDb.claimDedupKey = async () => { if (first) { first = false; return false; } return true; };
    anukeDb.anukePool.query = async () => ({ rows: [] });
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    anukeDb.claimDedupKey = async () => true;
    anukeDb.anukePool.query = async () => ({ rows: [] });

    const det = new AntiNukeDetector();
    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    mgr.detector = det;
    const guild = stubGuild();
    mgr._cache.set(guild.id, normalSettings());
    mgr._fetchMember = async () => ({ id: 'attacker', user: { tag: 'att#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    let responded = 0;
    mgr._alert = async () => { responded++; };

    const thr = rules.NUKE_ACTION_BY_KEY.roleDelete.threshold;
    let res = null;
    for (let i = 0; i < thr; i++) {
        res = await mgr.processEvent({
            guild, actionKey: 'roleDelete', knownExecutorId: 'attacker',
            details: { auditEntryId: `dup${i}`, targetId: `r${i}`, summary: 'x' },
        });
    }
    // The third (threshold-reaching) call hit the already-claimed dedup window
    // → stand down (deduped), no alert, no punishment.
    assert.ok(responded === 0, 'no alert/punishment when another node already claimed the incident');
    assert.ok(['deduped', 'below_threshold'].includes(res.reason), `stand down without duplicate response (got ${res.reason})`);
    mgr._seenEventIds.clear();
});

// ── Legacy protection preserved ────────────────────────────────────────────

test('the default response set still enables every response except log-only', () => {
    const s = rules.defaultAntiNukeSettings();
    const allButLogOnly = rules.NUKE_RESPONSES.map(r => r.key).filter(k => k !== 'logOnly');
    assert.deepEqual(s.responses.slice().sort(), allButLogOnly.slice().sort());
    assert.equal(s.dryRun, false, 'dry-run stays OFF — live protection remains the default');
    assert.ok(Object.keys(s.watched).length === rules.NUKE_ACTIONS.length, 'every action still watched by default');
});

test('an administrator is NOT auto-trusted (trust must be explicit)', () => {
    const s = rules.defaultAntiNukeSettings();
    assert.equal(rules.isTrusted({ userId: '555', roleIds: ['admin-role'], guildOwnerId: '999', settings: s }), false,
        'a plain Discord Administrator (not the owner, not in trusted list) is not auto-exempt');
    assert.equal(rules.isTrusted({ userId: '999', guildOwnerId: '999', settings: s }), true, 'the owner is always exempt');
});

test('the role-permission guard is reachable through the catalog index', () => {
    assert.ok(entry.actionsForAuditEvent('RoleUpdate').includes('rolePermissionUpdate'), 'RoleUpdate still maps rolePermissionUpdate');
    assert.ok(entry.actionsForAuditEvent('MemberRoleUpdate').includes('adminGrant'), 'MemberRoleUpdate still maps adminGrant');
});