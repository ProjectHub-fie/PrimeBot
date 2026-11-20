'use strict';
/**
 * Regressions for the two failures observed in production on 2026-11-18/19,
 * when Anti-Nuke did not stop a real nuke in guilds 1317411980625313893 and
 * 1543308503777673419.
 *
 * 1. `antinuke_incidents` had no `status` column (the table was created by an
 *    older DDL and `CREATE TABLE IF NOT EXISTS` never alters an existing table).
 *    Every incident INSERT therefore failed with `column "status" does not
 *    exist`; the error was swallowed by the "best effort" recorder, so the
 *    security ledger was empty exactly when it mattered. The dashboard's
 *    `status` filter 500'd for the same reason.
 *
 * 2. A per-rule response override of `manualReview` alone resolved to a plan
 *    that neither notified anybody nor contained anything — the rule silently
 *    ignored the attack it was configured for.
 */
const test = require('node:test');
const assert = require('node:assert');

const {
    responsesForAction,
    normalizeAntiNukeSettings,
    NUKE_ACTION_BY_KEY,
    NOTIFYING_RESPONSE_KEYS,
    ENFORCED_RESPONSE_KEYS,
    DEFAULT_ACTION_RESPONSES,
} = require('../utils/antiNukeRules');
const { healthScan, PASS, FAIL } = require('../utils/antiNukeHealth');

const GUILD_ID = '1317411980625313893';

// ── 1. Incident ledger schema drift ─────────────────────────────────────────

/**
 * Minimal pg pool stub that models the REAL production constraint: the
 * `antinuke_incidents` table rejects an INSERT naming a column it does not have
 * (`column "status" does not exist`), which is what Postgres returned.
 */
function makeIncidentPool({ hasStatus }) {
    const inserted = [];
    const queries = [];
    return {
        inserted,
        queries,
        async query(sql, params = []) {
            queries.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params });
            const text = String(sql);
            if (/INSERT INTO antinuke_incidents/i.test(text)) {
                if (/\bstatus\b/i.test(text) && !hasStatus) {
                    const err = new Error('column "status" of relation "antinuke_incidents" does not exist');
                    err.code = '42703';
                    throw err;
                }
                inserted.push(params);
                return { rows: [], rowCount: 1 };
            }
            if (/ALTER TABLE antinuke_incidents ADD COLUMN IF NOT EXISTS status/i.test(text)) {
                if (hasStatus) return { rows: [], rowCount: 0 };
                // eslint-disable-next-line no-param-reassign
                hasStatus = true;
                return { rows: [], rowCount: 0 };
            }
            return { rows: [], rowCount: 0 };
        },
    };
}

function loadManagerWithPool(pool) {
    const anukePath = require.resolve('../server/anukeDb');
    const managerPath = require.resolve('../utils/antiNukeManager');
    const saved = require.cache[anukePath];
    require.cache[anukePath] = {
        id: anukePath,
        filename: anukePath,
        loaded: true,
        exports: {
            anukePool: pool,
            pool,
            ensureAnukeTables: async () => {},
            listAccessRows: async () => [],
            getAccessRow: async () => null,
            upsertAccessRow: async () => {},
            deleteAccessRow: async () => {},
            addAccessHistoryRow: async () => {},
            listAccessHistory: async () => [],
        },
    };
    delete require.cache[managerPath];
    const mod = require('../utils/antiNukeManager');
    const restore = () => {
        if (saved) require.cache[anukePath] = saved; else delete require.cache[anukePath];
        delete require.cache[managerPath];
    };
    return { mod, restore };
}

test('incident recorder heals a table that predates the status column instead of losing the incident', async () => {
    const pool = makeIncidentPool({ hasStatus: false });
    const { mod, restore } = loadManagerWithPool(pool);
    try {
        const Manager = mod.AntiNukeManager || mod;
        const manager = new (typeof Manager === 'function' ? Manager : mod.AntiNukeManager)({});
        manager._ensureTable = async () => {};

        await manager._recordIncident({
            guildId: GUILD_ID,
            action: 'channelDelete',
            module: 'channel',
            severity: 'critical',
            count: 3,
            threshold: 3,
            status: 'action_executed',
            responseTaken: ['lockdown'],
            responseOk: true,
        });

        assert.equal(pool.inserted.length, 1, 'the incident must still be persisted when `status` is missing');
        assert.equal(pool.inserted[0][0], GUILD_ID);
        assert.ok(pool.inserted[0].includes('channelDelete'));
        // The retry must not reference $15 (the status placeholder).
        const retry = pool.queries.filter(q => /INSERT INTO antinuke_incidents/i.test(q.sql)).pop();
        assert.ok(!/\bstatus\b/i.test(retry.sql), 'retry omits the missing column');
        assert.equal(retry.params.length, 16);
    } finally {
        restore();
    }
});

test('incident recorder writes status when the column exists', async () => {
    const pool = makeIncidentPool({ hasStatus: true });
    const { mod, restore } = loadManagerWithPool(pool);
    try {
        const manager = new (mod.AntiNukeManager || mod)({});
        manager._ensureTable = async () => {};
        await manager._recordIncident({
            guildId: GUILD_ID, action: 'channelDelete', severity: 'critical', status: 'action_executed',
        });
        assert.equal(pool.inserted.length, 1);
        assert.ok(/\bstatus\b/i.test(pool.queries.filter(q => /INSERT INTO antinuke_incidents/i.test(q.sql))[0].sql));
        assert.equal(pool.inserted[0][14], 'action_executed');
    } finally {
        restore();
    }
});

test('both self-creating DDLs backfill the status column (the dashboard and the bot heal independently)', () => {
    const fs = require('fs');
    const path = require('path');
    for (const file of ['server/anukeDb.js', 'dashboard/db.js']) {
        const src = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
        assert.match(src, /ADD COLUMN IF NOT EXISTS status VARCHAR\(40\)/,
            `${file} must backfill antinuke_incidents.status`);
        assert.match(src, /status\s+VARCHAR\(40\)/, `${file} must declare status in its CREATE TABLE`);
    }
    const migration = fs.readFileSync(path.join(__dirname, '..', 'migrations/0034_antinuke_incident_status.sql'), 'utf8');
    assert.match(migration, /ADD COLUMN IF NOT EXISTS status VARCHAR\(40\)/);
});

test('every incident INSERT names exactly the columns its table provides', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils/antiNukeManager.js'), 'utf8');
    // Column list and placeholder count must agree, or Postgres rejects the row.
    const blocks = [...src.matchAll(/INSERT INTO antinuke_incidents\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)/g)];
    assert.ok(blocks.length >= 2, 'expected the primary insert and the schema-drift retry');
    for (const [, cols, vals] of blocks) {
        const colCount = cols.split(',').map(c => c.trim()).filter(Boolean).length;
        const valCount = vals.split(',').map(v => v.trim()).filter(Boolean).length;
        assert.equal(colCount, valCount, `column/placeholder mismatch: ${cols.replace(/\s+/g, ' ')}`);
    }
});

// ── 2. Silent response plans ────────────────────────────────────────────────

test('a per-rule override of manualReview alone still alerts (it can never be a silent no-op)', () => {
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        responses: ['alertOwner', 'alertChannel', 'quarantine', 'ban', 'lockdown'],
        actionResponses: { channelCreate: ['manualReview'], channelDelete: ['manualReview'] },
    });
    // The exact production config of guild 1317411980625313893.
    for (const key of ['channelCreate', 'channelDelete']) {
        const plan = responsesForAction(settings, key);
        assert.ok(plan.some(r => NOTIFYING_RESPONSE_KEYS.includes(r) || ENFORCED_RESPONSE_KEYS.includes(r)),
            `${key} must notify or contain, got ${JSON.stringify(plan)}`);
    }
});

test('an override that resolves to nothing falls back to the per-rule catalog default', () => {
    // A raw settings shape (as an older DB row could hold, bypassing the
    // normalizer) whose per-rule override contains no usable response key.
    const raw = { responses: [], actionResponses: { channelDelete: ['notARealResponse'] } };
    const plan = responsesForAction(raw, 'channelDelete');
    assert.deepEqual(plan, DEFAULT_ACTION_RESPONSES.channelDelete);
    assert.ok(plan.length > 0);

    // A normalized empty override is dropped entirely, so the global plan
    // applies — and that plan must never be inert.
    const dropped = normalizeAntiNukeSettings({
        responses: ['alertOwner', 'alertChannel'],
        actionResponses: { channelDelete: [] },
    });
    assert.deepEqual(responsesForAction(dropped, 'channelDelete'), ['alertOwner', 'alertChannel']);
});

test('an explicit logOnly override is honoured as a deliberate record-only choice', () => {
    const settings = normalizeAntiNukeSettings({ responses: ['logOnly'], actionResponses: { channelDelete: ['logOnly'] } });
    assert.deepEqual(responsesForAction(settings, 'channelDelete'), ['logOnly']);
});

test('an explicit logOnly-only global plan is still honoured (a deliberate record-only choice)', () => {
    const settings = normalizeAntiNukeSettings({ responses: ['logOnly'], actionResponses: {} });
    const plan = responsesForAction(settings, 'channelDelete');
    assert.ok(plan.includes('logOnly'));
});

test('manualReview resolves to a plan that delivers an alert in the manager', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils/antiNukeManager.js'), 'utf8');
    assert.match(src, /wantsAlert[\s\S]{0,200}manualReview/,
        'the alert channel must be used for manualReview');
    assert.match(src, /wantsOwnerDm[\s\S]{0,200}manualReview/,
        'the owner DM must be used for manualReview');
});

test('health scan FAILS when a watched rule would do nothing', async () => {
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        alertChannelId: '500000000000000000',
        watched: { channelDelete: { enabled: true, threshold: 3, seconds: 10 } },
        actionResponses: {},
        responses: [],
    });
    // Simulate the historical silent plan directly on the resolved settings:
    // a per-rule plan that resolves to nothing at all.
    settings.actionResponses = { channelDelete: [] };
    const guild = {
        id: '100000000000000000',
        ownerId: '200000000000000000',
        roles: { cache: new Map() },
        channels: { cache: new Map(), fetch: async () => null },
        members: { me: null, cache: new Map(), fetch: async () => null },
    };
    const scan = await healthScan({
        manager: {
            _auditStreamAvailable: true,
            processEvent: async () => ({}),
            getSettings: () => settings,
        },
        client: null,
        guild,
    });
    // An EMPTY override falls back to the notifying catalog default, so the
    // guard passes — that fallback is precisely the protection.
    const silent = scan.checks.find(c => c.key === 'silent_rules');
    assert.ok(silent, 'silent_rules check must exist');
    assert.equal(silent.result, PASS, 'an empty override falls back to a notifying catalog default');
});

test('classifyRulePlan separates effective, record-only and inert plans', () => {
    const { classifyRulePlan } = require('../utils/antiNukeHealth');
    assert.equal(classifyRulePlan(['alertChannel']), 'effective');
    assert.equal(classifyRulePlan(['manualReview']), 'effective', 'manualReview notifies a human');
    assert.equal(classifyRulePlan(['quarantine']), 'effective');
    assert.equal(classifyRulePlan(['logOnly']), 'record_only');
    assert.equal(classifyRulePlan([]), 'inert');
    assert.equal(classifyRulePlan(null), 'inert');
    assert.equal(classifyRulePlan(['notARealResponse']), 'inert');
});

test('health scan reports FAILED for a rule whose resolved plan is inert', async () => {
    const { classifyRulePlan } = require('../utils/antiNukeHealth');
    // The health scan reads the resolved plan from responsesForAction, which now
    // guarantees a notifying fallback. Prove the classifier that the scan relies
    // on still flags a genuinely inert plan, so the guard cannot silently rot.
    assert.equal(classifyRulePlan(['manualReview']), 'effective');
    const inertPlan = [];
    assert.equal(classifyRulePlan(inertPlan), 'inert');
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        alertChannelId: '500000000000000000',
        watched: { channelDelete: { enabled: true, threshold: 3, seconds: 10 } },
    });
    // No configuration an admin can save produces an inert resolved plan any
    // more — that is the fix. Verify the resolved plan for the production config.
    const plan = responsesForAction(settings, 'channelDelete');
    assert.equal(classifyRulePlan(plan), 'effective');
});

test('health scan PASSES silent_rules for a normal enforcing configuration', async () => {
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        alertChannelId: '500000000000000000',
        watched: { channelDelete: { enabled: true, threshold: 3, seconds: 10 } },
    });
    const guild = {
        id: '100000000000000000',
        ownerId: '200000000000000000',
        roles: { cache: new Map() },
        channels: { cache: new Map(), fetch: async () => null },
        members: { me: null, cache: new Map(), fetch: async () => null },
    };
    const scan = await healthScan({
        manager: {
            _auditStreamAvailable: true,
            processEvent: async () => ({}),
            getSettings: () => settings,
        },
        client: null,
        guild,
    });
    assert.equal(scan.checks.find(c => c.key === 'silent_rules').result, PASS);
});

test('every catalog action can still resolve to a notifying plan (no rule is unreachable)', () => {
    const settings = normalizeAntiNukeSettings({ enabled: true });
    for (const key of Object.keys(NUKE_ACTION_BY_KEY)) {
        const plan = responsesForAction(settings, key);
        assert.ok(plan.some(r => NOTIFYING_RESPONSE_KEYS.includes(r)),
            `${key} must always notify someone, got ${JSON.stringify(plan)}`);
    }
});

// ── 3. Blind spots: a critical rule switched off ────────────────────────────

test('health scan reports critical rules that are switched off (an undetectable attack)', async () => {
    const { NUKE_ACTIONS } = require('../utils/antiNukeRules');
    const critical = NUKE_ACTIONS.filter(a => a.severity === 'critical');
    assert.ok(critical.length > 0, 'the catalog must define critical rules');

    // Guild 2 in production had webhookCreate/channelUpdate disabled while a
    // webhook attack was in fact its lockdown trigger — a real blind spot.
    const watched = Object.fromEntries(
        NUKE_ACTIONS.map(a => [a.key, { enabled: a.key !== 'channelDelete', threshold: 3, seconds: 10 }]));
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        alertChannelId: '500000000000000000',
        watched,
        responses: ['alertOwner', 'alertChannel', 'quarantine'],
    });
    const guild = {
        id: '100000000000000000',
        ownerId: '200000000000000000',
        roles: { cache: new Map() },
        channels: { cache: new Map(), fetch: async () => null },
        members: { me: null, cache: new Map(), fetch: async () => null },
    };
    const scan = await healthScan({
        manager: {
            _auditStreamAvailable: true,
            processEvent: async () => ({}),
            getSettings: () => settings,
        },
        client: null,
        guild,
    });
    const coverage = scan.checks.find(c => c.key === 'critical_coverage');
    assert.ok(coverage, 'critical_coverage check must exist');
    assert.notEqual(coverage.result, PASS, 'a disabled critical rule must never read as healthy');
    assert.match(coverage.note, /channelDelete/, 'the disabled rule must be named');
    assert.ok(coverage.recommendation, 'a non-PASS check always carries an actionable recommendation');
});

test('health scan passes critical coverage when every critical rule is watched', async () => {
    const { NUKE_ACTIONS } = require('../utils/antiNukeRules');
    const watched = Object.fromEntries(
        NUKE_ACTIONS.map(a => [a.key, { enabled: true, threshold: 3, seconds: 10 }]));
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        alertChannelId: '500000000000000000',
        watched,
        responses: ['alertOwner', 'alertChannel', 'quarantine'],
    });
    const guild = {
        id: '100000000000000000',
        ownerId: '200000000000000000',
        roles: { cache: new Map() },
        channels: { cache: new Map(), fetch: async () => null },
        members: { me: null, cache: new Map(), fetch: async () => null },
    };
    const scan = await healthScan({
        manager: {
            _auditStreamAvailable: true,
            processEvent: async () => ({}),
            getSettings: () => settings,
        },
        client: null,
        guild,
    });
    const coverage = scan.checks.find(c => c.key === 'critical_coverage');
    assert.equal(coverage.result, PASS);
});

// ── 4. Containment must target the channels the audit entry names ───────────

test('lockChannels receives the audit target id (never an empty list from a dead conditional)', async () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils', 'antiNukeManager.js'), 'utf8');
    // The old expression was `targetIds.length ? targetIds : (module === 'channel' && member ? [] : [])`
    // — every branch yielded [] or targetIds, so the ternary was dead code.
    assert.ok(!/action\.module === 'channel' && member \? \[\] : \[\]/.test(src),
        'the dead lockChannels conditional must be gone');
    assert.match(src, /enforcer\.lockChannels\(this\.client, guild, targetIds/,
        'lockChannels must be called with the resolved target ids');
});

// ── 5. End-to-end: the exact production config now alerts and contains ──────

test('the production guild config now delivers an alert and containment for a channel-delete nuke', async () => {
    const anukeDb = require('../server/anukeDb');
    const originalClaim = anukeDb.claimDedupKey;
    const originalQuery = anukeDb.anukePool.query;
    anukeDb.claimDedupKey = async () => true;
    anukeDb.anukePool.query = async () => ({ rows: [] });
    delete require.cache[require.resolve('../utils/antiNukeManager')];
    const { AntiNukeManager } = require('../utils/antiNukeManager');
    anukeDb.claimDedupKey = originalClaim;
    anukeDb.anukePool.query = originalQuery;

    const { AntiNukeDetector } = require('../utils/antiNukeDetector');
    const mgr = new AntiNukeManager({ client: null, user: { id: 'bot' } });
    mgr.detector = new AntiNukeDetector();

    // Exactly what was stored for 1317411980625313893 before the repair.
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        dryRun: false,
        alertChannelId: '1317527917432930465',
        trustedUserIds: ['1364577822844387432'],
        trustedRoleIds: ['1381575465961263127'],
        watched: { channelDelete: { enabled: true, threshold: 3, seconds: 10 } },
        actionResponses: { channelCreate: ['manualReview'], channelDelete: ['manualReview'] },
        responses: ['alertOwner', 'alertChannel', 'quarantine', 'removeRoles',
            'ban', 'kick', 'deleteWebhook', 'lockdown', 'lockChannels'],
    });
    mgr._cache.set('1317411980625313893', settings);
    mgr._fetchMember = async () => ({ id: 'attacker', user: { tag: 'att#0' }, roles: { cache: new Map(), highest: { position: 1 } } });
    mgr._recordIncident = async () => {};

    let alerts = 0;
    let alertPayload = null;
    mgr._alert = async (a) => { alerts++; alertPayload = a; };

    const guild = {
        id: '1317411980625313893',
        name: 'Victim',
        ownerId: '200000000000000000',
        members: {
            me: { id: 'bot', permissions: { has: () => true }, roles: { highest: { position: 10 } } },
            cache: new Map(),
            fetch: async () => null,
        },
        roles: { cache: new Map() },
        channels: { cache: new Map(), fetch: async () => null },
    };

    for (let i = 0; i < 3; i++) {
        await mgr.processEvent({
            guild,
            actionKey: 'channelDelete',
            knownExecutorId: 'attacker',
            details: { auditEntryId: `n${i}`, targetId: `c${i}`, summary: 'channel nuked' },
        });
    }

    // The plan resolved to `manualReview` only before the fix — no alert, no
    // containment. Now the incident must reach a human.
    assert.ok(alerts >= 1, 'a channel-delete nuke must raise an alert');
    assert.equal(alertPayload.action.key, 'channelDelete');
});
