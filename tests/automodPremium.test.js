const test = require('node:test');
const assert = require('node:assert/strict');

// Pure tests for the premium AutoMod upgrade's new modules:
//   • automodPresets  — the ready-made protection profiles
//   • antiNukeRules   — the anti-nuke catalog, normalizer and burst detector
//   • automodRules additions — severity colorHex, state resolver, warn ladder
//
// No DB, no network: everything here is a pure transform.

const {
    PRESETS, PRESET_BY_KEY, metaForPreset, buildPresetPatch,
} = require('../utils/automodPresets');
const {
    NUKE_ACTIONS, NUKE_ACTION_KEYS, NUKE_RESPONSES, NUKE_RESPONSE_KEYS,
    defaultAntiNukeSettings, normalizeAntiNukeSettings, isTrusted, evaluateBurst,
} = require('../utils/antiNukeRules');
const {
    RULES, RULE_BY_KEY, SEVERITIES, SEVERITY_KEYS, ACTIONS, ACTION_KEYS,
    normalizeRules, normalizeWarnLadder, matchRule, metaFor, severityMeta,
    RULE_PARAMS, ruleParamDefs,
} = require('../utils/automodRules');

// ── Presets ─────────────────────────────────────────────────────────────────

test('every preset is well-formed and uses real rule/action keys', () => {
    assert.ok(PRESETS.length >= 4, 'expected several presets');
    for (const p of PRESETS) {
        assert.ok(p.key && p.label && p.description, `preset ${p.key} missing fields`);
        assert.ok(p.iconName, `preset ${p.key} missing iconName`);
        assert.ok(Array.isArray(p.rules) && p.rules.length, `preset ${p.key} has no rules`);
        assert.deepEqual(PRESET_BY_KEY[p.key], p);
        for (const r of p.rules) {
            assert.ok(RULE_BY_KEY[r.type], `preset ${p.key} references unknown rule "${r.type}"`);
            assert.ok(Array.isArray(r.actions) && r.actions.length, `preset ${p.key}/${r.type} has no actions`);
            for (const a of r.actions) assert.ok(ACTION_KEYS.includes(a), `preset ${p.key}/${r.type} unknown action "${a}"`);
        }
    }
});

test('preset keys are unique and metaForPreset resolves them', () => {
    assert.equal(new Set(PRESETS.map(p => p.key)).size, PRESETS.length);
    for (const p of PRESETS) assert.equal(metaForPreset(p.key), p);
    assert.equal(metaForPreset('does-not-exist'), null);
});

test('buildPresetPatch rejects unknown presets and never clobbers unrelated settings', () => {
    assert.equal(buildPresetPatch('nope', {}), null);
    // A preset owns the rules list (and its own ladder) and nothing else — a
    // guild's log channel, exemptions and master-switch state must survive.
    const current = {
        enabled: true, logChannelId: 'c1', exemptRoleIds: ['r1'], exemptChannelIds: ['ch1'],
        dmEnabled: false, rules: [{ type: 'caps', enabled: true, actions: ['delete'] }],
    };
    const patch = buildPresetPatch('community', current);
    assert.ok(Array.isArray(patch.rules) && patch.rules.length);
    assert.ok(!('logChannelId' in patch), 'preset must not touch the log channel');
    assert.ok(!('exemptRoleIds' in patch), 'preset must not touch exemptions');
    assert.ok(!('dmEnabled' in patch), 'preset must not touch DM config');
    assert.ok(!('enabled' in patch), 'an already-enabled server is left enabled');
    // Applying a preset to a disabled server enables it (never disables).
    assert.equal(buildPresetPatch('community', { enabled: false }).enabled, true);
    assert.equal(buildPresetPatch('community', {}).enabled, true, 'an unknown switch state enables the server');
});

test('presets normalize into a valid rule list', () => {
    for (const p of PRESETS) {
        const patch = buildPresetPatch(p.key, {});
        const normalized = normalizeRules(patch.rules);
        assert.equal(normalized.length, patch.rules.length, `preset ${p.key} lost rules in normalization`);
        for (const r of normalized) assert.ok(r.actions.length, `preset ${p.key} produced a rule with no actions`);
    }
});

// ── Severity ────────────────────────────────────────────────────────────────

test('severity catalog carries both an int color and a matching CSS colorHex', () => {
    assert.deepEqual(SEVERITY_KEYS, ['low', 'medium', 'high', 'critical']);
    for (const s of SEVERITIES) {
        assert.equal(typeof s.color, 'number');
        assert.match(s.colorHex, /^#[0-9A-F]{6}$/i);
        assert.equal(parseInt(s.colorHex.slice(1), 16), s.color, `${s.key} colorHex must equal color`);
    }
    assert.equal(severityMeta('bogus').key, 'medium', 'unknown severity falls back to medium');
});

// ── Warning ladder ──────────────────────────────────────────────────────────

test('normalizeWarnLadder produces sorted, action-bearing steps', () => {
    const ladder = normalizeWarnLadder([
        { count: 5, actions: ['kick'] },
        { count: 1, actions: ['warn'] },
        { count: 2, actions: ['timeout', 'notReal'] },
        'garbage',
        { count: 9, actions: [] }, // dropped — no valid actions
        { count: 7, actions: ['bogus'] }, // dropped — no valid actions
    ]);
    assert.equal(ladder.length, 3);
    assert.deepEqual(ladder.map(s => s.count), [1, 2, 5], 'stored ascending by count');
    assert.deepEqual(ladder[1].actions, ['timeout'], 'unknown actions are dropped');
});

test('normalizeWarnLadder dedupes repeated counts and keeps the first', () => {
    const ladder = normalizeWarnLadder([
        { count: 3, actions: ['timeout'] },
        { count: 3, actions: ['ban'] },
    ]);
    assert.equal(ladder.length, 1);
    assert.deepEqual(ladder[0].actions, ['timeout']);
});

test('normalizeWarnLadder falls back to a single step when given nothing usable', () => {
    const a = normalizeWarnLadder(null, { threshold: 4, warnActions: ['ban'] });
    assert.equal(a.length, 1);
    assert.equal(a[0].count, 4);
    assert.deepEqual(a[0].actions, ['ban']);
    const b = normalizeWarnLadder([]);
    assert.equal(b.length, 1);
    assert.deepEqual(b[0].actions, ['timeout']);
});

// ── Anti-nuke catalog + detection ───────────────────────────────────────────

test('anti-nuke catalog is well-formed with unique keys', () => {
    assert.equal(new Set(NUKE_ACTION_KEYS).size, NUKE_ACTION_KEYS.length);
    assert.equal(new Set(NUKE_RESPONSE_KEYS).size, NUKE_RESPONSE_KEYS.length);
    for (const a of NUKE_ACTIONS) {
        assert.ok(a.key && a.label && a.description && a.iconName, `nuke action ${a.key} missing fields`);
        assert.ok(a.threshold >= 1 && a.seconds >= 1, `nuke action ${a.key} bad defaults`);
    }
    for (const r of NUKE_RESPONSES) assert.ok(r.key && r.label && r.iconName, `nuke response ${r.key} missing fields`);
});

test('normalizeAntiNukeSettings is safe by default and sanitizes input', () => {
    const d = defaultAntiNukeSettings();
    assert.equal(d.enabled, false, 'anti-nuke must be off by default');
    assert.equal(d.dryRun, true, 'anti-nuke must default to dry-run');
    assert.deepEqual(d.responses, ['alertOwner', 'alertChannel', 'logOnly']);

    const n = normalizeAntiNukeSettings({
        enabled: 'yes',
        dryRun: 'nope',
        responses: ['alertOwner', 'bogusResponse'],
        trustedUserIds: ['111111111111111111', '111111111111111111', 'not-an-id', 222222222222222222],
        watched: { channelDelete: { enabled: true, threshold: 999, seconds: -5 }, bogusAction: { enabled: true } },
    });
    assert.equal(n.enabled, false, 'non-boolean coerces to false');
    assert.equal(n.dryRun, true, 'dryRun defaults true unless explicitly false');
    assert.deepEqual(n.responses, ['alertOwner'], 'unknown responses dropped');
    // A numeric (non-string) snowflake is rejected outright: JSON parses it as
    // a double and loses precision, so accepting it would trust the wrong user.
    assert.deepEqual(n.trustedUserIds, ['111111111111111111'], 'deduped string snowflakes only');
    // Unknown watched actions are never persisted.
    assert.ok(!('bogusAction' in n.watched), 'unknown watched action dropped');
    assert.deepEqual(Object.keys(n.watched).sort(), NUKE_ACTION_KEYS.slice().sort());
    // Thresholds clamp to the action's sane bounds.
    assert.ok(n.watched.channelDelete.threshold <= 100);
    assert.ok(n.watched.channelDelete.seconds >= 1);
});

test('normalizeAntiNukeSettings only turns dryRun off when explicitly false', () => {
    assert.equal(normalizeAntiNukeSettings({ dryRun: false }).dryRun, false);
    assert.equal(normalizeAntiNukeSettings({}).dryRun, true);
    assert.equal(normalizeAntiNukeSettings({ enabled: true }).enabled, true);
});

test('isTrusted exempts the owner and trusted users/roles, never others', () => {
    const U = '111111111111111111';
    const R = '222222222222222222';
    const settings = normalizeAntiNukeSettings({ trustedUserIds: [U], trustedRoleIds: [R] });
    assert.equal(isTrusted({ userId: 'owner', guildOwnerId: 'owner', settings }), true);
    assert.equal(isTrusted({ userId: U, guildOwnerId: 'owner', settings }), true);
    assert.equal(isTrusted({ userId: 'x', roleIds: [R], guildOwnerId: 'owner', settings }), true);
    assert.equal(isTrusted({ userId: 'x', roleIds: ['333333333333333333'], guildOwnerId: 'owner', settings }), false);
});

test('evaluateBurst only trips at/over threshold and respects disabled actions', () => {
    const now = Date.now();
    const settings = normalizeAntiNukeSettings({
        enabled: true,
        watched: { channelDelete: { enabled: true, threshold: 5, seconds: 10 } },
    });
    const at = (n) => Array.from({ length: n }, (_, i) => ({ ts: now - i * 100, userId: 'u' }));
    assert.deepEqual(evaluateBurst({ channelDelete: at(4) }, settings, now), [], 'below threshold never trips');
    const tripped = evaluateBurst({ channelDelete: at(5) }, settings, now);
    assert.equal(tripped.length, 1, 'at threshold trips');
    assert.equal(tripped[0].action, 'channelDelete');
    assert.equal(tripped[0].count, 5);
    // Entries outside the window are ignored, so a slow trickle never trips.
    const stale = Array.from({ length: 5 }, (_, i) => ({ ts: now - 60000 - i * 100, userId: 'u' }));
    assert.deepEqual(evaluateBurst({ channelDelete: stale }, settings, now), [], 'stale entries fall out of the window');

    const off = normalizeAntiNukeSettings({
        enabled: true,
        watched: { channelDelete: { enabled: false, threshold: 1, seconds: 10 } },
    });
    assert.deepEqual(evaluateBurst({ channelDelete: at(100) }, off, now), [], 'disabled watch never trips');
});

// ── Sidebar sections ────────────────────────────────────────────────────────

test('every rule belongs to a section the page can navigate to', () => {
    // render/automod-page.js maps rule categories to section keys; an unmapped
    // category would make rules unreachable outside the master list.
    const CATEGORY_TO_SECTION = { 'Anti-Spam': 'spam', 'Content Protection': 'content', 'Raid Protection': 'raid' };
    for (const r of RULES) {
        assert.ok(CATEGORY_TO_SECTION[r.category], `rule ${r.key} has category "${r.category}" with no section mapping`);
    }
});

test('every rule param is declared in the shared catalog and renders a value', () => {
    // The dashboard renderers build inputs from RULE_PARAMS. A rule referencing
    // an undeclared param would silently render nothing (and never be saved).
    for (const r of RULES) {
        for (const key of r.params || []) {
            assert.ok(RULE_PARAMS[key], `rule ${r.key} declares param "${key}" missing from RULE_PARAMS`);
        }
        const defs = ruleParamDefs(r.key);
        assert.equal(defs.length, (r.params || []).length, `rule ${r.key} lost param definitions`);
        for (const def of defs) {
            assert.ok(def.cssClass && def.valueKey && def.label, `param on ${r.key} missing cssClass/valueKey/label`);
            assert.ok(['list', 'number', 'switch'].includes(def.type), `param ${def.valueKey} has unknown type ${def.type}`);
        }
    }
});

test('every catalog param round-trips through normalizeRules', () => {
    // A param the client saves but whose value the normalizer drops would look
    // like "saved but nothing changed" — guard the whole catalog.
    for (const meta of RULES) {
        for (const def of ruleParamDefs(meta.key)) {
            const rule = { type: meta.key, enabled: true, actions: ['delete'] };
            if (def.type === 'switch') rule[def.valueKey] = true;
            else if (def.type === 'number') rule[def.valueKey] = 42;
            else rule[def.valueKey] = ['Alpha', 'Beta'];
            const out = normalizeRules([rule])[0];
            assert.notEqual(out[def.valueKey], undefined, `${meta.key}.${def.valueKey} dropped by normalizeRules`);
        }
    }
});

test('severity assigned to each rule is a real severity key', () => {
    for (const r of RULES) {
        assert.ok(SEVERITY_KEYS.includes(r.severity), `rule ${r.key} has invalid severity "${r.severity}"`);
        assert.ok(metaFor(r.key), `metaFor missing ${r.key}`);
    }
});

test('action catalog keys are all real and unique', () => {
    assert.equal(new Set(ACTION_KEYS).size, ACTION_KEYS.length);
    for (const a of ACTIONS) assert.ok(a.label && a.iconName, `action ${a.key} missing label/iconName`);
});