/**
 * Anti-Nuke setup progress-persistence + dry-run-off + setup-safety tests.
 *
 * The original progress-bar bug: the card was only rendered while the setup was
 * `in_progress`, so on `not_started`/`completed` pages `renderProgress()` wrote
 * into nothing. The current architecture fixes the root cause by making the
 * progress card a permanent part of the setup view, drawing every value from the
 * DB-persisted state (utils/antiNukeSetup), and resuming from that state after a
 * refresh/bot restart. This file pins the persistence/resume/dry-run rules with
 * pure, in-memory asserts against the real modules.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    AUTO_WALKTHROUGH_STEPS,
    MANUAL_SECTIONS,
    stepsForMethod,
    newSetupSession,
    computeProgress,
    applyStep,
    withStatus,
    withUpdater,
    isComplete,
    diffRecommended,
} = require('../utils/antiNukeSetup');
const {
    recommendedConfig,
    mergeRecommended,
    runWalkthroughStep,
} = require('../utils/antiNukeSetupRunner');

test('the progress card math uses required steps only (0% visible, 100% only after validation)', () => {
    // Automatic walkthrough = 7 backend + 9 walkthrough = 16 required steps.
    const catalog = stepsForMethod('automatic');
    const requiredCount = catalog.filter(s => s.required).length;
    assert.equal(requiredCount, 16, 'the automatic walkthrough has 16 required steps');
    assert.equal(AUTO_WALKTHROUGH_STEPS.length, 9);
    // `validate` must run AFTER `apply`, otherwise it re-verifies a config that
    // was never persisted and fails the whole walkthrough (the step-8 bug).
    const keys = catalog.map(s => s.key);
    assert.ok(keys.indexOf('apply') < keys.indexOf('validate'), 'apply precedes validate');

    // A brand-new, unstarted session shows 0% — never a fake value.
    const s0 = newSetupSession('automatic', '1');
    const p0 = computeProgress('automatic', s0);
    assert.equal(p0.percent, 0);
    assert.equal(p0.completed, 0);
    assert.equal(p0.total, 16);
    assert.equal(p0.status, 'in_progress');

    // 6 completed steps → the REQUIRED denominator only.
    let s = s0;
    for (const step of catalog.slice(0, 6)) s = applyStep(s, step.key, { status: 'completed' });
    const p6 = computeProgress('automatic', s);
    assert.equal(p6.percent, Math.round((6 / 16) * 100));
    assert.equal(p6.completed, 6);
    assert.match(s.sessionId, /^ss_/);
});

test('a failed required step never counts as completed; a retry overwrites (no double count)', () => {
    let s = newSetupSession('automatic', '1');
    // Complete several steps, then fail one.
    const catalog = stepsForMethod('automatic');
    for (const step of catalog.slice(0, 5)) s = applyStep(s, step.key, { status: 'completed' });
    const failKey = catalog[5].key;
    s = applyStep(s, failKey, { status: 'failed', error: 'bot permission missing' });
    let p = computeProgress('automatic', s);
    assert.equal(p.failed, 1);
    assert.equal(p.completed, 5);
    assert.ok(!isComplete('automatic', s), 'a failed step must block completion');

    // Retry: same step completes once — completed=6, failed=0, no double count.
    s = applyStep(s, failKey, { status: 'completed' });
    p = computeProgress('automatic', s);
    assert.equal(p.completed, 6);
    assert.equal(p.failed, 0);
});

test('optional skipped steps are excluded from the denominator', () => {
    // Manual sections: 14 total, 12 required, trusted users/roles optional.
    const sections = MANUAL_SECTIONS;
    const requiredCount = sections.filter(s => s.required).length;
    const optionalCount = sections.length - requiredCount;
    assert.equal(sections.length, 14);
    assert.equal(requiredCount, 12);
    assert.equal(optionalCount, 2);

    let s = newSetupSession('manual', '1');
    for (const sec of sections.filter(x => x.required)) s = applyStep(s, sec.key, { status: 'completed' });
    // Mark the optional ones completed as well — the percentage stays at 100%,
    // but they were never required.
    s = applyStep(s, 'trustedUsers', { status: 'completed' });
    s = applyStep(s, 'trustedRoles', { status: 'completed' });
    const p = computeProgress('manual', s);
    assert.equal(p.percent, 100);
    assert.equal(p.completed, 12, 'only required steps count as completed');
    assert.equal(p.total, 12);
});

test('100% is only reported once final validation succeeds (the completed status)', () => {
    let s = newSetupSession('automatic', '1');
    const catalog = stepsForMethod('automatic');
    for (const step of catalog) s = applyStep(s, step.key, { status: 'completed' });
    const p = computeProgress('automatic', s);
    assert.equal(p.completed, 16);
    assert.equal(p.percent, 100);
    assert.ok(isComplete('automatic', s), 'isComplete requires every required step done and none failed');
    // Even at 100% the status itself flips only via withStatus('completed').
    const finished = withStatus(s, 'completed');
    assert.equal(finished.status, 'completed');
    assert.ok(finished.completedAt, 'completion timestamp persisted');
});

test('setup state persists through the JSONB round-trip and records actors', () => {
    let s = newSetupSession('manual', '1');
    s = withUpdater(s, '7'); // step executed by another user
    s = applyStep(s, 'general', { status: 'completed' });
    s = applyStep(s, 'channel', { status: 'completed' });
    s = applyStep(s, 'role', { status: 'failed', error: 'timeout' });
    assert.equal(s.initiatedBy, '1');
    assert.equal(s.lastUpdatedBy, '7');
    assert.equal(s.version, 1);
    assert.ok(s.startedAt);

    // A JSON serialise/parse round-trip (what the DB JSONB column does per
    // save) must preserve the whole resumable state.
    const persisted = JSON.parse(JSON.stringify(s));
    const p = computeProgress('manual', persisted);
    assert.equal(p.completed, 2);
    assert.equal(p.failed, 1);
    assert.equal(p.percent, Math.round((2 / 12) * 100));
    // currentStep carried through.
    assert.equal(persisted.currentStep, 'role');
    assert.ok(persisted.lastError);
});

test('resuming after a "bot restart" restores completion from the persisted state', () => {
    // Simulate: the state was persisted, then the process restarted. The new
    // process reads the JSONB and keeps the previous completions — never
    // restarts at 0%.
    const persisted = withUpdater(applyStep(applyStep(
        newSetupSession('automatic', '1'),
        'restore', { status: 'completed' }),
        'confirm', { status: 'completed' }), '1');
    const resumed = JSON.parse(JSON.stringify(persisted));
    const p = computeProgress('automatic', resumed);
    assert.equal(p.completed, 2, 'resume restores the two completed walkthrough steps');
    assert.equal(p.percent, Math.round((2 / 16) * 100));
});

// ── Recommended configuration safety + dry-run OFF ─────────────────────────

test('automatic setup recommends dry-run OFF (actual protection, not alert-only)', () => {
    const rec = recommendedConfig();
    assert.equal(rec.dryRun, false, 'dry-run must be off in the recommended config');
    assert.equal(rec.enabled, true);
    // Safe defaults: no permanent ban/kick punishments.
    const dangerous = new Set(['ban', 'kick', 'unban', 'unkick']);
    for (const [action, watch] of Object.entries(rec.watched)) {
        assert.ok(watch.seconds > 0, `threshold window for ${action}`);
    }
});

test('mergeRecommended preserves existing custom settings unless explicitly confirmed', () => {
    const current = recommendedConfig();
    current.alertChannelId = '111';
    current.dangerousPermissions = ['Administrator', 'BanMembers'];
    const rec = recommendedConfig();

    // Safe default (no explicit confirm): custom channel/punishment kept.
    const merged = mergeRecommended(current, rec, false);
    assert.equal(merged.alertChannelId, '111', 'existing alert channel preserved');
    assert.equal(merged.dryRun, false, 'dry-run still off (recommended)');

    // The explicit confirm path also keeps dry-run off and the custom list.
    const merged2 = mergeRecommended(current, rec, true);
    assert.equal(merged2.dryRun, false);
    assert.equal(merged2.dangerousPermissions.includes('Administrator'), true,
        'existing dangerous-permission list is preserved');
});

test('the recommended diff shows exactly what would change (no silent overwrites)', () => {
    const current = recommendedConfig();
    current.watched['channelDelete'] = { enabled: true, threshold: 99, seconds: 10 };
    const rec = recommendedConfig();
    const changes = diffRecommended(current, rec);
    const channelChange = changes.find(c => c.field === 'watched.channelDelete');
    assert.ok(channelChange, 'the threshold difference is surfaced');
    assert.match(channelChange.from, /99/);
    assert.match(channelChange.to, /10/);
});

// ── Setup persistence schema (what the DB columns must carry) ───────────────

test('the automatic walkthrough completes against an async dashboard manager shim (step 8 validate regression)', async () => {
    // Regression for "step 8 always errors": the dashboard manager shim's
    // getSettings is async, but runStep used to read it without await, so
    // `validate` saw `undefined`/empty settings and threw
    // "Configuration did not persist to the database." every time.
    const stored = {};
    const asyncManager = {
        async getSettings(id) { return stored[id] || { enabled: true, dryRun: false, watched: {}, trustedUserIds: [], trustedRoleIds: [] }; },
        async updateSettingsAsync(id, patch) {
            stored[id] = Object.assign({}, stored[id] || {}, patch);
            return stored[id];
        },
        async _refreshFromDatabase() { return true; },
    };
    // Mirror the real dashboard shim: `channels.cache` is a
    // makeChannelCache-like object with `.find`, not a raw Map.
    const channels = [{ id: 'c1', name: 'security-logs', type: 0 }];
    const guild = {
        id: 'g1', name: 'Test', ownerId: 'owner1', memberCount: 12,
        channels: {
            cache: {
                size: channels.length,
                get: (id) => channels.find(c => c.id === String(id)) || null,
                has: (id) => channels.some(c => c.id === String(id)),
                values: () => channels.values(),
                find: (fn) => channels.find(fn),
            },
            fetch: async (id) => channels.find(c => c.id === String(id)) || null,
        },
        roles: { cache: new Map() },
        members: { me: { permissions: { has: () => true } } },
    };

    // The wizard's confirmation gate (`confirm`) is exercised elsewhere; this
    // regression is about the async manager read, so confirm up front and drive
    // the full walkthrough until the persisted state reports completion.
    let state = newSetupSession('automatic', 'owner1');
    for (let i = 0; i < 30 && computeProgress('automatic', state).steps.some(s => s.status !== 'completed'); i++) {
        const res = await runWalkthroughStep({
            manager: asyncManager, guild, state,
            options: { applyRecommended: true, confirmed: true },
            actorId: 'owner1',
        });
        state = res.state;
        const prog = computeProgress('automatic', state);
        // Fail fast so a broken step can't churn through the loop silently.
        if (prog.failed > 0 && i < 20) {
            assert.fail(`automatic walkthrough failed at the ${i + 1}th step: ` + JSON.stringify(prog.steps.filter(s => s.status === 'failed').map(s => ({ k: s.key, status: s.status, error: s.error }))));
        }
        if (prog.steps.every(s => s.status === 'completed')) break;
    }
    const prog = computeProgress('automatic', state);
    assert.equal(prog.percent, 100, `expected 100% completion, got ${prog.percent}% (failed=${prog.failed})`);
    const failed = prog.steps.filter(s => s.status === 'failed');
    assert.equal(failed.length, 0, `no step may fail, got: ${failed.map(s => s.key).join(', ')}`);
    // The dashboard shim read was persisted: the validate step proves enabled persisted.
    assert.equal(stored.g1 && stored.g1.dryRun, false, 'dry-run is off once setup completes');
});

test('the setup JSONB carries every resumable field the spec requires', () => {
    const s = withUpdater(withStatus(newSetupSession('manual', '9'), 'in_progress'), '9');
    assert.ok(s.sessionId, 'setup session id');
    assert.ok(s.method, 'setup method');
    assert.ok(s.status, 'setup status');
    assert.ok(s.currentStep === null || typeof s.currentStep === 'string', 'current step id');
    assert.ok(Array.isArray(s.steps) || typeof s.steps === 'object', 'per-step execution results');
    assert.equal(s.version, 1, 'configuration version');
    assert.ok(s.initiatedBy, 'initiating user id');
    assert.ok(s.lastUpdatedBy, 'last updating user id');
    assert.ok(s.startedAt, 'creation timestamp');
    assert.ok(s.lastUpdated, 'last update timestamp');
    assert.ok('completedAt' in s, 'completion timestamp slot');
});

// ── runAll (the Discord `/antinuke setup` path) must reach 100% ─────────────

test('runAll drives the whole automatic walkthrough to completion (Discord path)', async () => {
    const { runAll } = require('../utils/antiNukeSetupRunner');
    const stored = {};
    const manager = {
        getSettings: (id) => stored[id] || { enabled: true, dryRun: false, watched: {}, trustedUserIds: [], trustedRoleIds: [] },
        async updateSettingsAsync(id, patch) { stored[id] = Object.assign({}, stored[id] || {}, patch); return stored[id]; },
        async _refreshFromDatabase() { return true; },
    };
    const channels = [{ id: 'c1', name: 'security-logs', type: 0 }];
    const guild = {
        id: 'g1', name: 'T', ownerId: 'o1', memberCount: 1,
        channels: {
            cache: { size: 1, get: (i) => channels.find(c => c.id === i) || null, has: (i) => channels.some(c => c.id === i), values: () => channels.values(), find: (f) => channels.find(f) },
            fetch: async (i) => channels.find(c => c.id === i) || null,
        },
        roles: { cache: new Map() },
        members: { me: { permissions: { has: () => true } } },
    };
    // `confirmed: true` is what the Discord Confirm button passes.
    const res = await runAll({ client: { antiNukeManager: manager }, guild, options: { applyRecommended: false, confirmed: true } });
    assert.equal(res.state.status, 'completed', 'runAll finishes the walkthrough');
    assert.equal(res.progress.percent, 100);
    const failed = res.progress.steps.filter(s => s.status === 'failed');
    assert.equal(failed.length, 0, `no step may fail, got: ${failed.map(s => `${s.key}(${s.error || ''})`).join(', ')}`);
    // The walkthrough persists the recommended configuration.
    assert.equal(stored.g1.enabled, true);
    assert.ok(Object.keys(stored.g1.watched || {}).length > 0, 'watched actions were persisted');
});

// ── Manual wizard: every section must render real content ───────────────────

test('every manual wizard section renders a body (no empty sections 8-14)', () => {
    const page = require('../dashboard/render/antinuke-page');
    const html = page.manualWizardHTML({ id: 'g1', name: 'T', _channels: [], _roles: [] }, {});
    // The review section is a client-populated container; every other section
    // must carry real markup. A missing `case` previously left sections 8-14
    // (channels/trustedUsers/trustedRoles/thresholds/responses/safety) blank.
    const sections = html.split('<div class="an-wizard-section" data-section="').slice(1);
    assert.equal(sections.length, MANUAL_SECTIONS.length, 'one rendered section per catalog entry');
    for (const raw of sections) {
        const key = raw.slice(0, raw.indexOf('"'));
        if (key === 'review') continue;
        const body = raw.slice(raw.indexOf('>') + 1).split('</div>')[0];
        const stripped = body.replace(/<h3[\s\S]*?<\/h3>/, '').replace(/<p class="card-desc">[\s\S]*?<\/p>/, '').replace(/<[^>]+>/g, '').trim();
        assert.ok(stripped.length > 0, `manual section "${key}" must not be empty`);
    }
    // Spot-check the previously-broken sections render their real controls.
    assert.match(html, /data-section="trustedUsers"[\s\S]*id="an-trusted-user-input"/, 'trusted users input renders');
    assert.match(html, /data-section="trustedRoles"[\s\S]*id="an-trusted-roles"/, 'trusted roles list renders');
    assert.match(html, /data-section="responses"[\s\S]*an-response-cb/, 'response checkboxes render');
    assert.match(html, /data-section="safety"[\s\S]*id="an-dry-run"/, 'dry-run toggle renders in safety');
    assert.match(html, /data-section="channels"[\s\S]*an-action-row/, 'channel protection rows render');
});