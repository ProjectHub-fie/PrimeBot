const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Regression tests for the Anti-Nuke setup progress bar.
//
// The original bug: the server only rendered `.an-progress-card` when the setup
// status was `in_progress`. On the `not_started` and `completed` pages the card
// (and its `#an-progress-fill` / `#an-progress-meta` / `#an-step-list` children)
// simply did not exist, so every `renderProgress()` call silently wrote to
// nothing and the bar never moved.
//
// These tests drive the REAL dashboard/public/js/antinuke.js in a vm sandbox
// with a minimal DOM, and assert that:
//   1. the persisted progress is fetched and painted into the card on load, and
//   2. the manual wizard seeds its completed sections from the persisted state
//      (resume), rather than restarting at 0%.

const ANTI_JS = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'antinuke.js'), 'utf8');
const GUILD = '111111111111111111';

function makeEl(id, attrs = {}) {
    const listeners = {};
    const el = {
        id, tagName: attrs.tagName || 'DIV', type: attrs.type || 'div',
        value: attrs.value || '', checked: attrs.checked === true,
        dataset: attrs.dataset || {}, style: {}, disabled: false, hidden: attrs.hidden === true,
        classes: new Set(attrs.classes || []),
        children: [],
        _attrs: {},
        classList: {
            add: (...c) => c.forEach(x => el.classes.add(x)),
            remove: (...c) => c.forEach(x => el.classes.delete(x)),
            toggle: (c, on) => { if (on) el.classes.add(c); else el.classes.delete(c); },
            contains: c => el.classes.has(c),
        },
        addEventListener: (t, fn) => { (listeners[t] = listeners[t] || []).push(fn); },
        removeEventListener: () => {},
        dispatch: (t) => (listeners[t] || []).forEach(fn => fn({ target: el, preventDefault() {} })),
        querySelector: () => null,
        querySelectorAll: () => [],
        contains: () => false,
        closest: () => null,
        getAttribute: (k) => (k in el._attrs ? el._attrs[k] : (attrs[k] != null ? attrs[k] : null)),
        setAttribute: (k, v) => { el._attrs[k] = String(v); },
        focus: () => {},
        remove: () => {},
        appendChild: c => { el.children.push(c); c.parentNode = el; return c; },
        insertAdjacentHTML: () => {},
        get className() { return [...el.classes].join(' '); },
        set className(v) { el.classes = new Set(String(v).split(/\s+/).filter(Boolean)); },
        get textContent() { return el._text || ''; },
        set textContent(v) { el._text = v; },
        get innerHTML() { return el._html || ''; },
        set innerHTML(v) { el._html = v; },
        get outerHTML() { return ''; },
    };
    return el;
}

/* The server-rendered card: these elements must exist for renderProgress() to
 * paint anything. The ids mirror dashboard/render/antinuke-page.js. */
function progressEls() {
    const els = {
        'an-progress-card': makeEl('an-progress-card'),
        'an-progress-fill': makeEl('an-progress-fill'),
        'an-progress-track': makeEl('an-progress-track'),
        'an-progress-meta': makeEl('an-progress-meta'),
        'an-progress-status': makeEl('an-progress-status'),
        'an-progress-flags': makeEl('an-progress-flags'),
        'an-step-list': makeEl('an-step-list', { tagName: 'UL' }),
        'an-resume-setup': makeEl('an-resume-setup', { hidden: true }),
        'an-reset-setup': makeEl('an-reset-setup', { hidden: true }),
    };
    return els;
}

function boot({ view, setupResponse, els: seedEls, sections, setupState, settings, saveBar: saveBarOverride }) {
    const els = seedEls || progressEls();
    const calls = { api: [] };
    const docListeners = {};

    const document = {
        getElementById: id => els[id] || null,
        querySelector: sel => {
            if (sel === '.upcoming-locked-wrap.locked, .beta-locked-wrap.locked') return null;
            if (sel.startsWith('#')) return els[sel.slice(1)] || null;
            return null;
        },
        querySelectorAll: sel => {
            if (sel === '.an-setup-start') return els.__startBtns || [];
            if (sel === '.an-wizard-section') return sections || [];
            if (sel === '.an-danger-perm') return els.__dangerPerms || [];
            if (sel === '.an-response-cb') return els.__responseCbs || [];
            if (sel === '.an-trusted-role') return els.__trustedRoles || [];
            if (sel === '.an-action-row') return els.__actionRows || [];
            return [];
        },
        addEventListener: (t, fn) => { (docListeners[t] = docListeners[t] || []).push(fn); },
        removeEventListener: () => {},
        createElement: tag => makeEl('tmp-' + tag, { tagName: tag }),
        body: makeEl('body'),
        documentElement: makeEl('html'),
    };

    const api = async (url, opts) => {
        calls.api.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body });
        if (url.endsWith('/antinuke/setup')) return setupResponse;
        if (url.endsWith('/antinuke/setup/progress')) return { setup: { method: 'manual', status: 'in_progress', state: {} } };
        return {};
    };

    // The page's own `api()` wraps global `fetch`, so the sandbox needs a fetch
    // that returns a Response-like object (res.ok + res.json()).
    const fetch = async (url, opts) => {
        const data = await api(url, opts);
        return { ok: true, status: 200, json: async () => data };
    };

    const saveBar = saveBarOverride || { register: () => {}, track: () => {}, markDirty: () => {}, markClean: () => {}, onSaved: () => {}, syncControl: () => {} };

    const sandbox = {
        window: {
            guildData: { guildId: GUILD },
            __ANTINUKE_ACTIONS: [],
            __ANTINUKE_MODULES: [],
            __ANTINUKE_SETTINGS: settings || {},
            __ANTINUKE_SETUP: setupState || { status: 'not_started', state: {} },
            __ANTINUKE_VIEW: view || 'setup',
            saveBar, api,
            toast: (msg, type) => { calls.toasts = (calls.toasts || []).concat([{ msg, type }]); },
            svgIcon: () => '<svg></svg>',
            confirm: () => true,
            scrollTo: () => {},
            location: { search: '', pathname: '/guild/' + GUILD + '/antinuke', href: 'https://x/guild/' + GUILD + '/antinuke' },
        },
        document, console,
        URL, fetch,
        requestAnimationFrame: fn => setTimeout(fn, 0),
        setTimeout, clearTimeout, setInterval, clearInterval,
        Map, Set, Array, Object, JSON, Math, Number, String, Boolean, Date, Error, Promise, RegExp,
    };
    sandbox.window.document = document;
    sandbox.api = api;
    sandbox.toast = sandbox.window.toast;
    sandbox.esc = s => String(s == null ? '' : s);
    sandbox.svgIcon = () => '<svg></svg>';
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(ANTI_JS, sandbox);

    return { els, calls };
}

const SETUP_PROGRESS = {
    percent: 75,
    completed: 6,
    total: 8,
    failed: 0,
    skipped: 0,
    running: 1,
    remaining: 2,
    status: 'in_progress',
    steps: [
        { key: 'inspection', label: 'Inspecting server', required: true, status: 'completed' },
        { key: 'permissions', label: 'Checking bot permissions', required: true, status: 'completed' },
        { key: 'alertChannel', label: 'Alert channel', required: true, status: 'running' },
        { key: 'validate', label: 'Final validation', required: true, status: 'pending' },
    ],
};

test('the setup page paints the persisted progress into the card on load', async () => {
    const { els, calls } = boot({
        view: 'setup',
        setupResponse: { setup: { method: 'automatic', status: 'in_progress', state: {}, progress: SETUP_PROGRESS } },
    });
    await new Promise(r => setTimeout(r, 30));

    assert.ok(calls.api.some(c => c.url.endsWith('/antinuke/setup')), 'the client must fetch the persisted setup state');
    assert.equal(els['an-progress-fill'].style.width, '75%', 'the bar width reflects the real percentage');
    assert.equal(els['an-progress-track']._attrs['aria-valuenow'], '75', 'the track is accessible');
    assert.match(els['an-progress-meta'].innerHTML, /75%/, 'the percentage is shown');
    assert.match(els['an-progress-meta'].innerHTML, /6 of 8/, 'the completed count is shown');
    assert.equal(els['an-progress-status'].textContent, 'In progress');
    // The step list is painted (not left empty).
    assert.match(els['an-step-list'].innerHTML, /Inspecting server/);
    assert.match(els['an-step-list'].innerHTML, /an-step-completed/);
});

test('the resume/reset controls are revealed when a setup is in progress', async () => {
    const { els } = boot({
        view: 'setup',
        setupResponse: { setup: { method: 'automatic', status: 'in_progress', state: {}, progress: SETUP_PROGRESS } },
    });
    await new Promise(r => setTimeout(r, 30));
    assert.equal(els['an-resume-setup'].hidden, false, 'resume is offered for a resumable setup');
    assert.equal(els['an-reset-setup'].hidden, false);
});

test('a completed setup paints 100% and does not offer resume', async () => {
    const { els } = boot({
        view: 'setup',
        setupResponse: {
            setup: {
                method: 'automatic', status: 'completed', state: {},
                progress: { percent: 100, completed: 8, total: 8, failed: 0, skipped: 0, running: 0, remaining: 0, status: 'completed', steps: [] },
            },
        },
    });
    await new Promise(r => setTimeout(r, 30));
    assert.equal(els['an-progress-fill'].style.width, '100%');
    assert.equal(els['an-progress-status'].textContent, 'Completed');
    assert.equal(els['an-resume-setup'].hidden, true, 'nothing to resume once complete');
});

test('an unstarted setup shows 0% — never a fake/non-zero progress', async () => {
    const { els } = boot({
        view: 'setup',
        setupResponse: {
            setup: {
                method: null, status: 'not_started', state: {},
                progress: { percent: 0, completed: 0, total: 8, failed: 0, skipped: 0, running: 0, remaining: 8, status: 'not_started', steps: [] },
            },
        },
    });
    await new Promise(r => setTimeout(r, 30));
    assert.equal(els['an-progress-fill'].style.width, '0%');
    assert.match(els['an-progress-meta'].innerHTML, /<strong>0%<\/strong>/);
    assert.match(els['an-progress-meta'].innerHTML, /0 of 8 required steps/);
});

test('the manual wizard seeds completed sections from the persisted state (resume)', async () => {
    // Four sections; two are already completed in the persisted state. The
    // wizard must start at 50%, not 0%.
    const mkSection = (key) => {
        const title = makeEl('t-' + key);
        title._text = key;
        const sec = makeEl('sec-' + key, { 'data-section': key });
        sec.querySelector = (sel) => (sel === '.an-wizard-title' ? title : null);
        return sec;
    };
    const sections = ['general', 'channel', 'role', 'review'].map(mkSection);
    const els = progressEls();
    els['an-wizard-next'] = makeEl('an-wizard-next');
    els['an-wizard-save'] = makeEl('an-wizard-save');
    els['an-wizard-prev'] = makeEl('an-wizard-prev');

    boot({
        view: 'wizard',
        sections,
        els,
        setupState: {
            method: 'manual', status: 'in_progress',
            state: { steps: { general: { status: 'completed' }, channel: { status: 'completed' } } },
        },
        setupResponse: {
            setup: {
                method: 'manual', status: 'in_progress',
                state: { steps: { general: { status: 'completed' }, channel: { status: 'completed' } } },
                progress: SETUP_PROGRESS,
            },
        },
    });
    await new Promise(r => setTimeout(r, 30));

    // 2 of 4 sections completed → 50%.
    const meta = els['an-progress-meta'].innerHTML;
    assert.match(meta, /2 of 4/, 'the wizard counts the seeded completed sections');
    const pct = Number(els['an-progress-fill'].style.width.replace('%', ''));
    assert.equal(pct, 50, `expected 50%, got ${pct}%`);
    assert.ok(pct > 0, 'the wizard must not restart at 0% after a refresh');
});

// ── Console save must not wipe the dangerous-permission list ────────────────
//
// The console view renders `#an-dry-run` but NO `.an-danger-perm` checkboxes.
// `collectSettings()` used to always send `dangerousPermissions: []` from that
// page, so saving anything (e.g. turning dry-run off) sent an empty list and the
// server rejected it with "Keep at least one dangerous permission." The fix:
// only send the list when the page actually renders the checkboxes; otherwise
// preserve the saved value.

function consoleEls() {
    const els = {
        'an-enabled': makeEl('an-enabled', { type: 'checkbox', checked: true }),
        'an-dry-run': makeEl('an-dry-run', { type: 'checkbox', checked: true }),
        'an-alert-channel': makeEl('an-alert-channel', { value: '' }),
        'an-response-cooldown': makeEl('an-response-cooldown', { value: '30' }),
        'an-lockdown-enabled': makeEl('an-lockdown-enabled', { type: 'checkbox', checked: true }),
        'an-trusted-users': makeEl('an-trusted-users'),
        'an-trusted-roles': makeEl('an-trusted-roles'),
        'an-activity-body': makeEl('an-activity-body'),
        'an-activity-page': makeEl('an-activity-page'),
        'an-activity-prev': makeEl('an-activity-prev'),
        'an-activity-next': makeEl('an-activity-next'),
    };
    // The console renders NO `.an-danger-perm` inputs.
    els.__dangerPerms = [];
    els.__responseCbs = [makeEl('rc', { type: 'checkbox', checked: true, value: 'alertOwner' })];
    els.__trustedRoles = [];
    els.__actionRows = [];
    return els;
}

test('a console save preserves the saved dangerous-permission list (never sends [])', async () => {
    const els = consoleEls();
    const savers = [];
    const saveBar = {
        register: fn => savers.push(fn), track: () => {}, markDirty: () => {}, markClean: () => {},
        onSaved: () => {}, syncControl: () => {},
    };
    const { calls } = boot({
        view: 'console',
        els,
        saveBar,
        settings: {
            enabled: true, dryRun: true, dangerousPermissions: ['Administrator', 'ManageRoles'],
            responses: ['alertOwner'], lockdown: { enabled: true }, responseCooldownSeconds: 30,
            trustedUserIds: [], trustedRoleIds: [],
        },
        setupResponse: { setup: { method: 'automatic', status: 'completed', state: {}, progress: {} } },
    });
    await new Promise(r => setTimeout(r, 20));

    assert.equal(savers.length, 1, 'the console registers exactly one saveBar saver');
    // Turn dry-run OFF, then save (this is the action that used to be rejected).
    els['an-dry-run'].checked = false;
    const result = savers[0]();
    if (result && result.catch) await result.catch(() => {});
    await new Promise(r => setTimeout(r, 20));

    const patch = calls.api.filter(c => c.method === 'PATCH' && c.url.endsWith('/antinuke')).pop();
    assert.ok(patch, 'the save issued a PATCH to the Anti-Nuke endpoint');
    const body = JSON.parse(patch.body);
    assert.equal(body.dryRun, false, 'dry-run was turned off');
    assert.deepEqual(
        body.dangerousPermissions,
        ['Administrator', 'ManageRoles'],
        'the console must NOT send an empty list — it preserves the saved one',
    );
});

