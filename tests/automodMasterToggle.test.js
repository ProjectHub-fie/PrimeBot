const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// The AutoMod master switch persists IMMEDIATELY, unlike the rest of the page
// which batches into the floating save bar. These tests drive the real
// dashboard/public/js/automod.js in a vm sandbox with a minimal DOM, because
// the failure mode is invisible in a static render test: the switch saves, but
// the save bar keeps claiming there are unsaved changes unless that one control
// is re-baselined. Also asserts optimistic rollback when the server rejects.

const AUTOMOD_JS = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'automod.js'), 'utf8');

function makeEl(id, attrs = {}) {
    const listeners = {};
    const el = {
        id, tagName: 'DIV', type: attrs.type || 'checkbox',
        value: attrs.value || '', checked: attrs.checked === true,
        dataset: attrs.dataset || {}, style: {}, disabled: false,
        classes: new Set(attrs.classes || []),
        children: [], parentNode: null,
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
        getAttribute: () => null,
        setAttribute: () => {},
        focus: () => {},
        remove: () => {},
        appendChild: c => { el.children.push(c); c.parentNode = el; return c; },
        insertAdjacentHTML: () => {},
        get textContent() { return el._text || ''; },
        set textContent(v) { el._text = v; },
        get innerHTML() { return el._html || ''; },
        set innerHTML(v) { el._html = v; },
        get outerHTML() { return ''; },
    };
    return el;
}

function boot({ patchFails = false, patchResult = true } = {}) {
    const els = {
        'am-enabled': makeEl('am-enabled', { checked: true }),
        'am-status-pill': makeEl('am-status-pill', { classes: ['am-pill-on'] }),
        'am-status-text': makeEl('am-status-text'),
    };
    els['am-status-text']._text = 'Enabled';

    const docListeners = {};
    const calls = { patch: [] };

    const document = {
        getElementById: id => els[id] || null,
        querySelector: sel => {
            if (sel === '.upcoming-locked-wrap.locked, .beta-locked-wrap.locked') return null;
            if (sel.startsWith('#')) return els[sel.slice(1)] || null;
            return null;
        },
        querySelectorAll: () => [],
        addEventListener: (t, fn) => { (docListeners[t] = docListeners[t] || []).push(fn); },
        removeEventListener: () => {},
        dispatch: (t, ev) => (docListeners[t] || []).forEach(fn => fn(ev)),
        createElement: tag => makeEl('tmp-' + tag),
        body: makeEl('body'),
        documentElement: makeEl('html'),
    };

    const api = async (url, opts) => {
        calls.patch.push({ url, body: JSON.parse(opts.body) });
        if (patchFails) { const e = new Error('Server said no'); e.status = 500; throw e; }
        return { automod: { enabled: patchResult } };
    };

    const saveBar = {
        register: () => {}, track: () => {}, markDirty: () => {}, markClean: () => {},
        onSaved: () => {}, syncControl: el => { calls.syncControlEl = el; },
    };

    const sandbox = {
        window: {
            guildData: { guildId: '111111111111111111' },
            __AUTOMOD_RULES: [],
            __AUTOMOD_ACTIONS: [],
            __AUTOMOD_SEVERITIES: [{ key: 'medium', label: 'Medium', iconName: 'alert' }],
            __AUTOMOD_PRESETS: [],
            __AUTOMOD_PARAMS: {},
            __AUTOMOD_SETTINGS: { enabled: true, rules: [] },
            saveBar, api,
            toast: (msg, type) => { calls.toasts = (calls.toasts || []).concat([{ msg, type }]); },
            svgIcon: () => '<svg></svg>',
            location: { search: '', pathname: '/guild/111111111111111111/automod', href: 'https://x/guild/111111111111111111/automod' },
        },
        document, console,
        URL,
        requestAnimationFrame: fn => setTimeout(fn, 0),
        setTimeout, clearTimeout, setInterval, clearInterval,
        Map, Set, Array, Object, JSON, Math, Number, String, Boolean, Date, Error, Promise, RegExp,
    };
    sandbox.window.document = document;
    // common.js declares `api`/`toast`/`esc` as top-level functions, so in the
    // browser they are bare globals the page calls directly (not window.api).
    sandbox.api = api;
    sandbox.toast = sandbox.window.toast;
    sandbox.esc = s => String(s == null ? '' : s);
    sandbox.svgIcon = () => '<svg></svg>';
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(AUTOMOD_JS, sandbox);

    // The page binds ONE document-level change listener and filters on the id,
    // so "bubbling" a synthetic change from the input means invoking it directly.
    function fireDoc(type, target) {
        (docListeners[type] || []).forEach(fn => fn({ target, preventDefault() {} }));
    }
    return { els, calls, fireDoc };
}

test('flipping the master switch off persists it immediately', async () => {
    const { els, calls, fireDoc } = boot({ patchResult: false });
    els['am-enabled'].checked = false;
    fireDoc('change', els['am-enabled']);
    await new Promise(r => setTimeout(r, 25));
    assert.equal(calls.patch.length, 1, 'expected exactly one PATCH');
    assert.equal(calls.patch[0].url, '/api/guilds/111111111111111111/automod');
    assert.deepEqual(calls.patch[0].body, { enabled: false });
    assert.equal(els['am-status-text']._text, 'Disabled');
});

test('the master switch re-baselines the save bar so it does not claim unsaved edits', async () => {
    const { els, calls, fireDoc } = boot({ patchResult: false });
    els['am-enabled'].checked = false;
    fireDoc('change', els['am-enabled']);
    await new Promise(r => setTimeout(r, 25));
    assert.equal(calls.syncControlEl, els['am-enabled'], 'the persisted switch must be re-baselined');
});

test('a rejected master-switch save rolls the UI back and does not re-baseline', async () => {
    const { els, calls, fireDoc } = boot({ patchFails: true });
    els['am-enabled'].checked = false;
    fireDoc('change', els['am-enabled']);
    await new Promise(r => setTimeout(r, 25));
    assert.equal(els['am-enabled'].checked, true, 'switch must roll back to the server state');
    assert.equal(els['am-status-text']._text, 'Enabled');
    assert.equal(calls.syncControlEl, undefined, 'a failed save must not mark the control clean');
    assert.ok((calls.toasts || []).some(t => t.type === 'error'), 'expected an error toast');
});

test('the switch is re-enabled after a save so it cannot get stuck disabled', async () => {
    const { els, fireDoc } = boot({ patchResult: true });
    els['am-enabled'].checked = false;
    fireDoc('change', els['am-enabled']);
    await new Promise(r => setTimeout(r, 25));
    assert.equal(els['am-enabled'].disabled, false);
});
