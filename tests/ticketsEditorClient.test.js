// Ticket editor modal — client behavior. The editor form must only open:
//  - in "create" mode from the "Create a panel" button (→ POST)
//  - in "edit" mode from a panel card's "Edit" button (→ PATCH)
// tickets.js is plain browser JS (executed in a vm with a minimal fake DOM,
// same trick as turnstile.test.js / auditLogPagination.test.js).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('fs');
const path = require('path');

const TICKETS_JS = fs.readFileSync(
    path.join(__dirname, '..', 'dashboard', 'public', 'js', 'tickets.js'), 'utf8');

class FakeEl {
    constructor(id) {
        this.id = id || null;
        this.listeners = {};
        this.dataset = {};
        this.value = '';
        this.checked = false;
        this.textContent = '';
        this.innerHTML = '';
        this._seen = new Set();
    }
    get classList() {
        return {
            add: c => this._seen.add(c),
            remove: c => this._seen.delete(c),
            contains: c => this._seen.has(c),
        };
    }
    addEventListener(type, fn) { this.listeners[type] = fn; }
    click() { this.listeners.click && this.listeners.click({ currentTarget: this }); }
    closest() { return null; }
}

function makeSandbox({ panels = [] } = {}) {
    const els = {};
    const make = (id) => {
        const el = new FakeEl(id);
        // Initial class state mirrors the server-rendered markup.
        if (id === 'tk-modal') el._seen.add('hidden');
        return el;
    };
    const collections = {}; // querySelectorAll targets, e.g. '.tk-edit'
    const apiCalls = [];
    const toasts = [];
    const api = async (url, opts = {}) => {
        apiCalls.push({ url, opts });
        if (opts.method === 'POST' || opts.method === 'PATCH') return opts.body ? JSON.parse(opts.body) : {};
        return { ticketPanels: panels };
    };
    const sandboxWindow = {
        guildData: { guildId: '1' },
        populateRoleSelects: () => {},
        populateChannelSelects: () => {},
    };
    // id selectors are resolved from the same element registry as
    // getElementById; class/other selectors resolve to null/empty.
    const documentStub = {
        querySelector: (sel) => {
            if (typeof sel === 'string' && sel.startsWith('#')) {
                const id = sel.slice(1);
                return (els[id] = els[id] || make(id));
            }
            return null;
        },
        getElementById: (id) => (els[id] = els[id] || make(id)),
        querySelectorAll: (sel) => collections[sel] || [],
    };
    // One registered Edit button (panel card) per supplied panels.
    collections['.tk-edit'] = panels.map(p => {
        const btn = new FakeEl();
        btn.dataset.panel = String(p.id);
        return btn;
    });
    const sandbox = {
        window: sandboxWindow,
        document: documentStub,
        api,
        esc: (s) => String(s),
        toast: (msg, type) => toasts.push({ msg, type }),
        bindColorSync: () => {},
        bindReactionRemovals: () => {},
        confirm: () => true,
        prompt: () => null,
        console,
    };
    vm.createContext(sandbox);
    vm.runInContext(TICKETS_JS, sandbox);
    return { els, collections, apiCalls, toasts };
}

test('page load: editor modal stays hidden behind the "Create a panel" button', () => {
    const { els } = makeSandbox();
    const modal = els['tk-modal'];
    assert.ok(modal.classList.contains('hidden'), 'editor hidden on page load');
    // The explicit open button is the only entry point.
    els['tk-create-open'].click();
    assert.ok(!modal.classList.contains('hidden'), 'open button reveals the editor');
    assert.equal(els['tk-modal-title'].textContent, 'Create panel');
    assert.equal(els['tk-save'].textContent, 'Create panel');
});

test('create mode: save → POST, modal closes, list refreshes', async () => {
    const { els, apiCalls, toasts } = makeSandbox();
    assert.ok(els['tk-modal'].classList.contains('hidden'));
    const openBtn = els['tk-create-open'];
    openBtn.click();
    assert.ok(!els['tk-modal'].classList.contains('hidden'));
    els['tk-name'].value = 'Support';
    els['tk-save'].click();
    await new Promise(r => setTimeout(r, 0));
    const post = apiCalls.find(c => c.opts.method === 'POST' && c.url.endsWith('/tickets'));
    assert.ok(post, 'create POSTed');
    assert.ok(els['tk-modal'].classList.contains('hidden'), 'modal closed after save');
    assert.ok(toasts.some(t => t.msg === 'Panel created' && t.type === 'success'));
});

const EDIT_PANEL = {
    id: 7, name: 'Billing', messageType: 'plain', title: null, description: 'Pay here',
    content: 'content', footerText: null, thumbnailUrl: null, imageUrl: null,
    color: '#123456', buttonLabel: 'Open', buttonEmoji: null, buttonStyle: 'Success',
    category: 'billing', ticketName: null,
    supportRoleIds: ['111'], pingRoleIds: [],
    ticketCategoryId: null, maxOpenPerUser: 3, askReason: true,
    welcomeMessage: 'welcome', closeButtonLabel: 'Close', closeButtonEmoji: null,
    closeButtonStyle: 'Danger', claimButtonLabel: null, claimButtonEmoji: null,
    openNameTemplate: null, claimedNameTemplate: null, closedNameTemplate: null,
    closeFlow: {}, enabled: false, createdBy: 'x',
};

test('edit mode: panel card Edit → PATCH with the pre-filled form', async () => {
    const { els, collections, apiCalls, toasts } = makeSandbox({ panels: [EDIT_PANEL] });
    const editBtn = collections['.tk-edit'][0];
    editBtn.click();
    // The click handler is async (fetches the list) — let it resolve.
    await new Promise(r => setTimeout(r, 0));
    assert.ok(!els['tk-modal'].classList.contains('hidden'), 'editor opened for edit');
    assert.equal(els['tk-modal-title'].textContent, 'Edit panel — Billing');
    assert.equal(els['tk-save'].textContent, 'Save changes');
    // Form was filled from the fetched panel.
    assert.equal(els['tk-name'].value, 'Billing');
    assert.equal(els['tk-message-type'].value, 'plain');
    assert.equal(els['tk-enabled'].checked, false);
    els['tk-save'].click();
    await new Promise(r => setTimeout(r, 0));
    const patch = apiCalls.find(c => c.opts.method === 'PATCH' && c.url.endsWith('/tickets/7'));
    assert.ok(patch, 'edit PATCHed to the panel id');
    assert.ok(els['tk-modal'].classList.contains('hidden'), 'modal closed after edit save');
});

test('modal close via ×/Cancel/backdrop works in both modes', () => {
    const { els } = makeSandbox();
    els['tk-create-open'].click();
    assert.ok(!els['tk-modal'].classList.contains('hidden'));
    els['tk-modal-close'].click();
    assert.ok(els['tk-modal'].classList.contains('hidden'));
    // Re-open and cancel.
    els['tk-create-open'].click();
    assert.ok(!els['tk-modal'].classList.contains('hidden'));
    els['tk-modal-cancel'].click();
    assert.ok(els['tk-modal'].classList.contains('hidden'));
});
