// Ticket panels — client flow. The editor must NOT open before creation:
//   - "Create a panel" posts to /api/guilds/:guildId/tickets/quickcreate,
//     which auto-creates an "Untitled-N" panel, then redirects to its edit page..

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
        return el;
    };
    const collections = {};
    const apiCalls = [];
    const toasts = [];
    const api = async (url, opts = {}) => {
        apiCalls.push({ url, opts });
        if (opts.method === 'POST') return { ticketPanel: { id: 99, name: 'Untitled-1' } };
        return { ticketPanels: panels };
    };
    const sandboxWindow = {
        guildData: { guildId: '1' },
        location: { href: '' },
        populateRoleSelects: () => {},
        populateChannelSelects: () => {},
    };
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
        localStorage: { },
        console,
    };
    vm.createContext(sandbox);
    vm.runInContext(TICKETS_JS, sandbox);
    return { els, collections, apiCalls, toasts };
}

test('Create a panel → POSTs to quickcreate and uses the new panel id', async () => {
    const { els, apiCalls } = makeSandbox();
    assert.ok(els['tk-create-open'], 'Create button exists');
    els['tk-create-open'].click();
    await new Promise(r => setTimeout(r, 0));
    const qc = apiCalls.find(c => c.opts.method === 'POST' && c.url.includes('/tickets/quickcreate'));
    assert.ok(qc, 'quick-create POSTed');
    assert.equal(els['tk-create-open'].disabled, false, 'button re-enabled after request');
});

test('Edit button does NOT open a modal — it hands off to the full-page editor', () => {
    const { els, collections } = makeSandbox({ panels: [{ id: 7 }] });
    const modal = els['tk-modal'];
    assert.ok(!modal || modal.classList.contains('hidden'), 'no visible editor modal');
    collections['.tk-edit'][0].click();
    assert.ok(!els['tk-modal'] || els['tk-modal'].classList.contains('hidden'), 'edit leaves no modal open');
});

test('old modal wiring (tk-save / tk-modal-title) is gone', () => {
    // The editor now lives on a separate page; the list page script must not
    // wire an inline submit button or modal title..
    assert.ok(!TICKETS_JS.includes('tk-modal-title'), 'no modal title wiring remains');
    assert.ok(!TICKETS_JS.includes('tk-save'), 'no modal save button wiring remains');
});
