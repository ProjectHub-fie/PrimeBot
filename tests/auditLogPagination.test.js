// Audit log pagination: the General page's audit log renders max 10 rows per
// page with a Prev / numbered-pages / Next bar, keeping the page margin sane.
// general.js is plain browser JS — we run it in a vm with a minimal fake DOM
// (same trick as turnstile.test.js).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('fs');
const path = require('path');

const GENERAL_JS = fs.readFileSync(
    path.join(__dirname, '..', 'dashboard', 'public', 'js', 'general.js'), 'utf8');

class FakeEl {
    constructor(id) {
        this.id = id;
        this.innerHTML = '';
        this.listeners = {};
        this.dataset = (id && typeof id === 'object') ? id : {};
        this._qs = {};
    }
    addEventListener(type, fn) { this.listeners[type] = fn; }
    click() { this.listeners.click && this.listeners.click({}); }
    // Parse selector results out of current innerHTML but reuse element
    // instances per selector/page so listeners attached by the client survive
    // across its re-renders.
    querySelector(sel) {
        if (sel !== '.wlog-prev' && sel !== '.wlog-next') return null;
        if (!this.innerHTML.includes(sel.slice(1))) return null;
        return (this._qs[sel] = this._qs[sel] || new FakeEl(null));
    }
    querySelectorAll(sel) {
        if (sel !== '.wlog-page-btn[data-page]') return [];
        const pages = [...this.innerHTML.matchAll(/<button class="wlog-page-btn[^"]*" data-page="(\d+)"/g)].map(m => m[1]);
        return pages.map(p => (this._qs[`p${p}`] = this._qs[`p${p}`] || new FakeEl({ page: p })));
    }
}

function makeSandbox({ logs = [] } = {}) {
    const els = {};
    const sandbox = {
        window: { guildData: { guildId: '1' } },
        document: { getElementById: (id) => (els[id] = els[id] || new FakeEl(id)) },
        api: async () => ({ logs }),
        esc: (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])),
        setTimeout,
        console,
    };
    vm.createContext(sandbox);
    vm.runInContext(GENERAL_JS, sandbox);
    return { els, sandbox };
}

function makeLogs(n) {
    return Array.from({ length: n }, (_, i) => ({
        id: i + 1,
        adminUsername: 'admin',
        content: `action ${n - i}`,
        createdAt: '2026-01-01T00:00:00.000Z',
    }));
}

// Loading is async (api promise) — helper to flush microtasks.
async function flush() { await Promise.resolve(); await Promise.resolve(); }

test('server render: pagination container exists under the table', () => {
    const guildPages = require('../dashboard/render/guild-pages');
    const html = guildPages.prefixPage({
        guild: { id: '1', name: 'g', icon: null, _config: { server: {} }, _channels: [], _roles: [] },
        user: null,
    });
    assert.ok(html.includes('id="wlog-pagination"'), 'pagination container rendered');
});

test('35 logs → page 1 shows exactly 10 rows with a 4-page bar', async () => {
    const { els } = makeSandbox({ logs: makeLogs(35) });
    await flush();
    const body = els['wlog-body'];
    const pg = els['wlog-pagination'];
    const rows = (body.innerHTML.match(/<tr>/g) || []).length;
    assert.equal(rows, 10, 'max 10 rows rendered');
    for (const p of ['1', '2', '3', '4']) {
        assert.ok(pg.innerHTML.includes(`data-page="${p}"`), `page ${p} button present`);
    }
    assert.ok(pg.innerHTML.includes('wlog-next'), 'Next button present');
});

test('≤10 logs → no pagination buttons', async () => {
    const { els } = makeSandbox({ logs: makeLogs(7) });
    await flush();
    assert.equal(els['wlog-pagination'].innerHTML, '', 'bar suppressed for one page');
    const rows = (els['wlog-body'].innerHTML.match(/<tr>/g) || []).length;
    assert.equal(rows, 7, 'all rows shown on the only page');
});

test('clicking Next moves to page 2 and re-renders rows 11-20', async () => {
    const { els } = makeSandbox({ logs: makeLogs(35) });
    await flush();
    const pg = els['wlog-pagination'];
    const nextBtn = pg.querySelector('.wlog-next');
    nextBtn.click();
    const body = els['wlog-body'];
    // Serial numbers continue globally (11..20) after navigation.
    assert.ok(/<td class="wlog-sl">11<\/td>/.test(body.innerHTML), 'first row of page 2 is #11');
    const numbered = pg.querySelectorAll('.wlog-page-btn[data-page]');
    const page2 = numbered.find(b => b.dataset.page === '2');
    page2.click(); // Fresh click into numbered page also works.
    assert.ok(/<td class="wlog-sl">11<\/td>/.test(els['wlog-body'].innerHTML), 'still on page 2');
});
