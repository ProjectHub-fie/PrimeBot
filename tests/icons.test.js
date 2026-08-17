// Smoke test: the server-side renderers emit well-formed SVG icons and the
// shared icons.js module works in both Node (server render) and browser
// (window.svgIcon) contexts. Pure — no DB, no network.
const { test } = require('node:test');
const assert = require('node:assert');

const { ICONS, svgIcon } = require('../dashboard/public/js/icons');

test('svgIcon returns an <svg class="ico"> with the path body', () => {
    const out = svgIcon('zap');
    assert.match(out, /^<svg class="ico"/);
    assert.match(out, /viewBox="0 0 24 24"/);
    assert.match(out, /stroke="currentColor"/);
    assert.match(out, /<polygon/);
    assert.match(out, /aria-hidden="true"/);
});

test('svgIcon appends an extra class when given', () => {
    assert.match(svgIcon('zap', 'foo'), /^<svg class="ico foo"/);
});

test('svgIcon renders an empty svg for an unknown name (never throws)', () => {
    const out = svgIcon('does-not-exist');
    assert.match(out, /^<svg class="ico"/);
    assert.doesNotMatch(out, /<polygon|<path|<circle|<line|<rect/);
});

test('ICONS catalog has every name referenced by the dashboard tabs', () => {
    const { TABS } = require('../dashboard/render/guild');
    for (const t of TABS) {
        if (t.icon) {
            assert.ok(ICONS[t.icon], `tab ${t.key} references missing icon "${t.icon}"`);
        }
    }
});

test('server-rendered login page contains SVG icons (not emoji)', () => {
    const { loginPage } = require('../dashboard/render/pages');
    const html = loginPage({});
    assert.match(html, /<svg class="ico"/);
    // The old emoji brand mark / login button labels are gone.
    assert.doesNotMatch(html, /login-hero">⚡/);
    assert.doesNotMatch(html, />🚪 Login with Discord</);
    // Google Fonts are wired in.
    assert.match(html, /fonts\.googleapis\.com/);
});

test('server-rendered tab nav uses SVG icons + keeps beta/soon badges', () => {
    const { tabNavHTML, TABS } = require('../dashboard/render/guild');
    const html = tabNavHTML('123', 'welcome');
    assert.match(html, /<svg class="ico"/);
    // beta + upcoming badges still rendered for the relevant tabs.
    const betaTab = TABS.find(t => t.beta);
    const soonTab = TABS.find(t => t.upcoming);
    const betaHTML = tabNavHTML('123', betaTab.key);
    const soonHTML = tabNavHTML('123', soonTab.key);
    assert.match(betaHTML, /beta-badge/);
    assert.match(soonHTML, /soon-badge/);
    // menu-item now wraps label in a span (so icon + label align).
    assert.match(html, /<span class="menu-item-label">/);
});

test('icons.js exposes itself on window in a browser-like context', () => {
    // Simulate a browser global by evaluating the module in a sandbox.
    const vm = require('node:vm');
    const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'dashboard', 'public', 'js', 'icons.js'), 'utf8');
    const ctx = { window: {}, module: { exports: {} }, console };
    vm.createContext(ctx);
    vm.runInContext(src, ctx);
    assert.strictEqual(typeof ctx.window.svgIcon, 'function');
    assert.strictEqual(typeof ctx.window.ICONS, 'object');
    assert.ok(ctx.window.ICONS.zap, 'ICONS.zap present on window');
    assert.match(ctx.window.svgIcon('shield'), /^<svg class="ico"/);
});
