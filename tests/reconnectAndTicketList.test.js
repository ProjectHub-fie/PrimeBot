// Reconnect delay schedule (utils/stabilityUtils.js) + the tickets-tab
// page-load refresh (dashboard/public/js/tickets.js — created panels must show
// in the tab without any interaction after the server-rendered placeholder).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('fs');
const path = require('path');

const { RECONNECT_DELAYS, reconnectDelayFor } = require('../utils/stabilityUtils');

test('reconnect schedule matches the requested retry ladder', () => {
    assert.deepEqual(RECONNECT_DELAYS, [
        5000,   // 1st retry:  5 seconds
        10000,  // 2nd retry:  10 seconds
        20000,  // 3rd retry:  20 seconds
        30000,  // 4th retry:  30 seconds
        60000,  // 5th retry:  60 seconds
        120000,  // 6th retry:  2 minutes
        300000,  // 7th retry:  5 minutes
    ]);
    // Subsequent retries stay at every 5 minutes.
    assert.equal(RECONNECT_DELAYS.length, 7);
});

test('reconnectDelayFor picks the right delay for each retry count', () => {
    assert.equal(reconnectDelayFor(1), 5000);
    assert.equal(reconnectDelayFor(2), 10000);
    assert.equal(reconnectDelayFor(3), 20000);
    assert.equal(reconnectDelayFor(4), 30000);
    assert.equal(reconnectDelayFor(5), 60000);
    assert.equal(reconnectDelayFor(6), 120000);
    assert.equal(reconnectDelayFor(7), 300000);
    // 8th+ retries keep the 5-minute schedule.
    assert.equal(reconnectDelayFor(8), 300000);
    assert.equal(reconnectDelayFor(99), 300000);
    assert.equal(reconnectDelayFor(0), 5000);
    assert.equal(reconnectDelayFor(-1), 5000);
});

test('index.js reconnect uses the progressive schedule (not a fixed 5s)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    assert.match(src, /reconnectDelayFor\(reconnectAttempt\)/, 'index.js calls reconnectDelayFor');
    assert.ok(!/Attempting to reconnect in 5 seconds/.test(src), 'no hardcoded 5s reconnect log remains');
    assert.match(src, /reconnectAttempt =\s*0;/, 'retry counter resets after successful login');
});

test('connection-enhancer.js reconnect paths use the schedule', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'connection-enhancer.js'), 'utf8');
    assert.match(src, /reconnectDelayFor\(client\._reconnectAttempt\)/, 'enhancer calls reconnectDelayFor');
    // Every reconnect site should route through scheduleReconnect (no fixed 5000).
    assert.equal((src.match(/, 5000\);/g) || []).length, 0, 'no hardcoded 5s reconnect delays remain');
    const sites = (src.match(/scheduleReconnect\(client\);/g) || []).length;
    assert.equal(sites, 3, 'disconnect, ws-monitor,and heartbeat-monitor all use scheduleReconnect');
});

// tickets.js — the tab renders an empty placeholder server-side when panels
// exist (cards are client-rendered), so it must call refreshTicketList on load.

test('tickets.js refreshes the panel list on page load', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'tickets.js'), 'utf8');
    assert.match(src, /refreshTicketList\(\)\;\s*\} \/\/ end upcoming\/beta lock guard/, 'refreshes after bindTicketCardActions inside the guard');
});

test('refreshTicketList renders server-fetched panels into the tab', async () => {
    const TICKETS_JS = fs.readFileSync(
        path.join(__dirname, '..', 'dashboard', 'public', 'js', 'tickets.js'), 'utf8');

    class FakeEl {
        constructor(id) {
            this.id = id || null;
            this.innerHTML = '';
            this.dataset = {};
        }
        addEventListener() {}
        click() {}
    }
    let listInnerHTML = '';
    const sandbox = {
        window: { guildData: { guildId: '1' }, svgIcon: (n) => `<svg class="ico"></svg>`, ICONS: {} },
        document: {
            getElementById: (id) => (new FakeEl(id)),
            querySelector: (sel) => {
                if (sel === '.rr-list') {
                    return { set innerHTML(v) { listInnerHTML = v; } };
                }
                return null;
            },
            querySelectorAll: () => [],
        },
        api: async () => ({ ticketPanels: [{ id: 42, name: 'Support' }] }),
        esc: (s) => String(s),
        toast: () => {},
        confirm: () => true,
        prompt: () => null,
        console,
    };
    vm.createContext(sandbox);
    vm.runInContext(TICKETS_JS, sandbox);
    await new Promise(r => setTimeout(r, 0));

    assert.ok(listInnerHTML.includes('data-panel="42"'), 'panel card rendered on page load');
    assert.ok(listInnerHTML.includes('Support'), 'panel name rendered');
});

