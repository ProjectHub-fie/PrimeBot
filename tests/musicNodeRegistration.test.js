/**
 * Lavalink node registration must be retryable.
 *
 * `$play` answering "the audio node `LNODE` isn't connected yet" means Kazagumo
 * has no *usable* node — the registration either never ran or threw once.
 * The old code set its `nodesRegistered` flag BEFORE calling Shoukaku, so a
 * single throw (client not ready yet, transient Shoukaku error) disabled music
 * for the life of the process. These tests pin the retry semantics.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { ensureMusicNodes, describeNodes } = require('../music');

test('ensureMusicNodes re-registers when no node is present', () => {
    let calls = 0;
    const client = {
        manager: {
            shoukaku: { nodes: new Map() },
            ensureNodes: () => { calls += 1; },
        },
    };
    assert.equal(ensureMusicNodes(client), false, 'still no node after the retry');
    assert.equal(calls, 1, 'the registration was retried');
});

test('ensureMusicNodes is a no-op once a node is registered', () => {
    let calls = 0;
    const client = {
        manager: {
            shoukaku: { nodes: new Map([[ 'LNODE', { name: 'LNODE', state: 1 } ]]) },
            ensureNodes: () => { calls += 1; },
        },
    };
    assert.equal(ensureMusicNodes(client), true);
    assert.equal(calls, 0, 'a healthy node is never re-registered');
});

test('ensureMusicNodes survives a client without a music manager', () => {
    assert.equal(ensureMusicNodes({}), false);
    assert.equal(ensureMusicNodes(null), false);
    assert.equal(ensureMusicNodes({ manager: { shoukaku: null } }), false);
});

test('describeNodes reports the registered node states for diagnostics', () => {
    const client = { manager: { shoukaku: { nodes: new Map([['LNODE', { name: 'LNODE', state: 2 }]]) } } };
    assert.equal(describeNodes(client), 'LNODE=2');
    assert.equal(describeNodes({ manager: { shoukaku: { nodes: new Map() } } }), 'none registered');
});

test('a failed registration is retried instead of latching for the process lifetime', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'music', 'loaders', 'loadPlayerManager.js'), 'utf8');
    const block = src.slice(src.indexOf('const registerAll'), src.indexOf('manager.ensureNodes'));
    // The flag is set only after `registerNodes` returns.
    assert.match(
        block,
        /try \{\s*registerNodes\(cfg\.nodes\);\s*nodesRegistered = true;/,
        'nodesRegistered is set AFTER a successful registration',
    );
    assert.match(
        block,
        /catch \(err\) \{[\s\S]*?return false;/,
        'a throw returns false and leaves the flag unset',
    );
    assert.match(block, /\[5000, 15000\]/, 'bounded retries are scheduled after boot');
    assert.match(src, /manager\.ensureNodes = \(\) => registerAll\(\)/, 'the command path can self-heal');
});

test('both command paths call the self-heal before executing', () => {
    const prefix = fs.readFileSync(path.join(__dirname, '..', 'music', 'prefixRunner.js'), 'utf8');
    const slash = fs.readFileSync(path.join(__dirname, '..', 'music', 'interactions.js'), 'utf8');
    assert.match(prefix, /ensureMusicNodes\(client\)/);
    assert.match(slash, /ensureMusicNodes\(client\)/);
    // …and log the real node state when the failure still happens.
    assert.match(prefix, /no usable Lavalink node/);
    assert.match(slash, /no usable Lavalink node/);
});
