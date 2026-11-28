/**
 * Lavalink node identifier = `LNODE`.
 *
 * The audio node's name must never be confused with PrimeBot's three shard
 * clusters, and renaming it must not touch the connection (host / port /
 * password / TLS). These tests pin both halves of that contract, plus the
 * displays that surface the name.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CONFIG_KEYS = [
    'NODE_URL', 'NODE_PORT', 'NODE_AUTH', 'NODE_NAME', 'NODE_SECURE',
    'LAVALINK_NODES', 'LAVALINK_NAME', 'LAVALINK_HOST', 'LAVALINK_PORT',
    'LAVALINK_PASSWORD', 'LAVALINK_SECURE',
];

function withEnv(overrides, fn) {
    const saved = {};
    for (const k of CONFIG_KEYS) saved[k] = process.env[k];
    for (const k of CONFIG_KEYS) delete process.env[k];
    Object.assign(process.env, overrides);
    try {
        return fn();
    } finally {
        for (const k of CONFIG_KEYS) {
            if (saved[k] === undefined) delete process.env[k];
            else process.env[k] = saved[k];
        }
    }
}

const { resolveNodes, DEFAULT_NODE_NAME } = require('../music/config');

test('the Lavalink node identifier defaults to LNODE', () => {
    assert.equal(DEFAULT_NODE_NAME, 'LNODE');
    withEnv({ NODE_URL: 'lava.example.test:2333', NODE_AUTH: 'pw' }, () => {
        assert.equal(resolveNodes()[0].name, 'LNODE');
    });
});

test('renaming the node does not change host, port, password or TLS', () => {
    const before = withEnv({
        NODE_URL: 'lavalink.cloudewave.in',
        NODE_PORT: '2336',
        NODE_AUTH: 'pw-1',
        NODE_SECURE: 'false',
    }, () => resolveNodes()[0]);

    const after = withEnv({
        NODE_URL: 'lavalink.cloudewave.in',
        NODE_PORT: '2336',
        NODE_AUTH: 'pw-1',
        NODE_SECURE: 'false',
        LAVALINK_NAME: 'LNODE',
    }, () => resolveNodes()[0]);

    assert.equal(before.name, 'LNODE');
    assert.equal(after.name, 'LNODE');
    assert.equal(after.url, before.url);
    assert.equal(after.auth, before.auth);
    assert.equal(after.secure, before.secure);
    // Shoukaku's connection string is byte-for-byte identical.
    assert.equal(
        `${after.secure ? 'wss' : 'ws'}://${after.url}/v4/websocket`,
        `ws://lavalink.cloudewave.in:2336/v4/websocket`,
    );
});

test('the shard cluster identity never becomes the audio-node label', () => {
    // NODE_NAME is the shard identity (sn1/sn2/sn3 or a host label).
    for (const shardName of ['sn1', 'sn2', 'sn3', 'CloudeWave']) {
        withEnv({ NODE_URL: 'host:2333', NODE_AUTH: 'pw', NODE_NAME: shardName }, () => {
            assert.equal(resolveNodes()[0].name, 'LNODE', `NODE_NAME=${shardName} must not leak`);
        });
    }
});

test('LAVALINK_NAME is the only override, and LAVALINK_NODES keeps explicit names', () => {
    withEnv({ NODE_URL: 'host:2333', NODE_AUTH: 'pw', LAVALINK_NAME: 'LNODE' }, () => {
        assert.equal(resolveNodes()[0].name, 'LNODE');
    });
    withEnv({ NODE_URL: 'host:2333', NODE_AUTH: 'pw', LAVALINK_NAME: 'custom' }, () => {
        assert.equal(resolveNodes()[0].name, 'custom');
    });
    withEnv({
        LAVALINK_NODES: JSON.stringify([
            { name: 'LNODE', url: 'a:2333', auth: 'p1' },
            { url: 'b:2333', auth: 'p2' }, // no name → LNODE
        ]),
    }, () => {
        const nodes = resolveNodes();
        assert.deepEqual(nodes.map(n => n.name), ['LNODE', 'LNODE']);
        assert.deepEqual(nodes.map(n => n.url), ['a:2333', 'b:2333']);
    });
});

test('the resolved node never carries a credential in a display field', () => {
    withEnv({ NODE_URL: 'host:2333', NODE_AUTH: 'super-secret' }, () => {
        const node = resolveNodes()[0];
        assert.equal(node.auth, 'super-secret', 'auth is used for the handshake');
        for (const field of ['name', 'url']) {
            assert.ok(!String(node[field]).includes('super-secret'), `${field} must not leak the password`);
        }
    });
});

// ── displays ─────────────────────────────────────────────────────────────
test('musicNodeStatus reports the configured name and live state', () => {
    withEnv({ NODE_URL: 'host:2333', NODE_AUTH: 'pw' }, () => {
        const { musicNodeStatus } = require('../music');
        const client = {
            manager: { shoukaku: { nodes: new Map() } },
            __musicState: { enabled: true, connected: false },
        };
        const status = musicNodeStatus(client);
        assert.equal(status.name, 'LNODE');
        assert.equal(status.registered, 0);
        assert.equal(status.connected, false);

        client.manager.shoukaku.nodes.set('LNODE', { name: 'LNODE' });
        client.__musicState.connected = true;
        const live = musicNodeStatus(client);
        assert.equal(live.registered, 1);
        assert.equal(live.connected, true);
    });
});

test('the boot log names the node/endpoint and never the password', () => {
    const src = fs.readFileSync(path.join(ROOT, 'music/index.js'), 'utf8');
    // The boot line is built by buildBootReport(): name + ws(s) endpoint +
    // TLS flag + password PRESENCE ("auth set (N chars) from NODE_AUTH").
    assert.match(src, /Music initialized with \$\{cfg\.nodes\.length\} Lavalink node\(s\): \$\{report\.line\}/);
    assert.match(src, /buildBootReport\(cfg\.nodes\)/);
    assert.doesNotMatch(src, /n\.auth/, 'the auth field is never logged');

    const diag = fs.readFileSync(path.join(ROOT, 'music/nodeDiagnostics.js'), 'utf8');
    assert.match(diag, /authHint/, 'only a password hint (length) is reported');
    assert.doesNotMatch(diag, /auth:\s*n\.auth/, 'the password value is never rendered');
});

test('$music and $stats both surface the audio-node name', () => {
    const help = fs.readFileSync(path.join(ROOT, 'music/help.js'), 'utf8');
    assert.match(help, /Lavalink Node/);
    assert.match(help, /musicNodeStatus/);

    const command = fs.readFileSync(path.join(ROOT, 'events/messageCreate.js'), 'utf8');
    assert.match(command, /name: '🎵 Lavalink'/);
    assert.match(command, /musicNodeStatus\(client\)/);
});

test('a missing node produces a clear message, not a raw stack trace', () => {
    for (const rel of ['music/prefixRunner.js', 'music/interactions.js']) {
        const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
        // Recognises both our typed MUSIC_NODE_UNAVAILABLE and Kazagumo's raw
        // `No node found` (see music/nodeAvailability.js).
        assert.match(src, /isNodeUnavailableError/, `${rel} recognises the no-node state`);
        assert.match(src, /isn't connected yet/, `${rel} tells the user what is wrong`);
    }
    const availability = fs.readFileSync(path.join(ROOT, 'music/nodeAvailability.js'), 'utf8');
    assert.match(availability, /no node found/i, 'the raw Kazagumo error is still recognised');
});

test('documentation points at LAVALINK_NAME/LNODE, not NODE_NAME, for the audio node', () => {
    const env = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8');
    assert.match(env, /LAVALINK_NAME=LNODE/);
    assert.match(env, /SHARD CLUSTER identity/);

    const docs = fs.readFileSync(path.join(ROOT, 'dashboard/commandDocs.js'), 'utf8');
    assert.match(docs, /LNODE/);
    assert.doesNotMatch(docs, /NODE_NAME \/ NODE_SECURE/, 'docs no longer offer NODE_NAME as a Lavalink label');
});
