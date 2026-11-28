/**
 * Lavalink connection lifecycle — mocked Shoukaku/Kazagumo.
 *
 * Covers the production failure modes behind "the audio node isn't connected
 * yet": a missing password, a node that never answers (connection timeout), a
 * successful connection, a drop + bounded re-registration, and a playback
 * attempt while no node is usable. Every assertion also pins that no password
 * is ever rendered or logged.
 *
 * The two libraries are replaced through `Module._load`, so the real
 * player-manager code path (registration, error guard, createPlayer guard,
 * reconnect backoff) runs unchanged.
 */

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const Module = require('node:module');

const ROOT = path.join(__dirname, '..');
const PLAYER_MANAGER = path.join(ROOT, 'music/loaders/loadPlayerManager.js');
const MUSIC_INDEX = path.join(ROOT, 'music/index.js');

const ENV_KEYS = [
    'NODE_URL', 'NODE_PORT', 'NODE_AUTH', 'NODE_NAME', 'NODE_SECURE',
    'LAVALINK_NODES', 'LAVALINK_NAME', 'LAVALINK_HOST', 'LAVALINK_PORT',
    'LAVALINK_PASSWORD', 'LAVALINK_AUTH', 'LAVALINK_SECURE',
];

const PASSWORD = 'super-secret-pw';

const CLOUDEWAVE = {
    NODE_URL: 'lavalink.cloudewave.in',
    NODE_PORT: '2336',
    NODE_AUTH: PASSWORD,
    LAVALINK_NAME: 'cloudewave',
    NODE_SECURE: 'false',
};

// ── fake libraries ───────────────────────────────────────────────────────
class FakeNode extends EventEmitter {
    constructor(name) {
        super();
        this.name = name;
        this.state = 0; // Shoukaku CONNECTING
    }
}

function buildFakeLibraries() {
    class FakeShoukaku extends EventEmitter {
        constructor(connector, nodes, options) {
            super();
            this.connector = connector.set(this);
            this.options = options || {};
            this.nodes = new Map();
            this.players = new Map();
            this.addNodeCalls = 0;
            this.connector.listen(nodes);
        }

        addNode(options) {
            this.addNodeCalls += 1;
            const node = new FakeNode(options.name);
            node.auth = options.auth;
            node.url = options.url;
            this.nodes.set(options.name, node);
            return node;
        }
    }

    class FakeConnector {
        constructor(client) { this.client = client; }
        set(manager) { this.manager = manager; return this; }
        listen() { /* the real one binds clientReady; tests call ready() directly */ }
        ready(nodes) {
            for (const node of nodes) this.manager.addNode(node);
        }
    }

    class FakeKazagumo extends EventEmitter {
        constructor(options, connector, nodes, shoukakuOptions) {
            super();
            this.shoukaku = new FakeShoukaku(connector, nodes, shoukakuOptions);
            this.players = new Map();
            this.createPlayerCalls = 0;
        }

        async createPlayer() {
            this.createPlayerCalls += 1;
            return { guildId: 'g', created: true };
        }
    }

    return {
        kazagumo: { Kazagumo: FakeKazagumo, KazagumoTrack: class {} },
        shoukaku: {
            Connectors: { DiscordJS: FakeConnector },
            LoadType: { TRACK: 'TRACK', PLAYLIST: 'PLAYLIST', SEARCH: 'SEARCH' },
        },
    };
}

/** Async-safe env override (restores even after awaits). */
async function withEnv(overrides, fn) {
    const saved = {};
    for (const key of ENV_KEYS) {
        saved[key] = process.env[key];
        delete process.env[key];
    }
    Object.assign(process.env, overrides);
    try {
        return await fn();
    } finally {
        for (const key of ENV_KEYS) {
            if (saved[key] === undefined) delete process.env[key];
            else process.env[key] = saved[key];
        }
    }
}

/** Patch kazagumo/shoukaku and clear the music module graph for the body. */
async function withMockedLibraries(fn) {
    const libs = buildFakeLibraries();
    const originalLoad = Module._load;
    const cached = new Map();
    const clear = (file) => {
        const resolved = require.resolve(file);
        cached.set(resolved, require.cache[resolved]);
        delete require.cache[resolved];
    };
    Module._load = function patched(request, parent, isMain) {
        if (request === 'kazagumo') return libs.kazagumo;
        if (request === 'shoukaku') return libs.shoukaku;
        return originalLoad.call(this, request, parent, isMain);
    };
    clear(PLAYER_MANAGER);
    clear(MUSIC_INDEX);
    try {
        return await fn();
    } finally {
        Module._load = originalLoad;
        for (const [resolved, mod] of cached) {
            if (mod) require.cache[resolved] = mod;
            else delete require.cache[resolved];
        }
    }
}

/** Require the player manager (inside a mocked scope) and attach a client. */
function loadPlayerManagerWithMocks({ reconnectDelays } = {}) {
    const loadPlayerManager = require(PLAYER_MANAGER);
    const client = {
        user: { id: 'bot-id' },
        isReady: () => true,
        logger: { lines: [], log(line, level) { this.lines.push({ line, level }); } },
        __musicState: { enabled: true, connected: false },
    };
    const manager = loadPlayerManager(client, reconnectDelays ? { reconnectDelays } : {});
    return { manager, client };
}

/** A manager + node registered, inside a mocked scope, under the CLOUDEWAVE env. */
function withRegisteredNode(options, fn) {
    return withEnv(CLOUDEWAVE, () => withMockedLibraries(async () => {
        const { manager, client } = loadPlayerManagerWithMocks(options);
        manager.startNodes();
        return fn({ manager, client, node: [...manager.shoukaku.nodes.values()][0] });
    }));
}

let warnings;
const originalWarn = console.warn;

beforeEach(() => {
    warnings = [];
    console.warn = (...args) => { warnings.push(args.join(' ')); };
});

afterEach(() => {
    console.warn = originalWarn;
});

// ── 1. missing credentials ───────────────────────────────────────────────
test('a missing password is reported as a configuration problem (never a value)', async () => {
    const { resolveNodeConfig } = require('../music/config');
    const { describeNode, buildBootReport } = require('../music/nodeDiagnostics');

    await withEnv({ NODE_URL: 'lavalink.cloudewave.in', NODE_PORT: '2336', LAVALINK_NAME: 'cloudewave' }, async () => {
        const { nodes, problems } = resolveNodeConfig();
        assert.equal(nodes.length, 1);
        assert.equal(nodes[0].auth, '');
        assert.equal(nodes[0].authSource, 'none');
        assert.equal(problems.length, 0, 'an empty password is a boot-report problem, not a resolver error');

        const described = describeNode(nodes[0]);
        assert.equal(described.hasAuth, false);
        assert.equal(described.endpoint, 'ws://lavalink.cloudewave.in:2336/v4/websocket');
        assert.equal(described.authSource, 'none');

        const report = buildBootReport(nodes);
        assert.ok(report.problems.some(p => /no password/i.test(p)), 'the missing password is named');
        assert.match(report.line, /auth missing from none/);
    });

    await withEnv(CLOUDEWAVE, async () => {
        const { nodes } = resolveNodeConfig();
        const described = describeNode(nodes[0]);
        assert.equal(described.hasAuth, true);
        assert.equal(described.authSource, 'NODE_AUTH');
        assert.ok(!JSON.stringify(described).includes(PASSWORD), 'the password never leaves the node object');
        assert.ok(!buildBootReport(nodes).line.includes(PASSWORD));
    });
});

test('LAVALINK_PASSWORD / LAVALINK_AUTH aliases are honoured, and the source is named', async () => {
    const { resolveNodeConfig } = require('../music/config');
    for (const [key, expected] of [['LAVALINK_PASSWORD', 'LAVALINK_PASSWORD'], ['LAVALINK_AUTH', 'LAVALINK_AUTH']]) {
        await withEnv({ NODE_URL: 'host:2333', [key]: PASSWORD }, async () => {
            const node = resolveNodeConfig().nodes[0];
            assert.equal(node.auth, PASSWORD);
            assert.equal(node.authSource, expected);
        });
    }
});

test('the documented LAVALINK_NODES host/port/password shape resolves to a real url+auth', async () => {
    const { resolveNodeConfig } = require('../music/config');
    await withEnv({
        LAVALINK_NODES: JSON.stringify([
            { name: 'cloudewave', host: 'lavalink.cloudewave.in', port: 2336, password: PASSWORD, secure: false },
        ]),
    }, async () => {
        const node = resolveNodeConfig().nodes[0];
        assert.equal(node.url, 'lavalink.cloudewave.in:2336');
        assert.equal(node.auth, PASSWORD);
        assert.equal(node.secure, false);
        assert.equal(node.name, 'cloudewave');
    });
});

// ── 2. connection timeout ────────────────────────────────────────────────
test('the timeout diagnostic prints the real endpoint (no ":undefined") and the sanitized state', async () => {
    await withEnv(CLOUDEWAVE, async () => {
        const { startConnectDiagnostic } = require('../music');
        const client = {
            manager: { shoukaku: { nodes: new Map([['cloudewave', { name: 'cloudewave', state: 0 }]]) } },
            __musicState: { enabled: true, connected: false },
        };
        startConnectDiagnostic(client, 5, { extraDelays: [] });
        await new Promise(r => setTimeout(r, 40));

        assert.equal(warnings.length, 1, 'exactly one diagnostic line');
        const line = warnings[0];
        assert.match(line, /is not connected after 1s/);
        assert.match(line, /ws:\/\/lavalink\.cloudewave\.in:2336\/v4\/websocket/);
        assert.doesNotMatch(line, /undefined/, 'the endpoint must never contain ":undefined"');
        assert.match(line, /node state: CONNECTING/);
        assert.match(line, /auth set \(\d+ chars\) from NODE_AUTH/);
        assert.match(line, /Nothing came back from the node/);
        assert.ok(!line.includes(PASSWORD), 'the password is never printed');
        assert.equal(client.__musicState.connectDiagnostic, line, 'stored for $stats / the dashboard');
    });
});

test('the timeout diagnostic names an explicit error instead of guessing', () => {
    const { buildConnectDiagnostic } = require('../music/nodeDiagnostics');
    const node = { name: 'cloudewave', url: 'host:2336', auth: PASSWORD, secure: true, authSource: 'NODE_AUTH' };
    const line = buildConnectDiagnostic({
        node,
        status: { state: 3, registered: 1 },
        elapsedMs: 20000,
        lastError: `Unexpected server response: 401 (${PASSWORD})`,
    });
    assert.match(line, /wss:\/\/host:2336\/v4\/websocket/);
    assert.match(line, /node state: DISCONNECTED/);
    assert.match(line, /last error: Unexpected server response: 401 \(\[redacted\]\)/);
    assert.match(line, /NODE_AUTH does not match the node password/);
    assert.ok(!line.includes(PASSWORD));
});

// ── 3. successful connection ─────────────────────────────────────────────
test('a connected node reports connected/usable and suppresses the timeout diagnostic', async () => {
    await withEnv(CLOUDEWAVE, async () => {
        const { musicNodeStatus, hasUsableNode, startConnectDiagnostic } = require('../music');
        const client = {
            manager: { shoukaku: { nodes: new Map([['cloudewave', { name: 'cloudewave', state: 1 }]]) } },
            __musicState: { enabled: true, connected: true },
        };
        const status = musicNodeStatus(client);
        assert.equal(status.connected, true);
        assert.equal(status.stateName, 'CONNECTED');
        assert.equal(status.endpoint, 'ws://lavalink.cloudewave.in:2336/v4/websocket');
        assert.equal(status.hasAuth, true);
        assert.equal(hasUsableNode(client), true);

        startConnectDiagnostic(client, 5, { extraDelays: [] });
        await new Promise(r => setTimeout(r, 40));
        assert.equal(warnings.length, 0, 'a connected node is never reported as down');
    });
});

test('the node ready handler clears the recorded error and the diagnostic', async () => {
    const ready = require('../music/events/Node/ready');
    await withEnv(CLOUDEWAVE, async () => {
        const client = {
            __musicState: { enabled: true, connected: false, lastError: 'boom', lastErrorAt: 1, connectDiagnostic: 'x' },
            logger: { log() {} },
        };
        const originalLog = console.log;
        console.log = () => {};
        try {
            await ready.run(client, 'cloudewave');
        } finally {
            console.log = originalLog;
        }
        assert.equal(client.__musicState.connected, true);
        assert.equal(client.__musicState.lastError, null);
        assert.equal(client.__musicState.connectDiagnostic, null);
        assert.equal(client.__musicConnectDiagDone, true);
    });
});

// ── 4. reconnect ─────────────────────────────────────────────────────────
test('registration is deferred until startNodes() so an immediate failure cannot crash', () =>
    withEnv(CLOUDEWAVE, () => withMockedLibraries(async () => {
        const { manager } = loadPlayerManagerWithMocks();
        assert.equal(manager.shoukaku.nodes.size, 0, 'loadPlayerManager does not register by itself');
        assert.equal(manager.startNodes(), true);
        assert.equal(manager.shoukaku.nodes.size, 1, 'startNodes registers exactly one node');
        assert.equal(manager.shoukaku.addNodeCalls, 1);

        // Idempotent: a second call never opens a second socket.
        manager.startNodes();
        manager.ensureNodes();
        assert.equal(manager.shoukaku.addNodeCalls, 1);
    })));

test('a node error during registration is recorded, not thrown (no unhandled-error crash)', () =>
    withEnv(CLOUDEWAVE, () => withMockedLibraries(async () => {
        const { manager, client } = loadPlayerManagerWithMocks();
        let delivered = false;
        manager.shoukaku.once('error', () => { delivered = true; });

        // This is what addNode → connect() does when the provider is down and
        // the real `loadNodes` handler has not been bound yet. Before the fix
        // this emit threw ERR_UNHANDLED_ERROR and killed the process.
        assert.doesNotThrow(() => {
            manager.shoukaku.emit('error', 'cloudewave', new Error(`401 bad auth (${PASSWORD})`));
        });
        assert.equal(delivered, true, 'the error is delivered to listeners');
        assert.match(client.__musicState.lastError, /401 bad auth/);
        assert.ok(!client.__musicState.lastError.includes(PASSWORD), 'the password is redacted');
    })));

test('a dropped node is re-registered once after the backoff, never duplicated', () =>
    withEnv(CLOUDEWAVE, () => withMockedLibraries(async () => {
        const created = [];
        const { manager } = loadPlayerManagerWithMocks({ reconnectDelays: [5, 5] });
        const originalAdd = manager.shoukaku.addNode.bind(manager.shoukaku);
        manager.shoukaku.addNode = (options) => {
            const node = originalAdd(options);
            created.push(node);
            return node;
        };

        manager.startNodes();
        assert.equal(created.length, 1);

        // Shoukaku gives up: the node leaves the pool and emits `disconnect`.
        manager.shoukaku.nodes.delete('cloudewave');
        created[0].emit('disconnect');
        created[0].emit('disconnect'); // duplicate signal → still ONE timer
        await new Promise(r => setTimeout(r, 80));

        assert.equal(manager.shoukaku.nodes.size, 1, 'the node is back in the pool');
        assert.equal(manager.shoukaku.addNodeCalls, 2, 'exactly one re-registration');
    })));

test('reconnect backoff is bounded and resets on a successful connect', () =>
    withEnv(CLOUDEWAVE, () => withMockedLibraries(async () => {
        const { manager, client } = loadPlayerManagerWithMocks({ reconnectDelays: [5] });
        manager.startNodes();

        manager.shoukaku.nodes.delete('cloudewave');
        manager.scheduleNodeReconnect('test drop');
        await new Promise(r => setTimeout(r, 40));

        // Second drop with the budget exhausted: give up instead of storming.
        manager.shoukaku.nodes.delete('cloudewave');
        assert.equal(manager.scheduleNodeReconnect('again'), null);
        assert.ok(client.logger.lines.some(l => /gave up/.test(l.line)));

        // A ready event resets the budget.
        manager.shoukaku.emit('ready', 'cloudewave');
        assert.notEqual(manager.scheduleNodeReconnect('after ready'), null);
    })));

// ── 5. unavailable-node playback ─────────────────────────────────────────
test('createPlayer refuses to run while no node is CONNECTED (no voice, no player)', () =>
    withRegisteredNode({}, async ({ manager, client }) => {
        assert.equal([...manager.shoukaku.nodes.values()][0].state, 0, 'the node is still CONNECTING');

        await assert.rejects(
            () => manager.createPlayer({ guildId: 'g1', voiceId: 'v1', textId: 't1' }),
            (err) => {
                assert.equal(err.code, 'MUSIC_NODE_UNAVAILABLE');
                assert.match(err.message, /isn't connected yet/);
                return true;
            },
        );
        assert.equal(manager.createPlayerCalls, 0, 'Kazagumo never created a player');
        assert.ok(client.logger.lines.some(l => /Refusing to create a player/.test(l.line)));
    }));

test('createPlayer works as soon as a node is CONNECTED', () =>
    withRegisteredNode({}, async ({ manager, node }) => {
        node.state = 1;
        const player = await manager.createPlayer({ guildId: 'g1', voiceId: 'v1', textId: 't1' });
        assert.equal(player.created, true);
        assert.equal(manager.createPlayerCalls, 1);
    }));

test('the prefix runner replies with the friendly message and logs sanitized diagnostics', async () => {
    const { runPrefixCommand } = require('../music/prefixRunner');

    await withEnv(CLOUDEWAVE, async () => {
        const sent = [];
        const errors = [];
        const originalError = console.error;
        console.error = (...args) => { errors.push(args.join(' ')); };

        const client = {
            musicCommands: new Map([['play', {
                name: 'play',
                aliases: ['p'],
                execute: async () => {
                    throw require('../music/nodeAvailability').nodeUnavailableError(client);
                },
            }]]),
            manager: { players: new Map(), shoukaku: { nodes: new Map([['cloudewave', { name: 'cloudewave', state: 0 }]]) } },
            __musicState: { enabled: true, connected: false },
            emoji: {},
            color: 0,
        };
        const message = {
            guild: { id: 'g1', members: { me: null } },
            member: { voice: {}, permissions: { has: () => true } },
            author: { displayAvatarURL: () => '' },
            channel: { send: async (payload) => { sent.push(payload); return payload; } },
            channelId: 'c1',
        };

        try {
            await runPrefixCommand(client, message, 'play', ['song'], '$');
        } finally {
            console.error = originalError;
        }

        assert.equal(sent.length, 1);
        assert.match(String(sent[0]), /Music is temporarily unavailable/);
        assert.match(String(sent[0]), /`cloudewave` isn't connected yet/);
        assert.ok(errors.some(e => /no usable Lavalink node/.test(e)
            && /ws:\/\/lavalink\.cloudewave\.in:2336\/v4\/websocket/.test(e)));
        assert.ok(!errors.join(' ').includes(PASSWORD));
    });
});

// ── 6. init ordering / single init ───────────────────────────────────────
test('node/player event handlers are bound before the first node is registered', () => {
    const src = fs.readFileSync(MUSIC_INDEX, 'utf8');
    const loadNodesAt = src.indexOf('loadNodes(client)');
    const startAt = src.indexOf('manager.startNodes()');
    assert.ok(loadNodesAt > 0 && startAt > 0, 'both calls are present');
    assert.ok(loadNodesAt < startAt, 'loadNodes() must run before startNodes()');
    assert.match(src, /if \(client\.__musicInitialized\)/, 'init is guarded per client');

    const managerSrc = fs.readFileSync(PLAYER_MANAGER, 'utf8');
    const listenerAt = managerSrc.indexOf("manager.shoukaku.on('error'");
    const startNodesAt = managerSrc.indexOf('manager.startNodes = ');
    assert.ok(listenerAt > 0, 'a bootstrap error listener exists');
    assert.ok(listenerAt < startNodesAt, 'the error guard is bound before any registration can happen');
});

test('initMusic is idempotent — a second call never re-registers or re-binds', () =>
    withEnv(CLOUDEWAVE, () => withMockedLibraries(async () => {
        const { initMusic } = require('../music');
        const client = {
            user: { id: 'bot-id' },
            isReady: () => true,
            guilds: { cache: new Map() },
            channels: { cache: new Map() },
            commands: new Map(),
            slashCommands: new Map(),
            emoji: {},
            logger: { lines: [], log(line, level) { this.lines.push({ line, level }); } },
            on() {},
            once() {},
        };

        const first = initMusic(client);
        assert.equal(first.enabled, true);
        const manager = client.manager;
        assert.ok(manager, 'a manager exists');
        assert.equal(manager.shoukaku.addNodeCalls, 1);

        const second = initMusic(client);
        assert.equal(first, second, 'the same state object is returned');
        assert.equal(client.__musicInitialized, true);

        initMusic(client);
        assert.equal(manager.shoukaku.addNodeCalls, 1, 'no duplicate node registration across restarts');
    })));
