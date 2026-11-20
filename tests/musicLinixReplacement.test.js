/**
 * The Linix music replacement: verifies that PrimeBot's old music/radio
 * implementation is gone and that the vendored Linix tree is what is wired in.
 *
 * These tests drive the REAL modules (bootstrap, prefix dispatch, slash
 * dispatch, config resolution) with stubs only for the network/Lavalink layer.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { Collection } = require('discord.js');

const ROOT = path.join(__dirname, '..');

function makeClient() {
    return {
        commands: new Collection(), // PrimeBot's own slash commands
        slashCommands: new Collection(),
        guilds: { cache: new Map() },
        on() {},
        once() {},
        user: { id: 'bot-1', displayAvatarURL: () => 'https://cdn.example/avatar.png' },
        channels: { cache: new Map() },
    };
}

function withLavalinkEnv(fn) {
    const keys = ['NODE_URL', 'NODE_AUTH', 'NODE_SECURE', 'NODE_NAME', 'LAVALINK_NODES', 'LAVALINK_NAME', 'LAVALINK_HOST'];
    const saved = {};
    for (const k of keys) saved[k] = process.env[k];
    process.env.NODE_URL = 'lavalink.example:2333';
    process.env.NODE_AUTH = 'test-auth';
    process.env.NODE_SECURE = 'false';
    delete process.env.LAVALINK_NODES;
    delete process.env.LAVALINK_HOST;
    try {
        return fn();
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
}

test('the old PrimeBot music/radio implementation is gone', () => {
    const removed = [
        'commands/music.js',
        'commands/radio.js',
        'commands/playlist.js',
        'commands/247.js',
        'utils/music/musicManager.js',
        'utils/music/musicVoice.js',
        'utils/music/musicEmbed.js',
        'utils/music/providers/registry.js',
        'utils/music/engines/index.js',
        'utils/radioManager.js',
        'utils/radioVoice.js',
        'utils/radioEmbed.js',
        'utils/playbackMode.js',
        'utils/soundcloudSource.js',
        'utils/voiceReadiness.js',
        'server/musicDb.js',
        'dashboard/render/music-page.js',
        'dashboard/render/radio-page.js',
        'dashboard/public/js/music.js',
    ];
    for (const rel of removed) {
        assert.strictEqual(fs.existsSync(path.join(ROOT, rel)), false, `${rel} must be deleted`);
    }
});

test('nothing outside the music tree still requires a deleted music module', () => {
    const dead = [
        'utils/music/',
        'utils/radioManager',
        'utils/radioVoice',
        'utils/radioEmbed',
        'utils/playbackMode',
        'utils/soundcloudSource',
        'utils/voiceReadiness',
        'server/musicDb',
        'server/radioDb',
        'render/music-page',
        'render/radio-page',
    ];
    const offenders = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const p = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (['node_modules', '.git', 'music', 'tests', 'workspace'].includes(entry.name)) continue;
                walk(p);
                continue;
            }
            if (!entry.name.endsWith('.js')) continue;
            const src = fs.readFileSync(p, 'utf8');
            for (const rel of dead) {
                if (src.includes(`'${rel}`) || src.includes(`"${rel}`)) {
                    offenders.push(`${path.relative(ROOT, p)} -> ${rel}`);
                }
            }
        }
    };
    walk(ROOT);
    assert.deepStrictEqual(offenders, [], `dangling music imports: ${offenders.join(', ')}`);
});

test('initMusic loads the Linix prefix + slash trees and the Kazagumo manager', () => {
    withLavalinkEnv(() => {
        const { initMusic } = require('../music');
        const client = makeClient();
        const state = initMusic(client);

        assert.strictEqual(state.enabled, true, 'music must initialize with a configured node');
        assert.strictEqual(state.nodes, 1);
        assert.ok(client.manager, 'client.manager (Kazagumo) must be attached');

        // Linix prefix commands live in their own tree so PrimeBot's own slash
        // commands in `client.commands` are never shadowed.
        assert.ok(client.musicCommands.size >= 25, 'prefix tree must be loaded');
        assert.strictEqual(client.commands.size, 0, "PrimeBot's own command collection must be untouched");
        assert.ok(client.slashCommands.size >= 25, 'slash tree must be loaded');

        for (const name of ['play', 'skip', 'stop', 'queue', 'filter', 'autoplay', 'playlist', '247']) {
            assert.ok(client.musicCommands.has(name), `$${name} must be registered`);
        }
        for (const name of ['play', 'radio', 'bassboost', 'nightcore', '247']) {
            assert.ok(client.slashCommands.has(name), `/${name} must be registered`);
        }
    });
});

test('initMusic is idempotent and inert (never throws) without a node', () => {
    const keys = ['NODE_URL', 'LAVALINK_NODES', 'LAVALINK_HOST'];
    const saved = {};
    for (const k of keys) saved[k] = process.env[k];
    delete process.env.NODE_URL;
    delete process.env.LAVALINK_NODES;
    delete process.env.LAVALINK_HOST;
    try {
        const { initMusic } = require('../music');
        const client = makeClient();
        const state = initMusic(client);
        assert.strictEqual(state.enabled, false);
        assert.strictEqual(state.reason, 'no_lavalink_node');
        assert.ok(!client.manager, 'no player manager without a node');

        const again = initMusic(client);
        assert.strictEqual(again.enabled, false, 'a second call must not re-run the boot');
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
});

test('prefix aliases resolve exactly as Linix does ($p, $fs, $q, $v)', () => {
    withLavalinkEnv(() => {
        const { initMusic } = require('../music');
        const { findCommand } = require('../music/prefixRunner');
        const client = makeClient();
        initMusic(client);

        const expected = { p: 'play', fs: 'forceskip', q: 'queue', v: 'volume', dc: 'leave', j: 'join' };
        for (const [alias, target] of Object.entries(expected)) {
            const cmd = findCommand(client, alias);
            assert.ok(cmd, `$${alias} must resolve`);
            assert.strictEqual(cmd.name, target, `$${alias} must resolve to ${target}`);
        }
        assert.strictEqual(findCommand(client, 'definitely-not-a-command'), null);
        // `$np` belongs to PrimeBot's developer-only no-prefix command, whose
        // top-level case runs before the music fallback. Keeping Linix's `np`
        // alias would ship a dead command that answers "Access Denied".
        assert.strictEqual(findCommand(client, 'np'), null, '$np must stay with the developer command');
        assert.strictEqual(findCommand(client, 'nowplaying').name, 'nowplaying');
    });
});

test('the prefix runner enforces the Linix voice preconditions before running', async () => {
    const { runPrefixCommand } = require('../music/prefixRunner');
    const replies = [];
    let executed = false;
    const client = {
        color: 0x5865f2,
        manager: { players: { get: () => null } },
        musicCommands: new Map([['skip', {
            name: 'skip',
            player: true,
            inVoiceChannel: true,
            sameVoiceChannel: true,
            execute: async () => { executed = true; },
        }]]),
    };
    const message = {
        guild: { id: 'g1', members: { me: { permissions: { has: () => true }, voice: { channel: null, channelId: null } } } },
        member: { permissions: { has: () => true }, voice: { channelId: null } },
        channelId: 'c1',
        author: { displayAvatarURL: () => '' },
        channel: { send: async (p) => { replies.push(p); return p; } },
    };
    await runPrefixCommand(client, message, 'skip', [], '$');
    assert.ok(replies.length > 0, 'a precondition failure must reply');
    assert.strictEqual(executed, false, 'the command must not run without a player');
});

test('the slash router owns the music tree and leaves PrimeBot commands alone', () => {
    const { isMusicSlashCommand, isMusicCustomId, MUSIC_CUSTOM_IDS } = require('../music/interactions');
    withLavalinkEnv(() => {
        const { initMusic } = require('../music');
        const client = makeClient();
        initMusic(client);

        assert.strictEqual(isMusicSlashCommand(client, { commandName: 'play' }), true);
        assert.strictEqual(isMusicSlashCommand(client, { commandName: 'ticket' }), false);
        assert.strictEqual(isMusicSlashCommand(client, { commandName: 'antinuke' }), false);
    });

    // Every customId the Linix collectors answer must be passed through, or
    // PrimeBot's generic button switch double-answers the interaction.
    for (const id of ['disable_h', 'select-song', 'pause', 'resume', 'skip', 'stop', 'loop', 'shuffle',
        'clearbut', 'bassbut', '8dbut', 'nightbut', 'pitchbut', 'lofibut', 'distortbut', 'speedbut', 'vapobut']) {
        assert.ok(MUSIC_CUSTOM_IDS.has(id), `${id} must be passed through`);
        assert.strictEqual(isMusicCustomId(id), true);
    }
    assert.strictEqual(isMusicCustomId('ticketpanel:close'), false);
});

test('every button customId the player collectors answer is in the pass-through set', () => {
    const { MUSIC_CUSTOM_IDS } = require('../music/interactions');
    const src = fs.readFileSync(path.join(ROOT, 'music/events/Players/playerStart.js'), 'utf8');
    const ids = new Set();
    for (const m of src.matchAll(/case "([^"]+)":/g)) ids.add(m[1]);
    for (const m of src.matchAll(/setCustomId\("([^"]+)"\)/g)) ids.add(m[1]);
    for (const m of src.matchAll(/^\s+([a-z0-9]+): \{ op: "filters"/gm)) ids.add(m[1]);

    for (const id of ids) {
        assert.ok(MUSIC_CUSTOM_IDS.has(id), `player customId "${id}" must be in MUSIC_CUSTOM_IDS`);
    }
});

test('every collector customId in the whole music tree is passed through', () => {
    // PrimeBot's generic button/select switch answers any customId it does not
    // recognise with "This button is not currently functional", stealing the
    // interaction from Linix's own collector. Every collector id must be in the
    // pass-through set, so scan the ENTIRE vendored tree rather than one file.
    const { MUSIC_CUSTOM_IDS } = require('../music/interactions');
    const offenders = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) { walk(full); continue; }
            if (!entry.name.endsWith('.js')) continue;
            const src = fs.readFileSync(full, 'utf8');
            for (const m of src.matchAll(/setCustomId\(\s*["'`]([^"'`]+)["'`]\s*\)/g)) {
                if (!MUSIC_CUSTOM_IDS.has(m[1])) offenders.push(`${path.relative(ROOT, full)}: ${m[1]}`);
            }
        }
    };
    walk(path.join(ROOT, 'music'));
    assert.deepStrictEqual(offenders, [], `unpassed music customIds: ${offenders.join(', ')}`);
});

test('Lavalink config uses the authorized node env vars and never hardcodes credentials', () => {
    const { getMusicConfig } = require('../music/config');
    withLavalinkEnv(() => {
        const cfg = getMusicConfig();
        assert.strictEqual(cfg.nodes.length, 1);
        assert.strictEqual(cfg.nodes[0].url, 'lavalink.example:2333');
        assert.strictEqual(cfg.nodes[0].auth, 'test-auth');
        assert.strictEqual(cfg.nodes[0].secure, false);
        // No credential may be baked into the source.
        const src = fs.readFileSync(path.join(ROOT, 'music/config.js'), 'utf8');
        assert.doesNotMatch(src, /auth:\s*['"][^'"]{8,}['"]/, 'node auth must come from env only');
    });
});

test("LAVALINK_NAME wins over PrimeBot's shard NODE_NAME for the node label", () => {
    const { resolveNodes } = require('../music/config');
    const keys = ['NODE_URL', 'NODE_NAME', 'LAVALINK_NAME', 'LAVALINK_NODES'];
    const saved = {};
    for (const k of keys) saved[k] = process.env[k];
    process.env.NODE_URL = 'host:2333';
    process.env.NODE_NAME = 'NUKN09'; // shard identity
    process.env.LAVALINK_NAME = 'linix-node-1'; // Lavalink label
    delete process.env.LAVALINK_NODES;
    try {
        assert.strictEqual(resolveNodes()[0].name, 'linix-node-1');
        delete process.env.LAVALINK_NAME;
        assert.strictEqual(resolveNodes()[0].name, 'NUKN09', 'NODE_NAME is the Linix-compatible fallback');
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
});

test('Spotify credentials are env-driven and never baked into the source', () => {
    const { getMusicConfig } = require('../music/config');
    const keys = ['SPOTIFY_CLIENT_ID', 'SPOTIFY_CLIENT_SECRET'];
    const saved = {};
    for (const k of keys) saved[k] = process.env[k];
    delete process.env.SPOTIFY_CLIENT_ID;
    delete process.env.SPOTIFY_CLIENT_SECRET;
    try {
        assert.strictEqual(getMusicConfig().spotify.clientId, '');
        process.env.SPOTIFY_CLIENT_ID = 'id-from-env';
        process.env.SPOTIFY_CLIENT_SECRET = 'secret-from-env';
        const cfg = getMusicConfig();
        assert.strictEqual(cfg.spotify.clientId, 'id-from-env');
        assert.strictEqual(cfg.spotify.clientSecret, 'secret-from-env');
        const src = fs.readFileSync(path.join(ROOT, 'music/config.js'), 'utf8');
        assert.doesNotMatch(src, /clientSecret:\s*['"][A-Za-z0-9]{16,}['"]/);
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
});

test('messageCreate routes unmatched prefix commands into the Linix resolver', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events/messageCreate.js'), 'utf8');
    assert.match(src, /musicRunner\.findCommand\(client, commandName\)/);
    assert.match(src, /musicRunner\.runPrefixCommand\(client, message, commandName, args, prefix\)/);
    // The old inline radio/music switch must be gone.
    assert.doesNotMatch(src, /client\.radioManager/);
    assert.doesNotMatch(src, /client\.musicManager/);
    assert.doesNotMatch(src, /musicUi/);
});

test('interactionCreate dispatches music slash commands before its own lookup', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events/interactionCreate.js'), 'utf8');
    const musicIdx = src.indexOf("require('../music/interactions').isMusicSlashCommand");
    // The autocomplete branch has its own `client.commands.get`, so compare
    // against the chat-input dispatch that follows the music check.
    const ownIdx = src.indexOf('client.commands.get(interaction.commandName)', musicIdx);
    assert.ok(musicIdx > -1, 'the music router must be wired in');
    assert.ok(ownIdx > musicIdx, "music must be dispatched before PrimeBot's own command lookup");
    assert.doesNotMatch(src, /musicUi/);
});

test('voiceStateUpdate keeps the defense and no longer forwards to a deleted manager', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events/voiceStateUpdate.js'), 'utf8');
    assert.match(src, /voiceDefense/);
    assert.doesNotMatch(src, /radioManager/);
    assert.doesNotMatch(src, /musicManager/);
});

test('index.js boots the Linix subsystem and no longer constructs the old managers', () => {
    const src = fs.readFileSync(path.join(ROOT, 'index.js'), 'utf8');
    assert.match(src, /require\('\.\/music'\)/);
    assert.match(src, /initMusic\(client\)/);
    assert.doesNotMatch(src, /new RadioManager/);
    assert.doesNotMatch(src, /new MusicManager/);
});

test('deploy-commands registers the Linix slash tree alongside PrimeBot commands', () => {
    const src = fs.readFileSync(path.join(ROOT, 'deploy-commands.js'), 'utf8');
    assert.match(src, /music', 'slashCommands'/);
    assert.match(src, /Loaded music command:/);
});

test('the dashboard no longer exposes a music/radio surface', () => {
    const server = fs.readFileSync(path.join(ROOT, 'dashboard/server.js'), 'utf8');
    assert.doesNotMatch(server, /\/guild\/:guildId\/music/);
    assert.doesNotMatch(server, /\/guild\/:guildId\/radio/);
    assert.doesNotMatch(server, /api\/guilds\/:guildId\/music/);

    const db = fs.readFileSync(path.join(ROOT, 'dashboard/db.js'), 'utf8');
    assert.doesNotMatch(db, /getMusicSettings|upsertMusicSettings|getRadioSession|radioPool/);

    const tabs = fs.readFileSync(path.join(ROOT, 'dashboard/render/guild.js'), 'utf8');
    assert.doesNotMatch(tabs, /key: 'music'/);
    assert.doesNotMatch(tabs, /key: 'radio'/);
});

test('the help catalog describes the Linix command set', () => {
    const { CATALOG } = require('../utils/prefixHelp');
    const music = CATALOG.music;
    assert.ok(music, 'the music help category must exist');
    const text = JSON.stringify(music);
    for (const needle of ['247', 'filter', 'autoplay', 'playlist', 'play']) {
        assert.ok(text.includes(needle), `help must mention ${needle}`);
    }
    // Entries must be documented under the `music` command so the Sash drift
    // test keeps passing.
    for (const cmd of music.commands) {
        assert.deepStrictEqual(cmd.names, ['music'], `unexpected help name ${cmd.names}`);
    }
});

test('$music renders the overview card from the loaded tree', () => {
    const { musicHelpEmbed } = require('../music/help');
    withLavalinkEnv(() => {
        const { initMusic } = require('../music');
        const client = makeClient();
        initMusic(client);
        const json = musicHelpEmbed(client, '$').toJSON();
        assert.match(json.footer.text, /music commands loaded/);
        assert.match(json.description, /\$play/);
        assert.match(json.description, /\$247/);
    });
});

test('Lavalink nodes are registered even when music boots after clientReady', () => {
    // Shoukaku's connector only registers nodes from its own
    // `once('clientReady')` hook. A standby node that takes over, a reconnect
    // or a hot reload boots the subsystem *after* that event, so without the
    // explicit registration the node is never added and nothing can play.
    withLavalinkEnv(() => {
        const { initMusic } = require('../music');
        const client = makeClient();
        client.isReady = () => true;
        initMusic(client);

        const nodes = [...client.manager.shoukaku.nodes.values()];
        assert.strictEqual(nodes.length, 1, 'the configured node must be registered');
        assert.strictEqual(nodes[0].name, 'Lavalink');
    });
});

test('the node is registered exactly once when both boot paths run', () => {
    withLavalinkEnv(() => {
        const { initMusic } = require('../music');
        const client = makeClient();
        client.isReady = () => true;
        initMusic(client);

        const connector = client.manager.shoukaku.connector;
        // Simulate the connector's own clientReady hook firing afterwards.
        connector.ready([{ url: 'lavalink.example:2333', name: 'Lavalink', auth: 'test-auth', secure: false }]);

        assert.strictEqual(client.manager.shoukaku.nodes.size, 1, 'a second addNode would open a second socket');
    });
});

test("Shoukaku options use Shoukaku's units (seconds), not raw milliseconds", () => {
    const { resolveNodeOptions } = require('../music/config');
    const keys = ['LAVALINK_REST_TIMEOUT_MS', 'LAVALINK_RECONNECT_INTERVAL_MS', 'LAVALINK_VOICE_TIMEOUT_S'];
    const saved = {};
    for (const k of keys) saved[k] = process.env[k];
    process.env.LAVALINK_REST_TIMEOUT_MS = '10000';
    process.env.LAVALINK_RECONNECT_INTERVAL_MS = '5000';
    process.env.LAVALINK_VOICE_TIMEOUT_S = '20';
    try {
        const opts = resolveNodeOptions();
        // Shoukaku multiplies restTimeout by 1000 internally; passing 10000
        // would mean a ~2.8 hour REST timeout.
        assert.strictEqual(opts.restTimeout, 10);
        assert.strictEqual(opts.reconnectInterval, 5);
        assert.strictEqual(opts.voiceConnectionTimeout, 20);
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
});

test('a node that does not hold a guild never deletes that guild\'s 24/7 row', async () => {
    // PrimeBot runs several shard nodes against one database. Only the node
    // that actually has the guild cached can resolve its channels, so the
    // vendored `events/Node/ready.js` must skip (never delete) a row it cannot
    // see — otherwise every node restart wipes another node's sessions.
    const deleted = [];
    const dbPath = require.resolve('../music/schema/247');
    const readyPath = require.resolve('../music/events/Node/ready');
    const original = require.cache[dbPath];
    const originalReady = require.cache[readyPath];
    delete require.cache[readyPath];
    require.cache[dbPath] = {
        id: dbPath, filename: dbPath, loaded: true, exports: {
            find: async () => [
                { Guild: 'g-owned-by-another-node', TextId: 't1', VoiceId: 'v1', deleteOne: async () => deleted.push('foreign') },
            ],
        },
    };
    try {
        const event = require('../music/events/Node/ready');
        const created = [];
        const client = {
            guilds: { cache: new Map() },           // this node holds no guilds
            channels: { cache: new Map() },
            logger: { log() {} },
            manager: { createPlayer: async (o) => created.push(o) },
        };
        await event.run(client, 'Lavalink');
        assert.deepStrictEqual(deleted, [], 'a foreign guild\'s 24/7 row must be preserved');
        assert.deepStrictEqual(created, [], 'a foreign guild must not be joined');
    } finally {
        if (original) require.cache[dbPath] = original;
        else delete require.cache[dbPath];
        delete require.cache[readyPath];
        if (originalReady) require.cache[readyPath] = originalReady;
    }
});

test('a guild this node owns still has a stale 24/7 row pruned', async () => {
    const deleted = [];
    const dbPath = require.resolve('../music/schema/247');
    const readyPath = require.resolve('../music/events/Node/ready');
    const original = require.cache[dbPath];
    const originalReady = require.cache[readyPath];
    delete require.cache[readyPath];
    require.cache[dbPath] = {
        id: dbPath, filename: dbPath, loaded: true, exports: {
            find: async () => [
                { Guild: 'g1', TextId: 'gone', VoiceId: 'gone', deleteOne: async () => deleted.push('stale') },
            ],
        },
    };
    try {
        const event = require('../music/events/Node/ready');
        const client = {
            guilds: { cache: new Map([['g1', { id: 'g1', channels: { cache: new Map() } }]]) },
            channels: { cache: new Map() },
            logger: { log() {} },
            manager: { createPlayer: async () => { throw new Error('must not join a deleted channel'); } },
        };
        await event.run(client, 'Lavalink');
        assert.deepStrictEqual(deleted, ['stale'], 'an owned guild with deleted channels is pruned');
    } finally {
        if (original) require.cache[dbPath] = original;
        else delete require.cache[dbPath];
        delete require.cache[readyPath];
        if (originalReady) require.cache[readyPath] = originalReady;
    }
});
