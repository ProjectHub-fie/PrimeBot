/**
 * Env-driven music config + the removal of Linix hardcoded values.
 *
 * Covers: resolveEmoji (Unicode defaults + MUSIC_EMOJI_<KEY> overrides + the
 * keys the vendored code reads actually resolve), the node URL scheme
 * unwrapping (a wss:// NODE_URL must become host:port + secure), the
 * `$playlist` demo menu config, the card/owner/branding env keys, and a
 * static audit that no Linix custom-emoji ids, owner id, Discord CDN asset
 * URLs or Arrkiii branding survive in the vendored tree.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const MUSIC = path.join(ROOT, 'music');

const { getMusicConfig, resolveEmoji, resolveNodes, resolveNodeUrl } = require(path.join(MUSIC, 'config'));
const { resolvePerms } = require(path.join(MUSIC, 'utils', 'perms'));

const SAVED_MUSIC_ENV = [
    'MUSIC_EMOJI_DOT', 'MUSIC_EMOJI_PLAY', 'MUSIC_EMOJI_PAUSE', 'MUSIC_EMOJI_SKIP',
    'MUSIC_EMOJI_STOP', 'MUSIC_EMOJI_LOOP', 'MUSIC_EMOJI_SHUFFLE', 'MUSIC_EMOJI_RESUME',
    'MUSIC_EMOJI_MUSIC', 'MUSIC_EMOJI_QUEUE', 'MUSIC_EMOJI_VOLUMEHIGH', 'MUSIC_EMOJI_TICK',
    'MUSIC_EMOJI_CROSS', 'MUSIC_EMOJI_PLAYING', 'MUSIC_EMOJI_LEFT', 'MUSIC_EMOJI_RIGHT',
    'MUSIC_EMOJI_DELETE', 'MUSIC_EMOJI_REPLAY', 'MUSIC_EMOJI_FILTER', 'MUSIC_EMOJI_ADDSONG',
    'MUSIC_EMOJI_PLAYLIST', 'MUSIC_EMOJI_AUTOPLAY', 'MUSIC_EMOJI_JOIN', 'MUSIC_EMOJI_LEAVE',
    'MUSIC_EMOJI_REMOVE', 'MUSIC_EMOJI_FORWARD', 'MUSIC_EMOJI_REWIND', 'MUSIC_EMOJI_JUMP',
    'MUSIC_EMOJI_PREVIOUS', 'MUSIC_EMOJI_WARN', 'MUSIC_EMOJI_ABOUT',
    'MUSIC_POWERED_BY', 'MUSIC_CARD_IMAGE', 'MUSIC_CARD_NAME', 'MUSIC_SUPPORT_URL',
    'MUSIC_OWNER_ID', 'MUSIC_PLAYLISTS', 'MUSIC_PLAYLIST_LABEL', 'MUSIC_PLAYLIST_URL',
    'MUSIC_PLAYLIST_MENU_LABEL', 'NODE_URL', 'NODE_PORT', 'NODE_AUTH', 'NODE_NAME', 'NODE_SECURE',
];

function withEnv(env, fn) {
    const saved = {};
    for (const k of new Set([...SAVED_MUSIC_ENV, ...Object.keys(env)])) saved[k] = process.env[k];
    for (const k of Object.keys(env)) process.env[k] = env[k];
    try {
        return fn();
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
}

test('emoji map defaults to Unicode and every key the vendored code reads resolves', () => {
    withEnv({}, () => {
        const emoji = resolveEmoji();

        // Linix's custom emoji id must NOT be the default.
        assert.notStrictEqual(emoji.dot, '<:dot:1201841280577970176>');
        assert.ok(emoji.dot.length >= 1);

        for (const key of [
            'play', 'pause', 'skip', 'stop', 'loop', 'shuffle', 'resume', 'music',
            'queue', 'volumehigh', 'tick', 'cross', 'dot', 'playing', 'left', 'right',
            'delete', 'replay', 'filter', 'addsong', 'playlist', 'autoplay', 'join',
            'leave', 'remove', 'forward', 'rewind', 'jump', 'previous', 'warn', 'about',
        ]) {
            assert.ok(emoji[key] && String(emoji[key]).length >= 1, `emoji.${key} must resolve`);
        }

        // The JSON reference stays in sync with the resolver defaults.
        const json = require(path.join(MUSIC, 'utils', 'emoji.json'));
        for (const key of Object.keys(json)) {
            assert.strictEqual(emoji[key], json[key], `emoji.${key} default must match emoji.json`);
        }
    });
});

test('every client.emoji.<key> used by vendored code resolves from the env map', () => {
    const used = new Set();
    const walk = (dir) => {
        for (const f of fs.readdirSync(dir)) {
            const p = path.join(dir, f);
            const s = fs.statSync(p);
            if (s.isDirectory()) walk(p);
            else if (f.endsWith('.js')) {
                const t = fs.readFileSync(p, 'utf8');
                for (const m of t.matchAll(/client\.emoji\.([a-zA-Z_]+)/g)) used.add(m[1]);
            }
        }
    };
    walk(MUSIC);

    const emoji = resolveEmoji();
    const missing = [...used].filter((k) => !(k in emoji));
    assert.deepStrictEqual(missing, []);
});

test('MUSIC_EMOJI_<KEY> overrides the Unicode default', () => {
    withEnv({ MUSIC_EMOJI_DOT: '<a:dot:999999999999999999>', MUSIC_EMOJI_PLAY: '🎧' }, () => {
        const emoji = resolveEmoji();
        assert.strictEqual(emoji.dot, '<a:dot:999999999999999999>');
        assert.strictEqual(emoji.play, '🎧');
    });
});

test('NODE_URL scheme is unwrapped: wss://host:443 -> host:443 + secure', () => {
    withEnv(
        { NODE_URL: 'wss://lava.example.com:443', NODE_AUTH: 'pw', NODE_SECURE: '' },
        () => {
            const nodes = resolveNodes();
            assert.strictEqual(nodes.length, 1);
            assert.strictEqual(nodes[0].url, 'lava.example.com:443');
            assert.strictEqual(nodes[0].secure, true);
        },
    );
});

test('NODE_URL with an explicit ws:// scheme forces secure=false', () => {
    withEnv({ NODE_URL: 'ws://lava.example.com:2333', NODE_AUTH: 'pw', NODE_SECURE: 'true' }, () => {
        const nodes = resolveNodes();
        assert.strictEqual(nodes[0].url, 'lava.example.com:2333');
        // explicit scheme wins over the NODE_SECURE env value
        assert.strictEqual(nodes[0].secure, false);
    });
});

test('no Lavalink node is configured when NODE_URL and LAVALINK_NODES are unset', () => {
    withEnv({ NODE_URL: '', LAVALINK_NODES: '' }, () => {
        assert.deepStrictEqual(resolveNodes(), []);
    });
});

test('NODE_PORT is honoured for a bare NODE_URL host (CloudeWave config)', () => {
    withEnv(
        {
            NODE_URL: 'lavalink.cloudewave.in',
            NODE_PORT: '2336',
            NODE_AUTH: 'cloudewave.in',
            NODE_NAME: 'CloudeWave',
            NODE_SECURE: 'false',
        },
        () => {
            assert.strictEqual(resolveNodeUrl(), 'lavalink.cloudewave.in:2336');
            const nodes = resolveNodes();
            assert.strictEqual(nodes.length, 1);
            assert.strictEqual(nodes[0].url, 'lavalink.cloudewave.in:2336');
            assert.strictEqual(nodes[0].auth, 'cloudewave.in');
            assert.strictEqual(nodes[0].name, 'CloudeWave');
            assert.strictEqual(nodes[0].secure, false);
        },
    );
});

test('real Lavalink connection string for CloudeWave (ws + plaintext) is used by Shoukaku', () => {
    withEnv(
        {
            NODE_URL: 'lavalink.cloudewave.in',
            NODE_PORT: '2336',
            NODE_AUTH: 'cloudewave.in',
            NODE_SECURE: 'false',
        },
        () => {
            const node = resolveNodes()[0];
            // Shoukaku builds ws://<url>/v4/websocket when secure=false
            assert.strictEqual(`${node.secure ? 'wss' : 'ws'}://${node.url}/v4/websocket`,
                'ws://lavalink.cloudewave.in:2336/v4/websocket');
        },
    );
});

test('NODE_URL scheme forms still win over NODE_PORT for a full URL', () => {
    withEnv({ NODE_URL: 'wss://lava.example.com:443', NODE_PORT: '9999', NODE_AUTH: 'pw' }, () => {
        assert.strictEqual(resolveNodeUrl(), 'wss://lava.example.com:443');
        const nodes = resolveNodes();
        assert.strictEqual(nodes[0].url, 'lava.example.com:443');
        assert.strictEqual(nodes[0].secure, true);
    });
});

test('resolvePerms accepts Linix SCREAMING_SNAKE names without throwing', () => {
    // `EMBED_LINKS` is what every Linix music command declares as botPrams;
    // the installed discord.js resolves camelCase only, and the old
    // PermissionsBitField.resolve(['EMBED_LINKS']) threw BitFieldInvalid.
    assert.strictEqual(resolvePerms(['EMBED_LINKS']).toString(), '16384'); // EmbedLinks
    assert.strictEqual(resolvePerms(['CONNECT', 'SPEAK']).toString(), '3145728');
    assert.strictEqual(resolvePerms(['EmbedLinks']).toString(), '16384');
    // Unknown names are dropped silently; never throws.
    assert.strictEqual(resolvePerms(['NOT_A_FLAG', 'EMBED_LINKS']).toString(), '16384');
    assert.strictEqual(resolvePerms([]).toString(), '0');
    assert.strictEqual(resolvePerms(undefined).toString(), '0');
});

test('$playlist demo menu is disabled when nothing is configured', () => {
    withEnv({ MUSIC_PLAYLISTS: '', MUSIC_PLAYLIST_URL: '' }, () => {
        const cfg = getMusicConfig();
        assert.strictEqual(cfg.playlistMenu.enabled, false);
        assert.deepStrictEqual(cfg.playlistMenu.entries, []);
    });
});

test('$playlist demo menu supports the single-entry env form', () => {
    withEnv(
        {
            MUSIC_PLAYLIST_URL: 'https://open.spotify.com/playlist/abc',
            MUSIC_PLAYLIST_LABEL: 'PrimeBot Mix',
            MUSIC_PLAYLIST_MENU_LABEL: 'PrimeBot Quick Playlists',
        },
        () => {
            const cfg = getMusicConfig();
            assert.strictEqual(cfg.playlistMenu.enabled, true);
            assert.strictEqual(cfg.playlistMenu.label, 'PrimeBot Quick Playlists');
            assert.strictEqual(cfg.playlistMenu.entries.length, 1);
            assert.strictEqual(cfg.playlistMenu.entries[0].query, 'https://open.spotify.com/playlist/abc');
            assert.strictEqual(cfg.playlistMenu.entries[0].label, 'PrimeBot Mix');
        },
    );
});

test('$playlist demo menu supports the JSON multi-entry env form and drops malformed rows', () => {
    withEnv(
        {
            MUSIC_PLAYLISTS: JSON.stringify([
                { id: 'a1', label: 'One', query: 'https://x/one' },
                { id: 'b2', label: 'Two', query: 'https://x/two' },
                { label: 'broken (no id)' },
            ]),
        },
        () => {
            const cfg = getMusicConfig();
            assert.strictEqual(cfg.playlistMenu.entries.length, 2);
            assert.deepStrictEqual(cfg.playlistMenu.entries.map((e) => e.id), ['a1', 'b2']);
        },
    );
});

test('branding config is env-driven and defaulted', () => {
    const cfg = getMusicConfig();
    assert.strictEqual(cfg.embedColor, require(path.join(ROOT, 'config')).colors.primary);
    assert.strictEqual(cfg.links.power, 'PrimeBot');
    assert.ok(typeof cfg.cardName === 'string' && cfg.cardName.length > 0);
    assert.strictEqual(cfg.links.support, require(path.join(ROOT, 'config')).supportServer);
    assert.strictEqual(cfg.ownerId, '');
});

test('branding config picks up env overrides', () => {
    withEnv(
        {
            MUSIC_POWERED_BY: 'Powered by PrimeBot',
            MUSIC_CARD_NAME: 'pb.png',
            MUSIC_CARD_IMAGE: 'https://example.com/bg.png',
            MUSIC_SUPPORT_URL: 'https://discord.gg/support',
            MUSIC_OWNER_ID: '123456789012345678',
        },
        () => {
            const cfg = getMusicConfig();
            assert.strictEqual(cfg.links.power, 'Powered by PrimeBot');
            assert.strictEqual(cfg.cardName, 'pb.png');
            assert.strictEqual(cfg.links.image, 'https://example.com/bg.png');
            assert.strictEqual(cfg.links.support, 'https://discord.gg/support');
            assert.strictEqual(cfg.ownerId, '123456789012345678');
        },
    );
});

test('no Linix custom-emoji ids, owner id, CDN asset URLs or Arrkiii branding survive in the vendored tree', () => {
    const forbidden = [
        '1029065620878282792', // Linix bot owner id (hardcoded user fetch)
        ':dot:1201841280577970176',
        ':playing:1188088755819663400',
        ':RedDot:1127603979824672789',
        ':volumehigh:1188203004646666320',
        ':left:1127618224595406929',
        ':right:1127618208510255165',
        ':del:1188108090499923999',
        '1187323477032697867', // Linix CDN channel holding its asset PNGs/GIFs
        'cdn.discordapp.com/attachments',
        'top.gg/bot',
        'arrkiii.png',
        'Some Qt Playlists By Arrkiii',
        'Arrkiii By Ozuma xd',
    ];

    const walk = (dir, hits) => {
        for (const f of fs.readdirSync(dir)) {
            const p = path.join(dir, f);
            const s = fs.statSync(p);
            if (s.isDirectory()) walk(p, hits);
            else if (f.endsWith('.js') || f.endsWith('.json')) {
                const t = fs.readFileSync(p, 'utf8');
                for (const token of forbidden) {
                    // allow explanatory comments/documented history
                    const codeOnly = t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
                    if (codeOnly.includes(token)) hits.push(`${p} :: ${token}`);
                }
            }
        }
    };
    const hits = [];
    walk(path.join(MUSIC, 'commands'), hits);
    walk(path.join(MUSIC, 'slashCommands'), hits);
    walk(path.join(MUSIC, 'events'), hits);
    walk(path.join(MUSIC, 'utils'), hits);
    walk(path.join(MUSIC, 'loaders'), hits);
    walk(path.join(MUSIC, 'schema'), hits);
    walk(path.join(MUSIC, 'custom'), hits);
    assert.deepStrictEqual(hits, []);
});

test('no native `canvas` / `canvafy` in the runtime dependencies (Vercel build regression)', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    const lock = JSON.parse(fs.readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));

    // `canvafy` is the only vendored card package that hard-depends on the
    // native `canvas` module (Cairo/Pixman source compile) which Vercel's
    // Node 24 cannot build. The now-playing Spotify card must stay on
    // canvacard (prebuilt @napi-rs/canvas).
    assert.ok(!pkg.dependencies.canvafy, 'package.json must not list canvafy');
    assert.ok(!lock.packages['node_modules/canvafy'], 'package-lock must not contain canvafy');
    assert.ok(!lock.packages['node_modules/canvas'], 'package-lock must not contain the native canvas package');

    // Every card package that IS shipped must rely on prebuilt @napi-rs/canvas,
    // never the native `canvas` (regular, non-optional) dependency.
    for (const name of ['canvacard', 'musicard', 'musicard-quartz', 'songcard']) {
        const entry = lock.packages[`node_modules/${name}`];
        assert.ok(entry, `lock must contain ${name}`);
        const deps = entry.dependencies || {};
        assert.ok(!deps.canvas || deps.canvas.__resolved === undefined,
            `${name} must not hard-depend on native canvas`);
    }

    // spotifyCard.js uses canvacard (never requires canvafy).
    const spotifyCard = fs.readFileSync(path.join(MUSIC, 'utils', 'spotifyCard.js'), 'utf8');
    assert.ok(spotifyCard.includes("require('canvacard')"));
    assert.ok(!spotifyCard.includes("require('canvafy')"));
});