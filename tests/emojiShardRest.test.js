// Custom emojis on a shard node that does NOT own the emoji guilds.
//
// The emoji guilds live on ONE shard, so on the other nodes the gateway never
// delivers them: discord.js marks the guild unavailable (`guild_temporarily_
// unavailable`) and every custom emoji fell back to Unicode. REST is
// shard-independent, so the manager now reads the guild there.
//
// The client is stubbed (no network): `guilds.cache` is empty, `guilds.fetch`
// reports an unavailable guild, and `rest.get` serves the three endpoints.

const test = require('node:test');
const assert = require('node:assert/strict');

const { EmojiManager } = require('../utils/emojiManager');

const GUILD = '1190256755096158208';
const SILENT = { log() {}, warn() {}, error() {} };

function offShardClient({ failRest = false, unavailableGuild = true } = {}) {
    const calls = [];
    return {
        calls,
        guilds: {
            cache: new Map(),
            fetch: async () => (unavailableGuild ? { id: GUILD, available: false } : null),
        },
        application: null,
        rest: {
            get: async (route, opts) => {
                calls.push(route);
                if (failRest) throw new Error('ECONNRESET');
                if (route === `/guilds/${GUILD}/emojis`) {
                    return {
                        items: [
                            { id: '1201841280577970176', name: 'prc', animated: true, available: true },
                            { id: '1201841280577970177', name: 'crc', animated: false, available: true },
                            { id: '1201841280577970178', name: 'clc', animated: false, available: true },
                            { id: '1201841280577970179', name: 'gone', animated: false, available: false },
                        ],
                    };
                }
                if (route === `/guilds/${GUILD}/channels`) {
                    return [
                        { id: '1476413583263924247', name: 'emoji list', type: 0 },
                        { id: '1476413583263924248', name: 'general', type: 0 },
                    ];
                }
                if (route === '/channels/1476413583263924247/messages') {
                    assert.ok(opts && opts.query, 'messages are paged');
                    // Real API: `before` walks back through history and then
                    // returns an empty page.
                    if (opts.query.get('before')) return [];
                    return [
                        // Aliases must reference ids that exist in the guild
                        // (the manager validates every candidate against it).
                        { id: '1', content: 'online : <a:prc:1201841280577970176>' },
                        { id: '2', content: 'idle : <:crc:1201841280577970177>' },
                    ];
                }
                return [];
            },
        },
    };
}

test('an off-shard node resolves the emoji catalog over REST', async () => {
    const client = offShardClient();
    const manager = new EmojiManager({ client, guildIds: [GUILD], logger: SILENT });
    await manager.start(client);

    const report = manager.report();
    assert.equal(report.guilds.length, 1);
    assert.equal(report.guilds[0].ok, true);
    assert.equal(report.guilds[0].source, 'rest', 'read over REST, not the gateway');
    assert.equal(report.guilds[0].emojiCount, 3);
    assert.equal(report.guilds[0].channelFound, true);
    // Two lines, each yielding the bare token AND its `label :` alias.
    assert.equal(report.guilds[0].discoveredCount, 4, 'emoji-list aliases parsed over REST');

    assert.equal(manager.emoji('prc', 'X'), '<a:prc:1201841280577970176>');
    assert.equal(manager.emoji('crc', 'X'), '<:crc:1201841280577970177>');
    assert.equal(manager.emoji('clc', 'X'), '<:clc:1201841280577970178>');
    // Aliases from the `emoji list` channel.
    assert.equal(manager.emoji('online', 'X'), '<a:prc:1201841280577970176>');
    assert.equal(manager.emoji('idle', 'X'), '<:crc:1201841280577970177>');
    // `available: false` is never usable, and unknown keys fall back.
    assert.equal(manager.emoji('gone', 'FALLBACK'), 'FALLBACK');
    assert.equal(manager.emoji('nope', 'FALLBACK'), 'FALLBACK');

    assert.ok(client.calls.includes(`/guilds/${GUILD}/emojis`));
    assert.ok(client.calls.includes(`/guilds/${GUILD}/channels`));
});

test('a REST failure degrades to Unicode instead of throwing', async () => {
    const client = offShardClient({ failRest: true });
    const manager = new EmojiManager({ client, guildIds: [GUILD], logger: SILENT });
    await manager.start(client);

    const report = manager.report();
    assert.equal(report.guilds[0].ok, false);
    assert.match(String(report.guilds[0].error), /rest_emoji_fetch_failed/);
    assert.equal(manager.emoji('prc', '🔄'), '🔄');
});

test('an owning node keeps using the gateway (no REST calls)', async () => {
    const collection = new Map([
        ['1201841280577970176', { id: '1201841280577970176', name: 'prc', animated: true, available: true }],
    ]);
    const guild = {
        id: GUILD,
        available: true,
        emojis: { cache: collection, fetch: async () => collection },
        channels: { cache: new Map(), fetch: async () => new Map() },
    };
    const client = {
        guilds: { cache: new Map([[GUILD, guild]]), fetch: async () => guild },
        application: null,
        rest: { get: async () => { throw new Error('REST must not be used here'); } },
    };
    const manager = new EmojiManager({ client, guildIds: [GUILD], logger: SILENT });
    await manager.start(client);

    assert.equal(manager.emoji('prc', 'X'), '<a:prc:1201841280577970176>');
    assert.notEqual(manager.report().guilds[0].source, 'rest');
});

test('every node ends up with the same catalog', async () => {
    const owner = (() => {
        const collection = new Map([
            ['1201841280577970176', { id: '1201841280577970176', name: 'prc', animated: true, available: true }],
            ['1201841280577970177', { id: '1201841280577970177', name: 'crc', animated: false, available: true }],
        ]);
        const guild = {
            id: GUILD, available: true,
            emojis: { cache: collection, fetch: async () => collection },
            channels: { cache: new Map(), fetch: async () => new Map() },
        };
        return { guilds: { cache: new Map([[GUILD, guild]]), fetch: async () => guild }, application: null };
    })();

    const ownerManager = new EmojiManager({ client: owner, guildIds: [GUILD], logger: SILENT });
    await ownerManager.start(owner);

    const offShard = offShardClient();
    const offManager = new EmojiManager({ client: offShard, guildIds: [GUILD], logger: SILENT });
    await offManager.start(offShard);

    // The ids both nodes resolve must be identical — that is what makes a
    // message rendered on sn1 look the same as one rendered on sn3.
    for (const key of ['prc', 'crc']) {
        assert.equal(offManager.emoji(key, 'X'), ownerManager.emoji(key, 'X'), key);
    }
});
