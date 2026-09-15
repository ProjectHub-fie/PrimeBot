// $embed / /embed — sending a dashboard-saved embed into a channel.
//
// The slash command module and the prefix switch both run over the real code
// paths with a stubbed saved-embed store (no Postgres in CI). The page + help +
// docs surfaces are asserted against the real render/search sources.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const SAVED = {
    id: 7,
    guildId: '1',
    name: 'Rules',
    payload: {
        content: 'Please read',
        title: 'Server Rules',
        description: 'Be nice.',
        color: '#5865F2',
        timestamp: false,
        authorEnabled: false, authorName: '', authorUrl: '', authorIcon: '',
        thumbnailEnabled: false, thumbnailUrl: '',
        imageEnabled: false, imageUrl: '',
        footerEnabled: true, footerText: 'PrimeBot', footerIcon: '',
        fields: [{ name: 'Rule 1', value: 'Be respectful', inline: true }],
    },
};

// ── store (DB stubbed, real mapping logic) ───────────────────────────────
test('savedEmbedStore maps rows and matches by name (case-insensitive) or id', async () => {
    const storePath = path.join(ROOT, 'utils', 'savedEmbedStore.js');
    delete require.cache[require.resolve(storePath)];

    const embedDbPath = path.join(ROOT, 'server', 'embedDb.js');
    const realEmbedDb = require(embedDbPath);
    const rows = [{
        id: 7, guild_id: '1', name: 'Rules',
        payload: SAVED.payload,
    }, {
        id: 8, guild_id: '1', name: 'Welcome',
        payload: '{"title":"Hi"}', // a JSON *string* payload (legacy row)
    }];
    realEmbedDb.embedPool.query = async () => ({ rows });
    delete require.cache[require.resolve(storePath)];

    const store = require(storePath);
    const list = await store.listSavedEmbeds('1');
    assert.equal(list.length, 2);
    assert.deepEqual(list[0], { id: 7, guildId: '1', name: 'Rules', payload: SAVED.payload });
    assert.deepEqual(list[1].payload, { title: 'Hi' }, 'JSON string payload parsed');

    assert.equal((await store.findSavedEmbed('1', 'rules')).name, 'Rules', 'case-insensitive by name');
    assert.equal((await store.findSavedEmbed('1', '8')).name, 'Welcome', 'by numeric id');
    assert.equal(await store.findSavedEmbed('1', 'nope'), null);
    assert.equal(await store.findSavedEmbed('1', ''), null);
});

test('savedEmbedNames returns autocomplete choices and hides store errors', async () => {
    const embedDbPath = path.join(ROOT, 'server', 'embedDb.js');
    const storePath = path.join(ROOT, 'utils', 'savedEmbedStore.js');
    const realEmbedDb = require(embedDbPath);
    realEmbedDb.embedPool.query = async () => ({ rows: [{ id: 7, guild_id: '1', name: 'Rules', payload: '{}' }] });

    delete require.cache[require.resolve(storePath)];
    const store = require(storePath);
    assert.deepEqual(await store.savedEmbedNames('1', 'rul'), [{ name: 'Rules', value: '7' }]);
    assert.deepEqual(await store.savedEmbedNames('1', 'zzz'), []);

    realEmbedDb.embedPool.query = async () => { throw new Error('db down'); };
    assert.deepEqual(await store.savedEmbedNames('1', ''), [], 'degrades to [] instead of throwing');
});

//  /embed slash command ─────────────────────────────────────────────────
const STORE_PATH = require.resolve('../utils/savedEmbedStore');
const ORIGINAL_STORE = require(STORE_PATH);

function stubStore(overrides = {}) {
    require.cache[STORE_PATH] = {
        id: STORE_PATH, filename: STORE_PATH, loaded: true,
        exports: {
            listSavedEmbeds: async () => [SAVED],
            findSavedEmbed: async (_g, q) => (String(q).toLowerCase() === 'rules' ? SAVED : null),
            savedEmbedNames: async () => [{ name: 'Rules', value: '7' }],
            ...overrides,
        },
    };
    return () => { require.cache[STORE_PATH] = { id: STORE_PATH, filename: STORE_PATH, loaded: true, exports: ORIGINAL_STORE }; };
}

// The command must be re-required AFTER the store stub is installed so it
// picks up the stubbed exports (the store is resolved at require time).
function loadCommand() {
    delete require.cache[require.resolve('../commands/embed')];
    return require('../commands/embed');
}

function interactionStub({ sub = 'send', embed = 'Rules', channel = null, perms = true } = {}) {
    const sent = [];
    const replies = [];
    const target = channel || {
        id: '55', type: 0,
        permissionsFor: () => ({
            has: (flag) => perms,
        }),
        send: async (payload) => { sent.push(payload); return { id: '99', url: 'https://discord.com/x/99' }; },
    };
    return {
        _sent: sent, _replies: replies,
        guildId: '1',
        // The command falls back to interaction.channel when no channel option
        // is given, so it must be the same target we assert against.
        channel: target,
        guild: { members: { me: { id: 'bot' } } },
        memberPermissions: { has: () => true },
        options: {
            getSubcommand: () => sub,
            getString: () => embed,
            getChannel: () => channel,
            getFocused: () => '',
        },
        reply: async (p) => { replies.push(p); return p; },
        deferReply: async (p) => { replies.push({ deferred: true, ...p }); },
        editReply: async (p) => { replies.push(p); return p; },
        respond: async (p) => { replies.push(p); return p; },
    };
}

test('/embed is a slash command with send + list subcommands', () => {
    const restore = stubStore();
    const cmd = loadCommand();
    const json = cmd.data.toJSON();
    assert.equal(json.name, 'embed');
    assert.deepEqual(json.options.map(o => o.name), ['send', 'list']);
    const send = json.options[0].options;
    assert.deepEqual(send.map(o => o.name), ['embed', 'channel']);
    assert.equal(send[0].required, true);
    assert.equal(send[0].autocomplete, true);
    assert.equal(send[1].required, false);
    restore();
});

test('/embed send posts the saved embed payload to the target channel', async () => {
    const restore = stubStore();
    const cmd = loadCommand();
    const i = interactionStub();
    await cmd.execute(i);
    assert.equal(i._sent.length, 1, 'posted once');
    assert.equal(i._sent[0].content, 'Please read');
    assert.equal(i._sent[0].embeds[0].title, 'Server Rules');
    assert.equal(i._sent[0].embeds[0].color, 0x5865f2);
    assert.equal(i._sent[0].embeds[0].fields[0].name, 'Rule 1');
    assert.match(JSON.stringify(i._replies), /Embed sent/);
    restore();
});

test('/embed send errors clearly for an unknown embed', async () => {
    const restore = stubStore({ findSavedEmbed: async () => null });
    const cmd = loadCommand();
    const i = interactionStub({ embed: 'Ghost' });
    await cmd.execute(i);
    assert.equal(i._sent.length, 0, 'nothing posted');
    assert.match(JSON.stringify(i._replies), /No saved embed named/);
    restore();
});

test('/embed send refuses when the member lacks Manage Server', async () => {
    const restore = stubStore();
    const cmd = loadCommand();
    const i = interactionStub();
    i.memberPermissions = { has: () => false };
    await cmd.execute(i);
    assert.equal(i._sent.length, 0);
    assert.match(JSON.stringify(i._replies), /Manage Server/);
    restore();
});

test('/embed send refuses when the bot cannot embed in the target channel', async () => {
    const restore = stubStore();
    const cmd = loadCommand();
    const i = interactionStub({ perms: false });
    await cmd.execute(i);
    assert.equal(i._sent.length, 0);
    assert.match(JSON.stringify(i._replies), /Send Messages.*Embed Links/);
    restore();
});

test('/embed send reports an empty saved embed instead of posting nothing', async () => {
    const restore = stubStore({ findSavedEmbed: async () => ({ ...SAVED, payload: {} }) });
    const cmd = loadCommand();
    const i = interactionStub();
    await cmd.execute(i);
    assert.equal(i._sent.length, 0);
    assert.match(JSON.stringify(i._replies), /no content to send/i);
    restore();
});

test('/embed list shows saved embeds, and a friendly empty state', async () => {
    const restore = stubStore();
    const cmd = loadCommand();
    const i = interactionStub({ sub: 'list' });
    await cmd.execute(i);
    assert.match(JSON.stringify(i._replies), /Saved embeds/);
    assert.match(JSON.stringify(i._replies), /Rules/);
    restore();

    const restore2 = stubStore({ listSavedEmbeds: async () => [] });
    const cmd2 = loadCommand();
    const i2 = interactionStub({ sub: 'list' });
    await cmd2.execute(i2);
    assert.match(JSON.stringify(i2._replies), /No saved embeds/);
    restore2();
});

test('/embed autocomplete responds with saved-embed choices', async () => {
    const restore = stubStore();
    const cmd = loadCommand();
    const i = interactionStub();
    await cmd.autocomplete(i);
    assert.deepEqual(i._replies[0], [{ name: 'Rules', value: '7' }]);
    restore();
});

// ── prefix $embed command ────────────────────────────────────────────────
const messageCreateSrc = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');

test('prefix $embed is wired into the command switch with send/list/help', () => {
    assert.match(messageCreateSrc, /case "embed": \{/);
    assert.match(messageCreateSrc, /embedSub === "list"/);
    assert.match(messageCreateSrc, /embedSub !== "send"/);
    assert.match(messageCreateSrc, /embedUsageEmbed\(prefix\)/);
    assert.match(messageCreateSrc, /embedChannelMention\(message, embedArgs\)/);
    assert.match(messageCreateSrc, /toMessagePayload\(record\.payload\)/);
    assert.match(messageCreateSrc, /findSavedEmbed\(message\.guild\.id, embedQuery\)/);
});

test('prefix $embed reuses the same payload + permission guards as the slash command', () => {
    // Same converter, same Manage Server guard, same channel-permission check.
    assert.match(messageCreateSrc, /require\("\.\.\/shared\/embedPayload"\)/);
    assert.match(messageCreateSrc, /ManageGuild\)\) \{\s*return message\.reply\("You need the \*\*Manage Server\*\*/);
    assert.match(messageCreateSrc, /EmbedLinks\)\)\) \{\s*return message\.reply\(`I need \*\*Send Messages\*\* and \*\*Embed Links\*\*/);
    // A failure building the confirmation must not be reported as a send failure.
    assert.match(messageCreateSrc, /embedSent = await targetChannel\.send\(embedPayload\)/);
    assert.match(messageCreateSrc, /Sent, but the confirmation failed/);
});

// ─ prefix $embed end-to-end through the real messageCreate handler ──────
function runPrefix(content, { mentionsChannel = null, memberPerms = true, channelPerms = true, store } = {}) {
    global.botActive = true;
    // Always stub the store: these tests exercise the command wiring, not the DB.
    stubStore(store || {});
    const mcPath = require.resolve('../events/messageCreate');
    delete require.cache[mcPath];
    const mc = require(mcPath);

    const posted = [];
    const target = {
        id: '55', isTextBased: () => true,
        permissionsFor: () => ({ has: () => channelPerms }),
        send: async (p) => { posted.push(p); return { id: '99', url: 'https://discord.com/ch/1/99' }; },
    };
    const replies = [];
    const message = {
        content,
        guild: {
            id: '1',
            members: { me: { id: 'bot' } },
            channels: { cache: { get: () => target }, fetch: async () => target },
        },
        channel: target,
        member: { permissions: { has: () => memberPerms } },
        reply: async (p) => { replies.push(p); return { delete: async () => {} }; },
        author: { id: 'u', tag: 'u#0001', bot: false },
        mentions: { channels: { first: () => mentionsChannel } },
    };
    const client = { user: { id: 'bot', displayAvatarURL: () => '' }, commands: new Map() };
    return mc.execute(message, client).then(() => ({ posted, replies }));
}

test('prefix $embed send posts the saved embed through the real message handler', async () => {
    const r = await runPrefix('$embed send Rules');
    assert.equal(r.posted.length, 1, 'posted once');
    assert.equal(r.posted[0].embeds[0].title, 'Server Rules');
    assert.equal(r.posted[0].embeds[0].color, 0x5865f2);
    assert.match(JSON.stringify(r.replies), /Posted \*\*Rules\*\*/);
});

test('prefix $embed send routes to an explicit #channel mention', async () => {
    const r = await runPrefix('$embed send Rules <#55>');
    assert.equal(r.posted.length, 1);
    assert.match(JSON.stringify(r.replies), /<#55>/);
});

test('prefix $embed send reports an unknown embed without posting', async () => {
    const r = await runPrefix('$embed send Ghost');
    assert.equal(r.posted.length, 0);
    assert.match(JSON.stringify(r.replies), /Embed not found|No saved embed named/);
});

test('prefix $embed list shows the saved embeds', async () => {
    const r = await runPrefix('$embed list');
    assert.equal(r.posted.length, 0);
    assert.match(JSON.stringify(r.replies), /Saved embeds/);
    assert.match(JSON.stringify(r.replies), /Rules/);
});

test('prefix $embed without a subcommand shows usage (and posts nothing)', async () => {
    const r = await runPrefix('$embed');
    assert.equal(r.posted.length, 0);
    assert.match(JSON.stringify(r.replies), /\$embed send/);
});

test('prefix $embed send refuses without Manage Server', async () => {
    const r = await runPrefix('$embed send Rules', { memberPerms: false });
    assert.equal(r.posted.length, 0);
    assert.match(JSON.stringify(r.replies), /Manage Server/);
});

test('prefix $embed send refuses when the bot cannot embed in the channel', async () => {
    const r = await runPrefix('$embed send Rules', { channelPerms: false });
    assert.equal(r.posted.length, 0);
    assert.match(JSON.stringify(r.replies), /Send Messages.*Embed Links/);
});

test('prefix $embed send reports a database failure instead of crashing', async () => {
    const r = await runPrefix('$embed send Rules', {
        store: { findSavedEmbed: async () => { throw new Error('db down'); } },
    });
    assert.equal(r.posted.length, 0);
    assert.match(JSON.stringify(r.replies), /could not load the saved embeds/i);
});

// ── help menus ───────────────────────────────────────────────────────────
test('slash help menu lists /embed under the Administration category', () => {
    const helpSrc = fs.readFileSync(path.join(ROOT, 'commands', 'help.js'), 'utf8');
    const adminBlock = helpSrc.split("case 'admin':")[1];
    assert.match(adminBlock, /\/embed send/);
    assert.match(adminBlock, /\/embed list/);
});

test('prefix help catalog lists $embed under Administration', () => {
    const { CATALOG } = require('../utils/prefixHelp');
    const admin = CATALOG.admin;
    assert.ok(admin, 'Administration category exists');
    const embed = admin.commands.find(c => c.names.includes('embed'));
    assert.ok(embed, '$embed is in the Administration category');
    assert.match(embed.desc, /Embed Builder/);
    assert.equal(embed.args, '<send|list>');
});

test('sash help menu lists $embed under Administration', () => {
    const interactionSrc = fs.readFileSync(path.join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    const admin = interactionSrc.split('admin: {')[1];
    assert.match(admin, /\$\{prefix\}embed send/);
    assert.match(admin, /\$\{prefix\}embed list/);
});

// ── docs page ───────────────────────────────────────────────────────────
test('docs page includes the embed command with usage and a Configuration category', () => {
    const { buildCommandDocs, CATEGORIES } = require('../dashboard/commandDocs');
    const configCat = CATEGORIES.find(c => c.name === 'Configuration');
    assert.ok(configCat, 'Configuration category exists');

    const docs = buildCommandDocs();
    const cmd = docs.commands.find(c => c.name === 'embed');
    assert.ok(cmd, 'embed appears in the docs command list');
    assert.equal(cmd.category, 'Configuration');
    assert.match(cmd.description, /Embed Builder/);
    assert.deepEqual(cmd.usage, ['embed send <name|id> [#channel]', 'embed list']);
    assert.match(cmd.note, /\/embed send/);
});

test('the docs page renders the embed command with a searchable haystack', () => {
    const pages = require('../dashboard/render/pages');
    const html = pages.docsPage({ user: { username: 'u' } });
    assert.match(html, /embed send/);
    // The data-search haystack is what the client filters on.
    const card = html.split('doc-cmd').find(seg => seg.includes('>embed<')) || '';
    assert.match(html, /data-search="[^"]*embed send/);
    assert.match(html, /Embed Builder/);
    assert.ok(card !== undefined, 'the embed card is present');
});

// ── embed builder page hint (page-only, not in nav) ──────────────────────
test('embed builder page documents how to send a saved embed to a channel', () => {
    const gp = require('../dashboard/render/guild-pages');
    const guild = {
        id: '1', name: 'Test', icon: null, _beta: true, _bypassUpcoming: true,
        _channels: [], _roles: [],
        _config: { server: {}, welcome: {}, logging: {}, automod: {} },
    };
    const html = gp.embedPage({ guild, user: { username: 'u' } });
    assert.match(html, /embed-send-hint/, 'the hint block is rendered');
    assert.match(html, /\/embed send/);
    assert.match(html, /\$embed send/);
    assert.match(html, /\/embed list/);
    assert.match(html, /Manage Server/);
});

test('embed send hint is NOT a nav entry (stays on the page only)', () => {
    const guildJs = fs.readFileSync(path.join(ROOT, 'dashboard', 'render', 'guild.js'), 'utf8');
    const tabsBlock = guildJs.split('const TABS')[1].split('];')[0];
    assert.ok(!/send/i.test(tabsBlock), 'no "send" tab was added to the sidebar');
    assert.ok(!/how-to/i.test(tabsBlock), 'no how-to tab was added to the sidebar');
});

// ── "Premium features in free" badges ───────────────────────────────────
const BADGE = 'Premium features in free';

test('the Premium-features badge appears on live polls, live giveaways, role rewards and badges', () => {
    const gp = require('../dashboard/render/guild-pages');
    const guild = {
        id: '1', name: 'Test', icon: null, _beta: true, _bypassUpcoming: true,
        _channels: [], _roles: [],
        _config: { server: {}, welcome: {}, logging: {}, automod: {} },
    };
    const args = { guild, user: { username: 'u' } };

    for (const fn of ['livePollsPage', 'liveGiveawaysPage', 'roleRewardsPage', 'badgesPage']) {
        const html = gp[fn](args);
        assert.ok(html.includes(BADGE), `${fn} renders the "${BADGE}" badge`);
        assert.match(html, /embed-builder-badge/, `${fn} uses the shared badge class`);
    }
});

test('live pages keep their Refresh action alongside the new badge', () => {
    const gp = require('../dashboard/render/guild-pages');
    const guild = {
        id: '1', name: 'Test', icon: null, _beta: true, _bypassUpcoming: true,
        _channels: [], _roles: [],
        _config: { server: {}, welcome: {}, logging: {}, automod: {} },
    };
    for (const fn of ['livePollsPage', 'liveGiveawaysPage']) {
        const html = gp[fn]({ guild, user: { username: 'u' } });
        assert.ok(html.includes('live-refresh'), `${fn} still renders the Refresh button`);
        assert.match(html, /card-title-actions/, `${fn} groups badge + button`);
    }
});

test('the badge class + send-hint styles exist in the stylesheet', () => {
    const css = fs.readFileSync(path.join(ROOT, 'dashboard', 'public', 'styles.css'), 'utf8');
    assert.match(css, /\.embed-builder-badge\s*\{/);
    assert.match(css, /\.card-title-actions\s*\{/);
    assert.match(css, /\.embed-send-hint\s*\{/);
});