// Birthdays dashboard feature tests:
//  - birthdaysPage renders SVG icons + the settings form (channel, role,
//    custom embed image URL) pre-populated from guild._config.birthdaySettings.
//  - The bot's BirthdayManager stores the custom image URL per guild
//    (setEmbedImage) and applies it to every celebration embed, and re-reads
//    the DB periodically so dashboard saves reach the bot without a restart.
//
// The manager tests stub loadBirthdays (constructor boot) and the pg pool's
// query method — the same justified-stub pattern as serverSettingsInit.test.js
// (no Postgres in CI); everything else exercises the real code paths.

const { test } = require('node:test');
const assert = require('node:assert');

const guildPages = require('../dashboard/render/guild-pages');
const { svgIcon, ICONS } = require('../dashboard/public/js/icons');

function fakeGuild(config = {}) {
    return {
        id: '111', name: 'Test', icon: null,
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, ...config },
        _channels: [{ id: 'c1', name: 'general' }],
        _roles: [{ id: 'r1', name: 'Birthday' }],
    };
}

test('icons catalog includes the cake icon and renders an <svg class="ico">', () => {
    assert.ok(ICONS.cake, 'cake icon missing from ICONS');
    assert.match(svgIcon('cake'), /<svg class="ico"/);
});

test('birthdaysPage: SVG icons, pre-populated settings, no emoji card-title', () => {
    const html = guildPages.birthdaysPage({
        guild: fakeGuild({
            birthdaySettings: { channelId: 'c1', roleId: 'r1', imageUrl: 'https://img.example.com/bday.png' },
        }),
        user: { username: 'u' },
    });
    assert.match(html, /<svg class="ico"/);
    // No leftover emoji in the card-title icon span.
    assert.doesNotMatch(html, /class="icon">[^$<]/);
    // Settings are pre-populated from guild._config.birthdaySettings.
    assert.match(html, /value="https:\/\/img\.example\.com\/bday\.png"/);
    assert.ok(html.includes('id="bd-channel"'), 'channel select missing');
    assert.ok(html.includes('id="bd-role"'), 'role select missing');
    assert.ok(html.includes('id="bd-image-url"'), 'image URL input missing');
    // The preview is visible because an image URL is set.
    assert.match(html, /bd-image-preview-wrap(?![^"]*hidden)/);
    // The birthday list + add form render.
    assert.ok(html.includes('id="bd-list"'), 'birthday list container missing');
    assert.ok(html.includes('id="bd-add-btn"'), 'add button missing');
    // The page loads the birthdays client script.
    assert.ok(html.includes('/js/birthdays.js'), 'birthdays.js script missing');
});

test('birthdaysPage: preview hidden when no custom image is set', () => {
    const html = guildPages.birthdaysPage({ guild: fakeGuild(), user: { username: 'u' } });
    assert.match(html, /bd-image-preview-wrap hidden/);
});

// ── BirthdayManager: custom embed image + object-style setBirthday ──────────

const { birthdayPool } = require('../server/birthdayDb');
const BirthdayManager = require('../utils/birthdayManager');

const realLoad = BirthdayManager.prototype.loadBirthdays;
const realQuery = birthdayPool.query;

function freshManager() {
    BirthdayManager.prototype.loadBirthdays = async function () {};
    const mgr = new BirthdayManager({ guilds: { cache: new Map() } });
    BirthdayManager.prototype.loadBirthdays = realLoad;
    return mgr;
}

test('setEmbedImage stores the URL in cache + DB and clears with null', async () => {
    const mgr = freshManager();
    const queries = [];
    birthdayPool.query = async (sql, params) => { queries.push({ sql, params }); return { rows: [] }; };

    assert.strictEqual(await mgr.setEmbedImage('g1', 'https://img.example.com/a.png'), true);
    assert.strictEqual(mgr.birthdays.get('g1').imageUrl, 'https://img.example.com/a.png');
    assert.ok(queries.some(q => /embed_image_url/.test(q.sql) && q.params[1] === 'https://img.example.com/a.png'));

    assert.strictEqual(await mgr.setEmbedImage('g1', ''), true);
    assert.strictEqual(mgr.birthdays.get('g1').imageUrl, null);
    assert.ok(queries.some(q => /embed_image_url/.test(q.sql) && q.params[1] === null));

    birthdayPool.query = realQuery;
});

test('setBirthday accepts an options object (the slash-command call shape)', async () => {
    const mgr = freshManager();
    birthdayPool.query = async () => ({ rows: [] });

    const ok = await mgr.setBirthday({ guildId: 'g2', userId: 'u9', month: 6, day: 15, year: 2000 });
    assert.strictEqual(ok, true);
    const bd = mgr.getBirthday('g2', 'u9');
    assert.deepStrictEqual(bd, { month: 6, day: 15, year: 2000, lastCelebrated: null });

    birthdayPool.query = realQuery;
});

test('a custom image URL overrides the built-in image on the celebration embed', async () => {
    const mgr = freshManager();
    let sent = null;
    const channel = { send: async payload => { sent = payload; } };
    const member = {
        displayName: 'Sam',
        user: { displayAvatarURL: () => 'https://cdn.example.com/avatar.png' },
        roles: { add: async () => {} },
    };
    const guild = {
        members: { fetch: async () => member },
        channels: { cache: new Map([['c1', channel]]) },
    };
    mgr.client = { guilds: { cache: new Map([['g3', guild]]) } };

    const guildData = { channel: 'c1', role: null, imageUrl: 'https://img.example.com/custom.png', users: new Map() };
    await mgr.sendBirthdayCelebration('g3', 'u1', guildData);

    assert.ok(sent, 'no celebration message was sent');
    assert.strictEqual(sent.embeds[0].toJSON().image?.url, 'https://img.example.com/custom.png');
});

test('without a custom image the built-in embed image is kept', async () => {
    const mgr = freshManager();
    let sent = null;
    const channel = { send: async payload => { sent = payload; } };
    const member = {
        displayName: 'Sam',
        user: { displayAvatarURL: () => 'https://cdn.example.com/avatar.png' },
        roles: { add: async () => {} },
    };
    const guild = {
        members: { fetch: async () => member },
        channels: { cache: new Map([['c1', channel]]) },
    };
    mgr.client = { guilds: { cache: new Map([['g4', guild]]) } };

    const guildData = { channel: 'c1', role: null, imageUrl: null, users: new Map() };
    await mgr.sendBirthdayCelebration('g4', 'u1', guildData);

    const url = sent.embeds[0].toJSON().image?.url;
    assert.ok(url && url !== 'https://img.example.com/custom.png', 'built-in image should be used');
});

test('the constructor starts the periodic DB reload loop (dashboard saves reach the bot)', () => {
    const mgr = freshManager();
    assert.ok(mgr._reloadTimer, 'reload interval must be running');
    clearInterval(mgr._reloadTimer);
});

// ── Birthday list image: hardcoded default + per-server custom override ─────

test('getListImageUrl falls back to the hardcoded default when no custom image is set', () => {
    const mgr = freshManager();
    clearInterval(mgr._reloadTimer);
    assert.strictEqual(mgr.getListImageUrl('no-such-guild'), BirthdayManager.DEFAULT_LIST_IMAGE_URL);
    mgr.birthdays.set('g5', { channel: null, role: null, imageUrl: null, users: new Map() });
    assert.strictEqual(mgr.getListImageUrl('g5'), BirthdayManager.DEFAULT_LIST_IMAGE_URL);
    assert.ok(BirthdayManager.DEFAULT_LIST_IMAGE_URL.includes('images_1.jpeg'), 'default list image URL changed unexpectedly');
});

test('getListImageUrl returns the dashboard custom image when set', async () => {
    const mgr = freshManager();
    clearInterval(mgr._reloadTimer);
    birthdayPool.query = async () => ({ rows: [] });
    await mgr.setEmbedImage('g6', 'https://img.example.com/list.png');
    assert.strictEqual(mgr.getListImageUrl('g6'), 'https://img.example.com/list.png');
    birthdayPool.query = realQuery;
});
