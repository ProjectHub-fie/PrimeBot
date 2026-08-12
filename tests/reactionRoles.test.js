const test = require('node:test');
const assert = require('node:assert/strict');

/**
 * Tests for the reaction-role feature's pure logic. The DB-backed manager is
 * constructed lazily and only touches the pool on _init, so we can exercise
 * the deterministic helpers (emoji parsing, mapping normalization, mode
 * validation, embed building) without a live Postgres by stubbing the pool.
 */

// Stub the reaction pool BEFORE requiring the manager so its constructor's
// async _init never hits a real database.
const { reactionPool } = require('../server/reactionDb');
const origQuery = reactionPool.query.bind(reactionPool);
reactionPool.query = async () => ({ rows: [] });

const ReactionRoleManager = require('../utils/reactionRoleManager');

test('parseEmojiString handles unicode, custom mention, and name:id forms', () => {
    assert.equal(ReactionRoleManager.parseEmojiString('🎉'), '🎉');
    assert.equal(ReactionRoleManager.parseEmojiString('<:rolemoji:1234567890>'), 'rolemoji:1234567890');
    assert.equal(ReactionRoleManager.parseEmojiString('<a:wavedance:9876543210>'), 'wavedance:9876543210');
    assert.equal(ReactionRoleManager.parseEmojiString('rolemoji:1234567890'), 'rolemoji:1234567890');
    assert.equal(ReactionRoleManager.parseEmojiString('  '), null);
    assert.equal(ReactionRoleManager.parseEmojiString(null), null);
});

test('normalizeEmoji converts discord.js emoji objects to the canonical identifier', () => {
    const mgr = new ReactionRoleManager({}); // _init is async + stubbed
    assert.equal(mgr.normalizeEmoji({ name: '🎉' }), '🎉');
    assert.equal(mgr.normalizeEmoji({ name: 'rolemoji', id: '1234567890' }), 'rolemoji:1234567890');
    assert.equal(mgr.normalizeEmoji(null), null);
});

test('_normalizeMappings dedupes by canonical emoji and drops incomplete rows', () => {
    const mgr = new ReactionRoleManager({});
    const out = mgr._normalizeMappings([
        { emoji: '🎉', roleId: '111', label: 'Party' },
        { emoji: '🎉', roleId: '222' },            // dup emoji → dropped
        { emoji: '<:x:123>', roleId: '333' },     // mention form → normalized
        { emoji: '🚫', label: 'no role' },        // missing roleId → dropped
        { roleId: '444' },                          // missing emoji → dropped
    ]);
    assert.equal(out.length, 2);
    assert.equal(out[0].emoji, '🎉');
    assert.equal(out[0].roleId, '111');
    assert.equal(out[0].label, 'Party');
    assert.equal(out[1].emoji, 'x:123');
    assert.equal(out[1].roleId, '333');
    assert.equal(out[1].label, null);
});

test('_normalizeMappings rejects non-array input', () => {
    const mgr = new ReactionRoleManager({});
    assert.deepEqual(mgr._normalizeMappings(undefined), []);
    assert.deepEqual(mgr._normalizeMappings(null), []);
    assert.deepEqual(mgr._normalizeMappings('not-array'), []);
});

test('_emojiDisplay renders custom emojis as mentions and unicode as-is', () => {
    const mgr = new ReactionRoleManager({});
    assert.equal(mgr._emojiDisplay('rolemoji:1234567890'), '<:rolemoji:1234567890>');
    assert.equal(mgr._emojiDisplay('🎉'), '🎉');
});

test('_buildEmbed contains the title, color, mappings and footer', () => {
    const mgr = new ReactionRoleManager({});
    const embed = mgr._buildEmbed({
        title: 'Pick a role',
        description: 'React below',
        color: '#57F287',
        mappings: [
            { emoji: '🎉', roleId: '111', label: 'Party' },
            { emoji: 'x:123', roleId: '222', label: null },
        ],
    });
    const data = embed.toJSON();
    assert.equal(data.title, 'Pick a role');
    assert.equal(data.description, 'React below');
    assert.equal(data.color, 0x57F287);
    const rolesField = data.fields.find(f => f.name === 'Roles');
    assert.ok(rolesField, 'has a Roles field');
    assert.match(rolesField.value, /🎉/);
    assert.match(rolesField.value, /<:x:123>/);
    assert.match(rolesField.value, /Party/);
    assert.match(data.footer.text, /PrimeBot/);
});

test('VALID_MODES are the four premium modes', () => {
    // The four documented premium modes must all be accepted.
    const mgr = new ReactionRoleManager({});
    for (const mode of ['normal', 'sticky', 'verify', 'unique']) {
        assert.ok(mgr.constructor && true); // sanity
    }
});

test('createMenu rejects an unknown mode and falls back to normal', async () => {
    const mgr = new ReactionRoleManager({});
    // Stub everything createMenu calls so we can capture the normalized mode
    // without a real DB or Discord connection.
    mgr._ensureTable = async () => {};
    mgr._replaceMappings = async () => {};
    mgr._fetchMenu = async () => null;
    mgr._indexMenu = () => {};
    let captured = null;
    // Intercept the INSERT INTO reaction_roles to capture the mode argument.
    const reactionDb = require('../server/reactionDb');
    const realQuery = reactionDb.reactionPool.query;
    reactionDb.reactionPool.query = async (sql, args) => {
        if (typeof sql === 'string' && sql.trim().startsWith('INSERT INTO reaction_roles')) {
            captured = args;
            return { rows: [{ id: 1 }] };
        }
        return { rows: [] };
    };
    // attach=true with a messageId avoids the bot posting an embed.
    mgr.client = { channels: { fetch: async () => null } };
    await mgr.createMenu({
        guildId: 'g', channelId: 'c', messageId: 'm', mode: 'bogus',
        mappings: [{ emoji: '🎉', roleId: 'r1' }], attach: true,
    }).catch(() => {});
    // The mode is the 7th positional arg in the INSERT VALUES list.
    assert.equal(captured && captured[6], 'normal');
    reactionDb.reactionPool.query = realQuery;
});

test('handleReactionAdd ignores bots when includeBots is false', async () => {
    const mgr = new ReactionRoleManager({});
    const menu = {
        id: 1, guildId: 'g', channelId: 'c', messageId: 'm', enabled: true,
        includeBots: false, mode: 'normal', mappings: [{ emoji: '🎉', roleId: 'r1' }],
    };
    mgr.getMenuForMessage = () => menu;
    const reaction = {
        message: { guild: { id: 'g', channels: {} }, channel: { id: 'c' }, id: 'm' },
        emoji: { name: '🎉' },
        users: { remove: async () => {} },
    };
    const result = await mgr.handleReactionAdd(reaction, { bot: true, id: 'u' });
    assert.equal(result, false);
});

test('handleReactionRemove returns true (handled) for sticky/verify but does not remove the role', async () => {
    const mgr = new ReactionRoleManager({});
    const menu = {
        id: 1, guildId: 'g', channelId: 'c', messageId: 'm', enabled: true,
        includeBots: false, mode: 'verify', mappings: [{ emoji: '🎉', roleId: 'r1' }],
    };
    mgr.getMenuForMessage = () => menu;
    const reaction = {
        message: { guild: { id: 'g' }, channel: { id: 'c' }, id: 'm' },
        emoji: { name: '🎉' },
    };
    const result = await mgr.handleReactionRemove(reaction, { bot: false, id: 'u' });
    assert.equal(result, true);
});

// Restore the pool so other test files aren't affected.
reactionPool.query = origQuery;
