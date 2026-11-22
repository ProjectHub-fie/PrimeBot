const { test } = require('node:test');
const assert = require('node:assert');

const EmojiManager = require('../utils/emojiManager');
const ServerSettingsManager = require('../utils/serverSettingsManager');
const { applyAutoReactions, resolveReactionEmoji, canReact } = require('../utils/autoReaction');

const TICK = {
    key: 'tick',
    name: 'tick',
    id: '111111111111111111',
    animated: false,
    raw: '<:tick:111111111111111111>',
    sourceGuildId: '1190256755096158208',
};

function managerWith(entry = TICK) {
    const mgr = new EmojiManager({ global: true });
    mgr.byId.set(entry.id, entry);
    mgr.byName.set(entry.name, entry);
    mgr.bySemantic.set(entry.key || entry.name, entry);
    return mgr;
}

function fakeMessage({ permissions = true, reactError = null } = {}) {
    const reactions = [];
    return {
        guild: { id: '999', members: { me: { id: 'bot' } } },
        channel: {
            permissionsFor: () => ({ has: () => permissions }),
        },
        react: async (emoji) => {
            if (reactError) throw reactError;
            reactions.push(emoji);
        },
        reactions,
    };
}

test('Unicode reactions pass through unchanged', () => {
    managerWith();
    assert.equal(resolveReactionEmoji('👍', { id: '999' }), '👍');
});

test('validated custom emoji resolves to an emoji object (static + animated)', () => {
    managerWith();
    assert.deepEqual(resolveReactionEmoji('<:tick:111111111111111111>', { id: '999' }),
        { id: TICK.id, name: 'tick', animated: false });
    const animated = { ...TICK, id: '222222222222222222', name: 'playing', animated: true, raw: '<a:playing:222222222222222222>' };
    managerWith(animated);
    assert.deepEqual(resolveReactionEmoji('<a:playing:222222222222222222>', { id: '999' }),
        { id: animated.id, name: 'playing', animated: true });
});

test('unknown/deleted custom emoji resolves to null (never crashes)', () => {
    managerWith();
    assert.equal(resolveReactionEmoji('<:gone:999999999999999999>', { id: '999' }), null);
});

test('external emoji without UseExternalEmojis falls back to Unicode', () => {
    const mgr = managerWith();
    mgr.canUseIn = () => false;
    assert.equal(resolveReactionEmoji('<:tick:111111111111111111>', { id: '999', members: { me: {} } }), '✅');
});

test('applyAutoReactions adds Unicode + custom, skips missing, never throws', async () => {
    managerWith();
    const message = fakeMessage();
    const result = await applyAutoReactions(message, ['👍', '<:tick:111111111111111111>', '<:gone:999999999999999999>'], { delayMs: 0 });
    assert.equal(result.applied, 2);
    assert.equal(result.skipped, 1);
    assert.equal(message.reactions.length, 2);
});

test('missing channel permissions skip every reaction instead of failing', async () => {
    managerWith();
    const message = fakeMessage({ permissions: false });
    assert.equal(canReact(message), false);
    const result = await applyAutoReactions(message, ['👍'], { delayMs: 0, logger: { warn() {}, error() {} } });
    assert.deepEqual(result, { applied: 0, skipped: 1 });
    assert.equal(message.reactions.length, 0);
});

test('a rejected message.react is counted as skipped, not thrown', async () => {
    managerWith();
    const message = fakeMessage({ reactError: new Error('Missing Permissions') });
    const result = await applyAutoReactions(message, ['👍'], { delayMs: 0, logger: { warn() {}, error() {} } });
    assert.deepEqual(result, { applied: 0, skipped: 1 });
});

test('getTriggeredReactions ignores malformed rows and matches case-insensitively', () => {
    const realInit = ServerSettingsManager.prototype._init;
    ServerSettingsManager.prototype._init = async function () {};
    const mgr = new ServerSettingsManager({});
    ServerSettingsManager.prototype._init = realInit;
    mgr.serverSettings.set('g1', {
        autoReactions: {
            enabled: true,
            reactions: [
                { trigger: 'Hello', emoji: '👋', caseSensitive: false },
                { trigger: '', emoji: '❌' },
                { trigger: 'x' },
                null,
                { trigger: 'Case', emoji: '🔠', caseSensitive: true },
            ],
        },
    });
    assert.deepEqual(mgr.getTriggeredReactions('g1', 'say hello now'), ['👋']);
    assert.deepEqual(mgr.getTriggeredReactions('g1', 'case'), []);
    assert.deepEqual(mgr.getTriggeredReactions('g1', 'Case'), ['🔠']);
});

test('auto-reactions stay disabled when the guild switch is off', () => {
    const realInit = ServerSettingsManager.prototype._init;
    ServerSettingsManager.prototype._init = async function () {};
    const mgr = new ServerSettingsManager({});
    ServerSettingsManager.prototype._init = realInit;
    mgr.serverSettings.set('g1', {
        autoReactions: { enabled: false, reactions: [{ trigger: 'hi', emoji: '👋' }] },
    });
    assert.deepEqual(mgr.getTriggeredReactions('g1', 'hi'), []);
});
