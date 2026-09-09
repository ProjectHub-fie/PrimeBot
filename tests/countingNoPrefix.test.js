const test = require('node:test');
const assert = require('node:assert/strict');

/**
 * Counting-vs-no-prefix regression tests.
 *
 * In a no-prefix server, a user with no-prefix mode enabled had every message
 * parsed as a command — including plain counts ``1`` / ``4`` in the counting
 * channel, which were logged as ``$1`` / ``$4`` and hit the command switch
 * (breaking counting). The no-prefix guard now checks
 * `CountingManager.isBareCount` first, so a bare number in a counting channel
 * falls through to the counting manager instead of the command parser.

 * The class is constructed with a stubbed community pool (no Postgres in CI),
 * stubbing `loadCounting` so its async init never touches the DB.

 */

const { communityPool } = require('../server/communityDb');
communityPool.query = async () => ({ rows: [] });

const CountingManager = require('../utils/countingManager');

const realLoad = CountingManager.prototype.loadCounting;
function freshManager() {
    CountingManager.prototype.loadCounting = async function () {
        this.counting.set('count-ch', {});
    };
    const mgr = new CountingManager({});
    CountingManager.prototype.loadCounting = realLoad;
    return mgr;
}

test('isBareCount true for plain numbers + whitespace', () => {
    assert.equal(CountingManager.isBareCount('1'), true);
    assert.equal(CountingManager.isBareCount(' 4 '), true);
    assert.equal(CountingManager.isBareCount('1234567890'), true);
});

test('isBareCount false for words, mentions, and mixed content', () => {
    assert.equal(CountingManager.isBareCount('cstart'), false);
    assert.equal(CountingManager.isBareCount('1 2'), false);
    assert.equal(CountingManager.isBareCount('12345678901'), false);
    assert.equal(CountingManager.isBareCount('@user 1'), false);
    assert.equal(CountingManager.isBareCount('$cstart'), false);
    assert.equal(CountingManager.isBareCount(''), false);
});

test('a counting channel is recognized', () => {
    const mgr = freshManager();
    assert.equal(mgr.isCountingChannel('count-ch'), true);
    assert.equal(mgr.isCountingChannel('other-ch'), false);
});

test('no-prefix guard: counting channel + bare count passes isBareCount', () => {
    const mgr = freshManager();
    const msg = { content: '4', channel: { id: 'count-ch' } };
    const countingChannel = mgr.isCountingChannel(msg.channel.id);
    const bareCount = countingChannel && CountingManager.isBareCount(msg.content);
    assert.equal(bareCount, true);

    // Non-count commands in the channel still parse as commands.

    const cmd = { content: 'cstart', channel: { id: 'count-ch' } };
    const countingChannel2 = mgr.isCountingChannel(cmd.channel.id);
    const bareCount2 = countingChannel2 && CountingManager.isBareCount(cmd.content);
    assert.equal(bareCount2, false);
});