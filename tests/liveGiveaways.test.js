const test = require('node:test');
const assert = require('node:assert/strict');

/**
 * Tests for the live-giveaway feature's pure logic. The DB-backed manager
 * constructs lazily and only touches the pool on init, so we stub the pool
 * BEFORE requiring the manager so its constructor's async _init never hits a
 * real database.
 */

const { livePool } = require('../server/liveDb');
livePool.query = async () => ({ rows: [] });

const LiveGiveawayManager = require('../utils/liveGiveawayManager');

function makeManager() {
    return new LiveGiveawayManager(null);
}

test('generateGiveawayId / generatePassCode produce plausible unique values', () => {
    const mgr = makeManager();
    const id = mgr.generateGiveawayId();
    const code = mgr.generatePassCode();
    assert.ok(typeof id === 'string' && id.startsWith('lg') && id.length > 6);
    assert.ok(typeof code === 'string' && code.length > 0);
    // Pass codes are uppercase alphanumeric.
    assert.match(code, /^[A-Z0-9]+$/);
});

test('selectWinners returns all participants when fewer than count', () => {
    const mgr = makeManager();
    const participants = ['a', 'b'];
    assert.deepEqual(mgr.selectWinners(participants, 5), ['a', 'b']);
});

test('selectWinners returns empty for no participants', () => {
    const mgr = makeManager();
    assert.deepEqual(mgr.selectWinners([], 3), []);
});

test('selectWinners returns exactly count winners and never duplicates', () => {
    const mgr = makeManager();
    const participants = ['a', 'b', 'c', 'd', 'e'];
    const winners = mgr.selectWinners(participants, 3);
    assert.equal(winners.length, 3);
    assert.equal(new Set(winners).size, 3);
    for (const w of winners) assert.ok(participants.includes(w));
});

test('createGiveawayEmbed renders an active embed with join instructions', () => {
    const mgr = makeManager();
    const g = {
        giveawayId: 'lg123', passCode: 'ABC123', prize: 'Nitro',
        winnerCount: 1, description: 'desc', isActive: true, ended: false,
        participants: new Set(), endsAt: null,
    };
    const embed = mgr.createGiveawayEmbed(g, 0, [], false);
    const e = embed.toJSON ? embed.toJSON() : embed;
    assert.ok(e.title.includes('LIVE GIVEAWAY'));
    assert.equal(e.description, '**Prize**: Nitro');
    const flat = JSON.stringify(e);
    assert.ok(flat.includes('ABC123'));
    assert.ok(flat.includes('lg123'));
});

test('createGiveawayEmbed ended shows winners text', () => {
    const mgr = makeManager();
    const g = {
        giveawayId: 'lg1', passCode: 'ZZZ', prize: 'Nitro',
        winnerCount: 1, isActive: false, ended: true, participants: new Set(), endsAt: null,
    };
    const embed = mgr.createGiveawayEmbed(g, 2, ['42'], true);
    const e = embed.toJSON ? embed.toJSON() : embed;
    assert.ok(e.title.includes('ENDED'));
    assert.ok(JSON.stringify(e).includes('<@42>'));
});

test('createJoinButton builds a single ActionRow with one Join button', () => {
    const mgr = makeManager();
    const rows = [mgr.createJoinButton('lgx')];
    assert.equal(rows.length, 1);
    const btn = rows[0].components[0];
    assert.equal(btn.data.custom_id, 'lgive_lgx');
    assert.equal(btn.data.label, 'Join Giveaway');
});

test('createGiveaway in fallback (memory) mode stores the giveaway', async () => {
    const mgr = makeManager();
    mgr.dbReady = false; // force memory mode
    const res = await mgr.createGiveaway({ prize: 'Nitro', creatorId: 'u1', winnerCount: 2, duration: null });
    assert.ok(res.giveawayId && res.passCode);
    assert.equal(res.giveaway.prize, 'Nitro');
    assert.equal(mgr.giveaways.has(res.giveawayId), true);
});

test('joinGiveaway dedupes participants in memory mode', async () => {
    const mgr = makeManager();
    mgr.dbReady = false;
    const { giveawayId } = await mgr.createGiveaway({ prize: 'X', creatorId: 'u1', winnerCount: 1, duration: null });
    const r1 = await mgr.joinGiveaway(giveawayId, 'userA');
    assert.equal(r1.success, true);
    const r2 = await mgr.joinGiveaway(giveawayId, 'userA');
    assert.equal(r2.success, false);
    const g = mgr.giveaways.get(giveawayId);
    assert.equal(g.participants.size, 1);
});

test('endGiveaway rejects non-creators and ends for creators', async () => {
    const mgr = makeManager();
    mgr.dbReady = false;
    const { giveawayId } = await mgr.createGiveaway({ prize: 'X', creatorId: 'creator1', winnerCount: 1, duration: null });
    const blocked = await mgr.endGiveaway(giveawayId, 'someoneElse');
    assert.equal(blocked.success, false);
    // join then end
    await mgr.joinGiveaway(giveawayId, 'p1');
    await mgr.joinGiveaway(giveawayId, 'p2');
    const ended = await mgr.endGiveaway(giveawayId, 'creator1');
    assert.equal(ended.success, true);
    assert.equal(ended.winners.length, 1);
});
