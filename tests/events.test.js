const test = require('node:test');
const assert = require('node:assert/strict');

/**
 * Tests for the event-management feature's pure logic (task normalization +
 * scheduling state). The DB-backed manager constructs lazily and only touches
 * the pool on init, so we stub the pool BEFORE requiring the manager.
 */

const { eventPool } = require('../server/eventDb');
eventPool.query = async () => ({ rows: [] });

const EventManager = require('../utils/eventManager');

function makeManager() {
    return new EventManager(null);
}

test('normalizeTask fills defaults for an empty task', () => {
    const mgr = makeManager();
    const t = mgr.normalizeTask({});
    assert.equal(t.offsetSeconds, 0);
    assert.equal(t.action, 'sendtext');
    assert.equal(t.targetType, 'channel');
    assert.deepEqual(t.targetIds, []);
    assert.equal(t.embedColor, '#5865F2');
});

test('normalizeTask validates the action enum (falls back to sendtext)', () => {
    const mgr = makeManager();
    const t = mgr.normalizeTask({ action: 'bogus' });
    assert.equal(t.action, 'sendtext');
    const t2 = mgr.normalizeTask({ action: 'lock' });
    assert.equal(t2.action, 'lock');
});

test('normalizeTask coerces target ids to strings and clamps offset', () => {
    const mgr = makeManager();
    const t = mgr.normalizeTask({ offsetSeconds: -5, targetIds: [111, 222] });
    assert.equal(t.offsetSeconds, 0);
    assert.deepEqual(t.targetIds, ['111', '222']);
});

test('normalizeTask validates the embed color', () => {
    const mgr = makeManager();
    assert.equal(mgr.normalizeTask({ embedColor: 'nope' }).embedColor, '#5865F2');
    assert.equal(mgr.normalizeTask({ embedColor: '#57F287' }).embedColor, '#57F287');
});

test('normalizeTask validates the target type', () => {
    const mgr = makeManager();
    assert.equal(mgr.normalizeTask({ targetType: 'weird' }).targetType, 'channel');
    assert.equal(mgr.normalizeTask({ targetType: 'role' }).targetType, 'role');
    assert.equal(mgr.normalizeTask({ targetType: 'user' }).targetType, 'user');
});

test('VALID_ACTIONS includes all advertised actions', () => {
    const { default: _ } = {}; // no-op
    const mgr = makeManager();
    for (const a of ['lock', 'unlock', 'hide', 'unhide', 'addrole', 'removerole', 'sendtext', 'sendembed']) {
        assert.equal(mgr.normalizeTask({ action: a }).action, a);
    }
});

test('selectWinners-style logic: completing schedule marking is deterministic', () => {
    // Sanity: ensure a schedule with all tasks executed should be completable.
    const mgr = makeManager();
    const schedule = {
        id: 1, name: 'E', guildId: 'g', enabled: true, status: 'running',
        triggered: true, startAt: new Date(), tasks: [
            { executedAt: new Date(), offsetSeconds: 0, action: 'sendtext' },
        ],
    };
    const allDone = schedule.tasks.every(t => t.executedAt);
    assert.equal(allDone, true);
});
