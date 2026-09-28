// Tests for the shared cache scheduler and the idle activity gate.
//
// These two changes attack the actual source of the Neon bill. A 30-second
// fixed heartbeat plus ~15 independently-jittered settings pollers meant some
// query landed on the database every couple of minutes forever, so a Neon
// compute endpoint could never reach its ~5-minute idle suspension and stayed
// billed around the clock. The scheduler collapses every settings refresh onto
// ONE timer, and the activity gate lets the recurring loops slow right down
// when nothing is happening.

const { test } = require('node:test');
const assert = require('node:assert');

const activityGate = require('../utils/activityGate');
const { CacheScheduler } = require('../utils/cacheScheduler');

function stubActivityGate(isIdle) {
    const p = require.resolve('../utils/activityGate');
    const prev = require.cache[p];
    require.cache[p] = {
        id: p, filename: p, loaded: true,
        exports: { isIdle: () => isIdle, touch: () => {}, idleMs: () => 0 },
    };
    return () => { if (prev) require.cache[p] = prev; else delete require.cache[p]; };
}

// ── Activity gate ───────────────────────────────────────────────────────────

test('activity gate starts active and goes idle after the threshold', () => {
    activityGate.reset();
    assert.equal(activityGate.isIdle(1000), false, 'fresh activity is not idle');

    // Simulate the passage of time without sleeping.
    const realNow = Date.now;
    try {
        Date.now = () => realNow() + 5000;
        assert.equal(activityGate.isIdle(1000), true, 'quiet past the threshold is idle');
        activityGate.touch();
        assert.equal(activityGate.isIdle(1000), false, 'touch() clears idleness');
    } finally {
        Date.now = realNow;
        activityGate.reset();
    }
});

// ── Scheduler: one timer for every task ─────────────────────────────────────

test('all registered tasks run off one tick', async () => {
    const sched = new CacheScheduler({ initialMs: 5000, maxMs: 40000, jitterRatio: 0 });
    const ran = [];
    sched._scheduleNext = () => {}; // drive manually

    sched.register('a', async () => { ran.push('a'); return false; });
    sched.register('b', async () => { ran.push('b'); return false; });

    await sched._run();
    assert.deepEqual(ran.sort(), ['a', 'b'], 'both tasks shared the single tick');
});

test('a change resets the cadence; a quiet run backs off', async () => {
    const restore = stubActivityGate(false); // busy — use the normal ramp
    try {
        const sched = new CacheScheduler({ initialMs: 5000, maxMs: 80000, quietTicks: 1, factor: 2, jitterRatio: 0 });
        sched._scheduleNext = () => {};
        let changed = false;
        sched.register('t', async () => changed);

        await sched._run(); // quiet 1
        await sched._run(); // quiet 2 -> past quietTicks, doubles
        assert.equal(sched.intervalMs, 10000, 'backs off when quiet');

        changed = true;
        await sched._run();
        assert.equal(sched.intervalMs, 5000, 'a change snaps back to the fast interval');
    } finally {
        restore();
    }
});

test('when the bot is idle the scheduler jumps straight to the long interval', async () => {
    const restore = stubActivityGate(true); // idle
    try {
        const sched = new CacheScheduler({ initialMs: 5000, maxMs: 1800000, jitterRatio: 0 });
        sched._scheduleNext = () => {};
        sched.register('t', async () => false);

        await sched._run();
        assert.equal(sched.intervalMs, 1800000, 'idle skips the slow ramp and uses maxMs immediately');
    } finally {
        restore();
    }
});

test('an error keeps the fast cadence so a recovering DB is noticed quickly', async () => {
    const restore = stubActivityGate(false);
    try {
        const sched = new CacheScheduler({ initialMs: 5000, maxMs: 80000, jitterRatio: 0 });
        sched._scheduleNext = () => {};
        let errors = 0;
        sched.register('t', async () => { throw new Error('db down'); }, { onError: () => { errors++; } });

        await sched._run();
        await sched._run();
        assert.equal(errors, 2, 'the error handler ran');
        assert.equal(sched.intervalMs, 5000, 'errors never stretch the backoff');
    } finally {
        restore();
    }
});

test('stop() unregisters a task and halts the timer', () => {
    const sched = new CacheScheduler({ initialMs: 5000, maxMs: 40000, jitterRatio: 0 });
    const handle = sched.register('t', async () => false);
    assert.equal(sched.tasks.size, 1);

    handle.stop();
    assert.equal(sched.tasks.size, 0, 'stopping a handle removes the task');

    sched.stop();
    assert.equal(sched._timer, null, 'stop() clears the shared timer');
});

test('an empty scheduler holds no timer (nothing keeps the event loop alive)', () => {
    const sched = new CacheScheduler({ initialMs: 5000, maxMs: 10000 });
    sched._scheduleNext();
    assert.equal(sched._timer, null, 'no tasks means no timer');
});
