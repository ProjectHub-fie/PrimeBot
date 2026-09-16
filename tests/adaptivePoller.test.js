// Tests for AdaptivePoller — the jittered backoff used by every settings cache.
//
// The point of this class is Neon compute: a suspended Neon endpoint is
// effectively free, a continuously-polled one is billed for every second it is
// awake. Before it, ~10 managers ran fixed 5s + 15s/30s loops, so the database
// never got a chance to suspend. These tests pin the three behaviours that
// matter: a quiet table backs off, a change snaps back to the fast interval,
// and external activity (notifyActivity) resets the backoff.

const { test } = require('node:test');
const assert = require('node:assert');

const { AdaptivePoller, resolveConfig } = require('../utils/adaptivePoller');

function makePoller(task, overrides = {}) {
    const poller = new AdaptivePoller({
        name: 'TEST',
        task,
        initialMs: 5000,
        maxMs: 60000,
        factor: 2,
        quietTicks: 2,
        jitterRatio: 0,
        ...overrides,
    });
    // Drive ticks manually; never start a real timer.
    poller._schedule = () => {};
    poller._stopped = false;
    return poller;
}

test('a quiet table backs off up to maxMs', async () => {
    const poller = makePoller(async () => false);

    assert.equal(poller.intervalMs, 5000);

    await poller._run(); // quiet 1
    assert.equal(poller.intervalMs, 5000, 'first quiet tick stays at the fast interval');

    await poller._run(); // quiet 2
    assert.equal(poller.intervalMs, 5000, 'still inside the quiet grace window');

    await poller._run(); // quiet 3 — past quietTicks, start doubling
    assert.equal(poller.intervalMs, 10000);

    await poller._run();
    assert.equal(poller.intervalMs, 20000);

    await poller._run();
    assert.equal(poller.intervalMs, 40000);

    await poller._run();
    assert.equal(poller.intervalMs, 60000);

    await poller._run();
    assert.equal(poller.intervalMs, 60000, 'never grows past maxMs');
});

test('a detected change snaps back to the fast interval', async () => {
    let changed = false;
    const poller = makePoller(async () => changed);

    for (let i = 0; i < 6; i++) await poller._run();
    assert.equal(poller.intervalMs, 60000, 'backed off while quiet');

    changed = true;
    await poller._run();
    assert.equal(poller.intervalMs, 5000, 'a change resets the backoff immediately');
});

test('an error does NOT stretch the backoff (retries fast to recover)', async () => {
    const poller = makePoller(async () => { throw new Error('DB down'); });

    await poller._run();
    assert.equal(poller.intervalMs, 5000, 'a transient DB error must keep polling fast');

    await poller._run();
    assert.equal(poller.intervalMs, 5000);
});

test('notifyActivity resets the backoff and re-arms the fast interval', async () => {
    const poller = makePoller(async () => false);

    for (let i = 0; i < 6; i++) await poller._run();
    assert.equal(poller.intervalMs, 60000);

    poller.notifyActivity();
    assert.equal(poller.intervalMs, 5000, 'external activity restarts the fast cadence');
    assert.equal(poller.quietStreak, 0);
});

test('a tick already running is never overlapped', async () => {
    let running = 0;
    let maxConcurrent = 0;
    const poller = makePoller(async () => {
        running++;
        maxConcurrent = Math.max(maxConcurrent, running);
        await new Promise((r) => setTimeout(r, 5));
        running--;
        return false;
    });

    await Promise.all([poller._run(), poller._run(), poller._run()]);
    assert.equal(maxConcurrent, 1, 'concurrent ticks must collapse into one');
});

test('stop() cancels the timer and prevents further ticks', () => {
    let ran = 0;
    const poller = new AdaptivePoller({
        name: 'TEST',
        task: async () => { ran++; return false; },
        initialMs: 5000,
        maxMs: 60000,
    });
    poller.start();
    poller.stop();

    assert.equal(poller._timer, null, 'stop() must clear the timer');
    assert.equal(ran, 0);
});

test('resolveConfig honours env overrides and clamps sane minimums', () => {
    const prev = process.env.SETTINGS_POLL_INTERVAL_MS;
    process.env.SETTINGS_POLL_INTERVAL_MS = '1234';
    try {
        const cfg = resolveConfig();
        assert.equal(cfg.initialMs, 5000, 'a sub-5s interval is clamped up');
    } finally {
        if (prev === undefined) delete process.env.SETTINGS_POLL_INTERVAL_MS;
        else process.env.SETTINGS_POLL_INTERVAL_MS = prev;
    }

    const custom = resolveConfig({ initialMs: 20000, maxMs: 90000 });
    assert.equal(custom.initialMs, 20000);
    assert.equal(custom.maxMs, 90000);
});

test('idle cost is bounded: a dormant deployment ends up at maxMs', async () => {
    // 10 minutes idle should cost a handful of queries, not one every 5s.
    const poller = makePoller(async () => false, { initialMs: 30000, maxMs: 600000 });

    // Simulate ~10 minutes of idle ticks.
    const ticks = 20;
    for (let i = 0; i < ticks; i++) await poller._run();

    assert.equal(poller.intervalMs, 600000, 'the idle floor is the max interval');
    // Verify the growth actually happened (interval far above the initial).
    assert.ok(poller.intervalMs > 30000);
});