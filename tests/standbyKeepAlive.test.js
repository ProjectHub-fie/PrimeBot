// Regression test for the standby-node clean-exit restart loop.
//
// A standby node owns only unref'd timers (standby monitor, failover heartbeat),
// so the Node event loop empties and the process exits with code 0 while merely
// waiting to take over. A hosting panel reads that as a crash and restarts the
// container in a loop. utils/standbyKeepAlive.js owns the single ref'd timer
// that keeps a waiting node alive, and index.js must arm it when entering
// standby and clear it once the node connects to Discord.
//
// The keep-alive is exercised in a REAL child process — the only way to prove a
// timer actually holds the event loop open — alongside a control child that
// holds only an unref'd timer and is expected to exit on its own.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const keepAlive = require('../utils/standbyKeepAlive');

const REPO_ROOT = path.join(__dirname, '..');
const KEEP_ALIVE_PATH = path.join(REPO_ROOT, 'utils', 'standbyKeepAlive.js');
const INDEX_SRC = fs.readFileSync(path.join(REPO_ROOT, 'index.js'), 'utf8');

test('arm() is idempotent and clear() reports whether it was armed', () => {
    keepAlive.clear(); // start from a known state
    assert.equal(keepAlive.isArmed(), false);

    const first = keepAlive.arm();
    assert.ok(first, 'arm returns a timer handle');
    assert.equal(keepAlive.isArmed(), true);
    assert.equal(keepAlive.arm(), first, 'a second arm reuses the same handle');
    assert.equal(keepAlive.isArmed(), true);

    assert.equal(keepAlive.clear(), true, 'clear reports it disarmed an armed handle');
    assert.equal(keepAlive.isArmed(), false);
    assert.equal(keepAlive.clear(), false, 'clearing again is a no-op');
});

test('the keep-alive interval is long (a wake source, not a work timer)', () => {
    // A short interval would needlessly wake the event loop (and any timer-driven
    // DB work) far more often than needed just to hold the process open.
    assert.ok(keepAlive.KEEP_ALIVE_INTERVAL_MS >= 60 * 1000, 'keep-alive must be a long interval');
});

test('a process holding only unref\'d timers exits cleanly (the bug being fixed)', async () => {
    const code = 'setInterval(() => {}, 60000).unref(); console.log("READY");';
    const child = spawn(process.execPath, ['-e', code], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'inherit'] });

    const exited = await waitForExit(child, 5000);
    assert.equal(exited, true, 'an unref\'d timer must not keep the process alive');
    assert.equal(child.exitCode, 0, 'the unref-only process exits with code 0 (the panel "crash")');
});

test('arming the keep-alive holds a standby process open', async () => {
    const code = `require(${JSON.stringify(KEEP_ALIVE_PATH)}).arm(); `
        + 'setInterval(() => {}, 60000).unref(); console.log("READY");';
    const child = spawn(process.execPath, ['-e', code], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'inherit'] });

    await waitForOutput(child, 'READY', 5000);
    // Give the (unref'd) 60s timer and the loop time to prove they do not exit.
    const exited = await waitForExit(child, 1500);
    try {
        assert.equal(exited, false, 'the armed keep-alive must keep the standby process alive');
        assert.equal(child.exitCode, null, 'the process is still running');
    } finally {
        child.kill('SIGKILL');
    }
});

test('index.js arms the keep-alive in standby and clears it after login', () => {
    const standby = INDEX_SRC.match(/function startStandbyMonitor\(\)\s*\{[\s\S]*?\n\}/)[0];
    assert.match(standby, /standbyKeepAlive\.arm\(\)/, 'startStandbyMonitor must arm the keep-alive');

    // Clear it once the node actually connects — the gateway socket is then the
    // real keep-alive and the interval would otherwise be a permanent wake source.
    assert.match(INDEX_SRC, /standbyKeepAlive\.clear\(\)/, 'connectBot must clear the keep-alive after login');
    assert.match(INDEX_SRC, /require\('\.\/utils\/standbyKeepAlive'\)/, 'index.js must require the keep-alive module');
});

function waitForExit(child, timeoutMs) {
    if (child.exitCode !== null) return Promise.resolve(true);
    return new Promise((resolve) => {
        const timer = setTimeout(() => resolve(false), timeoutMs);
        child.once('exit', () => { clearTimeout(timer); resolve(true); });
    });
}

function waitForOutput(child, needle, timeoutMs) {
    return new Promise((resolve, reject) => {
        let buffer = '';
        const timer = setTimeout(() => reject(new Error(`timed out waiting for "${needle}"`)), timeoutMs);
        child.stdout.on('data', (chunk) => {
            buffer += chunk.toString();
            if (buffer.includes(needle)) { clearTimeout(timer); resolve(); }
        });
        child.once('exit', (code) => {
            if (!buffer.includes(needle)) { clearTimeout(timer); reject(new Error(`process exited early (code ${code})`)); }
        });
    });
}
