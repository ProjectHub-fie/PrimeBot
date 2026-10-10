/**
 * A failover step-down must not be a clean exit.
 *
 * When a higher-priority node returns, the active lower-priority node calls
 * stepDown(): it releases the lease, destroys its Discord client, and exits. It
 * cannot re-login in-process (discord.js marks its WS manager destroyed and
 * reuses the dead manager on a same-token login), so it must be replaced by a
 * fresh process that boots back into standby.
 *
 * Both the hosting panel (Wispbyte/Pterodactyl) and the local launcher
 * (start-bot.js) treat exit code 0 as a clean, intentional shutdown and do NOT
 * restart. Exiting 0 therefore left a stepped-down sn2 permanently down while
 * sn1 was online ("sn2 crashed while sn1 came back, and it's not in standby").
 */
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { stepDownExitCode, STEP_DOWN_EXIT_CODE, DEFAULT_STEP_DOWN_EXIT_CODE } = require('../utils/failoverExit');

const INDEX_SRC = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
const LAUNCHER_SRC = fs.readFileSync(path.join(__dirname, '..', 'start-bot.js'), 'utf8');

test('the step-down exit code is non-zero so a supervisor restarts the node', () => {
    assert.notEqual(STEP_DOWN_EXIT_CODE, 0, 'exit 0 is read as a clean shutdown and never restarted');
    assert.equal(STEP_DOWN_EXIT_CODE, DEFAULT_STEP_DOWN_EXIT_CODE);
    assert.ok(STEP_DOWN_EXIT_CODE > 0 && STEP_DOWN_EXIT_CODE <= 255);
});

test('STEP_DOWN_EXIT_CODE is honoured, but only when it is a usable code', () => {
    assert.equal(stepDownExitCode({ STEP_DOWN_EXIT_CODE: '13' }), 13, 'a valid override is used');
    // A typo must never silently turn a step-down into a clean exit.
    assert.equal(stepDownExitCode({ STEP_DOWN_EXIT_CODE: '0' }), DEFAULT_STEP_DOWN_EXIT_CODE);
    assert.equal(stepDownExitCode({ STEP_DOWN_EXIT_CODE: 'abc' }), DEFAULT_STEP_DOWN_EXIT_CODE);
    assert.equal(stepDownExitCode({ STEP_DOWN_EXIT_CODE: '999' }), DEFAULT_STEP_DOWN_EXIT_CODE);
    assert.equal(stepDownExitCode({}), DEFAULT_STEP_DOWN_EXIT_CODE);
});

test('stepDown exits with the non-zero step-down code, never 0', () => {
    const body = INDEX_SRC.match(/async function stepDown\(reason\)\s*\{[\s\S]*?\n\}/)[0];
    assert.match(body, /process\.exit\(STEP_DOWN_EXIT_CODE\)/, 'stepDown must exit with the step-down code');
    assert.ok(
        !/process\.exit\(0\)/.test(body),
        'stepDown must not exit 0 — that is what stops a stepped-down standby from coming back'
    );
    // Regression: the exact old line that caused the "sn2 vanished" report.
    assert.ok(
        INDEX_SRC.indexOf('process.exit(0), 500') === -1,
        'the delayed clean exit that killed a stepped-down node must be gone'
    );
});

test('the launcher does not restart on a clean exit but does on a step-down code', () => {
    // start-bot.js intentionally treats code 0 as "user asked to stop". That is
    // precisely why the step-down must NOT use 0.
    assert.match(LAUNCHER_SRC, /if \(code === 0\)/, 'launcher special-cases a clean exit');
    assert.match(LAUNCHER_SRC, /scheduleRestart\(code\)/, 'launcher restarts on a non-zero code');
});
