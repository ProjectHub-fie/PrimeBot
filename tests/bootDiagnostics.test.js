// Boot-log correctness: a deleted failover webhook must not be retried forever,
// and the Anti-Nuke readiness diagnostic must run after the manager exists.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');

const ROOT = path.join(__dirname, '..');
const indexSrc = fs.readFileSync(path.join(ROOT, 'index.js'), 'utf8');

// ── failover webhook: deleted webhook (HTTP 404) ──────────────────────────

function withFakeHttps(statusCode, run) {
    const requests = [];
    const original = https.request;
    https.request = (options, callback) => {
        const req = {
            on() { return req; },
            write() { return req; },
            end() {
                requests.push(options);
                callback({ statusCode, resume() {} });
            },
        };
        return req;
    };
    try {
        return run(requests);
    } finally {
        https.request = original;
    }
}

function captureConsole(run) {
    const lines = [];
    const original = { error: console.error, warn: console.warn, log: console.log };
    console.error = (...args) => lines.push(args.join(' '));
    console.warn = (...args) => lines.push(args.join(' '));
    console.log = (...args) => lines.push(args.join(' '));
    try {
        return run(lines);
    } finally {
        Object.assign(console, original);
    }
}

test('a deleted failover webhook is reported once and then disabled', () => {
    const logger = require('../utils/webhookLogger');
    logger.reset();
    process.env.FAILOVER_WEBHOOK_URL = 'https://discord.com/api/webhooks/123/supersecrettoken';

    withFakeHttps(404, (requests) => {
        captureConsole((lines) => {
            logger.send({ title: 'Online', type: 'online' });
            assert.equal(requests.length, 1, 'first send posts');
            assert.equal(logger.isDisabled(), true, 'a 404 disables the webhook');
            const text = lines.join('\n');
            assert.match(text, /HTTP 404/);
            assert.match(text, /webhook was deleted|channel no longer exists/);
            assert.match(text, /FAILOVER_WEBHOOK_URL/);
            assert.ok(!text.includes('supersecrettoken'), 'the webhook URL/token is never logged');

            // Later failover events must not hit the dead webhook again.
            logger.send({ title: 'Offline', type: 'offline' });
            logger.send({ title: 'Standby', type: 'standby' });
            assert.equal(requests.length, 1, 'no further requests after the permanent failure');
        });
    });

    logger.reset();
    delete process.env.FAILOVER_WEBHOOK_URL;
});

test('a transient 5xx keeps the webhook enabled', () => {
    const logger = require('../utils/webhookLogger');
    logger.reset();
    process.env.FAILOVER_WEBHOOK_URL = 'https://discord.com/api/webhooks/123/token';

    withFakeHttps(503, (requests) => {
        captureConsole(() => {
            logger.send({ title: 'Online', type: 'online' });
            logger.send({ title: 'Offline', type: 'offline' });
        });
    });

    assert.equal(logger.isDisabled(), false, '5xx is retried on the next event');
    logger.reset();
    delete process.env.FAILOVER_WEBHOOK_URL;
});

// ── Anti-Nuke readiness diagnostic ───────────────────────────────────────

function loadReadinessFn() {
    const match = indexSrc.match(/function reportAntiNukeReadiness\(client\) \{[\s\S]*?\n\}/);
    assert.ok(match, 'reportAntiNukeReadiness is defined in index.js');
    const factory = new Function(
        'GatewayIntentBits',
        `${match[0]}\nreturn reportAntiNukeReadiness;`
    );
    return factory({ GuildModeration: 1n });
}

function fakeClient({ manager = true, intent = true, listener = true } = {}) {
    return {
        antiNukeManager: manager ? { processEvent: async () => {} } : undefined,
        options: { intents: { has: () => intent } },
        listeners: () => (listener ? [{ name: 'guildAuditLogEntryCreate' }] : []),
    };
}

test('the Anti-Nuke diagnostic reports OPERATIONAL when the wiring is complete', () => {
    const readiness = loadReadinessFn();
    captureConsole((lines) => {
        assert.equal(readiness(fakeClient()), true);
        assert.match(lines.join('\n'), /Primary detection path OPERATIONAL/);
        assert.doesNotMatch(lines.join('\n'), /NOT fully operational/);
    });
});

test('the Anti-Nuke diagnostic names only what is actually missing', () => {
    const readiness = loadReadinessFn();

    captureConsole((lines) => {
        assert.equal(readiness(fakeClient({ manager: false })), false);
        const text = lines.join('\n');
        assert.match(text, /NOT fully operational — missing: AntiNukeManager\.processEvent\./);
        assert.doesNotMatch(text, /missing: [^.]*GuildModeration/, 'the intent is not listed as missing');
    });

    captureConsole((lines) => {
        assert.equal(readiness(fakeClient({ intent: false })), false);
        assert.match(lines.join('\n'), /missing: GuildModeration intent\./);
    });

    captureConsole((lines) => {
        assert.equal(readiness(fakeClient({ listener: false })), false);
        assert.match(lines.join('\n'), /missing: guildAuditLogEntryCreate handler\./);
    });
});

test('index.js runs the diagnostic after the managers exist, never at module scope', () => {
    const initBlock = indexSrc.slice(indexSrc.indexOf('async function initializeManagers'));
    const callIndex = initBlock.indexOf('reportAntiNukeReadiness(client)');
    const managersDone = initBlock.indexOf("[MANAGERS] All managers initialized.");
    assert.ok(callIndex > managersDone, 'diagnostic runs after "[MANAGERS] All managers initialized."');

    // The old module-scope block (a bare `try {` reading client.antiNukeManager)
    // must be gone, otherwise it reports a false negative again.
    const beforeInit = indexSrc.slice(0, indexSrc.indexOf('async function initializeManagers'));
    assert.doesNotMatch(beforeInit, /const anManager = client\.antiNukeManager/);
});

test('the standby boot line no longer claims managers are skipped', () => {
    assert.match(indexSrc, /standby mode \(all managers load so takeover is instant/);
    assert.doesNotMatch(indexSrc, /skipping heavy managers to save memory/);
});
