// Component-expiry scheduler (utils/stabilityUtils.js) — help-like menus
// (help, categories, sash help, prefix help, emoji lists, leaderboards)
// must have their buttons / dropdowns stripped 60s after being sent, so stale
// clickable controls don't linger and invite needless Discord interactions.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { scheduleComponentExpiry, MESSAGE_COMPONENT_TTL_MS } = require('../utils/stabilityUtils');

test('default TTL is 60 seconds', () => {
    assert.equal(MESSAGE_COMPONENT_TTL_MS, 60000);
});

test('scheduleComponentExpiry strips components after the ttl', async () => {
    let edited = null;
    const message = {
        deleted: false,
        editReply: (options) => {
            edited = options;
            return Promise.resolve();
        },
    };

    scheduleComponentExpiry(message, 25);
    assert.equal(edited, null, 'components are not stripped immediately');
    await new Promise(resolve => setTimeout(resolve, 80));
    assert.deepEqual(edited, { components: [] });
});

test('scheduleComponentExpiry skips deleted messages', async () => {
    let edited = false;
    const message = {
        deleted: true,
        edit: () => {
            edited = true;
            return Promise.resolve();
        },
    };

    scheduleComponentExpiry(message, 25);
    await new Promise(resolve => setTimeout(resolve, 80));
    assert.equal(edited, false, 'deleted message is never edited');
});

test('scheduleComponentExpiry falls back to edit for plain channel messages', async () => {
    let edited = null;
    const message = {
        deleted: false,
        edit: (options) => {
            edited = options;
            return Promise.resolve();
        },
    };

    scheduleComponentExpiry(message, 25);
    await new Promise(resolve => setTimeout(resolve, 80));
    assert.deepEqual(edited, { components: [] });
});

test('scheduleComponentExpiry tolerates edit failures', async () => {
    const message = {
        deleted: false,
        editReply: () => Promise.reject(new Error('missing permission')),
    };
    scheduleComponentExpiry(message, 25);
    await new Promise(resolve => setTimeout(resolve, 80));
    assert.ok(true, 'edit failure is swallowed');
});

test('scheduleComponentExpiry returns early on falsy message', () => {
    assert.doesNotThrow(() => scheduleComponentExpiry(null));
});