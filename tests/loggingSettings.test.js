const test = require('node:test');
const assert = require('node:assert/strict');

const {
    LOG_EVENTS,
    LOG_EVENT_KEYS,
    DEFAULT_ENABLED_EVENTS,
    normalizeEvents,
    isEventEnabled,
    metaFor,
} = require('../utils/logEvents');
const { buildLogEmbed, buildLogEmbedObject, colorInt } = require('../utils/serverLogger');

// ── logEvents ───────────────────────────────────────────────────────────────

test('every log event has a stable key, label, icon and hex color', () => {
    for (const e of LOG_EVENTS) {
        assert.ok(typeof e.key === 'string' && e.key.length > 0);
        assert.ok(typeof e.label === 'string' && e.label.length > 0);
        assert.ok(typeof e.icon === 'string' && e.icon.length > 0);
        assert.match(e.color, /^#[0-9a-fA-F]{6}$/);
        assert.ok(typeof e.category === 'string' && e.category.length > 0);
    }
});

test('event keys are unique', () => {
    const set = new Set(LOG_EVENT_KEYS);
    assert.equal(set.size, LOG_EVENT_KEYS.length);
});

test('normalizeEvents keeps known keys and drops unknown ones, dedupes', () => {
    assert.deepEqual(
        normalizeEvents(['memberJoin', 'memberJoin', 'bogus', 'messageDelete']),
        ['memberJoin', 'messageDelete']
    );
    assert.deepEqual(normalizeEvents('not-an-array'), []);
    assert.deepEqual(normalizeEvents([42, null, 'memberBan']), ['memberBan']);
});

test('isEventEnabled respects the master switch and the event list', () => {
    assert.equal(isEventEnabled({ enabled: true, events: ['memberJoin'] }, 'memberJoin'), true);
    // master switch off → never enabled
    assert.equal(isEventEnabled({ enabled: false, events: ['memberJoin'] }, 'memberJoin'), false);
    // event not in list
    assert.equal(isEventEnabled({ enabled: true, events: ['memberJoin'] }, 'messageDelete'), false);
    // missing settings
    assert.equal(isEventEnabled(null, 'memberJoin'), false);
    assert.equal(isEventEnabled({}, 'memberJoin'), false);
});

test('default enabled events are all valid keys', () => {
    const valid = new Set(LOG_EVENT_KEYS);
    for (const k of DEFAULT_ENABLED_EVENTS) {
        assert.ok(valid.has(k), `default event ${k} is not a known event`);
    }
});

test('metaFor returns metadata for known keys and a sane fallback for unknown', () => {
    assert.equal(metaFor('memberBan').icon, '🔨');
    const m = metaFor('doesNotExist');
    assert.equal(m.key, 'doesNotExist');
    assert.match(m.color, /^#[0-9a-fA-F]{6}$/);
});

// ── serverLogger ────────────────────────────────────────────────────────────

test('colorInt parses hex colors and falls back to blurple', () => {
    assert.equal(colorInt('#5865F2'), 0x5865F2);
    assert.equal(colorInt('5865F2'), 0x5865F2);
    assert.equal(colorInt('#ED4245'), 0xED4245);
    assert.equal(colorInt(null), 0x5865F2);
    assert.equal(colorInt('not-a-color'), 0x5865F2);
});

test('buildLogEmbed sets the icon-prefixed title, color, footer and fields', () => {
    const embed = buildLogEmbed({
        type: 'memberBan',
        title: 'Member Banned',
        description: 'naughty#1',
        fields: [{ name: 'Reason', value: 'spam', inline: false }],
    });
    const data = embed.toJSON();

    assert.match(data.title, /🔨 Member Banned/);
    assert.equal(data.color, 0xED4245); // memberBan default color
    assert.equal(data.description, 'naughty#1');
    assert.ok(data.fields.some(f => f.name === 'Reason' && f.value === 'spam'));
    assert.match(data.footer.text, /PrimeBot Logging/);
    assert.ok(data.timestamp, 'timestamp is set');
});

test('buildLogEmbed prefers an explicit color over the event default', () => {
    const data = buildLogEmbed({ type: 'memberBan', color: '#57F287' }).toJSON();
    assert.equal(data.color, 0x57F287);
});

test('buildLogEmbed skips fields with missing name/value', () => {
    const data = buildLogEmbedObject({
        type: 'commandUse',
        fields: [
            { name: 'Channel', value: '#general' },
            { name: 'Empty', value: '' },      // empty string value → dropped
            { name: '', value: 'x' },          // empty name → dropped
            { value: 'no-name' },              // no name → dropped
        ],
    });
    const names = data.fields.map(f => f.name);
    assert.deepEqual(names, ['Channel']);
});

test('buildLogEmbedObject produces a plain object usable as a webhook payload', () => {
    const obj = buildLogEmbedObject({ type: 'memberJoin', title: 'Member Joined' });
    assert.equal(typeof obj, 'object');
    assert.ok(!Array.isArray(obj));
    assert.ok(obj.title && obj.color != null);
});
