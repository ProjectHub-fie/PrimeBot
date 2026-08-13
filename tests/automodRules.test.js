const test = require('node:test');
const assert = require('node:assert/strict');

const {
    RULES,
    RULE_BY_KEY,
    ACTIONS,
    normalizeRules,
    normalizeAction,
    metaFor,
    matchRule,
} = require('../utils/automodRules');

const CTX = { guildId: 'g1', userId: 'u1', channelId: 'c1' };

// ── Catalog ──────────────────────────────────────────────────────────────────

test('RULES are unique, well-formed, and reachable via RULE_BY_KEY', () => {
    const keys = RULES.map(r => r.key);
    assert.equal(new Set(keys).size, keys.length, 'rule keys must be unique');
    for (const r of RULES) {
        assert.ok(r.key && r.label && r.icon, `rule ${r.key} missing label/icon`);
        assert.ok(Array.isArray(r.params), `rule ${r.key} params must be an array`);
        assert.deepEqual(RULE_BY_KEY[r.key], r, `RULE_BY_KEY missing ${r.key}`);
    }
});

test('ACTIONS are unique and every action has a key/icon/label', () => {
    const keys = ACTIONS.map(a => a.key);
    assert.equal(new Set(keys).size, keys.length, 'action keys must be unique');
    for (const a of ACTIONS) assert.ok(a.key && a.label && a.icon, 'action missing fields');
});

// ── normalizeRules / normalizeAction ──────────────────────────────────────────

test('normalizeRules coerces a messy rules array into clean objects', () => {
    const out = normalizeRules([
        { type: 'invites', enabled: true, action: 'delete' },
        { type: 'unknownRule', action: 'delete' }, // unknown types are dropped
        { type: 'blockedWords', words: ['Bad', 'Worse'], action: 'warn', enabled: false },
        { type: 'mentions', threshold: 7, action: 'timeout' },
        'not-an-object',
        { type: 'links' }, // missing action defaults to 'delete'
    ]);
    assert.equal(out.length, 4);
    assert.deepEqual(out[0], { type: 'invites', enabled: true, action: 'delete' });
    assert.equal(out[1].type, 'blockedWords');
    assert.deepEqual(out[1].words, ['bad', 'worse']); // lowercased + trimmed
    assert.equal(out[1].enabled, false);
    assert.equal(out[2].threshold, 7);
    assert.equal(out[3].action, 'delete'); // default action
});

test('normalizeRules handles non-array input and missing rules', () => {
    assert.deepEqual(normalizeRules(null), []);
    assert.deepEqual(normalizeRules(undefined), []);
    assert.deepEqual(normalizeRules('hello'), []);
});

test('normalizeAction falls back to the default for unknown actions', () => {
    assert.equal(normalizeAction('ban', 'delete'), 'ban');
    assert.equal(normalizeAction('notReal', 'delete'), 'delete');
    assert.equal(normalizeAction(null, 'timeout'), 'timeout');
});

// ── matchRule: per-rule behavior ──────────────────────────────────────────────

test('blockedWords matches a configured word (case-insensitive) and returns a reason', () => {
    const rule = { type: 'blockedWords', enabled: true, action: 'delete', words: ['spam', 'idiot'] };
    assert.equal(matchRule(rule, { ...CTX, content: 'You are an IDIOT' }).reason, 'Blocked word: `idiot`');
    assert.equal(matchRule(rule, { ...CTX, content: 'hello friend' }), null);
});

test('invites matches discord.gg and discord.com/invite links', () => {
    const rule = { type: 'invites', enabled: true, action: 'delete' };
    assert.ok(matchRule(rule, { ...CTX, content: 'join https://discord.gg/abc' }));
    assert.ok(matchRule(rule, { ...CTX, content: 'discord.com/invite/xyz' }));
    assert.equal(matchRule(rule, { ...CTX, content: 'just chatting' }), null);
});

test('links matches any URL', () => {
    const rule = { type: 'links', enabled: true, action: 'delete' };
    assert.ok(matchRule(rule, { ...CTX, content: 'see http://example.com/x' }));
    assert.equal(matchRule(rule, { ...CTX, content: 'no link here' }), null);
});

test('mentions counts user + role mentions against the threshold', () => {
    const rule = { type: 'mentions', enabled: true, action: 'warn', threshold: 3 };
    assert.equal(matchRule(rule, { ...CTX, content: '<@1> <@2> <@3>' }).reason, 'Mass mentions (3/3)');
    assert.equal(matchRule(rule, { ...CTX, content: '<@1> <@&2>' }), null);
});

test('spam tracks rapid duplicates across calls within the window', () => {
    const rule = { type: 'spam', enabled: true, action: 'delete', threshold: 3, seconds: 5 };
    const spamState = new Map();
    assert.equal(matchRule(rule, { ...CTX, content: 'spam me' }, spamState), null);
    assert.equal(matchRule(rule, { ...CTX, content: 'spam me' }, spamState), null);
    const third = matchRule(rule, { ...CTX, content: 'spam me' }, spamState);
    assert.ok(third, 'third duplicate should trip spam');
    assert.ok(third.reason.startsWith('Spam ('));
});

test('spam ignores messages outside its time window', () => {
    const rule = { type: 'spam', enabled: true, action: 'delete', threshold: 3, seconds: 1 };
    const spamState = new Map();
    // Inject an old entry to simulate expiry.
    spamState.set(`${CTX.guildId}|${CTX.userId}`, [
        { content: 'old', ts: Date.now() - 10_000 },
    ]);
    assert.equal(matchRule(rule, { ...CTX, content: 'new' }, spamState), null);
});

test('caps requires enough letters and clears the percentage threshold', () => {
    const rule = { type: 'caps', enabled: true, action: 'delete', threshold: 70 };
    assert.ok(matchRule(rule, { ...CTX, content: 'HELLO WORLD THIS IS LOUD' }));
    assert.equal(matchRule(rule, { ...CTX, content: 'HI' }), null); // too short
    assert.equal(matchRule(rule, { ...CTX, content: 'Hello World' }), null); // mixed case
});

test('emojiSpam counts custom + unicode emoji against the threshold', () => {
    const rule = { type: 'emojiSpam', enabled: true, action: 'delete', threshold: 3 };
    assert.ok(matchRule(rule, { ...CTX, content: '😀 😃 😄' }));
    assert.equal(matchRule(rule, { ...CTX, content: '😀' }), null);
});

test('newlines trips on a wall of text', () => {
    const rule = { type: 'newlines', enabled: true, action: 'delete', threshold: 5 };
    const wall = Array(5).fill('line').join('\n');
    assert.ok(matchRule(rule, { ...CTX, content: wall }));
    assert.equal(matchRule(rule, { ...CTX, content: 'one line' }), null);
});

test('zalgo trips on combining marks', () => {
    const rule = { type: 'zalgo', enabled: true, action: 'delete' };
    const zalgo = 'h̵e̸l̷l̴o̸ ̷w̵o̷r̸l̵d̷';
    assert.ok(matchRule(rule, { ...CTX, content: zalgo }));
    assert.equal(matchRule(rule, { ...CTX, content: 'hello world' }), null);
});

test('disabled rules never match', () => {
    const rule = { type: 'blockedWords', enabled: false, action: 'delete', words: ['bad'] };
    assert.equal(matchRule(rule, { ...CTX, content: 'this is bad' }), null);
});

test('unknown rule types return null', () => {
    assert.equal(matchRule({ type: 'nope', enabled: true, action: 'delete' }, { ...CTX, content: 'x' }), null);
    assert.equal(matchRule(null, { ...CTX, content: 'x' }), null);
});

// ── metaFor ───────────────────────────────────────────────────────────────────

test('metaFor returns the catalog entry or a safe fallback for unknown types', () => {
    assert.equal(metaFor('invites').label, 'Discord invites');
    assert.equal(metaFor('totallyUnknown').key, 'totallyUnknown');
    assert.ok(metaFor('totallyUnknown').icon);
});
