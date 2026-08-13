const test = require('node:test');
const assert = require('node:assert/strict');

const {
    RULES,
    RULE_BY_KEY,
    ACTIONS,
    normalizeRules,
    normalizeAction,
    normalizeActions,
    normalizeWarnActions,
    normalizeDmMessages,
    metaFor,
    matchRule,
    renderDmMessage,
    DEFAULT_DM_MESSAGES,
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
    assert.deepEqual(out[0], { type: 'invites', enabled: true, action: 'delete', actions: ['delete'] });
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

// ── New rule types ────────────────────────────────────────────────────────────

test('badLinks flags impersonation domains but whitelists the real ones', () => {
    const rule = { type: 'badLinks', enabled: true, actions: ['delete'] };
    assert.ok(matchRule(rule, { ...CTX, content: 'free nitro https://discrod.com/gift' }));
    assert.ok(matchRule(rule, { ...CTX, content: 'https://steamcommunitty.com/login' }));
    // Real discord link is whitelisted.
    assert.equal(matchRule(rule, { ...CTX, content: 'https://discord.com/channels/x' }), null);
    // No link.
    assert.equal(matchRule(rule, { ...CTX, content: 'no links here' }), null);
});

test('badLinks honours custom domains from the words param', () => {
    const rule = { type: 'badLinks', enabled: true, actions: ['delete'], words: ['evilphish'] };
    assert.ok(matchRule(rule, { ...CTX, content: 'https://evilphish.example/steal' }));
    assert.equal(matchRule(rule, { ...CTX, content: 'https://example.com/ok' }), null);
});

test('nsfw matches built-in and custom terms', () => {
    const rule = { type: 'nsfw', enabled: true, actions: ['delete'], words: ['mybadsite'] };
    assert.ok(matchRule(rule, { ...CTX, content: 'check out this porn video' }));
    assert.ok(matchRule(rule, { ...CTX, content: 'go to mybadsite now' }));
    assert.equal(matchRule(rule, { ...CTX, content: 'a normal message about cooking' }), null);
});

test('repeatedChars trips on a long run of the same character', () => {
    const rule = { type: 'repeatedChars', enabled: true, actions: ['delete'], threshold: 8 };
    assert.ok(matchRule(rule, { ...CTX, content: 'aaaaaaaaa spam' }));
    assert.equal(matchRule(rule, { ...CTX, content: 'aaaa not enough' }), null); // 4 < 8
});

test('newAccount trips when the author account is younger than the threshold', () => {
    const rule = { type: 'newAccount', enabled: true, actions: ['kick'], threshold: 7 };
    const young = { ...CTX, content: 'hi', authorCreatedAt: new Date(Date.now() - 1 * 86400000) };
    const old = { ...CTX, content: 'hi', authorCreatedAt: new Date(Date.now() - 365 * 86400000) };
    assert.ok(matchRule(rule, young));
    assert.equal(matchRule(rule, old), null);
    // Missing createdAt never matches (no false positives).
    assert.equal(matchRule(rule, { ...CTX, content: 'hi' }), null);
});

// ── Multi-action normalization ────────────────────────────────────────────────

test('normalizeActions accepts a string or array and dedupes, dropping unknowns', () => {
    assert.deepEqual(normalizeActions(['warn', 'ban', 'ban', 'x', '']), ['warn', 'ban']);
    assert.deepEqual(normalizeActions('kick'), ['kick']);
    assert.deepEqual(normalizeActions([], 'delete'), ['delete']);
    assert.deepEqual(normalizeActions(null, 'warn'), ['warn']);
});

test('normalizeRules produces a multi-action rule from actions and from legacy action', () => {
    const out = normalizeRules([
        { type: 'spam', enabled: true, actions: ['warn', 'delete'], threshold: 3, seconds: 5 },
        { type: 'invites', action: 'ban' }, // legacy single action
    ]);
    assert.deepEqual(out[0].actions, ['warn', 'delete']);
    assert.equal(out[0].action, 'warn'); // action mirrors actions[0]
    assert.deepEqual(out[1].actions, ['ban']);
    assert.equal(out[1].action, 'ban');
});

test('normalizeWarnActions drops delete and dedupes, falling back to a default', () => {
    assert.deepEqual(normalizeWarnActions(['delete', 'timeout', 'ban', 'timeout']), ['timeout', 'ban']);
    assert.deepEqual(normalizeWarnActions(['warn', 'kick']), ['warn', 'kick']);
    assert.deepEqual(normalizeWarnActions([], 'timeout'), ['timeout']);
});

// ── DM messages ───────────────────────────────────────────────────────────────

test('normalizeDmMessages keeps non-empty string overrides and drops the rest', () => {
    assert.deepEqual(normalizeDmMessages({ warn: '  ', ban: 'You are banned', delete: 123 }), { ban: 'You are banned' });
    assert.deepEqual(normalizeDmMessages(null), {});
});

test('renderDmMessage substitutes placeholders and falls back to the default', () => {
    const out = renderDmMessage('ban', { server: 'My Server', reason: 'spam' });
    assert.ok(out.includes('My Server'));
    assert.ok(out.includes('spam'));
    assert.ok(out.includes('banned'));
    const custom = renderDmMessage('warn', { server: 'S', reason: 'r' }, { warn: 'Custom {server} {reason}' });
    assert.equal(custom, 'Custom S r');
});

test('DEFAULT_DM_MESSAGES covers every action plus escalation', () => {
    for (const key of ['delete', 'warn', 'timeout', 'kick', 'ban', 'escalation']) {
        assert.ok(typeof DEFAULT_DM_MESSAGES[key] === 'string' && DEFAULT_DM_MESSAGES[key].length > 0, `missing default for ${key}`);
    }
});

test('every new rule type has a catalog entry and a matcher', () => {
    for (const key of ['badLinks', 'nsfw', 'repeatedChars', 'newAccount']) {
        assert.ok(RULE_BY_KEY[key], `RULE_BY_KEY missing ${key}`);
    }
});
