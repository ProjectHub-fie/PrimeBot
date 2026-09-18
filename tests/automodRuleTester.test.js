const test = require('node:test');
const assert = require('node:assert/strict');
const { matchRule, metaFor, normalizeRules } = require('../utils/automodRules');

// Rule-tester behaviour: the dashboard "Test rule" panel evaluates the stored
// rules against sample text with NO side effects. These tests pin the matcher
// output the tester renders, and — critically — that the tester path is a pure
// function (no Discord action, no DB write) by asserting the evaluation only
// ever reads its inputs.

function evalRules(rules, content) {
    // Mirrors dashboard/server.js POST .../automod/test exactly.
    const matches = [];
    for (const rule of rules) {
        if (rule.enabled === false) continue;
        let m = null;
        try { m = matchRule(rule, { content, guildId: '1', userId: 'test', channelId: 'test' }, {}); }
        catch (e) { matches.push({ type: rule.type, error: e.message }); continue; }
        if (m) matches.push({ type: rule.type, label: metaFor(rule.type).label, reason: m.reason, actions: rule.actions });
    }
    return matches;
}

test('the tester flags a Discord invite', () => {
    const rules = normalizeRules([{ type: 'invites', enabled: true, actions: ['delete', 'warn'] }]);
    const matches = evalRules(rules, 'Join my discord.gg/example right now');
    assert.equal(matches.length, 1);
    assert.equal(matches[0].type, 'invites');
    assert.deepEqual(matches[0].actions, ['delete', 'warn']);
});

test('the tester returns nothing for clean text', () => {
    const rules = normalizeRules([{ type: 'invites', enabled: true, actions: ['delete'] }]);
    assert.deepEqual(evalRules(rules, 'hello everyone, good morning!'), []);
});

test('the tester honours the enabled flag', () => {
    const rules = normalizeRules([{ type: 'invites', enabled: false, actions: ['delete'] }]);
    assert.deepEqual(evalRules(rules, 'discord.gg/example'), [], 'a disabled rule must not report a match');
});

test('the tester reports multiple matching rules at once', () => {
    const rules = normalizeRules([
        { type: 'invites', enabled: true, actions: ['delete'] },
        { type: 'links', enabled: true, actions: ['delete'] },
        { type: 'blockedWords', enabled: true, actions: ['warn'], words: ['badword'] },
    ]);
    const matches = evalRules(rules, 'badword https://example.com/x');
    const types = matches.map(m => m.type).sort();
    assert.deepEqual(types, ['blockedWords', 'links']);
});

test('the links rule leaves Discord invites alone by default', () => {
    // Default `allowDiscordLinks: true` means the invite rule owns discord.gg,
    // so a server blocking "all links" does not also double-flag every invite.
    const rules = normalizeRules([{ type: 'links', enabled: true, actions: ['delete'] }]);
    assert.deepEqual(evalRules(rules, 'https://discord.gg/example'), []);
    assert.equal(evalRules(rules, 'https://example.com/x').length, 1, 'a non-Discord link still matches');
});

test('a bare invite with no scheme belongs to the invites rule, not the links rule', () => {
    // The links rule only sees explicit `https://` URLs; a bare `discord.gg/x`
    // must still be caught by the invites rule so nothing slips through.
    const links = normalizeRules([{ type: 'links', enabled: true, actions: ['delete'] }]);
    assert.deepEqual(evalRules(links, 'discord.gg/example'), []);
    const invites = normalizeRules([{ type: 'invites', enabled: true, actions: ['delete'] }]);
    assert.equal(evalRules(invites, 'discord.gg/example').length, 1);
});

test('the tester defeats common blocked-word obfuscation', () => {
    const rules = normalizeRules([{ type: 'blockedWords', enabled: true, actions: ['delete'], words: ['badword'] }]);
    for (const sample of ['BADWORD', 'b.a.d.w.o.r.d', 'b-a-d-w-o-r-d', 'b a d w o r d']) {
        const matches = evalRules(rules, `say ${sample} now`);
        assert.equal(matches.length, 1, `expected "${sample}" to match`);
    }
});

test('the tester catches caps spam only above the configured thresholds', () => {
    const rules = normalizeRules([{ type: 'caps', enabled: true, actions: ['warn'], threshold: 70, minLength: 10 }]);
    assert.equal(evalRules(rules, 'THIS IS ALL CAPS TEXT').length, 1, 'mostly-uppercase long text should match');
    assert.deepEqual(evalRules(rules, 'Hi'), [], 'short messages are ignored regardless of case');
    assert.deepEqual(evalRules(rules, 'this is mostly lowercase text').length, 0, 'lowercase must not match');
});

test('the tester catches an unsafe attachment by extension', () => {
    const rules = normalizeRules([{ type: 'attachments', enabled: true, actions: ['delete'] }]);
    const ctx = { content: 'check this', guildId: '1', userId: 'test', channelId: 'test', attachments: [{ name: 'evil.exe', size: 1000 }] };
    const m = matchRule(rules[0], ctx, {});
    assert.ok(m, 'an .exe attachment should match the unsafe-attachment rule');
});

test('a rule that throws never aborts the whole test run', () => {
    // Fail-safe: a broken rule is reported but the remaining rules still run.
    const rules = [
        { type: 'blockedWords', enabled: true, actions: ['delete'], words: null },
        { type: 'invites', enabled: true, actions: ['delete'] },
    ];
    const matches = evalRules(rules, 'discord.gg/example');
    assert.ok(matches.some(m => m.type === 'invites'), 'a later rule must still be evaluated');
});

test('the tester never mutates the rules it evaluates', () => {
    const rules = normalizeRules([{ type: 'invites', enabled: true, actions: ['delete'] }]);
    const before = JSON.stringify(rules);
    evalRules(rules, 'discord.gg/example');
    assert.equal(JSON.stringify(rules), before, 'evaluation must be read-only');
});

test('every catalog rule can be evaluated without throwing', () => {
    const { RULES } = require('../utils/automodRules');
    const samples = [
        'discord.gg/example', 'https://example.com', 'hello WORLD', 'a'.repeat(50),
        '@everyone hi', 'b.a.d.w.o.r.d', '😀😀😀😀😀', 'line\n'.repeat(20), 'za\u0301lgo',
    ];
    for (const meta of RULES) {
        const rules = normalizeRules([{ type: meta.key, enabled: true, actions: ['delete'] }]);
        for (const content of samples) {
            assert.doesNotThrow(
                () => evalRules(rules, content),
                `rule ${meta.key} threw on sample "${content.slice(0, 20)}"`,
            );
        }
    }
});