// Embed Builder — client logic tests (vm sandbox over the REAL script).
//
// The client exposes a pure, DOM-free facade (window.PrimeBotEmbedBuilder) for
// the validation / import / export / template primitives. These tests exercise
// that real code path deterministically — no DOM, no network, no Postgres.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'embed-builder.js'), 'utf8');

// Run the real script in a sandbox; returns window.PrimeBotEmbedBuilder.
function makeBuilder() {
  const location = { href: '' };
  const windowObj = {
    location,
    addEventListener: () => {},
    svgIcon: () => '',
  };
  const doc = {
    readyState: 'complete',
    getElementById: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
  };
  const sandbox = {
    window: windowObj,
    document: doc,
    Date, Math, JSON, parseInt, Promise, console,
    URL, // needed by isValidUrl()
    localStorage: {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    },
    navigator: {},
  };
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox);
  return windowObj.PrimeBotEmbedBuilder;
}

test('validation: Discord embed limits enforced', () => {
  const B = makeBuilder();
  const ok = B.validateState({
    title: 'x'.repeat(200), description: 'hello', color: '#5865F2',
    authorName: 'Short', footerText: 'fine', content: '', fields: [],
  });
  assert.equal(ok.errors.length, 0, 'valid embed passes');

  const long = B.validateState({ ...B.DEFAULT_STATE, title: 'x'.repeat(257) });
  assert.ok(long.errors.some((e) => e.includes('Title')), 'title > 256 rejected');

  const manyFields = B.validateState({ ...B.DEFAULT_STATE, fields: Array.from({ length: 26 }, (_, i) => ({ name: `f${i}`, value: 'v', inline: false })) });
  assert.ok(manyFields.errors.some((e) => e.includes('fields')), '26 fields rejected');

  const emptyField = B.validateState({ ...B.DEFAULT_STATE, fields: [{ name: '', value: '  ', inline: false }] });
  assert.ok(emptyField.errors.some((e) => e.includes('empty')), 'blank field rejected');

  // Total character budget.
  const huge = B.validateState({ ...B.DEFAULT_STATE, description: 'a'.repeat(5900), title: 't'.repeat(150) });
  assert.ok(huge.errors.some((e) => e.includes('Total')), 'over 6000 total rejected');
});

test('validation: URL/color handling', () => {
  const B = makeBuilder();
  assert.ok(B.validUrl('https://example.com/x.png'), 'https accepted');
  assert.ok(B.validUrl('http://example.com'), 'http accepted');
  assert.ok(!B.validUrl('javascript:alert(1)'), 'javascript: rejected');
  assert.ok(!B.validUrl('not-a-url'), 'bare text rejected');

  const bad = B.validateState({ ...B.DEFAULT_STATE, imageUrl: 'javascript:alert(1)' });
  assert.ok(bad.errors.some((e) => e.includes('Image URL')), 'unsafe image URL rejected');
});

test('normalizeImported: full message payload + bare embed both parse safely', () => {
  const B = makeBuilder();
  const msg = {
    content: 'Hello',
    embeds: [{
      title: 'T', description: 'D', color: 5793266,
      fields: [{ name: 'a', value: 'b', inline: true }],
      footer: { text: 'F' }, thumbnail: { url: 'https://x/t.png' },
    }],
  };
  const s = B.normalizeImported(msg);
  assert.equal(s.content, 'Hello');
  assert.equal(s.title, 'T');
  assert.equal(s.color.toLowerCase(), '#5865f2');
  assert.equal(s.fields.length, 1);
  assert.equal(s.fields[0].name, 'a');
  assert.equal(s.fields[0].value, 'b');
  assert.equal(s.fields[0].inline, true);
  assert.equal(s.thumbnailUrl, 'https://x/t.png');

  const bare = B.normalizeImported({ title: 'bare' });
  assert.equal(bare.title, 'bare');
  assert.equal(bare.fields.length, 0);

  const garbage = B.normalizeImported('nope');
  assert.ok(garbage && typeof garbage === 'object', 'garbage input degrades to empty state');
});

test('normalizeImported: javascript: URLs are stripped, never injected', () => {
  const B = makeBuilder();
  const s = B.normalizeImported({ embeds: [{ image: { url: 'javascript:alert(1)' }, footer: { icon_url: 'javascript:evil' } }] });
  // Import keeps the strings, but the exporter refuses them (validUrl check)
  // so they can never reach a payload.
  assert.equal(s.imageUrl, 'javascript:alert(1)');
  assert.equal(s.footerIcon, 'javascript:evil');
  const payload = B.buildPayload(s);
  assert.equal(payload.embeds.length, 1, 'embed kept');
  const embed = payload.embeds[0];
  assert.ok(!embed.image, 'unsafe image omitted');
  assert.ok(!embed.footer, 'unsafe footer omitted');
  assert.ok(!embed.author && !embed.thumbnail && !embed.url, 'only the safe color survives');
});

test('buildEmbedObject produces Discord-compatible JSON (color int, fields, timestamp)', () => {
  const B = makeBuilder();
  const s = {
    ...B.DEFAULT_STATE,
    title: 'Hello', description: 'World', color: '#5865F2', timestamp: true,
    url: 'https://example.com',
    footerEnabled: true, footerText: 'PrimeBot',
    fields: [{ name: 'A', value: 'B', inline: true }],
  };
  const obj = B.buildEmbedObject(s);
  assert.equal(obj.title, 'Hello');
  assert.equal(obj.color, 5793266, 'hex → int');
  assert.ok(typeof obj.timestamp === 'string' && !Number.isNaN(Date.parse(obj.timestamp)), 'timestamp is ISO string');
  assert.equal(obj.url, 'https://example.com');
  assert.equal(obj.fields.length, 1);
  assert.equal(obj.fields[0].name, 'A');
  assert.equal(obj.fields[0].value, 'B');
  assert.equal(obj.fields[0].inline, true);

  const payload = B.buildPayload(s);
  assert.equal(payload.embeds.length, 1);
  assert.equal(payload.embeds[0].title, 'Hello');
});

test('buildEmbedObject omits disabled sections entirely', () => {
  const B = makeBuilder();
  const s = {
    ...B.DEFAULT_STATE,
    authorEnabled: false, authorName: 'Ghost',
    thumbnailEnabled: false, thumbnailUrl: 'https://x/t.png',
    footerEnabled: false, footerText: 'No footer',
  };
  const obj = B.buildEmbedObject(s);
  assert.ok(!obj.author, 'disabled author omitted');
  assert.ok(!obj.thumbnail, 'disabled thumbnail omitted');
  assert.ok(!obj.footer, 'disabled footer omitted');
});

test('templates: every EMBED_TEMPLATES chips has a working TEMPLATES entry', () => {
  const B = makeBuilder();
  const chips = Object.keys(B.TEMPLATES);
  assert.ok(chips.length >= 11, 'at least 11 templates');
  for (const key of chips) {
    const t = B.TEMPLATES[key];
    const s = { ...B.DEFAULT_STATE, ...t };
    const v = B.validateState(s);
    assert.equal(v.errors.length, 0, `template ${key} is valid (${v.errors.join('; ')})`);
    assert.ok(t.title || t.description, `template ${key} has content`);
  }
});

test('totalCharacters reflects Discord embed size', () => {
  const B = makeBuilder();
  const s = { ...B.DEFAULT_STATE, title: '12345', description: 'abcdef' };
  assert.equal(B.totalCharacters(s), 11);
});

test('no eval / Function anywhere in the client', () => {
  assert.doesNotMatch(SRC, /\beval\s*\(/, 'no eval');
  assert.doesNotMatch(SRC, /\bnew\s+Function\b/, 'no new Function');
  assert.ok(SRC.includes('textContent'), 'preview built with textContent (XSS-safe)');
});