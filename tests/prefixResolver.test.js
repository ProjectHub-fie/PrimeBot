const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeGuildPrefix } = require('../utils/prefixHelper');

test('normalizes a valid custom prefix', () => {
  assert.equal(normalizeGuildPrefix('!'), '!');
  assert.equal(normalizeGuildPrefix('  !  '), '!');
});

test('falls back when the prefix is empty or invalid', () => {
  assert.equal(normalizeGuildPrefix('   ', '$'), '$');
  assert.equal(normalizeGuildPrefix('long prefix', '$'), '$');
});
