const test = require('node:test');
const assert = require('node:assert/strict');

const { buildCommandDocs } = require('../dashboard/commandDocs');
const { channelOptions, roleOptions } = require('../dashboard/render/layout');
const prefixHelp = require('../utils/prefixHelp');

function namesInHelp(catalog, categoryKey) {
  return (catalog[categoryKey].commands || []).flatMap(c => c.names);
}

test('docs metadata covers rmr and appealchannel with real descriptions', () => {
  const docs = buildCommandDocs();
  const rmr = docs.commands.find(c => c.name === 'rmr');
  const appeal = docs.commands.find(c => c.name === 'appealchannel');
  assert.ok(rmr, 'rmr should be auto-extracted');
  assert.ok(appeal, 'appealchannel should be auto-extracted');
  assert.match(rmr.description, /[A-Za-z]/, 'rmr should have a curated description');
  assert.match(appeal.description, /[a-z]/, 'appealchannel should have a curated description');
  assert.equal(rmr.category, 'Moderation');
  assert.equal(appeal.category, 'Moderation');
});

test('prefix help catalog includes rmr, appealchannel and dev', () => {
  const mod = namesInHelp(prefixHelp.CATALOG, 'moderation');
  assert.ok(mod.includes('rmr'), 'rmr missing from prefix help moderation');
  assert.ok(mod.includes('appealchannel'), 'appealchannel missing from prefix help moderation');
  const admin = namesInHelp(prefixHelp.CATALOG, 'admin');
  assert.ok(admin.includes('dev'), 'dev missing from prefix help admin');
});

test('channelOptions preserves a saved selection missing from the (incomplete) list', () => {
  const html = channelOptions([
    { id: '111', name: 'general' },
  ], '222');
  assert.match(html, /<option value="222" selected>#222/);
  // Selections present in the list are unchanged.

  const normal = channelOptions([
    { id: '111', name: 'general' },
  ], '111');

  assert.doesNotMatch(normal, /kept —/);
});