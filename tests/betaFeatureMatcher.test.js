const test = require('node:test');
const assert = require('node:assert/strict');

const { getBetaFeatureCandidates, isBetaFeature } = require('../utils/betaFeatureMatcher');

test('expands slash subcommands for beta feature matching', () => {
  const candidates = getBetaFeatureCandidates('leveling', 'badges');
  assert.deepEqual(candidates, ['leveling', 'badges', 'leveling:badges']);
  assert.equal(isBetaFeature('leveling', 'badges', null, ['badges']), true);
  assert.equal(isBetaFeature('leveling', 'badges', null, ['leveling:badges']), true);
});

test('matches nested subcommand groups when present', () => {
  assert.equal(isBetaFeature('admin', 'manage', 'roles', ['roles']), true);
});
