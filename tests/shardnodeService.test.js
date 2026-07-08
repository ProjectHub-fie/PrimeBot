const test = require('node:test');
const assert = require('node:assert/strict');

const { buildHeartbeatPayload } = require('../utils/shardnodeService');

test('buildHeartbeatPayload includes runtime and bot metadata', () => {
  const payload = buildHeartbeatPayload({
    client: {
      guilds: { cache: { size: 12 } },
      users: { cache: { size: 240 } },
      ws: { ping: 84 },
      user: { tag: 'PrimeBot#0001' }
    },
    nodeName: 'wispbyte-node',
    status: 'online'
  });

  assert.equal(payload.nodeName, 'wispbyte-node');
  assert.equal(payload.status, 'online');
  assert.equal(payload.guildCount, 12);
  assert.equal(payload.userCount, 240);
  assert.equal(payload.pingMs, 84);
  assert.equal(typeof payload.timestamp, 'string');
  assert.ok(payload.uptimeSeconds >= 0);
});
