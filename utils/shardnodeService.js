const packageInfo = (() => {
  try {
    return require('../package.json');
  } catch (err) {
    return {};
  }
})();

function buildHeartbeatPayload(input = {}) {
  const client = input.client || {};
  const guilds = client.guilds?.cache || {};
  const users = client.users?.cache || {};

  const payload = {
    nodeName: input.nodeName || process.env.NODE_NAME || 'unknown-shard-node',
    status: input.status || 'online',
    guildCount: Number(guilds.size || 0),
    userCount: Number(users.size || 0),
    pingMs: Number(client.ws?.ping || 0),
    uptimeSeconds: Number.isFinite(Number(input.uptimeSeconds))
      ? Number(input.uptimeSeconds)
      : Number(process.uptime() || 0),
    timestamp: new Date().toISOString(),
    runtime: {
      pid: process.pid,
      uptimeSeconds: Number(process.uptime() || 0),
      platform: process.platform,
      nodeVersion: process.version,
    },
    bot: {
      tag: client.user?.tag || null,
      username: client.user?.username || null,
      id: client.user?.id || null,
      version: packageInfo.version || null,
    },
  };

  return payload;
}

module.exports = {
  buildHeartbeatPayload,
};
