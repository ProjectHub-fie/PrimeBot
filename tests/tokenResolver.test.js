const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { resolveDiscordToken } = require('../utils/tokenResolver');

function writeTempEnv(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'primebot-token-'));
  const file = path.join(dir, '.env');
  fs.writeFileSync(file, content);
  return { dir, file };
}

function withEnv(overrides, fn) {
  const originalEnv = { ...process.env };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  try {
    fn();
  } finally {
    process.env = originalEnv;
  }
}

(function run() {
  const envFile = writeTempEnv('DISCORD_TOKEN=test-token-from-file\n');
  withEnv({ DISCORD_TOKEN: undefined, BOT_TOKEN: undefined }, () => {
    const token = resolveDiscordToken({ cwd: envFile.dir });
    assert.strictEqual(token, 'test-token-from-file');
  });

  withEnv({ DISCORD_TOKEN: undefined, BOT_TOKEN: 'env-bot-token' }, () => {
    const token = resolveDiscordToken({ cwd: envFile.dir });
    assert.strictEqual(token, 'env-bot-token');
  });

  withEnv({ DISCORD_TOKEN: 'env-discord-token', BOT_TOKEN: 'env-bot-token' }, () => {
    const token = resolveDiscordToken({ cwd: envFile.dir });
    assert.strictEqual(token, 'env-discord-token');
  });

  console.log('tokenResolver tests passed');
})();
