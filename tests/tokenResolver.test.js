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
  withEnv({ DISCORD_TOKEN2: undefined, DISCORD_TOKEN: undefined, BOT_TOKEN: undefined }, () => {
    const token = resolveDiscordToken({ cwd: envFile.dir });
    assert.strictEqual(token, 'test-token-from-file');
  });

  withEnv({ DISCORD_TOKEN2: undefined, DISCORD_TOKEN: undefined, BOT_TOKEN: 'env-bot-token' }, () => {
    const token = resolveDiscordToken({ cwd: envFile.dir });
    assert.strictEqual(token, 'env-bot-token');
  });

  withEnv({ DISCORD_TOKEN2: undefined, DISCORD_TOKEN: 'env-discord-token', BOT_TOKEN: 'env-bot-token' }, () => {
    const token = resolveDiscordToken({ cwd: envFile.dir });
    assert.strictEqual(token, 'env-discord-token');
  });

  // DISCORD_TOKEN2 is the primary production token and must win over any
  // other token in the environment (a stale DISCORD_TOKEN must not shadow it).
  withEnv({ DISCORD_TOKEN2: 'primary-token', DISCORD_TOKEN: 'legacy-token', BOT_TOKEN: 'env-bot-token' }, () => {
    const token = resolveDiscordToken({ cwd: envFile.dir });
    assert.strictEqual(token, 'primary-token');
  });

  console.log('tokenResolver tests passed');
})();

// ───────────────────────────────────────────────────────────────────────────
// $tokentest reads DISCORD_TOKEN, by design.
//
// The command shells out to `node token-test.js` from the RUNNING bot, and
// index.js exports the resolved token as DISCORD_TOKEN (`process.env.DISCORD_TOKEN
// = token`), so the child process inherits it no matter which variable the
// deployment sets (DISCORD_TOKEN2 / BOT_TOKEN / ...). token-test.js therefore
// reads the generic DISCORD_TOKEN on purpose — do not "fix" it to call
// resolveDiscordToken(), the inherited env var is the contract.
// ───────────────────────────────────────────────────────────────────────────
(function runTokenTestWiring() {
  const script = fs.readFileSync(path.join(__dirname, '..', 'token-test.js'), 'utf8');

  assert.ok(
    /process\.env\.DISCORD_TOKEN\b/.test(script),
    'token-test.js reads process.env.DISCORD_TOKEN'
  );
  assert.ok(
    !/resolveDiscordToken\(/.test(script),
    'token-test.js must not re-resolve — the parent bot already exports ' +
    'the resolved token as DISCORD_TOKEN for the child process'
  );

  // index.js is the other half of that contract.
  const indexSrc = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
  assert.ok(
    /process\.env\.DISCORD_TOKEN = token/.test(indexSrc),
    'index.js exports the resolved token as DISCORD_TOKEN so child processes inherit it'
  );

  console.log('tokenTest wiring tests passed');
})();
