const fs = require('fs');
const path = require('path');

function readEnvFile(cwd = process.cwd()) {
  const envPath = path.join(cwd, '.env');
  if (!fs.existsSync(envPath)) {
    return {};
  }

  const content = fs.readFileSync(envPath, 'utf8');
  const values = {};

  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const match = trimmed.match(/^([A-Za-z0-9_]+)=(.*)$/);
    if (!match) continue;

    const [, key, rawValue] = match;
    const value = rawValue.replace(/^['"]|['"]$/g, '').trim();
    values[key] = value;
  }

  return values;
}

function resolveDiscordToken(options = {}) {
  const cwd = options.cwd || process.cwd();
  const envFileValues = readEnvFile(cwd);

  // DISCORD_TOKEN2 leads: the production bot runs on that token, so a stray
  // legacy DISCORD_TOKEN in the environment must not shadow it. Everything
  // after it is the historical fallback chain, unchanged.
  const candidates = [
    process.env.DISCORD_TOKEN2,
    envFileValues.DISCORD_TOKEN2,
    process.env.DISCORD_TOKEN,
    process.env.BOT_TOKEN,
    process.env.TOKEN,
    process.env.CLIENT_TOKEN,
    envFileValues.DISCORD_TOKEN,
    envFileValues.BOT_TOKEN,
    envFileValues.TOKEN,
    envFileValues.CLIENT_TOKEN,
  ];

  const token = candidates.find(value => typeof value === 'string' && value.trim().length > 0);

  if (token) {
    return token.trim();
  }

  return null;
}

module.exports = {
  readEnvFile,
  resolveDiscordToken,
};
