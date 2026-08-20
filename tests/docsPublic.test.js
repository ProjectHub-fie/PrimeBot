const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('path');
const Module = require('module');

// Regression test: /docs is a PUBLIC page (linked from the login screen), so it
// must render for logged-out visitors instead of requireAuth-bouncing them to
// /login. Anonymous renders use the no-nav login shell (like /privacy + /terms);
// authenticated renders keep the full nav. Auth-guarded pages stay guarded.
//
// Boots the real dashboard/server.js with only dashboard/db, dashboard/discord
// and server/seasonDb mocked (same interception pattern as
// tests/sessionIdleHttp.test.js), so the real routes + auth module run.

const DASH = path.join(__dirname, '..', 'dashboard');

function mockDb() {
  return {
    getPlatformStats: async () => ({ servers: 0, botName: 'PrimeBot', botVersion: '1.0.0', features: {} }),
    getNodeStats: async () => ({ nodes: [], lease: null, thresholdMs: 45000 }),
    getLivePolls: async () => [], getLiveGiveaways: async () => [],
    getEndedLivePolls: async () => [], getEndedLiveGiveaways: async () => [],
    getGuildConfig: async () => ({ server: {}, welcome: {}, logging: {}, reactionRoles: [], automod: {}, ticketPanels: [] }),
    getServerSettings: async () => ({}),
    upsertServerSettings: async (gid, patch) => patch,
  };
}

function mockDiscord() {
  return {
    getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
    getBotGuildCount: async () => 0,
    getBotGuild: async (id) => ({ id, name: 'Test', approximate_member_count: 1 }),
    getGuildChannels: async () => [],
    getGuildRoles: async () => [],
    exchangeCode: async () => ({ access_token: 'fake-access', refresh_token: 'fake-refresh', expires_in: 3600 }),
    getCurrentUser: async () => ({ id: '1', username: 'tester', discriminator: '0', global_name: 'Tester', avatar: null }),
    getUserGuilds: async () => [],
  };
}

function mockSeasonDbThrow() {
  throw new Error('mock: no season db pool — use MemoryStore for sessions');
}

function bootApp() {
  const savedDbUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
  process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
  process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
  process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

  const origLoad = Module._load;
  Module._load = function (request, parent) {
    const fromServer = parent && parent.filename && parent.filename.startsWith(DASH + path.sep + 'server.js');
    if (fromServer && request === './db') return mockDb();
    if (fromServer && request === './discord') return mockDiscord();
    if (fromServer && request === '../server/seasonDb') throw mockSeasonDbThrow();
    return origLoad.apply(this, arguments);
  };
  let app;
  try {
    delete require.cache[require.resolve('../dashboard/server')];
    app = require('../dashboard/server');
  } finally {
    Module._load = origLoad;
    if (savedDbUrl !== undefined) process.env.DATABASE_URL = savedDbUrl;
  }
  return app;
}

function fetchOnce(server, urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request({ port: server.address().port, path: urlPath, method: 'GET' }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function withServer(fn) {
  const app = bootApp();
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  try {
    await fn(server);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('GET /docs without a session renders the docs page (no login bounce)', async () => {
  await withServer(async (server) => {
    const res = await fetchOnce(server, '/docs');
    assert.equal(res.status, 200);
    assert.match(res.body, /Command documentation/i);
    // Anonymous visitors get the no-nav shell: no topnav, no idle-timeout script.
    assert.ok(!res.body.includes('topnav'), 'anon docs should not render the top nav');
    assert.ok(!res.body.includes('session-timeout.js'), 'anon docs should not load the idle-timeout script');
  });
});

test('GET /privacy and /terms stay public alongside /docs', async () => {
  await withServer(async (server) => {
    assert.equal((await fetchOnce(server, '/privacy')).status, 200);
    assert.equal((await fetchOnce(server, '/terms')).status, 200);
  });
});

test('auth-guarded pages still redirect anonymous visitors to /login', async () => {
  await withServer(async (server) => {
    for (const p of ['/', '/dashboard', '/stats', '/live/polls']) {
      const res = await fetchOnce(server, p);
      assert.equal(res.status, 302, `${p} should redirect`);
      assert.equal(res.headers.location, '/login');
    }
  });
});

test('docsPage renders the nav for authenticated users only', () => {
  const pages = require('../dashboard/render/pages');
  const authed = pages.docsPage({ user: { id: '1', username: 'tester', globalName: 'Tester' } });
  assert.ok(authed.includes('topnav'));
  assert.ok(authed.includes('session-timeout.js'));
  const anon = pages.docsPage({ user: null });
  assert.ok(!anon.includes('topnav'));
});
