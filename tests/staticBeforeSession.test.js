// Regression test for the General-tab layout collapse (and all "nothing but
// CSS-less HTML" symptoms): the dashboard served express.static AFTER the
// session middleware, so a cookie-bearing request for /styles.css went through
// connect-pg-simple's store.get(). When that Postgres query fails (DB down /
// session table missing on Vercel), express-session next(err)-ed and the error
// handler replaced the stylesheet with a 500 HTML page. The browser then
// parsed zero CSS rules, .general-grid collapsed to display:block, and the
// prefix/audit-log cards on the General tab stacked (overlapped) instead of
// sitting in the 2-column grid.
//
// The fix serves express.static BEFORE the session middleware. This test boots
// the REAL dashboard server with a seasonDb whose pool.query always throws
// (worst-case store failure) and asserts static assets are never pulled into
// the session path.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const Module = require('node:module');
const cookieSignature = require('cookie-signature');

const SESSION_SECRET = 'test-secret';
const DASH = path.join(__dirname, '..', 'dashboard');

// A signed session cookie that express-session will accept and try to load
// from the store. `s:<sid>.<hmac>` is what cookie-parser's signedCookie
// produces; with saveUninitialized:false + a matching signature,
// express-session calls store.get(sid) on EVERY request carrying it — under
// the old middleware order that included static assets.
function signedSessionCookie(sid = 'deadbeefcafe1234') {
  // cookie-signature.sign already returns `<sid>.<hmac>`; the `s:` prefix is
  // what cookie-parser uses to detect a signed cookie.
  return `primebot.sid=s:${cookieSignature.sign(sid, SESSION_SECRET)};`;
}

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

// A seasonPool whose query ALWAYS rejects — the worst-case session-store
// failure. buildSessionStore consumes the real ../server/seasonDb module; we
// intercept that require and hand it a poisoned pool so connect-pg-simple
// gets on get()/set() every time.
function mockBrokenSeasonDb() {
  return {
    seasonPool: {
      query: async () => { throw new Error('mock: session DB unavailable'); },
      end: async () => {},
    },
  };
}

function bootApp() {
  const savedDbUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  process.env.SESSION_SECRET = SESSION_SECRET;
  process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
  process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
  process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    const fromServer = parent && parent.filename && parent.filename.startsWith(DASH + path.sep + 'server.js');
    if (fromServer && request === './db') return mockDb();
    if (fromServer && request === './discord') return mockDiscord();
    // Force the session store to be broken (PgSession get/set rejects).
    if (fromServer && request === '../server/seasonDb') return mockBrokenSeasonDb();
    return origLoad.apply(this, arguments);
  };
  try {
    delete require.cache[require.resolve('../dashboard/server')];
    const app = require('../dashboard/server');
    return app;
  } finally {
    Module._load = origLoad;
    if (savedDbUrl !== undefined) process.env.DATABASE_URL = savedDbUrl;
  }
}

function startServer(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });
}
function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

function fetchOnce(server, urlPath, opts = {}) {
  const { method = 'GET', headers = {}, body } = opts;
  return new Promise((resolve, reject) => {
    const req = http.request(
      { port: server.address().port, path: urlPath, method, headers: { ...headers } },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function withServer(fn) {
  const app = bootApp();
  const server = await startServer(app);
  try {
    await fn(server);
  } finally {
    await closeServer(server);
  }
}

test('static assets are served before the session middleware (broken store never 500s the CSS)', async () => {
  await withServer(async (server) => {
    // Cookie-bearing request — under the old middleware order this hit the
    // (broken) session store and came back 500 text/html with 0 css rules.
    const res = await fetchOnce(server, '/styles.css', {
      headers: { Cookie: signedSessionCookie() },
    });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers['content-type'] || '', /text\/css/);
    assert.ok(res.body.includes('.general-grid'), 'styles.css should contain real CSS, not an error page');
  });
});

test('a fresh visitor (no session cookie) still gets the login page when the store is down', async () => {
  await withServer(async (server) => {
    // No cookie => express-session skips store.get() (saveUninitialized:false),
    // so the login page must render even while the session DB is unavailable.
    const res = await fetchOnce(server, '/login');
    assert.strictEqual(res.status, 200);
    assert.match(res.headers['content-type'] || '', /text\/html/);
  });
});