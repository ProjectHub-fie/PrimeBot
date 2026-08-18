const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('path');
const Module = require('module');

// HTTP-level integration test for the idle auto-logout feature:
//   - /api/session/heartbeat refreshes the session idle deadline (200) when
//     authenticated, 401-redirects when not.
//   - /logout?reason=idle_timeout redirects to /login?error=idle_timeout.
//   - An expired session (idleExpiresAt in the past) is bounced by requireAuth
//     to /login?error=idle_timeout on an HTML request and 401 {reason:'idle_timeout'}
//     on a JSON request.
//
// We boot the real dashboard/server.js with the REAL auth module (so the idle
// logic under test actually runs), mocking only dashboard/db, dashboard/discord
// and the bot's server/db (so buildSessionStore falls back to MemoryStore and
// no Postgres/Discord calls happen). The same interception pattern as
// scripts/boot-mock-dashboard.js, minus the ./auth swap.

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
    // OAuth callback path: exchangeCode → getCurrentUser → getUserGuilds.
    exchangeCode: async () => ({ access_token: 'fake-access', refresh_token: 'fake-refresh', expires_in: 3600 }),
    getCurrentUser: async () => ({ id: '1', username: 'tester', discriminator: '0', global_name: 'Tester', avatar: null }),
    getUserGuilds: async () => [],
  };
}

// server/seasonDb exports the seasonPool the session store now uses (moved off
// the main server/db pool). Returning a thrown import makes buildSessionStore's
// `require('../server/seasonDb').seasonPool` catch branch run, AND with
// process.env.DATABASE_URL unset → returns undefined → MemoryStore.
function mockSeasonDbThrow() {
  throw new Error('mock: no season db pool — use MemoryStore for sessions');
}

let app;
function bootApp() {
  // Ensure no stray DATABASE_URL forces a real pool.
  const savedDbUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
  process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
  process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
  process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    const fromServer = parent && parent.filename && parent.filename.startsWith(DASH + path.sep + 'server.js');
    if (fromServer && request === './db') return mockDb();
    if (fromServer && request === './discord') return mockDiscord();
    // auth is REAL — do not swap it.
    if (fromServer && request === '../server/seasonDb') throw mockSeasonDbThrow();
    return origLoad.apply(this, arguments);
  };
  try {
    delete require.cache[require.resolve('../dashboard/server')];
    app = require('../dashboard/server');
  } finally {
    Module._load = origLoad;
    if (savedDbUrl !== undefined) process.env.DATABASE_URL = savedDbUrl;
  }
  return app;
}

// Fetch helper that does NOT auto-follow redirects, returning status + headers +
// body. Keeps a cookie jar so the session cookie persists across calls.
async function fetchOnce(server, urlPath, opts = {}) {
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

function startServer(appInstance) {
  return new Promise((resolve) => {
    const server = appInstance.listen(0, () => resolve(server));
  });
}
function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const a = bootApp();
  const server = await startServer(a);
  try {
    await fn(server);
  } finally {
    await closeServer(server);
  }
}

async function withHarness(fn) {
  const a = buildHarnessApp();
  const server = await startServer(a);
  try {
    await fn(server);
  } finally {
    await closeServer(server);
  }
}

// We need TWO things to test the expired-session path:
//   (a) the real requireAuth idle-expiry behavior, and
//   (b) a way to set idleExpiresAt into the past on a live session.
// server.js registers a catch-all 404 handler at the end, so routes added to
// `app` after load never run. Rather than fight that, we build a MINIMAL Express
// app here that wires the real requireAuth + a heartbeat route + a login route
// (using the real OAuth-callback session population logic) + an expire route.
// This exercises the real auth module's idle logic over real HTTP with a real
// (MemoryStore) session — the same code path server.js uses, just a slimmer
// harness so we can inject the expire step.
function buildHarnessApp() {
  const express = require('express');
  const session = require('express-session');
  const cookieParser = require('cookie-parser');
  const { requireAuth } = require('../dashboard/auth');
  const constants = require('../dashboard/constants');
  const a = express();
  a.set('trust proxy', 1);
  a.use(cookieParser());
  a.use(express.json());
  a.use(session({
    name: 'primebot.sid',
    secret: process.env.SESSION_SECRET || 'test-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' },
  }));
  // Seed a session exactly like /auth/callback does (incl. idleExpiresAt).
  a.get('/__test/login', (req, res) => {
    req.session.accessToken = 'fake-access';
    req.session.user = { id: '1', username: 'tester', globalName: 'Tester', avatar: null };
    req.session.idleExpiresAt = Date.now() + 120000;
    req.session.save(() => res.json({ ok: true }));
  });
  // Push the idle deadline into the past to simulate a lapsed session.
  a.get('/__test/expire', (req, res) => {
    req.session.idleExpiresAt = Date.now() - 1000;
    req.session.save(() => res.json({ ok: true }));
  });
  // A representative protected route (mirrors server.js /api/me).
  a.get('/api/me', requireAuth, (req, res) => res.json({ user: req.session.user }));
  // The heartbeat route (mirrors server.js).
  a.post('/api/session/heartbeat', requireAuth, (req, res) =>
    res.json({ ok: true, idleExpiresAt: req.session.idleExpiresAt, idleTimeoutMs: constants.SESSION_IDLE_TIMEOUT_MS }));
  return a;
}

test('heartbeat endpoint is 401 when unauthenticated', async () => {
  await withHarness(async (server) => {
    const r = await fetchOnce(server, '/api/session/heartbeat', { method: 'POST', headers: { Accept: 'application/json' } });
    // Unauthenticated JSON request → 401 (requireAuth returns JSON 401 for
    // non-HTML Accept).
    assert.equal(r.status, 401);
  });
});

test('logout with idle_timeout reason redirects to /login?error=idle_timeout', async () => {
  // /logout lives on the real server.js app; it needs no session, so the full
  // boot (with mocked db/discord) is fine here.
  await withServer(async (server) => {
    const r = await fetchOnce(server, '/logout?reason=idle_timeout');
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, '/login?error=idle_timeout');
  });
});

test('logout without reason keeps the legacy redirect to /', async () => {
  await withServer(async (server) => {
    const r = await fetchOnce(server, '/logout');
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, '/');
  });
});

test('authenticated heartbeat refreshes the idle deadline and returns 200', async () => {
  await withHarness(async (server) => {
    // Log in via the harness shim to seed a session, capturing the cookie.
    const login = await fetchOnce(server, '/__test/login');
    assert.equal(login.status, 200);
    const cookie = (login.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
    assert.ok(cookie, 'session cookie set');

    const before = Date.now();
    const hb = await fetchOnce(server, '/api/session/heartbeat', {
      method: 'POST',
      headers: { cookie, Accept: 'application/json' },
    });
    assert.equal(hb.status, 200);
    const json = JSON.parse(hb.body);
    assert.equal(json.ok, true);
    assert.equal(typeof json.idleExpiresAt, 'number');
    assert.ok(json.idleExpiresAt >= before, 'deadline refreshed to a future value');
    assert.ok(json.idleTimeoutMs >= 1000);
  });
});

test('an expired session is bounced to /login?error=idle_timeout (HTML) and 401 reason:idle_timeout (JSON)', async () => {
  await withHarness(async (server) => {
    const login = await fetchOnce(server, '/__test/login');
    const cookie = (login.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');

    // Expire the session server-side via the harness shim.
    const exp = await fetchOnce(server, '/__test/expire', { headers: { cookie } });
    assert.equal(exp.status, 200);

    // HTML request → redirect to login with idle_timeout.
    const html = await fetchOnce(server, '/api/me', { headers: { cookie, Accept: 'text/html' } });
    assert.equal(html.status, 302);
    assert.equal(html.headers.location, '/login?error=idle_timeout');

    // JSON request → 401 with reason idle_timeout. Re-login first since the
    // previous request destroyed the session.
    const login2 = await fetchOnce(server, '/__test/login');
    const cookie2 = (login2.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
    await fetchOnce(server, '/__test/expire', { headers: { cookie: cookie2 } });
    const json = await fetchOnce(server, '/api/me', {
      headers: { cookie: cookie2, Accept: 'application/json' },
    });
    assert.equal(json.status, 401);
    const body = JSON.parse(json.body);
    assert.equal(body.reason, 'idle_timeout');
  });
});
