// HTTP-level integration test for the Embed Builder API:
//   - GET  /api/guilds/:guildId/embeds          → 401 unauthenticated, 200 + list authenticated
//   - POST /api/guilds/:guildId/embeds          → saves a named embed
//   - PATCH .../embeds/:id                      → renames it
//   - POST .../embeds/:id/duplicate             → creates a copy
//   - DELETE .../embeds/:id                     → removes it
//   - Payload validation: no name → 400; non-object payload → 400
//
// Boots the real dashboard/server.js with the REAL auth module; mocks only
// dashboard/db, dashboard/discord, server/db and the dedicated embed pool
// (server/embedDb stub → in-memory Postgres-like store), so no Postgres runs.
// This keeps Neon usage at exactly zero in CI while exercising the real routes.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('path');
const Module = require('module');

const DASH = path.join(__dirname, '..', 'dashboard');

// In-memory fake for the saved_embeds table (mirrors the SQL the helpers emit).
function makeMemEmbedDb() {
  const rows = [];
  let seq = 1;
  const now = () => new Date().toISOString();
  const match = (sql) => (sql || '').replace(/\s+/g, ' ').trim();
  const query = async (sql, params = []) => {
    const q = match(sql);
    if (q.includes('CREATE TABLE')) return { rows: [] };
    if (q.includes('CREATE INDEX')) return { rows: [] };
    if (q.includes('INSERT INTO saved_embeds') && q.includes('VALUES')) {
      const row = {
        id: seq++, guild_id: params[0], name: params[1],
        payload: JSON.parse(params[2] || '{}'),
        created_by: params[3] || null, created_at: now(), updated_at: now(),
      };
      rows.push(row);
      return { rows: [row] };
    }
    if (q.includes('INSERT INTO saved_embeds') && q.includes('SELECT guild_id')) {
      const src = rows.find((r) => String(r.guild_id) === String(params[0]) && Number(r.id) === Number(params[1]));
      if (!src) return { rows: [] };
      const row = { ...src, id: seq++, name: params[2], created_at: now(), updated_at: now() };
      rows.push(row);
      return { rows: [row] };
    }
    if (q.includes('DELETE FROM saved_embeds')) {
      const idx = rows.findIndex((r) => String(r.guild_id) === String(params[0]) && Number(r.id) === Number(params[1]));
      if (idx >= 0) rows.splice(idx, 1);
      return { rows: [] };
    }
    if (q.includes('UPDATE saved_embeds')) {
      const row = rows.find((r) => String(r.guild_id) === String(params[0]) && Number(r.id) === Number(params[1]));
      if (row) {
        if (q.includes('name = $')) row.name = params[2];
        if (q.includes('payload = $')) row.payload = params[3];
        row.updated_at = now();
      }
      return { rows: row ? [row] : [] };
    }
    if (q.includes('SELECT id, guild_id')) {
      return { rows: rows.filter((r) => String(r.guild_id) === String(params[0] || r.guild_id)) };
    }
    return { rows: [] };
  };
  return { query };
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

    // Saved embeds → backed by the in-memory fake (no Postgres).
    getSavedEmbeds: async (guildId) => (await mem.query('SELECT id, guild_id FROM saved_embeds WHERE guild_id = $1', [guildId])).rows,
    getSavedEmbed: async (guildId, id) => (await mem.query('SELECT id, guild_id FROM saved_embeds WHERE guild_id = $1 AND id = $2', [guildId, id])).rows[0] || null,
    createSavedEmbed: async (guildId, { name, payload }, createdById) => {
      const r = await mem.query('INSERT INTO saved_embeds (guild_id, name, payload, created_by) VALUES ($1, $2, $3, $4)', [guildId, name, JSON.stringify(payload || {}), createdById]);
      return r.rows[0];
    },
    updateSavedEmbed: async (guildId, id, patch) => {
      const r = await mem.query('UPDATE saved_embeds SET name = $3 WHERE guild_id = $1 AND id = $2', [guildId, id, patch.name]);
      return r.rows[0] || null;
    },
    duplicateSavedEmbed: async () => null,
    deleteSavedEmbed: async (guildId, id) => { await mem.query('DELETE FROM saved_embeds WHERE guild_id = $1 AND id = $2', [guildId, id]); return { ok: true }; },

    // The audit-log write that follows a save must not crash the request.
    addWebsiteLog: async () => {},
    getWebsiteLogs: async () => ([]),
  };
}
// The server routes call dashboardDb.* which resolve the embed pool lazily via
// require('../server/embedDb'). We swap that module here so the helpers run
// against our in-memory fake.
let mem = makeMemEmbedDb();
const embedDbPath = require.resolve('../server/embedDb');
require.cache[embedDbPath] = { id: embedDbPath, filename: embedDbPath, loaded: true, exports: { embedPool: { query: (...a) => mem.query(...a) } } };

function mockDiscord() {
  return {
    getBotSelf: async () => ({ id: '999', username: 'PrimeBot' }),
    getBotGuildCount: async () => 0,
    getBotGuild: async (id) => ({ id, name: 'Test', approximate_member_count: 1 }),
    getGuildChannels: async () => [],
    getGuildRoles: async () => [],
    exchangeCode: async () => ({ access_token: 'f', refresh_token: 'f', expires_in: 3600 }),
    getCurrentUser: async () => ({ id: '1', username: 'tester', discriminator: '0', global_name: 'Tester', avatar: null }),
    // The tester is an admin of guild 123456789012345678 (permission bit 8 = ADMINISTRATOR).
    getUserGuilds: async () => ([{ id: '123456789012345678', name: 'Test', permissions: '8' }]),
    canManageGuild: (permissions) => (BigInt(permissions || 0) & 8n) !== 0n,
  };
}

let app;
function bootApp() {
  const savedDbUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
  process.env.DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '999';
  process.env.DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || 'secret';
  process.env.DASHBOARD_BOT_TOKEN = process.env.DASHBOARD_BOT_TOKEN || 'fake-token';

  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    const fromDash = parent && parent.filename && parent.filename.startsWith(DASH + path.sep);
    if (fromDash && request === './db') return mockDb();
    if (fromDash && request === './discord') return mockDiscord();
    // auth is REAL.
    if (fromDash && request === '../server/seasonDb') throw new Error('mock: no season db — MemoryStore');
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
  return new Promise((resolve) => resolve(appInstance.listen(0, () => { /* resolve after listening */ })).then(() => appInstance));
}
function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}
async function withServer(fn) {
  const a = bootApp();
  const server = a.listen(0);
  await new Promise((r) => server.once('listening', r));
  try { await fn(server); } finally { await closeServer(server); }
}

// Authenticate against the real server using the OAuth callback flow with
// mocked Discord. Capture the session cookie.
async function login(server) {
  const r = await fetchOnce(server, '/auth/callback?code=fake');
  const cookie = (r.headers['set-cookie'] || []).map((c) => c.split(';')[0]).join('; ');
  return cookie;
}

function json(server, method, urlPath, cookie, body) {
  const headers = { Accept: 'application/json' };
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  return fetchOnce(server, urlPath, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
}

test.beforeEach(() => { mem = makeMemEmbedDb(); });

test('embeds API is 401 unauthenticated', async () => {
  await withServer(async (server) => {
    const r = await json(server, 'GET', '/api/guilds/123456789012345678/embeds', null);
    assert.equal(r.status, 401);
  });
});

test('embeds API full CRUD + validation over real HTTP + real auth', async () => {
  await withServer(async (server) => {
    const cookie = await login(server);
    assert.ok(cookie, 'logged in');

    // Empty list.
    const list0 = await json(server, 'GET', '/api/guilds/123456789012345678/embeds', cookie);
    assert.equal(list0.status, 200);
    assert.deepEqual(JSON.parse(list0.body).embeds, []);

    // Validation: missing name.
    const bad = await json(server, 'POST', '/api/guilds/123456789012345678/embeds', cookie, { payload: {} });
    assert.equal(bad.status, 400, 'missing name → 400');

    // Validation: non-object payload.
    const badPayload = await json(server, 'POST', '/api/guilds/123456789012345678/embeds', cookie, { name: 'X', payload: 'nope' });
    assert.equal(badPayload.status, 400, 'string payload → 400');

    // Create.
    const created = await json(server, 'POST', '/api/guilds/123456789012345678/embeds', cookie, { name: 'Welcome', payload: { title: 'Hi', color: '#5865F2' } });
    assert.equal(created.status, 200);
    const createdBody = JSON.parse(created.body);
    assert.ok(createdBody.embed && createdBody.embed.id, 'embed created with id');
    assert.equal(createdBody.embed.name, 'Welcome');

    // Rename.
    const renamed = await json(server, 'PATCH', `/api/guilds/123456789012345678/embeds/${createdBody.embed.id}`, cookie, { name: 'Welcome v2', payload: {} });
    assert.equal(renamed.status, 200);
    assert.equal(JSON.parse(renamed.body).embed.name, 'Welcome v2');

    // Duplicate.
    const dup = await json(server, 'POST', `/api/guilds/123456789012345678/embeds/${createdBody.embed.id}/duplicate`, cookie, {});
    assert.equal(dup.status, 200);
    const dupName = JSON.parse(dup.body).embed.name;
    assert.match(dupName, /\(copy\)/, 'duplicate gets a copy name');

    // List now has 2.
    const list1 = await json(server, 'GET', '/api/guilds/123456789012345678/embeds', cookie);
    assert.equal(JSON.parse(list1.body).embeds.length, 2);

    // Duplicate name generation avoids collisions.
    const dup2 = await json(server, 'POST', `/api/guilds/123456789012345678/embeds/${createdBody.embed.id}/duplicate`, cookie, {});
    assert.equal(JSON.parse(dup2.body).embed.name, 'Welcome v2 (copy 2)', 'third copy name avoids collisions');

    // Delete one.
    const del = await json(server, 'DELETE', `/api/guilds/123456789012345678/embeds/${createdBody.embed.id}`, cookie);
    assert.equal(del.status, 200);
    const list2 = await json(server, 'GET', '/api/guilds/123456789012345678/embeds', cookie);
    assert.equal(JSON.parse(list2.body).embeds.length, 2);

    // Unauthenticated after the cookie expires → not reachable (sanity: remove
    // cookie → 401).
    const noCookie = await json(server, 'GET', '/api/guilds/123456789012345678/embeds', null);
    assert.equal(noCookie.status, 401);
  });
});