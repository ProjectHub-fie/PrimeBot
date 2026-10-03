// Regression tests for SSL propagation through the shared pool factory.
//
// Two managed-Postgres failures are pinned here:
//
//   1. `configFromUrl` strips `sslmode` from the URL and expresses SSL as the
//      config's `ssl` field. Re-parsing that bare connection string drops the
//      `ssl` (pg-connection-string only creates an `ssl` key for an explicit
//      `?ssl=...`), so the connect is plaintext and Neon/Supabase rejects every
//      query with "connection is insecure".
//   2. `server/db.js` used to pass `dbConfig.connectionString` to createPool,
//      triggering exactly that re-parse for the MAIN pool. It must pass the
//      parsed config object.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { configFromUrl, shouldEnableSsl } = require('../server/poolConfig');
const { createPool } = require('../server/createPool');

const NEON_URL = 'postgresql://u:p@ep-x.neon.tech/db?sslmode=require';

test('configFromUrl turns sslmode=require into an ssl config', () => {
    const cfg = configFromUrl(NEON_URL);
    assert.ok(cfg, 'a valid URL must parse');
    assert.deepEqual(cfg.ssl, { rejectUnauthorized: false });
});

test('re-parsing configFromUrl output drops ssl (the bug createPool must not hit)', () => {
    const cfg = configFromUrl(NEON_URL);
    const reparsed = configFromUrl(cfg.connectionString);
    assert.equal(reparsed.ssl, false, 'the sslmode is gone once stripped, so re-parsing yields ssl=false');
});

test('createPool keeps the ssl config when handed a parsed config object', () => {
    const cfg = configFromUrl(NEON_URL);
    const pool = createPool(cfg, { label: 'SSL TEST config' });
    assert.deepEqual(pool.options.ssl, { rejectUnauthorized: false });
});

test('createPool re-derives ssl when handed a raw connection string', () => {
    const pool = createPool(NEON_URL, { label: 'SSL TEST string' });
    assert.deepEqual(pool.options.ssl, { rejectUnauthorized: false });
});

test('server/db.js passes the parsed config (not the bare connection string) to createPool', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'db.js'), 'utf8');
    assert.ok(
        /createPool\(\s*dbConfig,/m.test(src),
        'the main pool must pass dbConfig so the ssl field survives'
    );
    assert.ok(
        !/createPool\(\s*dbConfig\.connectionString/m.test(src),
        'passing dbConfig.connectionString re-parses the URL and drops ssl'
    );
});

test('shouldEnableSsl also honours the DB_SSL override', () => {
    const prev = process.env.DB_SSL;
    try {
        process.env.DB_SSL = 'require';
        assert.equal(shouldEnableSsl('postgresql://u:p@host/db'), true);
    } finally {
        if (prev === undefined) delete process.env.DB_SSL;
        else process.env.DB_SSL = prev;
    }
});
