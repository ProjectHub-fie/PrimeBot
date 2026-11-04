// FALLBACK_DATABASE_URL routing.
//
// Every per-feature pool resolves its connection string through
// server/resolveDbUrl.js, so the precedence is defined once:
//
//   <FEATURE>_DATABASE_URL  ->  FALLBACK_DATABASE_URL  ->  DATABASE_URL
//
// These tests cover the resolver itself plus a static audit of every pool
// module + the main pool, the dashboard session pool, livePollManager and the
// drizzle config, so a future pool cannot silently skip the fallback step.
// No database is contacted — resolveDbUrl only reads process.env.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { resolveDbUrl } = require('../server/resolveDbUrl');

const ROOT = path.join(__dirname, '..');

// The DB env vars are saved/restored around each test so the suite never
// leaks configuration into another test file sharing this process.
const DB_VARS = ['FALLBACK_DATABASE_URL', 'DATABASE_URL', 'LOG_DATABASE_URL', 'AUTOMOD_DATABASE_URL', 'ANUKE_DATABASE_URL', 'ANTI_DATABASE_URL'];

function withEnv(vars, fn) {
    const saved = {};
    for (const key of DB_VARS) saved[key] = process.env[key];
    try {
        for (const key of DB_VARS) delete process.env[key];
        for (const [key, value] of Object.entries(vars)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
        }
        return fn();
    } finally {
        for (const key of DB_VARS) {
            if (saved[key] === undefined) delete process.env[key];
            else process.env[key] = saved[key];
        }
    }
}

test('resolveDbUrl prefers the feature-specific variable', () => {
    withEnv({ LOG_DATABASE_URL: 'postgres://feature', FALLBACK_DATABASE_URL: 'postgres://fallback', DATABASE_URL: 'postgres://main' }, () => {
        assert.equal(resolveDbUrl('LOG_DATABASE_URL'), 'postgres://feature');
    });
});

test('resolveDbUrl falls back to FALLBACK_DATABASE_URL when the feature variable is unset', () => {
    withEnv({ FALLBACK_DATABASE_URL: 'postgres://fallback', DATABASE_URL: 'postgres://main' }, () => {
        assert.equal(resolveDbUrl('LOG_DATABASE_URL'), 'postgres://fallback');
    });
});

test('resolveDbUrl falls back to FALLBACK_DATABASE_URL when the feature variable is empty', () => {
    withEnv({ LOG_DATABASE_URL: '', FALLBACK_DATABASE_URL: 'postgres://fallback', DATABASE_URL: 'postgres://main' }, () => {
        assert.equal(resolveDbUrl('LOG_DATABASE_URL'), 'postgres://fallback');
    });
});

test('resolveDbUrl falls back to DATABASE_URL when both the feature variable and FALLBACK are unset', () => {
    withEnv({ DATABASE_URL: 'postgres://main' }, () => {
        assert.equal(resolveDbUrl('LOG_DATABASE_URL'), 'postgres://main');
    });
});

test('resolveDbUrl returns null when nothing is configured', () => {
    withEnv({}, () => {
        assert.equal(resolveDbUrl('LOG_DATABASE_URL'), null);
    });
});

test('Anti-Nuke prefers ANTI_DATABASE_URL over the legacy ANUKE_DATABASE_URL alias', () => {
    // The pool module is re-required with a fresh env so its module-level
    // resolveConnectionString() runs against the test values.
    withEnv({ ANTI_DATABASE_URL: 'postgres://anti', ANUKE_DATABASE_URL: 'postgres://anuke', DATABASE_URL: 'postgres://main' }, () => {
        const mod = require('../server/anukeDb');
        assert.equal(mod.resolveConnectionString(), 'postgres://anti');
    });
});

test('Anti-Nuke falls back to ANUKE_DATABASE_URL when ANTI_DATABASE_URL is unset', () => {
    withEnv({ ANUKE_DATABASE_URL: 'postgres://anuke', DATABASE_URL: 'postgres://main' }, () => {
        const mod = require('../server/anukeDb');
        assert.equal(mod.resolveConnectionString(), 'postgres://anuke');
    });
});

test('Anti-Nuke falls back to FALLBACK/DATABASE_URL when neither anti var is set', () => {
    withEnv({ FALLBACK_DATABASE_URL: 'postgres://fallback', DATABASE_URL: 'postgres://main' }, () => {
        const mod = require('../server/anukeDb');
        assert.equal(mod.resolveConnectionString(), 'postgres://fallback');
    });
});

// ── Static audit ────────────────────────────────────────────────────────────

test('every dedicated pool resolves through the shared resolver', () => {
    const dir = path.join(ROOT, 'server');
    const poolFiles = fs.readdirSync(dir).filter((f) => f.endsWith('Db.js'));
    assert.ok(poolFiles.length >= 18, `expected the full pool set, found ${poolFiles.length}`);

    for (const file of poolFiles) {
        const src = fs.readFileSync(path.join(dir, file), 'utf8');
        const expected = file.replace(/Db\.js$/, '').toUpperCase() + '_DATABASE_URL';
        assert.ok(
            src.includes("require('./resolveDbUrl')"),
            `${file} must import the shared resolver`
        );
        assert.match(
            src,
            /function resolveConnectionString\(\) \{[\s\S]*?resolveDbUrl\(/,
            `${file} resolveConnectionString must delegate to resolveDbUrl`
        );
        // anukeDb.js resolves ANUKE_DATABASE_URL (the legacy alias) through the
        // resolver, with ANTI_DATABASE_URL checked first as the canonical name.
        const resolvedVar = file === 'anukeDb.js' ? 'ANUKE_DATABASE_URL' : expected;
        assert.ok(
            src.includes(`resolveDbUrl('${resolvedVar}')`),
            `${file} must resolve its own ${resolvedVar} variable`
        );
    }
});

test('no pool reads DATABASE_URL directly (fallback must go through the resolver)', () => {
    const dir = path.join(ROOT, 'server');
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('Db.js'))) {
        const src = fs.readFileSync(path.join(dir, file), 'utf8');
        assert.ok(
            !src.includes('process.env.DATABASE_URL'),
            `${file} should not read process.env.DATABASE_URL directly — use resolveDbUrl()`
        );
    }
});

test('main pool, dashboard session pool and drizzle config honour FALLBACK_DATABASE_URL', () => {
    const dbSrc = fs.readFileSync(path.join(ROOT, 'server/db.js'), 'utf8');
    assert.match(dbSrc, /process\.env\.DATABASE_URL \|\| process\.env\.FALLBACK_DATABASE_URL/);

    const serverSrc = fs.readFileSync(path.join(ROOT, 'dashboard/server.js'), 'utf8');
    assert.match(serverSrc, /process\.env\.FALLBACK_DATABASE_URL \|\| process\.env\.DATABASE_URL/);

    const drizzleSrc = fs.readFileSync(path.join(ROOT, 'drizzle.config.js'), 'utf8');
    assert.match(drizzleSrc, /process\.env\.DATABASE_URL \|\| process\.env\.FALLBACK_DATABASE_URL/);

    const liveSrc = fs.readFileSync(path.join(ROOT, 'utils/livePollManager.js'), 'utf8');
    assert.match(liveSrc, /process\.env\.LIVE_DATABASE_URL \|\| process\.env\.FALLBACK_DATABASE_URL/);
});
