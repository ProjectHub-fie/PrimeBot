// Regression guard for the "Server marked as offline" crash.
//
// Production runs `npm install` (no --omit, no node_modules cached) then
// `node index.js`. It crashed with:
//
//   Error: Cannot find module '/home/container/node_modules/discord-api-types/v10.js'
//
// because package-lock.json had been committed with every `resolved` and
// `integrity` field stripped by the editor/tooling that produced it. npm trusts
// a lockfile that lists entries, reports "up to date" and skips the fetch, so
// the incomplete tree was never repaired — discord.js requires
// `discord-api-types/v10` at runtime and the bot died on boot.
//
// A lockfile without `resolved`/`integrity` is not a valid npm lockfile; this
// test fails before such a file can be merged again.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const lockPath = path.join(ROOT, 'package-lock.json');

function readLock() {
    return JSON.parse(fs.readFileSync(lockPath, 'utf8'));
}

test('package-lock.json ships resolved + integrity for every registry package', () => {
    const lock = readLock();
    const entries = Object.entries(lock.packages || {}).filter(([k]) => k);
    assert.ok(entries.length > 0, 'lockfile has package entries');

    const missing = entries
        .filter(([key, meta]) => {
            // The root "" entry is the project itself; local file/link deps
            // legitimately have neither field.
            if (meta.link || meta.resolved === undefined && !meta.version) return false;
            return !meta.resolved || !meta.integrity;
        })
        .map(([key]) => key);

    assert.deepEqual(
        missing,
        [],
        `these lockfile entries are missing resolved/integrity and would break ` +
        `\`npm install\` on a clean machine: ${missing.join(', ')}`
    );
});

test('the lockfile records the greedy install target for discord.js', () => {
    // The crash was specifically about discord-api-types behind discord.js.
    const lock = readLock();
    assert.ok(lock.packages['node_modules/discord.js'], 'discord.js is in the lockfile');
    assert.ok(lock.packages['node_modules/discord-api-types'], 'discord-api-types is in the lockfile');
    const dat = lock.packages['node_modules/discord-api-types'];
    assert.ok(dat.resolved, 'discord-api-types has a resolved URL');
    assert.ok(dat.integrity, 'discord-api-types has an integrity hash');
    // discord.js requires the v10 subpath export; a truncated package (only
    // dist/, no v10.js) is what produced MODULE_NOT_FOUND.
    assert.match(dat.resolved, /^https:\/\/registry\.npmjs\.org\//, 'resolved points at the public registry');
});

test('the lockfile and package.json agree on the direct dependencies', () => {
    const lock = readLock();
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    const lockRoot = lock.packages[''] || {};
    assert.deepEqual(
        Object.keys(lockRoot.dependencies || {}).sort(),
        Object.keys(pkg.dependencies || {}).sort(),
        'lockfile root dependencies mirror package.json'
    );
});

test('the .npmrc keeps npm pinned to the public registry', () => {
    // The lockfile was originally generated behind a private Replit firewall;
    // the committed .npmrc forces the real registry so CI/panel installs can
    // actually fetch the resolved URLs the lockfile points at.
    const npmrc = fs.readFileSync(path.join(ROOT, '.npmrc'), 'utf8');
    assert.match(npmrc, /registry=https:\/\/registry\.npmjs\.org\//);
    assert.ok(
        !/package-firewall\.replit\.local/.test(npmrc.replace(/^#.*$/gm, '')),
        '.npmrc must not actively point npm at the unreachable Replit firewall host'
    );
});