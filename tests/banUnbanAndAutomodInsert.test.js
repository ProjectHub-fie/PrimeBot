const test = require('node:test');
const assert = require('node:assert/strict');

const resolveUserId = require('../utils/resolveUserId');

// ── resolveUserId (used by $ban / $unban / $kick …) ─────────────────────────

test('resolveUserId parses bare snowflakes, bot/user mentions, and rejects junk', () => {
    assert.equal(resolveUserId('123456789012345678'), '123456789012345678');
    assert.equal(resolveUserId(' 987654321098765432 '), '987654321098765432');
    assert.equal(resolveUserId('<@123456789012345678>'), '123456789012345678');
    assert.equal(resolveUserId('<@!123456789012345678>'), '123456789012345678');
    assert.equal(resolveUserId('@someone'), null);
    assert.equal(resolveUserId(''), null);
    assert.equal(resolveUserId(undefined), null);
    assert.equal(resolveUserId('123'), null);
    assert.equal(resolveUserId('abc123456789012345678'), null);
});

// ── automod_settings INSERT must have only as many VALUES placeholders as
// ── columns — a mismatch throws Postgres "INSERT has more expressions than
// ── target columns" (which surfaced as the dashboard "Appeal not turning on" bug).

function columnCounts(sql) {
    const cols = sql.match(/INSERT INTO automod_settings\s*\(([\s\S]*?)\)\s*VALUES/im);
    assert.ok(cols, 'missing automod_settings INSERT');
    const columns = cols[1].split(',').map(s => s.trim().replace(/\s+/g, ' '));
    const values = cols[0].match(/\$(\d+)/g) || [];
    assert.ok(values.length >= 1, 'expected $N placeholders');
    const maxParam = Math.max(...values.map(v => parseInt(v.slice(1), 10)));
    return { columns, placeholders: maxParam, hasNow: /NOW\(\)/.test(cols[0]) };
}

test('dashboard upsertAutomodSettings column/value parity', () => {
    const fs = require('fs');
    const src = fs.readFileSync(require.resolve('../dashboard/db.js'), 'utf8');
    // Grab robot-visible inserts (there may be several helper stanzas).
    const inserts = [...src.matchAll(/INSERT INTO automod_settings\s*\(([\s\S]*?)\)\s*VALUES\s*\(([\s\S]*?)\)\s*ON CONFLICT/gim)];
    assert.ok(inserts.length >= 1, 'dashboard automod INSERT not found');
    for (const m of inserts) {
        const columns = m[1].split(',').map(s => s.trim());
        const values = m[2].split(',').map(s => s.trim());
        // updated_at             = NOW() → the trailing placeholder count for columns
        // preceding updated_at must equal the placeholder count in VALUES (all values
        // other than NOW() are $1..$N consecutively).
        const maxPlaceholder = Math.max(...values.filter(v => v.startsWith('$')).map(v => parseInt(v.slice(1), 10)));
        assert.equal(maxPlaceholder, columns.length - 1, 'dashboard: placeholders must be columns minus 1 (updated_at uses NOW())');
        assert.ok(values.includes('NOW()'), 'dashboard: updated_at should use NOW()');
    }
});

test('bot automodManager _saveAsync column/value parity', () => {
    const fs = require('fs');
    const src = fs.readFileSync(require.resolve('../utils/automodManager.js'), 'utf8');
    const inserts = [...src.matchAll(/INSERT INTO automod_settings\s*\(([\s\S]*?)\)\s*VALUES\s*\(([\s\S]*?)\)\s*ON CONFLICT/gim)];
    assert.ok(inserts.length >= 1, 'bot automod INSERT not found');
    for (const m of inserts) {
        const columns = m[1].split(',').map(s => s.trim());
        const values = m[2].split(',').map(s => s.trim());
        const maxPlaceholder = Math.max(...values.filter(v => v.startsWith('$')).map(v => parseInt(v.slice(1), 10)));
        assert.equal(maxPlaceholder, columns.length - 1, 'bot: placeholders must be columns minus 1 (updated_at uses NOW())');
        assert.ok(values.includes('NOW()'), 'bot: updated_at should use NOW()');
    }
});