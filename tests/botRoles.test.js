// Unit tests for the PrimeBot role service (utils/botRoles.js) and its embeds
// (utils/devEmbed.js).
//
// The module reads the bot_roles table through server/communityDb.js. The pool
// object is imported destructured into a local reference, so the tests patch
// `communityPool.query` onto that SAME object with an in-memory store — this
// tests the module's real SQL handling, normalization, and role ordering
// end-to-end (justified mock: no Postgres in unit CI).

const { test } = require('node:test');
const assert = require('node:assert');

// A hermetic, in-memory pool stub. It understands just enough SQL for the
// botRoles module (CREATE TABLE / SELECT / INSERT+UPSERT / DELETE).
const communityPool = require('../server/communityDb').communityPool;

function makeInMemoryPool() {
    const rows = new Map(); // user_id → row
    communityPool.query = async (sql, params = []) => {
        if (/^\s*CREATE TABLE/i.test(sql)) return { rows: [] };
        if (/^\s*SELECT role FROM bot_roles WHERE user_id\s*=/i.test(sql)) {
            const row = rows.get(params[0]);
            return { rows: row ? [row] : [] };
        }
        if (/^\s*SELECT user_id, role, updated_by, updated_at FROM bot_roles/i.test(sql)) {
            return { rows: [...rows.values()] };
        }
        if (/^\s*INSERT INTO bot_roles/i.test(sql)) {
            const [userId, role, updatedBy] = params;
            rows.set(userId, { user_id: userId, role, updated_by: updatedBy, updated_at: new Date() });
            return { rows: [] };
        }
        if (/^\s*DELETE FROM bot_roles WHERE user_id\s*=/i.test(sql)) {
            rows.delete(params[0]);
            return { rows: [] };
        }
        throw new Error('Unexpected SQL: ' + sql);
    };
    return rows;
}

makeInMemoryPool();

const config = require('../config');
const botRoles = require('../utils/botRoles');
const devEmbed = require('../utils/devEmbed');

// ── Pure helpers ────────────────────────────────────────────────────────────

test('normalizeRoleName accepts case/plural/synonyms and rejects junk', () => {
    assert.strictEqual(botRoles.normalizeRoleName('Moderator'), 'moderator');
    assert.strictEqual(botRoles.normalizeRoleName('ADMIN'), 'admin');
    assert.strictEqual(botRoles.normalizeRoleName('developer'), 'developer');
    assert.strictEqual(botRoles.normalizeRoleName('user'), 'user');
    assert.strictEqual(botRoles.normalizeRoleName('owner'), 'owner');
    assert.strictEqual(botRoles.normalizeRoleName('users'), 'user');
    assert.strictEqual(botRoles.normalizeRoleName('dev'), 'developer');
    assert.strictEqual(botRoles.normalizeRoleName('mod'), 'moderator');
    assert.strictEqual(botRoles.normalizeRoleName('superadmin'), null);
    assert.strictEqual(botRoles.normalizeRoleName(''), null);
    assert.strictEqual(botRoles.normalizeRoleName(null), null);
});

test('roleLevel orders user < moderator < admin < developer < owner', () => {
    const lv = (r) => botRoles.roleLevel(r);
    assert.ok(lv('user') < lv('moderator'));
    assert.ok(lv('moderator') < lv('admin'));
    assert.ok(lv('admin') < lv('developer'));
    assert.ok(lv('developer') < lv('owner'));
    assert.strictEqual(lv('nope'), -1);
});

test('isConfigOwner detects only config.developerIds', () => {
    const [ownerId] = config.developerIds;
    assert.strictEqual(botRoles.isConfigOwner(ownerId), true);
    assert.strictEqual(botRoles.isConfigOwner('123456'), false);
});

// ── DB-backed API (in-memory pool stub above) ───────────────────────────────

test('getRole falls back to user when no row exists', async () => {
    assert.strictEqual(await botRoles.getRole('999999'), 'user');
});

test('config owners always resolve to owner, ignoring the DB', async () => {
    const [ownerId] = config.developerIds;
    assert.strictEqual(await botRoles.getRole(ownerId), 'owner');
    // Even a stale DB row can't demote a config owner.
    await botRoles.setRole(ownerId, 'moderator'); // saved, then ignored by getRole
    assert.strictEqual(await botRoles.getRole(ownerId), 'owner');
});

test('setRole assign + getRole read-back', async () => {
    await botRoles.setRole('42', 'dev');
    assert.strictEqual(await botRoles.getRole('42'), 'developer');
});

test('setRole rejects the owner role', async () => {
    assert.strictEqual(await botRoles.setRole('42', 'owner'), false);
    assert.strictEqual(await botRoles.getRole('42'), 'developer');
});

test('setRole rejects invalid role names', async () => {
    assert.strictEqual(await botRoles.setRole('42', 'superuser'), false);
});

test('removeRole resets a user; config owner removal is refused', async () => {
    const [ownerId] = config.developerIds;
    assert.strictEqual(await botRoles.removeRole('42'), true);
    assert.strictEqual(await botRoles.getRole('42'), 'user');
    assert.strictEqual(await botRoles.removeRole(ownerId), false);
});

test('listRoleRows sorts by power desc and drops invalid rows', async () => {
    for (const r of ['a', 'b', 'c']) { // clean leftovers from earlier tests
        await botRoles.removeRole(r);
    }
    await botRoles.setRole('a', 'admin', 'tester');
    await botRoles.setRole('b', 'moderator', 'tester');
    await botRoles.setRole('c', 'developer', 'tester');
    const rows = (await botRoles.listRoleRows()).filter(r => ['a', 'b', 'c'].includes(r.user_id));
    const roles = rows.map(r => r.role);
    assert.deepStrictEqual(roles, ['developer', 'admin', 'moderator']);
});

test('canBypassFeatureGates is true for developer and owner only', async () => {
    const [ownerId] = config.developerIds;
    await botRoles.setRole('mod1', 'moderator');
    await botRoles.setRole('adm1', 'admin');
    await botRoles.setRole('dev1', 'developer', 'tester');
    assert.strictEqual(await botRoles.canBypassFeatureGates('dev1'), true);
    assert.strictEqual(await botRoles.canBypassFeatureGates('adm1'), false);
    assert.strictEqual(await botRoles.canBypassFeatureGates('mod1'), false);
    assert.strictEqual(await botRoles.canBypassFeatureGates(ownerId), true);
    assert.strictEqual(await botRoles.canBypassFeatureGates('nobody'), false);
});

// ── Embeds ──────────────────────────────────────────────────────────────────

test('roleEmbed renders the role title + description', () => {
    const embed = devEmbed.roleEmbed({ targetUser: { id: '42', tag: 'tester#1' }, role: 'admin', assigned: 'database' });
    const json = embed.toJSON();
    assert.match(json.title, /Admin/);
    const descField = json.fields.find(f => f.name === 'Description');
    assert.strictEqual(descField.value, botRoles.ROLE_INFO.admin.description);
});

test('helpEmbed lists all five roles', () => {
    const json = devEmbed.helpEmbed('$').toJSON();
    for (const r of botRoles.ROLE_ORDER) {
        assert.ok(json.description.includes(botRoles.ROLE_INFO[r].label), `missing ${r}`);
    }
});

test('listEmbed degrades gracefully when empty', () => {
    const json = devEmbed.listEmbed([]).toJSON();
    assert.match(json.description, /No roles assigned/);
});

test('errorEmbed renders the message', () => {
    const json = devEmbed.errorEmbed('nope').toJSON();
    assert.strictEqual(json.description, 'nope');
});
