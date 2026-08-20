// Shared no-prefix embeds: fields are complete/consistent for slash + prefix.
const { test } = require('node:test');
const assert = require('node:assert');

const npEmbed = require('../utils/npEmbed');
const automodManagerModule = require('../utils/automodManager');

const fakeUser = { id: '123456789', tag: 'target#0001', toString() { return `<@${this.id}>`; } };

function fieldNames(embed) {
    return embed.toJSON().fields?.map((f) => f.name) || [];
}

test('grantEmbed: target, duration, expiry, usage fields', () => {
    const embed = npEmbed.grantEmbed({
        targetUser: fakeUser, minutes: 30, lifetime: false, expiresAt: Date.now() + 30 * 60000,
    });
    const json = embed.toJSON();
    assert.ok(json.title.includes('No-Prefix'));
    assert.deepStrictEqual(fieldNames(embed), ['Target User', 'Duration', 'Expires', 'How to use']);
    assert.match(String(json.fields[1].value), /30 minutes/);
});

test('grantEmbed: lifetime grant expires never', () => {
    const embed = npEmbed.grantEmbed({ targetUser: fakeUser, minutes: null, lifetime: true, expiresAt: 'lifetime' });
    const names = fieldNames(embed);
    assert.strictEqual(embed.toJSON().fields[names.indexOf('Expires')].value, 'Never');
});

test('revokeEmbed: removed vs not-active variants', () => {
    const removed = npEmbed.revokeEmbed({ targetUser: fakeUser, removed: true }).toJSON();
    const missing = npEmbed.revokeEmbed({ targetUser: fakeUser, removed: false }).toJSON();
    assert.ok(fieldNames(npEmbed.revokeEmbed({ targetUser: fakeUser, removed: true })).includes('Status'));
    assert.ok(String(removed.title).includes('Disabled'));
    assert.ok(String(missing.title).includes('Not Active'));
});

test('statusEmbed: enabled, lifetime and disabled variants', () => {
    const on = npEmbed.statusEmbed({ targetUser: fakeUser, expiresAt: Date.now() });
    const lifetime = npEmbed.statusEmbed({ targetUser: fakeUser, expiresAt: 'lifetime' });
    const off = npEmbed.statusEmbed({ targetUser: fakeUser, expiresAt: null });
    assert.ok(fieldNames(on).includes('Expires'));
    assert.ok(fieldNames(lifetime).includes('Duration'));
    assert.deepStrictEqual(fieldNames(off), ['Target User', 'Status']);
});

test('helpEmbed lists every subcommand usage', () => {
    const json = npEmbed.helpEmbed('$').toJSON();
    const names = fieldNames(npEmbed.helpEmbed('$')).join('|');
    for (const sub of ['add', 'remove', 'status', 'enable', 'disable']) {
        assert.ok(names.includes(`np ${sub}`), `help embed missing ${sub}`);
    }
    assert.ok(json.fields.length >= 5);
});

test('automod manager exposes a responsible-moderator label helper', () => {
    const proto = automodManagerModule.AutomodManager?.prototype || automodManagerModule.prototype || null;
    assert.ok(proto, 'AutomodManager class should be exported');
    const emptyCtx = Object.create(proto);
    assert.strictEqual(emptyCtx._moderatorLabel(null), 'PrimeBot Automod (automatic)');
    assert.strictEqual(emptyCtx._moderatorLabel({ user: { id: '42', tag: 'mod#9' } }), 'mod#9 (<@42>)');
    assert.strictEqual(emptyCtx._moderatorLabel({ author: { id: '7', username: 'mod' } }), 'mod (<@7>)');
});
