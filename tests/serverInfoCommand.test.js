const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const { buildServerInfoEmbed } = require('../utils/serverInfoEmbed');
const help = require('../utils/prefixHelp');
const command = require('../commands/serverinfo');

function fakeGuild() {
    const channels = new Map([
        ['1', { type: 0 }], ['2', { type: 0 }], ['3', { type: 2 }], ['4', { type: 4 }], ['5', { type: 5 }],
    ]);
    return {
        id: '123456789012345678',
        name: 'PrimeBot HQ',
        ownerId: '999999999999999999',
        memberCount: 1234,
        premiumSubscriptionCount: 7,
        premiumTier: 2,
        verificationLevel: 2,
        createdAt: new Date('2024-01-02T03:04:05Z'),
        vanityURLCode: 'primebot',
        iconURL: () => 'https://cdn.example/icon.png',
        channels: { cache: channels },
        roles: { cache: new Map([['1', {}], ['2', {}], ['3', {}]]) },
        emojis: { cache: new Map([['1', {}], ['2', {}]]) },
        stickers: { cache: new Map([['1', {}]]) },
    };
}

test('/si is a guild-only slash command', () => {
    const json = command.data.toJSON();
    assert.equal(json.name, 'si');
    assert.match(json.description, /server/i);
    assert.equal(json.dm_permission, false);
    assert.equal(typeof command.execute, 'function');
});

test('the server info embed reports the real guild values', () => {
    const embed = buildServerInfoEmbed(fakeGuild()).toJSON();
    assert.equal(embed.title, 'Server information');
    assert.equal(embed.author.name, 'PrimeBot HQ');
    assert.equal(embed.thumbnail.url, 'https://cdn.example/icon.png');

    const field = name => embed.fields.find(f => f.name === name)?.value;
    assert.equal(field('Owner'), '<@999999999999999999>');
    assert.equal(field('Members'), '1,234');
    assert.equal(field('Roles'), '3');
    assert.equal(field('Channels'), '3 text • 1 voice • 1 categories');
    assert.equal(field('Boosts'), '7 (Tier 2)');
    assert.equal(field('Verification'), 'Medium');
    assert.match(field('Created'), /<t:\d+:F>/);
    assert.equal(field('Vanity URL'), 'discord.gg/primebot');
    assert.equal(field('Emojis & stickers'), '2 emoji • 1 stickers');
    assert.match(embed.footer.text, /Server ID: 123456789012345678/);
    assert.ok(embed.timestamp);
});

test('the embed degrades gracefully for a minimal guild object', () => {
    const embed = buildServerInfoEmbed({ id: '1', name: 'Bare', memberCount: 1 }).toJSON();
    assert.equal(embed.author.name, 'Bare');
    const field = name => embed.fields.find(f => f.name === name)?.value;
    assert.equal(field('Owner'), 'Unknown');
    assert.equal(field('Roles'), '0');
    assert.equal(field('Channels'), '0 text • 0 voice • 0 categories');
    assert.ok(!embed.thumbnail, 'no icon means no thumbnail');
});

test('si lives in the Information category with its aliases', () => {
    const info = help.CATALOG.information.commands;
    const entry = info.find(c => c.names.includes('si'));
    assert.ok(entry, 'si is missing from the Information category');
    assert.deepEqual(entry.names, ['si', 'serverinfo', 'server']);
    assert.match(entry.desc, /server information/i);
    assert.ok(help.categoryText('information').includes('`si`'));
});

test('the prefix handler routes $si, $serverinfo and $server to the embed', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events', 'messageCreate.js'), 'utf8');
    const block = src.slice(src.indexOf('case "si":'), src.indexOf('case "about":'));
    assert.match(block, /case "si":/);
    assert.match(block, /case "serverinfo":/);
    assert.match(block, /case "server":/);
    assert.match(block, /buildServerInfoEmbed\(message\.guild\)/);
    assert.match(block, /only works inside a server/);
});

test('/docs lists si with its usage', () => {
    const docs = require('../dashboard/commandDocs').buildCommandDocs();
    const entry = docs.commands.find(c => c.name === 'si');
    assert.ok(entry, 'si is missing from the docs');
    assert.equal(entry.category, 'Utility');
    assert.ok(entry.usage.includes('si'));
});
