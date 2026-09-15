// Shared embed-payload helpers — pure, no DB, no discord.js.
//
// These convert a saved embed's stored builder state into a sendable Discord
// message payload, shared by the bot's $embed / /embed commands and the
// dashboard's Embed Builder format.
const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    LIMITS,
    normalizeEmbedState,
    toApiEmbed,
    toMessagePayload,
    colorToHex,
    hexToInt,
} = require('../shared/embedPayload');

test('colorToHex / hexToInt normalize builder colours both ways', () => {
    assert.equal(colorToHex('#5865F2'), '#5865f2');
    assert.equal(colorToHex(0x5865f2), '#5865f2');
    assert.equal(colorToHex('not-a-color'), '#5865F2');
    assert.equal(colorToHex(null), '#5865F2');
    assert.equal(hexToInt('#5865F2'), 0x5865f2);
});

test('normalizeEmbedState reads the builder state shape', () => {
    const s = normalizeEmbedState({
        title: 'Hello',
        description: 'World',
        color: '#ff0000',
        timestamp: true,
        authorEnabled: true, authorName: 'PrimeBot', authorIcon: 'https://x/y.png',
        footerEnabled: true, footerText: 'footer',
        fields: [{ name: 'a', value: 'b', inline: true }],
    });
    assert.equal(s.title, 'Hello');
    assert.equal(s.color, '#ff0000');
    assert.equal(s.authorEnabled, true);
    assert.equal(s.fields.length, 1);
    assert.equal(s.fields[0].inline, true);
});

test('normalizeEmbedState also accepts a full Discord message payload', () => {
    const s = normalizeEmbedState({
        content: 'look at this',
        embeds: [{ title: 'T', color: 0x00ff00, fields: [{ name: 'n', value: 'v' }] }],
    });
    assert.equal(s.content, 'look at this');
    assert.equal(s.title, 'T');
    assert.equal(s.color, '#00ff00');
    assert.equal(s.fields[0].name, 'n');
});

test('normalizeEmbedState accepts a bare API embed object', () => {
    const s = normalizeEmbedState({ title: 'Bare', description: 'embed' });
    assert.equal(s.title, 'Bare');
    assert.equal(s.description, 'embed');
});

test('toApiEmbed converts state to a Discord API embed (colour as int)', () => {
    const embed = toApiEmbed({ title: 'Title', description: 'Desc', color: '#5865F2', timestamp: true });
    assert.equal(embed.title, 'Title');
    assert.equal(embed.description, 'Desc');
    assert.equal(embed.color, 0x5865f2);
    assert.ok(embed.timestamp, 'timestamp serialized');
    assert.ok(!embed.fields, 'no empty fields array');
});

test('toApiEmbed drops invalid URLs but keeps valid ones', () => {
    const embed = toApiEmbed({
        title: 'x',
        url: 'javascript:alert(1)',
        imageEnabled: true, imageUrl: 'not a url',
        thumbnailEnabled: true, thumbnailUrl: 'https://example.com/t.png',
    });
    assert.ok(!embed.url, 'non-http(s) url rejected');
    assert.ok(!embed.image, 'invalid image dropped');
    assert.deepEqual(embed.thumbnail, { url: 'https://example.com/t.png' });
});

test('toApiEmbed returns null when nothing is renderable', () => {
    assert.equal(toApiEmbed({}), null);
    assert.equal(toApiEmbed({ color: '#5865F2' }), null, 'colour alone is not renderable');
    assert.equal(toApiEmbed({ footerEnabled: true, footerText: '' }), null);
});

test('toApiEmbed truncates fields to the Discord limits', () => {
    const embed = toApiEmbed({
        title: 'x'.repeat(300),
        description: 'y'.repeat(5000),
        fields: [{ name: 'n'.repeat(300), value: 'v'.repeat(2000) }],
    });
    assert.equal(embed.title.length, LIMITS.TITLE);
    assert.equal(embed.description.length, LIMITS.DESCRIPTION);
    assert.equal(embed.fields[0].name.length, LIMITS.FIELD_NAME);
    assert.equal(embed.fields[0].value.length, LIMITS.FIELD_VALUE);
});

test('toApiEmbed caps the field count at 25', () => {
    const fields = Array.from({ length: 30 }, (_, i) => ({ name: `f${i}`, value: 'v' }));
    const embed = toApiEmbed({ title: 'x', fields });
    assert.equal(embed.fields.length, LIMITS.FIELD_COUNT);
});

test('toMessagePayload includes content, embeds, or both', () => {
    const withBoth = toMessagePayload({ content: 'hi', title: 'T' });
    assert.equal(withBoth.content, 'hi');
    assert.equal(withBoth.embeds.length, 1);

    const contentOnly = toMessagePayload({ content: 'just text' });
    assert.equal(contentOnly.content, 'just text');
    assert.ok(!contentOnly.embeds);

    const embedOnly = toMessagePayload({ title: 'just embed' });
    assert.ok(!embedOnly.content);
    assert.equal(embedOnly.embeds.length, 1);
});

test('toMessagePayload returns null for an empty payload', () => {
    assert.equal(toMessagePayload({}), null);
    assert.equal(toMessagePayload(null), null);
});

test('toMessagePayload truncates content to 2000 chars', () => {
    const payload = toMessagePayload({ content: 'z'.repeat(3000) });
    assert.equal(payload.content.length, LIMITS.CONTENT);
});