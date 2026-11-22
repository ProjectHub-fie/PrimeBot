'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { stripEmbedColor, stripEmbedColors } = require('../shared/embedStyle');
const { installEmojiTransformer } = require('../utils/emojiTransformer');

test('stripEmbedColor removes only the colour', () => {
    const embed = {
        color: 0x5865F2,
        title: 'Title',
        description: 'Description',
        fields: [{ name: 'A', value: 'B' }],
        footer: { text: 'Footer' },
    };
    const out = stripEmbedColor(embed);
    assert.equal(out.color, undefined);
    assert.equal(out.title, 'Title');
    assert.equal(out.description, 'Description');
    assert.deepEqual(out.fields, embed.fields);
    assert.deepEqual(out.footer, embed.footer);
    assert.equal(embed.color, 0x5865F2, 'input is not mutated');
});

test('stripEmbedColors handles message and webhook payloads', () => {
    const payload = {
        content: 'hi',
        embeds: [{ color: 1, title: 'one' }, { color: 2, title: 'two' }],
        allowed_mentions: { parse: [] },
    };
    const out = stripEmbedColors(payload);
    assert.equal(out.content, 'hi');
    assert.deepEqual(out.allowed_mentions, { parse: [] });
    assert.deepEqual(out.embeds.map(e => e.color), [undefined, undefined]);
    assert.deepEqual(out.embeds.map(e => e.title), ['one', 'two']);
    assert.equal(payload.embeds[0].color, 1, 'input is not mutated');
});

test('stripEmbedColors handles a bare embed payload and arrays', () => {
    assert.equal(stripEmbedColors({ embed: { color: 1, title: 'x' } }).embed.color, undefined);
    const arr = stripEmbedColors([{ embeds: [{ color: 1 }] }]);
    assert.equal(arr[0].embeds[0].color, undefined);
});

test('the REST transformer strips embed colours even without an emoji manager', async () => {
    const calls = [];
    const client = {
        rest: {
            post: (route, options) => { calls.push({ route, options }); return Promise.resolve(); },
            patch: () => Promise.resolve(),
            put: () => Promise.resolve(),
        },
    };
    assert.equal(installEmojiTransformer(client, null), true);
    await client.rest.post('/channels/1/messages', {
        body: { content: 'hi', embeds: [{ color: 0x5865F2, title: 'T' }] },
    });
    assert.equal(calls[0].options.body.embeds[0].color, undefined);
    assert.equal(calls[0].options.body.content, 'hi');

    await client.rest.post('/applications/1/commands', {
        body: { embeds: [{ color: 0x5865F2 }] },
    });
    assert.equal(calls[1].options.body.embeds[0].color, 0x5865F2, 'non-message routes untouched');
});

test('the failover webhook payload has no colour', () => {
    const src = require('node:fs').readFileSync(require.resolve('../utils/webhookLogger'), 'utf8');
    assert.ok(!/^\s*color,\s*$/m.test(src), 'webhookLogger no longer puts color on the embed');
});
