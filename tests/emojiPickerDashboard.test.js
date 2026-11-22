'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const guildPages = require('../dashboard/render/guild-pages');

const ROOT = path.join(__dirname, '..');

function fakeGuild() {
    return {
        id: '123', name: 'Test Guild', icon: null, _bypassUpcoming: true,
        _channels: [], _roles: [],
        _ticketPanel: {
            id: 42, name: 'Support', messageType: 'embed', title: 'Need help?',
            description: 'Click below', buttonLabel: 'Open', buttonStyle: 'Primary',
            buttonEmoji: '🎫', closeButtonEmoji: '🔒',
            closeFlow: { confirmYes: { emoji: '✅' }, confirmNo: { emoji: '✖️' } },
        },
    };
}

test('ticket editor renders custom-emoji picker fields and loads the picker script', () => {
    const html = guildPages.ticketEditPage({ guild: fakeGuild(), user: null });
    assert.ok(html.includes('/js/emoji-picker.js'), 'picker script loaded');
    assert.ok(html.includes('id="tk-button-emoji" data-emoji-picker'), 'open button emoji is pickable');
    assert.ok(html.includes('id="tk-btn-close-emoji" data-emoji-picker'), 'close button emoji is pickable');
});

test('ticket editor component emoji templates are pickable', () => {
    const src = fs.readFileSync(path.join(ROOT, 'dashboard/render/guild-pages.js'), 'utf8');
    assert.match(src, /class="pcomp-emoji" data-emoji-picker/);
    assert.match(src, /class="pcomp-opt-emoji" data-emoji-picker/);
});

test('emoji picker stores a canonical token and previews animated emojis', () => {
    const src = fs.readFileSync(path.join(ROOT, 'dashboard/public/js/emoji-picker.js'), 'utf8');
    assert.match(src, /`<\$\{emoji\.animated \? 'a' : ''\}:\$\{emoji\.name\}:\$\{emoji\.id\}>`/);
    assert.match(src, /cdn\.discordapp\.com\/emojis/);
    assert.match(src, /emoji\.animated \? 'gif' : 'png'/);
    assert.match(src, /dataset\.emojiId/);
    assert.match(src, /dataset\.emojiName/);
    assert.match(src, /dataset\.emojiAnimated/);
    assert.match(src, /input\[data-emoji-picker\]/);
});

test('the dashboard exposes an authenticated emoji catalog API', () => {
    const src = fs.readFileSync(path.join(ROOT, 'dashboard/server.js'), 'utf8');
    assert.match(src, /app\.get\('\/api\/emojis', requireAuth/);
    assert.match(src, /app\.post\('\/api\/emojis\/validate', requireAuth/);
    assert.match(src, /getEmojiCatalog\(\)/);
});
