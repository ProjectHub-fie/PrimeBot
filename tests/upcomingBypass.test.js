// The Events page renders the "Coming Soon" overlay for everyone
// (`upcoming: true` in render/guild.js TABS). Users holding a developer/owner
// bot role bypass the gate: the dashboard sets guild._bypassUpcoming
// (dashboard/auth.js) and eventsPage then renders the real editor.
// Tickets has been RELEASED (the `upcoming: true` flag was removed), so
// ticketsPage always renders the real panel list.

const { test } = require('node:test');
const assert = require('node:assert');

const guildPages = require('../dashboard/render/guild-pages');

function fakeGuild(bypass) {
    return {
        id: '123456789012345678',
        name: 'Test Guild',
        icon: null,
        approximate_member_count: 1,
        _bypassUpcoming: bypass,
        _channels: [],
        _roles: [],
        _beta: false,
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, ticketPanels: [] },
    };
}

test('eventsPage renders the Coming Soon overlay for ordinary users', () => {
    const html = guildPages.eventsPage({ guild: fakeGuild(false), user: null });
    assert.ok(html.includes('upcoming-locked-wrap locked'), 'expected the locked overlay');
});

test('eventsPage renders the real editor when guild._bypassUpcoming is set', () => {
    const html = guildPages.eventsPage({ guild: fakeGuild(true), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'overlay should be skipped');
    assert.ok(html.includes('id="ev-form"'), 'real editor form must render');
});

test('antiNukePage renders the Coming Soon overlay for ordinary users', () => {
    const html = guildPages.antiNukePage({ guild: fakeGuild(false), user: null });
    assert.ok(html.includes('upcoming-locked-wrap locked'), 'expected the locked overlay');
});

test('antiNukePage renders the real editor when guild._bypassUpcoming is set', () => {
    const html = guildPages.antiNukePage({ guild: fakeGuild(true), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'overlay should be skipped');
    assert.ok(html.includes('id="an-enabled"'), 'real Anti-Nuke editor must render');
});

test('ticketsPage renders the real panel list for ordinary users (released)', () => {
    const html = guildPages.ticketsPage({ guild: fakeGuild(false), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'overlay must NOT be present — tickets is released');
    assert.ok(html.includes('id="tk-create-open"'), 'create button renders');
});

test('ticketsPage renders the real panel list for bypass users too', () => {
    const html = guildPages.ticketsPage({ guild: fakeGuild(true), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'overlay should not be present for bypass users');
    assert.ok(html.includes('id="tk-create-open"'), 'create button renders');
});
