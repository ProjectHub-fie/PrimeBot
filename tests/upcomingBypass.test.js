// The Events and Tickets pages normally render the "Coming Soon" overlay for
// everyone (both are `upcoming: true` in render/guild.js TABS. Users holding
// a developer/owner bot role bypass the gate: the dashboard sets
// guild._bypassUpcoming (dashboard/auth.js)and eventsPage / ticketsPage must
// then render the real editor instead of the locked overlay.

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

test('ticketsPage renders the Coming Soon overlay for ordinary users', () => {
    const html = guildPages.ticketsPage({ guild: fakeGuild(false), user: null });
    assert.ok(html.includes('upcoming-locked-wrap locked'), 'expected the locked overlay — tickets is gated until release');
});

test('ticketsPage renders the real panel list when guild._bypassUpcoming is set', () => {
    const html = guildPages.ticketsPage({ guild: fakeGuild(true), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'overlay should be skipped for bypass users');
    assert.ok(html.includes('id="tk-create-open"'), 'create button renders');
});
