// Event Management renders the "Coming Soon" overlay for everyone
// (`upcoming: true` in render/guild.js TABS). Users holding a developer/owner bot
// role bypass the gate: the dashboard sets guild._bypassUpcoming
// (dashboard/auth.js) and the page then renders the real editor.
//
// Anti-Nuke and Tickets are RELEASED and render their real content for every
// authorized administrator — no overlay, no gate.

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
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, ticketPanels: [], events: [], eventTotal: 0, eventPolicy: { managerRoleId: null, permissions: [] } },
    };
}

test('eventsPage renders the Coming Soon overlay for ordinary users (upcoming)', () => {
    const html = guildPages.eventsPage({ guild: fakeGuild(false), user: null });
    assert.ok(html.includes('upcoming-locked-wrap locked'), 'ordinary users get the overlay');
    assert.ok(html.includes('Event Management'), 'the feature is named in the overlay');
});

test('eventsPage renders the real Event Management page for bypass users', () => {
    const html = guildPages.eventsPage({ guild: fakeGuild(true), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'overlay should be skipped for bypass users');
    assert.ok(html.includes('Create Event'), 'the real create button renders for bypass users');
});

test('antiNukePage is RELEASED — no overlay for ordinary users', () => {
    const html = guildPages.antiNukePage({ guild: fakeGuild(false), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'Anti-Nuke is released — no overlay');
    assert.ok(html.includes('PrimeBot Anti-Nuke'), 'the real page renders');
});

test('antiNukePage renders the setup chooser before setup is complete', () => {
    const html = guildPages.antiNukePage({ guild: fakeGuild(false), user: null });
    assert.ok(html.includes('data-method="automatic"'), 'automatic setup button renders');
    assert.ok(html.includes('data-method="manual"'), 'manual setup button renders');
});

test('antiNukePage renders the protection console once setup is complete', () => {
    const guild = fakeGuild(false);
    guild._config.antiNuke = { enabled: true, dryRun: true, watched: {}, responses: ['alertOwner'] };
    guild._config.antiNukeSetup = { status: 'completed', progress: { percent: 100, completed: 8, total: 8, steps: [] } };
    guild._config.antiNukePermissions = { ok: true, checks: [], missing: [] };
    const html = guildPages.antiNukePage({ guild, user: null });
    assert.ok(html.includes('Threat detection'), 'console renders');
    assert.ok(html.includes('DRY RUN ACTIVE'), 'dry-run banner renders');
    assert.ok(html.includes('an-activity-table'), 'security activity table renders');
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
