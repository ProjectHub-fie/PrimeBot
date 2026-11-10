// Event Management renders the "Coming Soon" overlay for everyone
// (`upcoming: true` in render/guild.js TABS). Users holding a developer/owner bot
// role bypass the gate: the dashboard sets guild._bypassUpcoming
// (dashboard/auth.js) and the page then renders the real editor.
//
// Anti-Nuke is RELEASED (`upcoming` removed from render/guild.js TABS). It does
// NOT use the shared upcoming overlay — it has its own owner-controlled access
// gate, so an ordinary admin sees the no-access panel and the owner sees the
// editor. Tickets is RELEASED too and renders its real content for every admin.

const { test } = require('node:test');
const assert = require('node:assert');

const guildPages = require('../dashboard/render/guild-pages');

function fakeGuild(bypass) {
    return {
        id: '123456789012345678',
        name: 'Test Guild',
        icon: null,
        approximate_member_count: 1,
        owner_id: '1',
        _bypassUpcoming: bypass,
        // The Anti-Nuke page is gated by the owner-controlled hierarchy (not
        // the upcoming overlay). The `bypass` fixture doubles as the owner so
        // the real markup is asserted; `false` doubles as a non-owner admin.
        _antiNukeAccess: bypass
            ? { ok: true, isOwner: true, role: 'owner', level: 1, permissions: [] }
            : { ok: true, isOwner: false, role: 'none', level: 4, permissions: [] },
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

test('antiNukePage renders the no-access panel for an ordinary administrator (not the overlay, not the editor)', () => {
    // The feature is unreleased, but its gate is the owner-controlled access
    // hierarchy (not the shared upcoming overlay). An ordinary Discord
    // Administrator gets the explanatory panel, never the editor.
    const html = guildPages.antiNukePage({ guild: fakeGuild(false), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'Anti-Nuke uses its own access gate, shared upcoming overlay is not used');
    assert.ok(html.includes('No Anti-Nuke access'), 'the viewer sees the no-access panel');
    assert.ok(!html.includes('data-method="automatic"'), 'the setup wizard is never rendered without access');
});

test('antiNukePage renders the real setup wizard for the actual server owner', () => {
    const html = guildPages.antiNukePage({ guild: fakeGuild(true), user: null });
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'the owner is not wrapped in the overlay');
    assert.ok(html.includes('data-method="automatic"'), 'automatic setup button renders');
    assert.ok(html.includes('data-method="manual"'), 'manual setup button renders');
});

test('antiNukePage renders the setup chooser (owner) before setup is complete', () => {
    const html = guildPages.antiNukePage({ guild: fakeGuild(true), user: null });
    assert.ok(html.includes('data-method="automatic"'), 'automatic setup button renders');
    assert.ok(html.includes('data-method="manual"'), 'manual setup button renders');
});

test('antiNukePage renders the protection console once setup is complete (owner)', () => {
    const guild = fakeGuild(true);
    guild._config.antiNuke = { enabled: true, dryRun: false, watched: {}, responses: ['alertOwner'] };
    guild._config.antiNukeSetup = { status: 'completed', progress: { percent: 100, completed: 16, total: 16, steps: [] } };
    guild._config.antiNukePermissions = { ok: true, checks: [], missing: [] };
    const html = guildPages.antiNukePage({ guild, user: null });
    assert.ok(html.includes('Threat detection'), 'console renders');
    assert.ok(!html.includes('DRY RUN ACTIVE'), 'dry-run banner does NOT render — dry run is off after setup');
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

test('Anti-Nuke and Tickets are released (no `upcoming` flag); Events is still upcoming', () => {
    const { TABS } = require('../dashboard/render/guild');
    const flag = (key) => {
        const tab = TABS.find(t => t.key === key);
        assert.ok(tab, `tab ${key} exists`);
        return tab.upcoming === true;
    };
    assert.equal(flag('antinuke'), false, 'Anti-Nuke is released — no SOON badge, no upcoming gate');
    assert.equal(flag('tickets'), false, 'Tickets is released');
    assert.equal(flag('events'), true, 'Event Management is still upcoming');
    // The nav renders the SOON badge for upcoming tabs only.
    const { tabNavHTML } = require('../dashboard/render/guild');
    const nav = tabNavHTML({ active: 'antinuke', guildId: '1' });
    const after = (label) => nav.slice(nav.indexOf(label), nav.indexOf(label) + 160);
    assert.ok(!after('Anti-Nuke').includes('soon-badge'), 'Anti-Nuke shows no SOON badge');
    assert.ok(after('Event Management').includes('soon-badge'), 'Events keeps its SOON badge');
});
