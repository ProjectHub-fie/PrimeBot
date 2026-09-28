// Event Management feature tests (pure + render + repo-normalization).
//
// No Postgres and no Discord API: the pg pool is stubbed before requiring the
// repo, and the render modules are pure. Covers the shared catalogs, the
// status lifecycle, the message builders, the admin-authored normalization
// (never trusting client input), permission checks, and the dashboard pages.

const { test } = require('node:test');
const assert = require('node:assert');

// Stub the pg pool before requiring the repo so no real connection is made.
const { eventMgmtPool } = require('../server/eventMgmtDb');
eventMgmtPool.query = async () => ({ rows: [], rowCount: 0 });

const C = require('../shared/eventConstants');
const M = require('../shared/eventMessages');
const repo = require('../server/eventMgmtRepo');

// ── Catalogs ────────────────────────────────────────────────────────────────
test('event type catalog covers the required types and has valid SVG icons', () => {
    const { ICONS } = require('../dashboard/public/js/icons');
    const required = ['community', 'gaming', 'tournament', 'giveaway', 'meeting', 'watchparty', 'custom'];
    for (const key of required) {
        assert.ok(C.EVENT_TYPE_KEYS.includes(key), `missing type ${key}`);
    }
    for (const t of C.EVENT_TYPES) {
        assert.ok(t.icon, `type ${t.key} missing emoji icon`);
        assert.ok(t.iconName && ICONS[t.iconName], `type ${t.key} missing SVG icon "${t.iconName}"`);
    }
});

test('event status/filter catalogs have SVG icons', () => {
    const { ICONS } = require('../dashboard/public/js/icons');
    for (const s of C.EVENT_STATUSES) {
        assert.ok(ICONS[s.icon], `status ${s.key} missing SVG icon "${s.icon}"`);
    }
});

test('event permission catalog + normalizer', () => {
    assert.ok(C.EVENT_PERMISSION_KEYS.length >= 5);
    assert.deepEqual(C.normalizeEventPermissions(['manage_events', 'bogus']), ['manage_events']);
    assert.deepEqual(C.normalizeEventPermissions(null).sort(), C.EVENT_PERMISSION_KEYS.slice().sort());
});

test('event templates never auto-publish and each has a patch object', () => {
    for (const t of C.EVENT_TEMPLATES) {
        assert.ok(t.key && t.label && t.patch && typeof t.patch === 'object');
        assert.ok(!('status' in t.patch), `template ${t.key} must not force a status`);
    }
});

// ── Status lifecycle ────────────────────────────────────────────────────────
test('status transitions follow the lifecycle', () => {
    assert.ok(C.canTransition('draft', 'scheduled'));
    assert.ok(C.canTransition('scheduled', 'registration_open'));
    assert.ok(C.canTransition('registration_open', 'live'));
    assert.ok(C.canTransition('live', 'completed'));
    assert.ok(C.canTransition('registration_open', 'cancelled'));
    assert.ok(!C.canTransition('completed', 'live'));
    assert.ok(!C.canTransition('cancelled', 'scheduled'));
    assert.ok(C.canTransition('live', 'live'), 'same-status is a no-op, allowed');
});

test('registration is only allowed while the status is registration_open', () => {
    assert.ok(C.statusAllowsRegistration('registration_open'));
    assert.ok(!C.statusAllowsRegistration('scheduled'));
    assert.ok(!C.statusAllowsRegistration('registration_closed'));
    assert.ok(!C.statusAllowsRegistration('cancelled'));
});

// ── Message builders ────────────────────────────────────────────────────────
function sampleEvent(over = {}) {
    return {
        id: 7, guildId: '111111111111111111', name: 'Gaming Night', type: 'gaming',
        status: 'registration_open', registrationMode: 'open',
        startAt: new Date('2030-01-01T20:00:00Z').toISOString(),
        endAt: null, locationType: 'voice', locationValue: '222222222222222222',
        maxParticipants: 50, trackAttendance: false, embedColor: '#5865F2',
        reminders: ['1h'], ...over,
    };
}

test('announcement payload has one embed + a components row with the event buttons', () => {
    const payload = M.buildAnnouncementPayload(sampleEvent(), { participants: 24 });
    assert.equal(payload.embeds.length, 1);
    assert.equal(payload.components.length, 1);
    const ids = payload.components[0].components.map(c => c.custom_id);
    for (const id of ['evjoin:7', 'evleave:7', 'evparts:7', 'evinfo:7', 'evremind:7']) {
        assert.ok(ids.includes(id), `missing ${id}`);
    }
    // No mention parsing (anti-ping abuse).
    assert.deepEqual(payload.allowed_mentions, { parse: [] });
});

test('a cancelled/completed event disables the join/leave buttons', () => {
    for (const status of ['cancelled', 'completed']) {
        const payload = M.buildAnnouncementPayload(sampleEvent({ status }));
        const ids = payload.components.flatMap(r => r.components.map(c => c.custom_id));
        assert.ok(!ids.some(id => id.startsWith('evjoin:')), `${status} still shows Join`);
        assert.ok(!ids.some(id => id.startsWith('evleave:')), `${status} still shows Leave`);
        assert.ok(ids.includes('evparts:7'), 'Participants button should remain');
    }
});

test('a live event with attendance tracking shows the Check In button', () => {
    const payload = M.buildAnnouncementPayload(sampleEvent({ status: 'live', trackAttendance: true }));
    const ids = payload.components.flatMap(r => r.components.map(c => c.custom_id));
    assert.ok(ids.includes('evcheckin:7'));
});

test('every component row respects Discord’s 5-buttons-per-row cap', () => {
    const payload = M.buildAnnouncementPayload(sampleEvent({ status: 'live', trackAttendance: true }));
    for (const row of payload.components) {
        assert.ok(row.components.length <= 5, `row has ${row.components.length} components`);
    }
});

test('customIds never exceed the 100-char limit', () => {
    const payload = M.buildAnnouncementPayload(sampleEvent({ id: '1234567890' }));
    for (const c of payload.components.flatMap(r => r.components)) {
        assert.ok(c.custom_id.length <= 100, `${c.custom_id} too long`);
    }
});

test('the embed colour follows the event, falling back to the type colour', () => {
    const withColor = M.buildAnnouncementPayload(sampleEvent({ embedColor: '#ABCDEF' })).embeds[0];
    assert.equal(withColor.color, 0xABCDEF);
    const noColor = M.buildAnnouncementPayload(sampleEvent({ embedColor: null })).embeds[0];
    assert.equal(noColor.color, 0x57F287); // gaming green
});

test('reminder payload includes the event name and the humanized offset', () => {
    const p = M.buildReminderPayload(sampleEvent(), 60);
    assert.match(p.content, /Gaming Night/);
    assert.match(p.content, /1 hour/);
    assert.deepEqual(p.allowed_mentions, { parse: [] });
});

test('discord timestamps render for valid dates and are omitted for invalid', () => {
    assert.match(M.discordTimestamp(new Date('2030-01-01T00:00:00Z'), 'R'), /^<t:\d+:R>$/);
    assert.equal(M.discordTimestamp('not-a-date', 'R'), '');
});

// ── Repository normalisation (never trusts client input) ─────────────────────
test('normalizeEventConfig trims, clamps and validates fields', () => {
    const cfg = repo.normalizeEventConfig({
        name: '   My Event   ',
        type: 'not-a-type',
        maxParticipants: 0,
        startAt: '2030-01-01T10:00:00Z',
        endAt: '2029-01-01T00:00:00Z', // before start → dropped
        embedColor: 'nope',
        imageUrl: 'javascript:alert(1)',
        reminders: ['1h', '1h', 'bogus', '5m'],
        eventPermissions: ['manage_events', 'hacker'],
        description: 'x',
    });
    assert.equal(cfg.name, 'My Event');
    assert.equal(cfg.type, 'custom');            // invalid type → custom
    assert.equal(cfg.maxParticipants, 1);        // 0 clamps up to 1
    assert.equal(cfg.endAt, null);               // end before start dropped
    assert.equal(cfg.embedColor, '#5865F2');     // invalid colour → default
    assert.equal(cfg.imageUrl, null);            // non-http url rejected
    assert.deepEqual(cfg.reminders, ['1h', '5m']); // deduped + validated
    assert.deepEqual(cfg.eventPermissions, ['manage_events']);
});

test('normalizeEventConfig keeps existing values when a key is absent (patch)', () => {
    const existing = repo.rowToEvent({
        id: 1, guild_id: 'g', name: 'Old', type: 'gaming', status: 'scheduled',
        registration_mode: 'open', timezone: 'UTC', location_type: 'none',
        waitlist_enabled: true, track_attendance: false, embed_color: '#5865F2',
        event_permissions: ['manage_events'], embed_fields: [], reminders: ['1h'],
    });
    const patched = repo.normalizeEventConfig({ name: 'New Name' }, existing);
    assert.equal(patched.name, 'New Name');
    assert.equal(patched.type, 'gaming');     // untouched
    assert.equal(patched.status, 'scheduled'); // untouched
    assert.deepEqual(patched.reminders, ['1h']);
});

test('normalizeEventConfig caps an oversized name and description', () => {
    const cfg = repo.normalizeEventConfig({ name: 'a'.repeat(500), description: 'b'.repeat(20000) });
    assert.equal(cfg.name.length, 100);
    assert.equal(cfg.description.length, 8000);
});

test('normalizeEventConfig validates embed fields (count + lengths)', () => {
    const cfg = repo.normalizeEventConfig({
        embedFields: Array.from({ length: 40 }, (_, i) => ({ name: 'n'.repeat(500), value: 'v'.repeat(2000), inline: i % 2 === 0 })),
    });
    assert.equal(cfg.embedFields.length, 25);
    assert.equal(cfg.embedFields[0].name.length, 256);
    assert.equal(cfg.embedFields[0].value.length, 1024);
    assert.equal(cfg.embedFields[0].inline, true);
});

test('rowToEvent maps snake_case columns to the camelCase API shape', () => {
    const ev = repo.rowToEvent({
        id: 3, guild_id: 'g1', creator_id: 'u1', name: 'E', type: 'custom', status: 'draft',
        start_at: '2030-01-01T00:00:00Z', end_at: null, timezone: 'UTC',
        location_type: 'none', location_value: null, registration_mode: 'open',
        max_participants: null, waitlist_enabled: true, registration_deadline: null,
        track_attendance: false, announcement_channel_id: null, announcement_message_id: null,
        participant_role_id: null, staff_role_id: null, winner_role_id: null,
        attendance_role_id: null, event_manager_role_id: null, event_permissions: [],
        image_url: null, thumbnail_url: null, embed_title: null, embed_description: null,
        embed_color: '#5865F2', embed_fields: [], embed_footer: null, reminders: [],
        result: null, created_at: '2030-01-01T00:00:00Z', updated_at: '2030-01-01T00:00:00Z',
        participation_count: 0,
    });
    assert.equal(ev.guildId, 'g1');
    assert.equal(ev.registrationMode, 'open');
    assert.equal(ev.waitlistEnabled, true);
    assert.equal(ev.participantCount, 0);
});

// ── Permissions middleware ──────────────────────────────────────────────────
test('event permission middleware allows the owner and denies a non-manager', async () => {
    const eventAuth = require('../dashboard/eventAuth');
    const mw = eventAuth.requireEventPermission('manage_events');

    // Owner bypasses.
    let called = false;
    await mw({ guild: { id: 'g', userIsOwner: true }, user: { id: 'u' }, session: { userGuildPermissions: '0' } }, {}, () => { called = true; });
    assert.ok(called, 'owner should pass');

    // Non-admin without the manager role → 403.
    // Stub the repo so getGuildEvents returns an event with a manager role.
    const { eventMgmtPool: pool } = require('../server/eventMgmtDb');
    const origQuery = pool.query;
    pool.query = async (sql) => {
        if (/FROM em_events/.test(sql)) {
            return { rows: [{ id: 1, guild_id: 'g', event_manager_role_id: 'ROLE', event_permissions: ['manage_events'] }], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
    };
    // Stub the Discord member-role lookup to return no matching role.
    const discord = require('../dashboard/discord');
    const origRoles = discord.getGuildMemberRoles;
    discord.getGuildMemberRoles = async () => ['OTHER'];
    eventAuth.clearEventPolicyCache('g');

    let status = null;
    const res = { status(code) { status = code; return { json() {} }; } };
    await mw({ guild: { id: 'g', userIsOwner: false }, user: { id: 'u' }, session: { userGuildPermissions: '0' } }, res, () => { throw new Error('should not pass'); });
    assert.equal(status, 403);

    // With the manager role → passes.
    discord.getGuildMemberRoles = async () => ['ROLE'];
    eventAuth.clearEventPolicyCache('g');
    let passed = false;
    await mw({ guild: { id: 'g', userIsOwner: false }, user: { id: 'u' }, session: { userGuildPermissions: '0' } }, { status() { return { json() {} }; } }, () => { passed = true; });
    assert.ok(passed, 'event manager should pass');

    pool.query = origQuery;
    discord.getGuildMemberRoles = origRoles;
    eventAuth.clearEventPolicyCache();
});

test('requireEventOwnership rejects cross-guild access (IDOR)', async () => {
    const eventAuth = require('../dashboard/eventAuth');
    const { eventMgmtPool: pool } = require('../server/eventMgmtDb');
    const orig = pool.query;
    pool.query = async () => ({ rows: [{ id: 9, guild_id: 'OTHER_GUILD', name: 'x' }], rowCount: 1 });
    let status = null;
    const res = { status(code) { status = code; return { json() {} }; } };
    await eventAuth.requireEventOwnership({ params: { id: '9' }, guild: { id: 'MY_GUILD' } }, res, () => { throw new Error('should not pass'); });
    assert.equal(status, 404);
    pool.query = orig;
});

test('requireEventOwnership sets req.event for the owning guild', async () => {
    const eventAuth = require('../dashboard/eventAuth');
    const { eventMgmtPool: pool } = require('../server/eventMgmtDb');
    const orig = pool.query;
    pool.query = async () => ({
        rows: [{ id: 9, guild_id: 'MY_GUILD', name: 'x', type: 'custom', status: 'draft', registration_mode: 'open', timezone: 'UTC', location_type: 'none', waitlist_enabled: true, track_attendance: false, embed_color: '#5865F2', event_permissions: [], embed_fields: [], reminders: [] }],
        rowCount: 1,
    });
    const req = { params: { id: '9' }, guild: { id: 'MY_GUILD' } };
    let passed = false;
    await eventAuth.requireEventOwnership(req, {}, () => { passed = true; });
    assert.ok(passed);
    assert.equal(req.event.id, 9);
    pool.query = orig;
});

// ── Dashboard render ────────────────────────────────────────────────────────
function fakeGuild(over = {}) {
    return {
        id: '111111111111111111', name: 'Test Guild', icon: null, approximate_member_count: 10,
        _config: { server: {}, welcome: {}, logging: {}, automod: {}, antiNuke: {}, events: [], eventTotal: 0, eventPolicy: { managerRoleId: null, permissions: [] } },
        _channels: [{ id: '111111111111111112', name: 'general' }],
        _roles: [], _beta: false, _bypassUpcoming: false,
        ...over,
    };
}

test('eventsPage renders the premium hero, stats and create button for bypass developers', () => {
    const gp = require('../dashboard/render/guild-pages');
    // Developer/owner roles bypass the upcoming gate and see the real page.
    const html = gp.eventsPage({ guild: fakeGuild({ _bypassUpcoming: true }), user: { username: 'u' } });
    assert.match(html, /Event Management/);
    assert.match(html, /Create, manage, and run Discord events with ease\./);
    assert.match(html, /Premium features in free\./);
    assert.match(html, /Create Event/);
    assert.match(html, /Manage Events/);
    assert.match(html, /Active Events/);
    assert.match(html, /Upcoming Events/);
    assert.match(html, /Completed Events/);
    assert.match(html, /Total Participants/);
    assert.ok(!html.includes('upcoming-locked-wrap locked'), 'bypass users get the real editor, not the overlay');
    assert.match(html, /<svg class="ico"/);
});

test('eventsPage renders the Coming Soon overlay for ordinary users (upcoming)', () => {
    const gp = require('../dashboard/render/guild-pages');
    const html = gp.eventsPage({ guild: fakeGuild(), user: { username: 'u' } });
    assert.match(html, /upcoming-locked-wrap locked/, 'ordinary users see the locked overlay');
    assert.match(html, /Event Management……/, 'overlay names the feature');
});

test('eventWizardPage and eventManagePage are gated for ordinary users but usable by bypass developers', () => {
    const gp = require('../dashboard/render/guild-pages');
    const ev = { id: 5, guildId: '111111111111111111', name: 'Night', type: 'gaming', status: 'registration_open', registrationMode: 'open', startAt: new Date().toISOString(), maxParticipants: 50, waitlistEnabled: true, trackAttendance: true, reminders: ['1h'], eventPermissions: [], participantRoleId: null };
    const wizardGated = gp.eventWizardPage({ guild: fakeGuild(), user: null, template: 'gaming-night' });
    assert.match(wizardGated, /upcoming-locked-wrap locked/, 'wizard gated for ordinary users');
    const manageGated = gp.eventManagePage({ guild: fakeGuild(), user: null, event: ev, participants: [], activity: [], activeTab: 'overview' });
    assert.match(manageGated, /upcoming-locked-wrap locked/, 'manage page gated for ordinary users');

    const wizard = gp.eventWizardPage({ guild: fakeGuild({ _bypassUpcoming: true }), user: null, template: 'gaming-night' });
    assert.ok(!wizard.includes('upcoming-locked-wrap locked'), 'bypass users get the wizard');
    const manage = gp.eventManagePage({ guild: fakeGuild({ _bypassUpcoming: true }), user: null, event: ev, participants: [], activity: [], activeTab: 'overview' });
    assert.ok(!manage.includes('upcoming-locked-wrap locked'), 'bypass users get the manage page');
});

test('eventsPage shows the branded empty state when there are no events', () => {
    const gp = require('../dashboard/render/guild-pages');
    const html = gp.eventsPage({ guild: fakeGuild({ _bypassUpcoming: true }), user: { username: 'u' } });
    assert.match(html, /No events yet/);
    assert.match(html, /Create your first community event/);
});

test('eventWizardPage renders all eight steps + a progress indicator', () => {
    const gp = require('../dashboard/render/guild-pages');
    const html = gp.eventWizardPage({ guild: fakeGuild({ _bypassUpcoming: true }), user: { username: 'u' }, template: 'gaming-night' });
    for (const step of ['Basic Information', 'Schedule', 'Location', 'Registration', 'Roles', 'Discord Message', 'Advanced Settings', 'Review']) {
        assert.ok(html.includes(step), `wizard missing step "${step}"`);
    }
    assert.match(html, /ev-step-panel/);
    assert.match(html, /id="ev-wizard-dots"/);
    // Template prefilled the name without publishing.
    assert.match(html, /Community Gaming Night/);
});

test('eventManagePage renders every management tab', () => {
    const gp = require('../dashboard/render/guild-pages');
    const ev = { id: 5, guildId: '111111111111111111', name: 'Night', type: 'gaming', status: 'registration_open', registrationMode: 'open', startAt: new Date().toISOString(), maxParticipants: 50, waitlistEnabled: true, trackAttendance: true, reminders: ['1h'], eventPermissions: [], participantRoleId: null };
    const html = gp.eventManagePage({ guild: fakeGuild({ _bypassUpcoming: true }), user: { username: 'u' }, event: ev, participants: [], activity: [], activeTab: 'overview' });
    for (const tab of ['Overview', 'Participants', 'Announcements', 'Reminders', 'Settings', 'Activity Log']) {
        assert.ok(html.includes(tab), `manage page missing tab "${tab}"`);
    }
    assert.match(html, /[Cc]ancel [Ee]vent/);
});

test('participants panel renders participant rows with actions', () => {
    const { eventManagePage } = require('../dashboard/render/guild-pages');
    const ev = { id: 5, guildId: '111111111111111111', name: 'Night', type: 'gaming', status: 'registration_open', registrationMode: 'open', startAt: new Date().toISOString(), maxParticipants: 50, waitlistEnabled: true, trackAttendance: true, reminders: [], eventPermissions: [], participantRoleId: null };
    const participants = [
        { userId: '222222222222222222', username: 'alice', status: 'registered', attendanceStatus: 'present', registeredAt: new Date().toISOString() },
        { userId: '333333333333333333', username: 'bob', status: 'waiting', attendanceStatus: 'unknown', registeredAt: new Date().toISOString() },
    ];
    const html = eventManagePage({ guild: fakeGuild({ _bypassUpcoming: true }), user: { username: 'u' }, event: ev, participants, activity: [], activeTab: 'participants' });
    assert.match(html, /alice/);
    assert.match(html, /bob/);
    assert.match(html, /ev-pt-remove/);
    assert.match(html, /ev-pt-promote/); // waiting-list promote button
    assert.match(html, /ev-pt-checkin/);
});

// ── $test command + npm script ──────────────────────────────────────────────
test('the bot exposes a developer-only $test command and npm has a test script', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'events', 'messageCreate.js'), 'utf8');
    assert.match(src, /case "test":/);
    assert.match(src, /exec\('npm test'/);
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    assert.match(pkg.scripts.test, /node --test tests\/\*\.test\.js/);
});

// ── Adaptive scheduler reuse ─────────────────────────────────────────────────
test('the EventMgmtManager reuses the shared AdaptivePoller (no fixed timer)', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils', 'eventMgmtManager.js'), 'utf8');
    assert.match(src, /AdaptivePoller/);
    // No per-second polling of the database.
    assert.ok(!/setInterval\([^)]*,\s*1000\s*\)/.test(src), 'must not poll the DB every second');
});

test('the countdown is client-side only (no fetch in the countdown tick)', () => {
    const fs = require('fs');
    const path = require('path');
    for (const f of ['events-hub.js', 'events-manage.js']) {
        const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', f), 'utf8');
        // Locate the countdown tick function and assert it contains no api()/fetch.
        const tickMatch = src.match(/function tick(?:Countdowns)?\(\)\s*\{[\s\S]*?\n  \}/);
        if (tickMatch) {
            assert.ok(!/api\(|fetch\(/.test(tickMatch[0]), `${f}: countdown must not perform network calls`);
        }
    }
});

// ── Rate-limit protection ───────────────────────────────────────────────────
test('role operations and DMs are paced through serial queues', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils', 'eventMgmtManager.js'), 'utf8');
    assert.match(src, /SerialQueue/);
    assert.match(src, /_roleQueue/);
    assert.match(src, /_dmQueue/);
    const discordSrc = fs.readFileSync(path.join(__dirname, '..', 'utils', 'eventDiscord.js'), 'utf8');
    assert.match(discordSrc, /class SerialQueue/);
    assert.match(discordSrc, /role\.position >= me\.roles\.highest\.position/); // role hierarchy guard
});

test('SerialQueue runs tasks in order and survives a throwing task', async () => {
    const { SerialQueue } = require('../utils/eventDiscord');
    const q = new SerialQueue({ delayMs: 1 });
    const order = [];
    q.push(async () => order.push(1));
    q.push(async () => { throw new Error('boom'); });
    q.push(async () => order.push(3));
    await q.drain();
    assert.deepEqual(order, [1, 3]);
});
