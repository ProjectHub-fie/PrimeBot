/* Anti-Nuke premium console + new protection surfaces.
 *
 * Covers the redesign deliverable (one horizontal rail, 15 sections, no full
 * page reloads) and the new backend helpers (backup capture/compare/restore
 * planning, lockdown profiles, overview aggregates). Pure — no DB/network.
 */
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const page = require('../dashboard/render/antinuke-page.js');
const guildPages = require('../dashboard/render/guild-pages.js');
const constants = require('../dashboard/constants');

const EXPECTED_SECTIONS = [
    'overview', 'protection', 'antiraid', 'permission', 'channel', 'role',
    'webhook', 'bot', 'responses', 'backups', 'lockdown', 'access',
    'incidents', 'health', 'settings',
];

function fixture() {
    return {
        id: '1', name: 'Test', _channels: [], _roles: [],
        _config: {
            antiNuke: {
                enabled: true, dryRun: false, watched: {}, responses: ['alertOwner'],
                raid: { enabled: true, joinThreshold: 10, joinWindowSeconds: 30 },
                lockdown: { enabled: true },
            },
            antiNukeLockdown: { active: false },
            antiNukePermissions: { ok: true, checks: [], missing: [] },
            antiNukeSummary: { total: 0, byAction: [] },
            antiNukeSetup: { status: 'completed', progress: { percent: 100, completed: 16, total: 16, steps: [] } },
        },
        _antiNukeAccess: { ok: true, role: 'owner', isOwner: true, level: 0, permissions: [] },
    };
}

function body(html) { return typeof html === 'string' ? html : html.body; }

// ── Section rail ────────────────────────────────────────────────────────────

test('SECTION_ORDER exposes exactly the 15 requested sections in order', () => {
    assert.deepEqual(page.SECTION_ORDER.map(s => s.key), EXPECTED_SECTIONS);
});

test('every section is rendered exactly once and has a matching rail button', () => {
    const html = body(guildPages.antiNukePage({ guild: fixture(), user: { username: 'u' } }));
    for (const key of EXPECTED_SECTIONS) {
        const rendered = (html.match(new RegExp(`class="an-section" data-section="${key}"`, 'g')) || []).length;
        assert.equal(rendered, 1, `section ${key} rendered ${rendered} times`);
        assert.ok(html.includes(`data-section="${key}"`), `missing rail/section ${key}`);
    }
    const buttons = (html.match(/class="am-section-btn[^"]*" data-section="([a-z]+)"/g) || []);
    assert.equal(buttons.length, EXPECTED_SECTIONS.length, 'rail button count');
});

test('the rail is a single horizontal, sticky, scrollable row (no wrapping)', () => {
    const css = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'styles.css'), 'utf8');
    const m = css.match(/\.an-sections\s*\{[^}]*\}/);
    assert.ok(m, 'no .an-sections rule');
    assert.match(m[0], /position:\s*sticky/);
    assert.match(m[0], /flex-wrap:\s*nowrap/);
    assert.match(m[0], /overflow-x:\s*auto/);
});

test('the client keeps the active section in the URL and on refresh', () => {
    const js = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'antinuke.js'), 'utf8');
    assert.match(js, /searchParams\.set\('section'/);
    assert.match(js, /searchParams\.get\('section'\)/);
    assert.match(js, /scrollIntoView/);
    assert.match(js, /ArrowRight/);
    assert.match(js, /popstate/);
});

test('the overview section renders real stat slots, not hardcoded numbers', () => {
    const html = body(guildPages.antiNukePage({ guild: fixture(), user: { username: 'u' } }));
    assert.ok(html.includes('id="an-overview-live"'));
    assert.ok(html.includes('id="an-overview-range"'));
    // The date filter offers 24h / 7d / 30d / all time.
    for (const v of ['1', '7', '30', '0']) assert.ok(html.includes(`value="${v}"`), `missing range ${v}`);
});

// ── Backups (pure planning) ─────────────────────────────────────────────────

const backup = require('../utils/antiNukeBackup');

test('buildSnapshot captures roles + channels with permission bitfields', () => {
    const snap = backup.buildSnapshot({
        guildId: 'g1', name: 'snap', createdBy: 'u1',
        reader: {
            roles: [{ id: 'r1', name: 'Admin', position: 5, permissions: '8', color: 0 }],
            channels: [{ id: 'c1', name: 'general', type: 0, position: 1, permissionOverwrites: [{ id: 'g1', type: 0, allow: '0', deny: '2048' }] }],
        },
    });
    assert.equal(snap.counts.roles, 1);
    assert.equal(snap.counts.channels, 1);
    assert.equal(snap.roles[0].permissions, '8');
    assert.equal(snap.channels[0].permissionOverwrites[0].deny, '2048');
});

test('compareSnapshot detects missing + modified structure', () => {
    const snapshot = { roles: [{ id: 'r1', name: 'A', permissions: '8', position: 1 }], channels: [{ id: 'c1', name: 'x', type: 0 }] };
    const live = { roles: [{ id: 'r1', name: 'A', permissions: '0', position: 1 }], channels: [] };
    const diff = backup.compareSnapshot(snapshot, live);
    assert.equal(diff.modifiedRoles.length, 1);
    assert.equal(diff.missingChannels.length, 1);
    assert.equal(diff.missingRoles.length, 0);
});

test('planRestore skips safe roles and roles above the bot, and labels new ids', () => {
    const snapshot = { roles: [
        { id: 'owner-role', name: 'Owner', permissions: '8', position: 10 },
        { id: 'r2', name: 'Mod', permissions: '8', position: 2 },
        { id: 'r3', name: 'High', permissions: '8', position: 99 },
    ], channels: [{ id: 'c9', name: 'gone', type: 0 }] };
    const plan = backup.planRestore(snapshot, { roles: [], channels: [] }, { safeRoleIds: ['owner-role'], botHighestPosition: 5 });
    assert.equal(plan.roleCreates, 1, 'only the in-range, non-safe role is recreated');
    assert.equal(plan.channelCreates, 1);
    assert.ok(plan.ops.some(o => o.target === 'r2'));
    assert.ok(!plan.ops.some(o => o.target === 'owner-role'));
    assert.ok(!plan.ops.some(o => o.target === 'r3'));
});

// ── Lockdown profiles ───────────────────────────────────────────────────────

test('LOCKDOWN_PROFILE_LABELS covers the five requested profiles', () => {
    const actions = require('../dashboard/antiNukeActions');
    assert.deepEqual(Object.keys(actions.LOCKDOWN_PROFILE_LABELS).sort(),
        ['channel', 'full', 'join', 'message', 'permission']);
});

test('planLockdownProfile computes ops for each profile without writing', async () => {
    // Stub the discord REST layer BEFORE requiring antiNukeActions — the module
    // captures `require('./discord')` at load time.
    const discordPath = require.resolve('../dashboard/discord');
    const actionsPath = require.resolve('../dashboard/antiNukeActions');
    const origDiscord = require.cache[discordPath];
    const origActions = require.cache[actionsPath];
    require.cache[discordPath] = {
        id: discordPath, filename: discordPath, loaded: true,
        exports: {
            getGuildRaw: async () => ({ verification_level: 0 }),
            getGuildChannelsRaw: async () => ([
                { id: 'c1', name: 'general', type: 0, permission_overwrites: [] },
            ]),
            getGuildRoles: async () => ([{ id: 'r1', name: 'Admin', position: 1, managed: false, permissions: '8' }]),
            getBotMember: async () => ({ roles: ['botrole'] }),
            API_BASE: 'https://discord.com/api/v10',
        },
    };
    delete require.cache[actionsPath];
    try {
        const actions = require('../dashboard/antiNukeActions');
        const join = await actions.planLockdownProfile('g1', 'join');
        assert.ok(join.ops.some(o => o.kind === 'verification_level'));
        assert.ok(join.ops.some(o => o.kind === 'pause_invites'));
        const full = await actions.planLockdownProfile('g1', 'full');
        const kinds = new Set(full.ops.map(o => o.kind));
        assert.ok(kinds.has('verification_level') && kinds.has('deny_send_messages') && kinds.has('hide_channel') && kinds.has('strip_dangerous'));
    } finally {
        if (origDiscord) require.cache[discordPath] = origDiscord; else delete require.cache[discordPath];
        if (origActions) require.cache[actionsPath] = origActions; else delete require.cache[actionsPath];
    }
});

// ── Anti-Raid ───────────────────────────────────────────────────────────────

test('Anti-Raid section renders its detection signals (joinBurst etc.)', () => {
    const html = body(guildPages.antiNukePage({ guild: fixture(), user: { username: 'u' } }));
    assert.ok(html.includes('data-section="antiraid"'));
    for (const key of ['joinBurst', 'newAccountWave', 'coordinatedJoin']) {
        assert.ok(html.includes(`data-action="${key}"`), `missing raid action row ${key}`);
    }
    assert.ok(html.includes('id="an-raid-incidents-body"'));
});

// ── Overview aggregator is wired to real DB ─────────────────────────────────

test('getAntiNukeOverview is exported and queries the incident ledger', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'db.js'), 'utf8');
    assert.match(src, /async function getAntiNukeOverview/);
    assert.match(src, /FROM antinuke_incidents/);
    const db = require('../dashboard/db');
    assert.equal(typeof db.getAntiNukeOverview, 'function');
});

// ── Health recommendations ──────────────────────────────────────────────────

test('every non-PASS health check carries a repair recommendation', async () => {
    const { healthScan, PASS } = require('../utils/antiNukeHealth');
    const manager = {
        _auditStreamAvailable: false,
        processEvent: () => {},
        getSettings: async () => ({ enabled: true, dryRun: true, watched: {}, responses: ['logOnly'] }),
    };
    const guild = { id: 'g1', ownerId: 'o1', members: { me: { permissions: { has: () => false }, roles: { highest: { position: 0 } } } }, roles: { cache: { values: () => [].values() } } };
    const scan = await healthScan({ manager, client: null, guild });
    const nonPass = scan.checks.filter(c => c.result !== PASS);
    assert.ok(nonPass.length > 0, 'expected some non-pass checks in this stub');
    for (const c of nonPass) {
        assert.ok(c.recommendation, `no recommendation for ${c.key} (${c.result})`);
    }
});

// ── Endpoints exist ─────────────────────────────────────────────────────────

test('the new Anti-Nuke endpoints are registered', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'server.js'), 'utf8');
    for (const route of [
        '/antinuke/overview', '/antinuke/raid', '/antinuke/backups',
        '/antinuke/backups/:id/compare', '/antinuke/backups/:id/restore-preview',
        '/antinuke/backups/:id/restore', '/antinuke/lockdown/profile/:profile',
    ]) {
        assert.ok(src.includes(route), `missing route ${route}`);
    }
});

test('all six requested new permissions exist in the registry', () => {
    const { ANTI_NUKE_PERMISSIONS } = require('../shared/antiNukePermissions');
    const ids = new Set(ANTI_NUKE_PERMISSIONS.map(p => p.id));
    for (const id of ['antinuke.raid.manage', 'antinuke.backup.view', 'antinuke.backup.create',
                      'antinuke.backup.restore', 'antinuke.incidents.export', 'antinuke.health.view']) {
        assert.ok(ids.has(id), `missing permission ${id}`);
    }
});
