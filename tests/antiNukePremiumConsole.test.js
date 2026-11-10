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

// ── Setup auto-create + one-shot apply + centered window ────────────────────

test('the automatic walkthrough has no review/confirm step and applies in one shot', async () => {
    const { AUTO_WALKTHROUGH_STEPS, stepsForMethod } = require('../utils/antiNukeSetup');
    assert.ok(!stepsForMethod('automatic').some(s => s.key === 'confirm'), 'no confirm step');
    assert.ok(!AUTO_WALKTHROUGH_STEPS.some(s => s.key === 'confirm'));
    const { runWalkthroughStepOp } = require('../utils/antiNukeSetupRunner');
    const stored = { g1: { enabled: false, dryRun: true, watched: {}, responses: [] } };
    const manager = {
        getSettings: async (id) => stored[id],
        updateSettingsAsync: async (id, patch) => { stored[id] = Object.assign({}, stored[id], patch); return stored[id]; },
    };
    // No `confirmed` flag is required any more — apply must succeed without it.
    const res = await runWalkthroughStepOp('apply', {
        manager, guild: { id: 'g1' },
        state: { method: 'automatic', steps: { alert: { result: { channelId: 'c1' } } } },
        options: {},
    });
    assert.equal(res.appliedRecommended, true);
    assert.equal(stored.g1.enabled, true, 'apply enables protection');
    assert.equal(stored.g1.dryRun, false, 'apply turns dry-run OFF');
    assert.equal(stored.g1.alertChannelId, 'c1', 'the alert channel resolved earlier is kept');
});

test('createIsolationRole sends a bitfield-string permissions (REST rejects an array)', async () => {
    const { createIsolationRole } = require('../utils/antiNukeSetupRunner');
    const seen = [];
    const guild = {
        members: { me: { roles: { highest: { position: 6 } } } },
        roles: {
            cache: new Map(),
            create: async (opts) => { seen.push(opts); return { id: 'iso', name: opts.name, position: opts.position, setPosition: async () => {} }; },
        },
    };
    await createIsolationRole(guild, 'isolated');
    assert.equal(typeof seen[0].permissions, 'string', 'permissions must be a string bitfield');
    assert.equal(seen[0].position, 5, 'created just below the bot role');
});

test('the dashboard REST shim creates a role WITHOUT position then PATCHes it', async () => {
    const discordPath = require.resolve('../dashboard/discord');
    const actionsPath = require.resolve('../dashboard/antiNukeActions');
    const origDiscord = require.cache[discordPath];
    const origActions = require.cache[actionsPath];
    const createBodies = [];
    const patchBodies = [];
    require.cache[discordPath] = {
        id: discordPath, filename: discordPath, loaded: true,
        exports: {
            getBotGuild: async () => ({ id: 'g1', name: 'G', owner_id: 'o1' }),
            getGuildRaw: async () => ({ name: 'G', owner_id: 'o1' }),
            computeBotPermissions: async () => 8,
            getGuildRoles: async () => ([
                { id: 'botrole', name: 'PrimeBot', position: 5, managed: true, permissions: '8' },
            ]),
            getGuildChannelsRaw: async () => ([{ id: 'c1', name: 'general', type: 0, position: 3, permission_overwrites: [] }]),
            getBotMember: async () => ({ roles: ['botrole'] }),
            createGuildRole: async (gid, body) => { createBodies.push(body); return { id: 'newrole', name: body.name }; },
            modifyGuildRole: async (gid, rid, body) => { patchBodies.push({ rid, body }); return { id: rid }; },
            API_BASE: 'https://discord.com/api/v10',
        },
    };
    delete require.cache[actionsPath];
    try {
        const actions = require('../dashboard/antiNukeActions');
        const guild = await actions.buildDashboardGuildShim('g1');
        const role = await guild.roles.create({ name: 'isolated', permissions: '0', position: 4 });
        assert.equal(role.id, 'newrole');
        assert.equal(createBodies.length, 1);
        assert.equal('position' in createBodies[0], false, 'position must not be sent on CREATE');
        assert.equal(patchBodies.length, 1, 'position is applied with a PATCH afterwards');
        assert.equal(patchBodies[0].body.position, 4);
    } finally {
        if (origDiscord) require.cache[discordPath] = origDiscord; else delete require.cache[discordPath];
        if (origActions) require.cache[actionsPath] = origActions; else delete require.cache[actionsPath];
    }
});

test('the REST shim channel descriptors carry a numeric position', async () => {
    const discordPath = require.resolve('../dashboard/discord');
    const actionsPath = require.resolve('../dashboard/antiNukeActions');
    const origDiscord = require.cache[discordPath];
    const origActions = require.cache[actionsPath];
    require.cache[discordPath] = {
        id: discordPath, filename: discordPath, loaded: true,
        exports: {
            getBotGuild: async () => ({ id: 'g1', name: 'G', owner_id: 'o1' }),
            getGuildRaw: async () => ({ name: 'G', owner_id: 'o1' }),
            computeBotPermissions: async () => 8,
            getGuildRoles: async () => ([]),
            getGuildChannelsRaw: async () => ([{ id: 'c1', name: 'general', type: 0, position: 7, permission_overwrites: [] }]),
            getBotMember: async () => ({ roles: [] }),
            API_BASE: 'https://discord.com/api/v10',
        },
    };
    delete require.cache[actionsPath];
    try {
        const actions = require('../dashboard/antiNukeActions');
        const guild = await actions.buildDashboardGuildShim('g1');
        const ch = guild.channels.cache.get('c1');
        assert.equal(ch.position, 7, 'channel position is exposed for hierarchy checks');
    } finally {
        if (origDiscord) require.cache[discordPath] = origDiscord; else delete require.cache[discordPath];
        if (origActions) require.cache[actionsPath] = origActions; else delete require.cache[actionsPath];
    }
});

test('the warning tells the admin to set the bot in the top 3 and press Resume', () => {
    const { botRolePositionCheck } = require('../utils/antiNukeSetup');
    const roles = [{ id: 'r1', position: 9 }, { id: 'r2', position: 8 }, { id: 'r3', position: 7 }, { id: 'r4', position: 6 }];
    const guild = {
        roles: { cache: { values: () => roles.values() } },
        members: { me: { roles: { highest: { position: 6 } } } },
    };
    const r = botRolePositionCheck(guild);
    assert.equal(r.ok, false);
    assert.match(r.message, /top 3 role position/i);
    assert.match(r.message, /press Resume/i);
});

test('the setup choice window is a premium centered overlay (CSS)', () => {
    const css = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'styles.css'), 'utf8');
    assert.match(css, /\.an-modal-overlay\s*\{[^}]*align-items:\s*center/);
    assert.match(css, /\.an-modal-overlay\s*\{[^}]*justify-content:\s*center/);
    assert.match(css, /\.an-modal\s*\{/);
    assert.match(css, /\.an-modal-foot\s*\{/);
    assert.match(css, /\.an-modal-error\s*\{/);
    // The window markup uses the premium head/icon/foot structure, not the
    // legacy plain modal.
    const js = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'public', 'js', 'antinuke.js'), 'utf8');
    assert.match(js, /an-modal-ico/);
    assert.match(js, /Make automatically/);
    assert.match(js, /an-modal-error/);
});

test('the manual wizard renders "Make automatically" for the channel and role', () => {
    const html = body(guildPages.antiNukePage({ guild: fixture(), user: { username: 'u' }, view: 'wizard' }));
    assert.match(html, /data-create="alert_channel"/);
    assert.match(html, /data-create="isolation_role"/);
    assert.match(html, /id="an-wizard-check-result"/);
});
