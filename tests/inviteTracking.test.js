// Invite Tracking — behaviour tests.
//
// The repo (pg) layer is replaced by an in-memory stub: there is no Postgres in
// CI, and the behaviour under test is the attribution / counting logic, not SQL.
// The stub models the exact contract the manager relies on (snapshot baseline,
// join ledger, atomic stat increments).
//
// Run with: node --test tests/inviteTracking.test.js

process.env.INVITE_DELTA_RETRIES = '1';
process.env.INVITE_DELTA_RETRY_MS = '10';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function makeRepoStub() {
    const state = {
        settings: [],
        snapshots: new Map(),   // guildId -> Map(code -> snapshot)
        joins: [],
        stats: [],
        activity: [],
        replaced: [],
        left: [],
        openJoin: null,
        snapshotsWritten: 0,
    };
    const repo = {
        DEFAULT_SETTINGS: {
            enabled: true, logChannelId: null, joinNotifications: false, leaveNotifications: false,
            vanityTracking: true, excludeBots: true, excludedUserIds: [],
        },
        ensureInviteTables: async () => {},
        getAllInviteSettings: async () => state.settings,
        getSnapshotGuildIds: async () => Array.from(state.snapshots.keys()),
        getSnapshots: async (g) => Array.from((state.snapshots.get(String(g)) || new Map()).values()),
        replaceGuildSnapshots: async (g, invites) => {
            state.snapshots.set(String(g), new Map(invites.map(i => [i.code, i])));
            state.replaced.push({ guildId: String(g), invites });
            state.snapshotsWritten += 1;
        },
        upsertSnapshot: async (g, inv) => {
            const map = state.snapshots.get(String(g)) || new Map();
            map.set(inv.code, inv);
            state.snapshots.set(String(g), map);
        },
        markSnapshotDeleted: async () => {},
        addJoin: async (j) => {
            const row = { id: state.joins.length + 1, ...j };
            state.joins.push(row);
            return row;
        },
        findOpenJoin: async () => state.openJoin,
        markJoinLeft: async (id) => { state.left.push(id); return { id }; },
        addInviteStat: async (g, u, p) => { state.stats.push({ guildId: g, userId: u, ...p }); },
        addInviteActivity: async (g, e) => { state.activity.push(e); },
    };
    return { repo, state };
}

function loadTracker(repoStub) {
    const repoPath = require.resolve('../server/inviteRepo');
    const prev = require.cache[repoPath];
    require.cache[repoPath] = { id: repoPath, filename: repoPath, loaded: true, exports: repoStub };
    delete require.cache[require.resolve('../utils/inviteTracker')];
    const { InviteTracker } = require('../utils/inviteTracker');
    const tracker = new InviteTracker(null);
    const restore = () => {
        tracker.stop();
        if (prev) require.cache[repoPath] = prev;
        else delete require.cache[repoPath];
        delete require.cache[require.resolve('../utils/inviteTracker')];
    };
    return { tracker, restore };
}

function invite(code, inviterId, uses, extra = {}) {
    return {
        code, uses, maxUses: null, maxAge: null, temporary: false,
        inviter: inviterId ? { id: inviterId } : null,
        channel: { id: 'c1' },
        ...extra,
    };
}

function makeGuild({ id = 'g1', invites = [], vanity = null, fail = false } = {}) {
    return {
        id,
        vanityURLCode: vanity,
        invites: {
            fetch: async () => {
                if (fail) throw new Error('Missing Access');
                return new Map(invites.map(i => [i.code, i]));
            },
        },
        channels: { cache: new Map(), fetch: async () => null },
    };
}

function makeMember(guild, id, { bot = false } = {}) {
    return {
        id,
        guild,
        user: { id, username: `user${id}`, bot, tag: `user${id}#0001`, displayAvatarURL: () => '' },
    };
}

function seedBaseline(state, guildId, invites) {
    state.snapshots.set(String(guildId), new Map(invites.map(i => [i.code, i])));
}

// ── Attribution ─────────────────────────────────────────────────────────────

test('a single invite whose uses increased attributes the join exactly', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 4), invite('beta', 'inviter2', 7)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 5), invite('beta', 'inviter2', 7)] });
        const join = await tracker.handleMemberAdd(makeMember(guild, 'member1'));

        assert.strictEqual(join.attribution, 'exact');
        assert.strictEqual(join.source, 'invite');
        assert.strictEqual(join.inviterId, 'inviter1');
        assert.strictEqual(join.inviteCode, 'alpha');
        assert.deepStrictEqual(state.stats[0], { guildId: 'g1', userId: 'inviter1', joins: 1 });
        // Baseline persisted with the post-join counts.
        assert.strictEqual(state.snapshots.get('g1').get('alpha').uses, 5);
    } finally { restore(); }
});

test('two invite counters increasing at once is recorded as ambiguous, never guessed', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 1), invite('beta', 'inviter2', 1)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 2), invite('beta', 'inviter2', 2)] });
        const join = await tracker.handleMemberAdd(makeMember(guild, 'member1'));

        assert.strictEqual(join.attribution, 'ambiguous');
        assert.strictEqual(join.inviterId, null);
        assert.strictEqual(state.stats.length, 0, 'no inviter is credited when attribution is ambiguous');
    } finally { restore(); }
});

test('no counter change with a vanity URL is marked as a probable vanity join', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ vanity: 'mystic', invites: [invite('alpha', 'inviter1', 3)] });
        const join = await tracker.handleMemberAdd(makeMember(guild, 'member1'));

        assert.strictEqual(join.source, 'vanity');
        assert.strictEqual(join.attribution, 'probable');
        assert.strictEqual(join.inviterId, null);
        assert.strictEqual(state.stats.length, 0);
    } finally { restore(); }
});

test('no counter change and no vanity URL is recorded as unknown', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 3)] });
        const join = await tracker.handleMemberAdd(makeMember(guild, 'member1'));

        assert.strictEqual(join.attribution, 'unknown');
        assert.strictEqual(join.inviterId, null);
    } finally { restore(); }
});

test('a failed invite fetch records unknown and never overwrites the baseline', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ fail: true });
        const join = await tracker.handleMemberAdd(makeMember(guild, 'member1'));

        assert.strictEqual(join.attribution, 'unknown');
        assert.strictEqual(state.replaced.length, 0, 'a failed fetch must not clobber the persisted baseline');
        assert.strictEqual(state.snapshots.get('g1').get('alpha').uses, 3);
    } finally { restore(); }
});

test('vanity tracking disabled turns a no-delta join into unknown', async () => {
    const { repo, state } = makeRepoStub();
    state.settings = [{ guildId: 'g1', enabled: true, vanityTracking: false, excludeBots: true, excludedUserIds: [] }];
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ vanity: 'mystic', invites: [invite('alpha', 'inviter1', 3)] });
        const join = await tracker.handleMemberAdd(makeMember(guild, 'member1'));
        assert.strictEqual(join.source, 'unknown');
    } finally { restore(); }
});

// ── Bots / exclusions / dedupe ──────────────────────────────────────────────

test('bot joins are recorded separately and never counted', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 4)] });
        await tracker.handleMemberAdd(makeMember(guild, 'bot1', { bot: true }));

        assert.strictEqual(state.joins.length, 1);
        assert.strictEqual(state.joins[0].isBot, true);
        assert.strictEqual(state.joins[0].source, 'bot');
        assert.strictEqual(state.stats.length, 0);
        // Baseline still advances so the next human join is not mis-attributed.
        assert.strictEqual(state.snapshots.get('g1').get('alpha').uses, 4);
    } finally { restore(); }
});

test('excluded members are skipped entirely (but the baseline advances)', async () => {
    const { repo, state } = makeRepoStub();
    state.settings = [{ guildId: 'g1', enabled: true, vanityTracking: true, excludeBots: true, excludedUserIds: ['member1'] }];
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 4)] });
        const join = await tracker.handleMemberAdd(makeMember(guild, 'member1'));
        assert.strictEqual(join, null);
        assert.strictEqual(state.joins.length, 0);
        assert.strictEqual(state.snapshots.get('g1').get('alpha').uses, 4);
    } finally { restore(); }
});

test('a duplicate gateway event for the same member is de-duplicated', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 4)] });
        const member = makeMember(guild, 'member1');
        await tracker.handleMemberAdd(member);
        await tracker.handleMemberAdd(member);
        assert.strictEqual(state.joins.length, 1);
        assert.strictEqual(state.stats.length, 1);
    } finally { restore(); }
});

test('tracking disabled records nothing', async () => {
    const { repo, state } = makeRepoStub();
    state.settings = [{ guildId: 'g1', enabled: false, vanityTracking: true, excludeBots: true, excludedUserIds: [] }];
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 3)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 4)] });
        assert.strictEqual(await tracker.handleMemberAdd(makeMember(guild, 'member1')), null);
        assert.strictEqual(state.joins.length, 0);
    } finally { restore(); }
});

// ── Leaves ──────────────────────────────────────────────────────────────────

test('a leave closes the open join and increments the inviter\'s leave count', async () => {
    const { repo, state } = makeRepoStub();
    state.openJoin = { id: 42, guildId: 'g1', userId: 'member1', inviterId: 'inviter1', joinedAt: new Date().toISOString() };
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        await tracker.handleMemberRemove(makeMember(makeGuild(), 'member1'));
        assert.deepStrictEqual(state.left, [42]);
        assert.deepStrictEqual(state.stats[0], { guildId: 'g1', userId: 'inviter1', leaves: 1 });
        assert.strictEqual(state.activity[0].type, 'leave');
    } finally { restore(); }
});

test('a leave for an unknown join records nothing', async () => {
    const { repo, state } = makeRepoStub();
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        await tracker.handleMemberRemove(makeMember(makeGuild(), 'member1'));
        assert.strictEqual(state.left.length, 0);
        assert.strictEqual(state.stats.length, 0);
    } finally { restore(); }
});

// ── Restart / persistence ───────────────────────────────────────────────────

test('a restart reloads the persisted baseline and keeps attributing correctly', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('alpha', 'inviter1', 10)]);
    const first = loadTracker(repo);
    try {
        await first.tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 11)] });
        await first.tracker.handleMemberAdd(makeMember(guild, 'member1'));
    } finally { first.restore(); }

    // A brand-new manager instance (simulated restart) must read the persisted
    // baseline and attribute the next join from 11 -> 12.
    const second = loadTracker(repo);
    try {
        await second.tracker.ready();
        const guild = makeGuild({ invites: [invite('alpha', 'inviter1', 12)] });
        const join = await second.tracker.handleMemberAdd(makeMember(guild, 'member2'));
        assert.strictEqual(join.attribution, 'exact');
        assert.strictEqual(join.inviterId, 'inviter1');
    } finally { second.restore(); }
});

// ── Invite lifecycle ────────────────────────────────────────────────────────

test('inviteCreate seeds the baseline so the new code is not read as a use', async () => {
    const { repo, state } = makeRepoStub();
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        await tracker.handleInviteCreate({ guild: makeGuild(), ...invite('newcode', 'inviter9', 0) });
        assert.strictEqual(state.snapshots.get('g1').get('newcode').uses, 0);
        assert.strictEqual(state.activity[0].type, 'invite_create');
    } finally { restore(); }
});

test('inviteDelete removes the code from the in-memory baseline', async () => {
    const { repo, state } = makeRepoStub();
    seedBaseline(state, 'g1', [invite('gone', 'inviter1', 5)]);
    const { tracker, restore } = loadTracker(repo);
    try {
        await tracker.ready();
        await tracker.handleInviteDelete({ guild: { id: 'g1' }, code: 'gone' });
        const baseline = tracker._baselineFor('g1');
        assert.strictEqual(baseline.has('gone'), false);
        assert.strictEqual(state.activity[0].type, 'invite_delete');
    } finally { restore(); }
});

// ── Static wiring / commands / page ─────────────────────────────────────────

test('slash command registers the expected invite subcommands and does not collide with /invite', () => {
    const cmd = require('../commands/invites');
    assert.strictEqual(cmd.data.name, 'invites');
    assert.deepStrictEqual(cmd.data.options.map(o => o.name).sort(),
        ['config', 'info', 'leaderboard', 'reset', 'stats']);
    // The existing /invite (bot invite link) command must remain untouched.
    const legacy = require('../commands/invite');
    assert.strictEqual(legacy.data.name, 'invite');
});

test('prefix handler and help/docs reference the invite command', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events/messageCreate.js'), 'utf8');
    assert.match(src, /case "invite":/);
    assert.match(src, /case "invites":/);
    assert.match(src, /inviteRepo\.getLeaderboard/);

    const help = fs.readFileSync(path.join(ROOT, 'utils/prefixHelp.js'), 'utf8');
    assert.match(help, /names: \['invite', 'invites'\]/);

    const docs = require('../dashboard/commandDocs');
    const built = docs.buildCommandDocs();
    const names = built.commands.map(c => c.name);
    assert.ok(names.includes('invite'), 'invite appears in /docs');
});

test('dashboard page renders every section with SVG icons and no legacy emoji chrome', () => {
    const gp = require('../dashboard/render/guild-pages');
    const guild = {
        id: '111111111111111111', name: 'Test Guild', memberCount: 10,
        _channels: [{ id: '222222222222222222', name: 'logs', type: 0 }],
        _roles: [],
        _config: {
            invites: {
                settings: { enabled: true, logChannelId: null, joinNotifications: false, leaveNotifications: false, vanityTracking: true, excludeBots: true, excludedUserIds: [] },
                totals: { totalJoins: 12, totalLeaves: 3, net: 9, joins24h: 2, uniqueInviters: 4, unknownJoins: 1 },
                leaderboard: [{ userId: '333333333333333333', joins: 7, leaves: 1, net: 6, activeInvites: 2 }],
                total: 1, page: 1, totalPages: 1,
                recentJoins: [{ userId: '444444444444444444', inviterId: '333333333333333333', inviteCode: 'abc', attribution: 'exact', source: 'invite', joinedAt: new Date().toISOString() }],
                activity: [{ type: 'join', userId: '444444444444444444', detail: 'via abc', createdAt: new Date().toISOString() }],
                diagnostics: { ok: true },
            },
        },
    };
    const html = gp.invitesPage({ guild, user: { username: 'u' } });
    for (const needle of ['Invite Tracking', 'Top inviters', 'Tracking status', 'Recent joins',
        'Configuration', 'Reset statistics', 'iv-leaderboard', 'iv-config', 'iv-reset-confirm']) {
        assert.ok(html.includes(needle), `page is missing ${needle}`);
    }
    assert.match(html, /<svg class="ico"/);
    assert.ok(!/📨|🏆|⚙️|🧹/.test(html), 'no emoji chrome in the page markup');
    assert.match(html, /\/js\/invites\.js/);
});

test('invite settings are isolated per guild and never expose another guild\'s rows', () => {
    const src = fs.readFileSync(path.join(ROOT, 'server/inviteRepo.js'), 'utf8');
    // Every read/write is keyed by guild_id (no unscoped SELECT * FROM invite_joins).
    assert.doesNotMatch(src, /SELECT \* FROM invite_joins\s*(WHERE (?!guild_id))/);
    assert.match(src, /WHERE guild_id = \$1/);
    // Reset is scoped too.
    const resetBlock = src.slice(src.indexOf('async function resetGuildInviteStats'));
    assert.match(resetBlock, /DELETE FROM invite_joins WHERE guild_id = \$1/);
    assert.match(resetBlock, /DELETE FROM invite_stats WHERE guild_id = \$1/);
});

test('dashboard API routes are auth + admin guarded and reset requires explicit confirmation', () => {
    const src = fs.readFileSync(path.join(ROOT, 'dashboard/server.js'), 'utf8');
    assert.match(src, /app\.get\('\/api\/guilds\/:guildId\/invites', requireAuth, requireGuildAdmin/);
    assert.match(src, /app\.get\('\/api\/guilds\/:guildId\/invites\/member\/:userId', requireAuth, requireGuildAdmin/);
    assert.match(src, /app\.patch\('\/api\/guilds\/:guildId\/invites', requireAuth, requireGuildAdmin/);
    assert.match(src, /app\.post\('\/api\/guilds\/:guildId\/invites\/reset', requireAuth, requireGuildAdmin/);
    assert.match(src, /req\.body\.confirm !== true/);
    // The page route is server-rendered and preloads the overview.
    assert.match(src, /app\.get\('\/guild\/:guildId\/invites', requireAuth/);
    assert.match(src, /buildInviteOverview\(req\.guild\.id/);
});

test('INVITE_DATABASE_URL resolves through the shared fallback chain', () => {
    const saved = { invite: process.env.INVITE_DATABASE_URL, fallback: process.env.FALLBACK_DATABASE_URL, main: process.env.DATABASE_URL };
    try {
        delete process.env.INVITE_DATABASE_URL;
        delete process.env.FALLBACK_DATABASE_URL;
        delete process.env.DATABASE_URL;
        const mod = require('../server/inviteDb');
        assert.strictEqual(mod.resolveConnectionString(), null);
        process.env.DATABASE_URL = 'postgres://main';
        assert.strictEqual(mod.resolveConnectionString(), 'postgres://main');
        process.env.FALLBACK_DATABASE_URL = 'postgres://fallback';
        assert.strictEqual(mod.resolveConnectionString(), 'postgres://fallback');
        process.env.INVITE_DATABASE_URL = 'postgres://invite';
        assert.strictEqual(mod.resolveConnectionString(), 'postgres://invite');
    } finally {
        for (const [key, value] of Object.entries({ INVITE_DATABASE_URL: saved.invite, FALLBACK_DATABASE_URL: saved.fallback, DATABASE_URL: saved.main })) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
        }
    }
});

test('no credential is ever written to logs or returned by the manager', () => {
    const files = ['utils/inviteTracker.js', 'server/inviteRepo.js', 'commands/invites.js', 'dashboard/render/invite-page.js'];
    for (const file of files) {
        const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
        assert.ok(!/console\.log\([^)]*(process\.env|API_KEY|DATABASE_URL)/.test(src), `${file} logs a credential`);
        assert.ok(!/process\.env\.DATABASE_URL/.test(src), `${file} reads DATABASE_URL directly`);
    }
});

test('the help menu has a dedicated Invite category listing the config subcommands', () => {
    const help = require('../utils/prefixHelp');
    assert.ok(help.CATEGORY_ORDER.includes('invite'), 'invite category missing from the menu order');
    assert.ok(help.CATEGORY_ORDER.indexOf('invite') < help.CATEGORY_ORDER.indexOf('moderation'), 'Invite sits with the community-style categories');

    const text = help.categoryText('invite');
    for (const expected of ['`invite`', '`invite leaderboard`', '`invite info`', '`invite config`', '`invite reset`']) {
        assert.ok(text.includes(expected), `Invite category missing ${expected}: ${text}`);
    }
    assert.equal(help.getCategoryPermissionLevel('invite'), 'Everyone (Manage Server to configure)');
    assert.equal(help.getCategoryPermissionLevel('extra'), 'Manage Channels');
    // The config subcommand is documented with its real options + permission.
    const row = help.CATALOG.invite.commands.find(c => c.display === 'invite config');
    assert.ok(row, 'invite config row missing');
    assert.match(row.args, /channel=#/);
    assert.match(row.args, /join=on/);
    assert.match(row.desc, /Manage Server/);

    // The Sash menu renders one field per row and honours `display`.
    const src = require('node:fs').readFileSync(require('node:path').join(ROOT, 'events', 'interactionCreate.js'), 'utf8');
    assert.match(src, /const primary = c\.display \|\| c\.names\[0\]/);
});
