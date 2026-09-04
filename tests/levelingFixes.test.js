// Regression tests for fixes to the DB-backed LevelingManager:
// - createLeaderboardEmbed() (missing method that crashed `$leaderboard`)
// - setLevel() (new DB-backed setter that replaced the legacy in-memory `userLevels` mutation
//
// These tests drive the manager's pure logic with the DB/discord layers stubbed,
// mirroring the pattern in tests/autoResponder.test.js that avoids Postgres in CI.

const { test } = require('node:test');
const assert = require('node:assert');

const LevelingManager = require('../utils/levelingManager');

function makeManager(fakes = {}) {
    const mgr = Object.create(LevelingManager.prototype);
    Object.assign(mgr, {
        dbReady: true,
        db: {},
        schema: { userLevels: 'userLevels', userBadges: 'userBadges' },
        client: {
            guilds: {
                resolve: fakes.resolveGuild || (() => ({ members: { fetch: fakes.fetchMember || (async () => ({ displayName: 'Stubber' })) } })),
                cache: new Map()
            },
            user: { displayAvatarURL: () => 'https://cdn.example/avatar.png' }
        },
        getLeaderboard: fakes.getLeaderboard || (async () => []),
        getUserProfile: fakes.getUserProfile || (async () => null),
        calculateRequiredMessages: fakes.calcMessages || ((level) => level * 15),
        _loadRoleRewards: async () => {},
        _startRoleRewardsReload() {},
        ...fakes.overrides
    });
    return mgr;
}

test('createLeaderboardEmbed returns the leaderboard embed with pagination', async () => {
    const leaderboard = Array.from({ length: 25 }, (_, i) => ({
        userId: `u${i + 1}`,
        level: 25 - i,
        xp: (25 - i) * 100,
        messages: (25 - i) * 15
    }));
    const fetchMember = async userId => ({ displayName: `Member${userId.slice(1)}` });
    const mgr = makeManager({ getLeaderboard: async () => leaderboard, fetchMember });

    const result = await mgr.createLeaderboardEmbed('g1', 3);

    assert.ok(result, 'embed must be built');
    assert.equal(result.maxPage,3,'25 users/10 per page = 3 pages');
    assert.equal(result.currentPage,3);
    assert.ok(result.embed instanceof require('discord.js').EmbedBuilder);
    assert.match(result.embed.data.description, /Member21/);
});

test('createLeaderboardEmbed returns null when nobody is ranked', async () => {
    const mgr = makeManager({ getLeaderboard: async () => [] });
    assert.equal(await mgr.createLeaderboardEmbed('g1'),null);
});

test('setLevel persists to the DB via update when the user exists', async () => {
    let updateCalled = false, insertsCalled = false;
    const mgr = makeManager({
        getUserProfile: async () => ({ xp: 50, level: 1, messages: 5 }),
        overrides: {
            db: {
                update: () => ({
                    set: () => ({
                        where: () => { updateCalled = true; return Promise.resolve({ affectedRows: 1 }); }
                    })
                }),
                insert: () => ({ values: () => { insertsCalled = true; return Promise.resolve(); } })
            }
        }
    });

    const result = await mgr.setLevel('g1','u1',5);
    assert.ok(result.success);
    assert.equal(updateCalled,true,'existing user should be updated, not inserted');
    assert.equal(insertsCalled,false);
});

test('setLevel persists via insert when the user has no profile yet', async () => {
    let insertsCalled = false;
    const mgr = makeManager({
        getUserProfile: async () => null,
        overrides: {
            db: {
                insert: () => ({ values: () => { insertsCalled = true; return Promise.resolve(); } })
            }
        }
    });

    const result = await mgr.setLevel('g1','u77',3);
    assert.ok(result.success);
    assert.equal(insertsCalled,true);
    assert.equal(mgr.dbReady,true);
});

test('setLevel returns failure without throwing when DB write rejects', async () => {
    const mgr = makeManager({
        getUserProfile: async () => ({}),
        overrides: {
            db: {
                update: () => ({
                    set: () => ({
                        where: () => Promise.reject(new Error('db down'))
                    })
                }),
                insert: () => ({ values: () => Promise.resolve() })
            }
        }
    });

    // Patch getUserProfile to throw so update path errors propagate into the catch.
    mgr.getUserProfile = async () => ({});

    const result = await mgr.setLevel('g1','u1',4);
    assert.equal(result.success,false);
    assert.ok(result.message);
});

test('getGuildData assembles role rewards and users into the legacy shape', async () => {
    const userRows = [
        { userId: 'u1', xp: 100, level: 5, messages: 75 },
        { userId: 'u2', xp: 50, level: 2, messages: 30 }
    ];
    const badgeRows = [
        { userId: 'u1', badgeId: 'milestone_5' },
        { userId: 'u1', badgeId: 'milestone_10' }
    ];
    const mgr = makeManager({
        getRoleRewards: () => [ { level: 5, roleId: 'r5' } ],
        overrides: {
            getGuildUserLevels: async () => userRows,
            getGuildBadges: async () => badgeRows,
            getRoleRewards: () => [ { level: 5, roleId: 'r5' } ]
        }
    });

    const data = await mgr.getGuildData('g1');
    assert.ok(data);
    assert.deepEqual(data.roleRewards,{ 5: 'r5' });
    assert.equal(data.users['u1'].level,5);
    assert.deepEqual(data.users['u1'].badges,['milestone_5','milestone_10']);
    assert.deepEqual(data.users['u2'].badges,[]);
});

test('saveGuildData persists user rows and replaces badges via the DB', async () => {
const calls = { updates: 0, inserts:   0, deletes:   0 };
    const fakeDb = {
        rows: [{ guildId:'g1' }, { guildId:'g1' }],
        select() { return this; },
        from() { return this; },
        where() { return this; },
        limit() { return this.rows; },
        insert() { calls.inserts++; return { values: async () => {} }; },
        update() { calls.updates++; return { set: () => ({ where: async () => {} }) }; },
        delete() { calls.deletes++; return { where: async () => {} }; }
    };
    const mgr = makeManager({ overrides: { db: fakeDb } } );

    const ok = await mgr.saveGuildData('g1',{
        users: {
            u1: { xp: 200, level: 7, messages: 105, badges: ['milestone_5'] }
        }
    });
    assert.equal(ok,true);
    assert.equal(calls.updates,1,'existing row -> update');
    assert.equal(calls.deletes,1,'badges replaced via delete');
    assert.equal(calls.inserts,1,'badge row insert (user row was updated instead)');
});
