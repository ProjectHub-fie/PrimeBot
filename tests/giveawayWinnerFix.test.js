// Static giveaway winner-declaration regression tests.
//
// Two real bugs caused "winner is not declared after giveaway end":
//
//  1. `endGiveaway` marked `ended = true` but never cleared `active`. The DB
//     write then used `ended: !giveaway.active` → `ended` persisted as FALSE,
//     so after a restart the giveaway was reloaded as "still active" and
//     re-processed (or, on cold boot, silently discarded with no winner).
//
//  2. `loadGiveaways` "silently ended" expired giveaways at startup — it just
//     flipped the DB flags and `continue`d, declaring NO winners and never
//     updating the giveaway embed.
//
// The manager talks to Postgres via drizzle; CI has no Postgres, so we inject a
// fake `db`/`schema` (justified mock — same pattern as liveGiveaways.test.js)
// and drive the REAL `endGiveaway` / `loadGiveaways` code paths.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const GiveawayManager = loadManager();

function loadManager() {
    const origLoad = Module._load;
    Module._load = function (request, parent) {
        // Isolate from the real community pool + pg Pool: with no DATABASE_URL
        // createPool returns a stub whose connect() throws. We still don't want
        // the real Pool/connection machinery at all.
        if (request === '../server/communityDb') {
            return { communityDb: null, communityPool: { connect: async () => { throw new Error('no db'); } } };
        }
        if (request === '../server/createPool' || request === 'pg') {
            return { createPool: () => ({ connect: async () => { throw new Error('no db'); }, query: async () => { throw new Error('no db'); }, end: async () => {} }) };
        }
        return origLoad.apply(this, arguments);
    };
    try {
        delete require.cache[require.resolve('../utils/giveawayManager')];
        return require('../utils/giveawayManager');
    } finally {
        Module._load = origLoad;
    }
}

// ── Fakes ────────────────────────────────────────────────────────────────────

/**
 * Minimal chainable drizzle-like fake that records every call.
 * It understands real drizzle `eq(...)` conditions well enough to filter rows:
 * `queryChunks` reconstruct to `'' isActive = true ''` — we grab the column
 * and the RHS literal (boolean/number/quoted string).
 */
// Recursively fold a drizzle condition graph (`and(eq(...), eq(...))` nests
// SQL objects) into one flat SQL string.
function flattenCond(cond) {
    if (cond == null) return '';
    if (typeof cond === 'string') return cond;
    if (typeof cond !== 'object') return String(cond);
    if ('column' in cond && 'value' in cond) return `${cond.column} = ${JSON.stringify(cond.value)}`;
    if (Array.isArray(cond.queryChunks)) {
        return cond.queryChunks.map(flattenCond).join('');
    }
    // drizzle's leaf StringChunk carries `value` as an array of fragments.
    if (cond.value !== undefined) {
        if (Array.isArray(cond.value)) return cond.value.map(flattenCond).join('');
        if (typeof cond.value === 'object') return flattenCond(cond.value);
        return String(cond.value);
    }
    return '';
}

function condMatches(cond, row) {
    if (!cond) return true;
    const sql = flattenCond(cond);
    const re = /(\w+)\s*=\s*(true|false|\d+|'([^']*)')/g;
    let m;
    const conds = [];
    while ((m = re.exec(sql)) !== null) {
        const [, col, raw] = m;
        let want;
        if (raw === 'true') want = true;
        else if (raw === 'false') want = false;
        else if (/^\d+$/.test(raw)) want = Number(raw);
        else want = raw;
        conds.push([col, want]);
    }
    if (!conds.length) return true;
    return conds.every(([col, want]) => row[col] === want);
}

/** Minimal chainable drizzle-like fake that records every call. */
function makeFakeDb() {
    const calls = { updates: [], inserts: [], selects: [] };
    // Keyed by the schema TABLE OBJECT `select().from(table)` receives.
    const rowsByTable = new Map();
    const tableByName = {}; // 'giveaways' -> schema object (registered by makeManager)

    const db = {
        _calls: calls,
        _rowsByTable: rowsByTable,
        _tableByName: tableByName,
        _seed(name, rows) {
            const key = tableByName[name] || name;
            rowsByTable.set(key, rows);
        },

        select() {
            return {
                from: (table) => ({
                    where: async (cond) => {
                        const rows = rowsByTable.get(table) || [];
                        const out = rows.filter(r => condMatches(cond, r));
                        calls.selects.push({ table, cond });
                        return out;
                    },
                }),
            };
        },
        update(table) {
            return {
                set: (obj) => ({
                    where: async (cond) => {
                        calls.updates.push({ table, obj, cond });
                        return {};
                    },
                }),
            };
        },
        insert(table) {
            return {
                values: (obj) => ({
                    then: (resolve) => { calls.inserts.push({ table, obj }); return Promise.resolve({}).then(resolve); },
                }),
            };
        },
    };
    return db;
}

/** eq() mock — turns (col, val) into a serializable condition the fake reads. */
function fakeEq(col, val) {
    return { column: col, value: val };
}

/** Minimal discord.js client stub with a fetchable channel. */
function makeClient({ participants = [] } = {}) {
    const messages = {
        edited: [],
        async fetch() { return { id: 'msg1', edit: (opts) => { messages.edited.push(opts); return Promise.resolve(); } }; },
    };
    const sent = [];
    const channel = {
        id: 'chan1',
        messages,
        send: (opts) => { sent.push(opts); return Promise.resolve({ id: 'sent-' + sent.length }); },
    };
    const client = {
        channels: {
            fetch: async (id) => (id === 'chan1' ? channel : null),
        },
        user: { id: 'bot' },
        _sent: sent,
        _edited: messages.edited,
    };
    return client;
}

function makeManager({ client = makeClient(), fakeDb } = {}) {
    // Object.create skips the constructor, which would otherwise start the DB
    // connect/retry loop and the AdaptivePoller — both keep the test process
    // alive. We hand-assemble the exact state `endGiveaway`/`loadGiveaways` read.
    const mgr = Object.create(GiveawayManager.prototype);
    mgr.client = client;
    mgr.giveaways = new Map();
    mgr._savedSignatures = new Map();
    mgr.dbReady = true;
    mgr.db = fakeDb;
    mgr.schema = {
        giveaways: { isActive: 'isActive', ended: 'ended', messageId: 'messageId', endsAt: 'endsAt', winnerCount: 'winnerCount', hostId: 'hostId', prize: 'prize', description: 'description', channelId: 'channelId' },
        giveawayParticipants: { giveawayId: 'giveawayId', userId: 'userId' },
        giveawayWinners: { giveawayId: 'giveawayId', userId: 'userId' },
    };
    if (fakeDb && fakeDb._tableByName) {
        fakeDb._tableByName.giveaways = mgr.schema.giveaways;
        fakeDb._tableByName.giveawayParticipants = mgr.schema.giveawayParticipants;
    }
    mgr.startupComplete = false;
    mgr.startCheckingGiveaways = () => {
        mgr.startupComplete = true;
    };
    return mgr;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('endGiveaway clears active so the DB persists ended=true (winner declared once)', async () => {
    const fakeDb = makeFakeDb();
    const client = makeClient();
    const mgr = makeManager({ client, fakeDb });
    mgr.giveaways.set('msg1', {
        messageId: 'msg1', channelId: 'chan1', guildId: 'guild1',
        prize: 'Nitro', winnerCount: 1, endTime: Date.now() - 1000,
        description: '', thumbnail: null, requiredRoleId: null,
        participants: new Set(['u1', 'u2', 'u3']), active: true, ended: false,
    });

    const ok = await mgr.endGiveaway('msg1');
    assert.equal(ok, true);

    const g = mgr.giveaways.get('msg1');
    assert.equal(g.ended, true);
    assert.equal(g.active, false, 'active must be cleared so the DB row ends');

    // The DB update must carry isActive=false AND ended=true.
    const saveUpdate = fakeDb._calls.updates.find(u => u.obj && 'ended' in u.obj);
    assert.ok(saveUpdate, 'endGiveaway must persist the updated giveaway');
    assert.equal(saveUpdate.obj.isActive, false);
    assert.equal(saveUpdate.obj.ended, true);

    // The embed was updated + the winner announced exactly once.
    assert.equal(client._edited.length, 1, 'giveaway embed should be edited to the ended state');
    assert.ok(client._edited[0].embeds[0].data.title.includes('GIVEAWAY ENDED'));
    assert.equal(client._sent.length, 1, 'winner announcement sent once');
    assert.match(client._sent[0].content, /You won the \*\*Nitro\*\*/);
});

test('loadGiveaways declares winners for a giveaway that ended while the bot was offline', async () => {
    const fakeDb = makeFakeDb();
    const client = makeClient();
    const mgr = makeManager({ client, fakeDb });

    // The expired giveaway row (active in DB, ends_at in the past).
    fakeDb._seed('giveaways', [{
        messageId: 'msg1', channelId: 'chan1', guildId: 'guild1',
        prize: 'Steam Game', description: '', winnerCount: 1, hostId: 'bot',
        isActive: true, ended: false, endsAt: new Date(Date.now() - 60_000),
    }]);
    fakeDb._seed('giveawayParticipants', [
        { giveawayId: 'msg1', userId: 'u1' },
        { giveawayId: 'msg1', userId: 'u2' },
    ]);

    await mgr.loadGiveaways();

    // Winner was declared: the embed edited + announcement sent.
    assert.equal(client._edited.length, 1, 'startup recovery must update the giveaway embed');
    assert.ok(client._edited[0].embeds[0].data.title.includes('GIVEAWAY ENDED'));
    assert.equal(client._sent.length, 1, 'startup recovery must announce the winner');
    assert.match(client._sent[0].content, /You won the \*\*Steam Game\*\*/);

    // The giveaway was processed (not just flagged): participants loaded, etc.
    assert.ok(mgr.giveaways.get('msg1'), 'giveaway kept in memory for the ended flow');
});

test('loadGiveaways does NOT re-declare winners for a giveaway that ended at runtime', async () => {
    const fakeDb = makeFakeDb();
    const client = makeClient();
    const mgr = makeManager({ client, fakeDb });

    // Already-ended giveaway row: not active, already ended.
    fakeDb._seed('giveaways', [{
        messageId: 'gone', channelId: 'chan1', guildId: 'guild1',
        prize: 'Nitro', description: '', winnerCount: 1, hostId: 'bot',
        isActive: false, ended: true, endsAt: new Date(Date.now() - 10 * 60_000),
    }]);
    fakeDb._seed('giveawayParticipants', [{ giveawayId: 'gone', userId: 'u1' }]);

    await mgr.loadGiveaways();

    assert.equal(client._edited.length, 0, 'already-ended giveaways must not be re-announced');
    assert.equal(client._sent.length, 0, 'already-ended giveaways must not spam winners');
});