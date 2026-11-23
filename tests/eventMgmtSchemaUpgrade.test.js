// Event Management schema upgrade regression.
//
// Production hit `column "recurrence_parent_id" does not exist` on boot because
// the table DDL created an index on a column that an older `em_events` table
// lacked, and that index ran BEFORE the ALTERs. Postgres runs a multi-statement
// query in one implicit transaction, so the whole bootstrap aborted and Event
// Management silently fell back to "no events loaded".
//
// Run with: node --test tests/eventMgmtSchemaUpgrade.test.js

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const db = require('../server/eventMgmtDb');

function declaredColumns(sql) {
    const map = new Map();
    const re = /CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\(([\s\S]*?)\n\);/g;
    let m;
    while ((m = re.exec(sql))) {
        const [, table, body] = m;
        const cols = new Set();
        for (const line of body.split('\n')) {
            const col = line.trim().match(/^(\w+)\s+/);
            if (col && !['PRIMARY', 'UNIQUE', 'FOREIGN', 'CONSTRAINT', 'CHECK'].includes(col[1].toUpperCase())) {
                cols.add(col[1].toLowerCase());
            }
        }
        map.set(table, cols);
    }
    return map;
}

function alteredColumns(sql) {
    const map = new Map();
    const re = /ALTER TABLE\s+(\w+)\s+ADD COLUMN IF NOT EXISTS\s+(\w+)/gi;
    let m;
    while ((m = re.exec(sql))) {
        const table = m[1];
        if (!map.has(table)) map.set(table, new Set());
        map.get(table).add(m[2].toLowerCase());
    }
    return map;
}

function indexes(sql) {
    const out = [];
    const re = /CREATE INDEX IF NOT EXISTS\s+(\w+)\s+ON\s+(\w+)\s*\(([^)]+)\)/gi;
    let m;
    while ((m = re.exec(sql))) {
        out.push({
            name: m[1],
            table: m[2],
            columns: m[3].split(',').map(c => c.trim().split(/\s+/)[0].toLowerCase()),
        });
    }
    return out;
}

test('table DDL never creates an index (indexes run after the ALTERs)', () => {
    assert.ok(db.CREATE_TABLES_SQL.includes('CREATE TABLE IF NOT EXISTS em_events'));
    assert.ok(!/CREATE\s+INDEX/i.test(db.CREATE_TABLES_SQL),
        'CREATE INDEX inside the table DDL can reference a column an older table lacks and abort the whole bootstrap');
});

test('every index column exists in the CREATE TABLE or an ALTER', () => {
    const declared = declaredColumns(db.CREATE_TABLES_SQL);
    const altered = alteredColumns(db.ALTER_EVENTS_SQL);
    const all = indexes(db.CREATE_TABLES_SQL + '\n' + db.CREATE_INDEXES_SQL);
    assert.ok(all.length >= 12, `expected the full index set, got ${all.length}`);

    for (const idx of all) {
        const cols = new Set([...(declared.get(idx.table) || []), ...(altered.get(idx.table) || [])]);
        for (const col of idx.columns) {
            assert.ok(cols.has(col),
                `index ${idx.name} references ${idx.table}.${col} which neither the CREATE TABLE nor an ALTER declares`);
        }
    }
});

test('the recurrence columns are upgraded on an existing table', () => {
    for (const col of ['recurrence', 'recurrence_until', 'recurrence_parent_id', 'scheduled_event_id', 'sync_scheduled_event']) {
        assert.match(db.ALTER_EVENTS_SQL, new RegExp(`ALTER TABLE em_events ADD COLUMN IF NOT EXISTS ${col}\\b`));
    }
    assert.match(db.CREATE_INDEXES_SQL, /em_events_recurrence_parent_idx ON em_events \(recurrence_parent_id\)/);
});

test('every column the repo writes is declared or altered', () => {
    const repo = fs.readFileSync(path.join(ROOT, 'server/eventMgmtRepo.js'), 'utf8');
    const block = repo.match(/const EVENT_COLUMNS = \[([\s\S]*?)\];/);
    assert.ok(block, 'EVENT_COLUMNS not found');
    const columns = [...block[1].matchAll(/'([a-z_]+)'/g)].map(m => m[1]);
    assert.ok(columns.length > 30);

    const declared = declaredColumns(db.CREATE_TABLES_SQL).get('em_events') || new Set();
    const altered = alteredColumns(db.ALTER_EVENTS_SQL).get('em_events') || new Set();
    for (const col of columns) {
        assert.ok(declared.has(col) || altered.has(col), `EVENT_COLUMNS writes ${col} but the schema never creates it`);
    }
});

test('ensureEventMgmtTables runs CREATE, then ALTER, then INDEX', async () => {
    const original = db.eventMgmtPool.query;
    const calls = [];
    db.eventMgmtPool.query = async (sql) => { calls.push(sql); return { rows: [] }; };
    // The module memoizes after a successful run; reset so this test executes it.
    const freshPath = require.resolve('../server/eventMgmtDb');
    delete require.cache[freshPath];
    const fresh = require('../server/eventMgmtDb');
    fresh.eventMgmtPool.query = async (sql) => { calls.push(sql); return { rows: [] }; };
    try {
        await fresh.ensureEventMgmtTables();
        assert.equal(calls.length, 3, 'expected exactly three bootstrap queries');
        assert.match(calls[0], /CREATE TABLE IF NOT EXISTS em_events/);
        assert.ok(!/CREATE INDEX/i.test(calls[0]));
        assert.match(calls[1], /ALTER TABLE em_events ADD COLUMN IF NOT EXISTS recurrence_parent_id/);
        assert.match(calls[2], /CREATE INDEX IF NOT EXISTS em_events_recurrence_parent_idx/);
    } finally {
        db.eventMgmtPool.query = original;
        delete require.cache[freshPath];
        require('../server/eventMgmtDb');
    }
});

test('the repair migration is idempotent and adds the recurrence columns', () => {
    const sql = fs.readFileSync(path.join(ROOT, 'migrations/0037_fix_eventmgmt_schema.sql'), 'utf8');
    assert.match(sql, /ADD COLUMN IF NOT EXISTS recurrence_parent_id/);
    assert.match(sql, /ADD COLUMN IF NOT EXISTS recurrence_until/);
    const alterIdx = sql.indexOf('ADD COLUMN IF NOT EXISTS recurrence_parent_id');
    const indexIdx = sql.indexOf('CREATE INDEX IF NOT EXISTS em_events_recurrence_parent_idx');
    assert.ok(alterIdx !== -1 && indexIdx > alterIdx, 'the index must be created after the column exists');
});

// ── Init recovery ───────────────────────────────────────────────────────────
function loadEventManager(repoStub) {
    const repoPath = require.resolve('../server/eventMgmtRepo');
    const prev = require.cache[repoPath];
    require.cache[repoPath] = { id: repoPath, filename: repoPath, loaded: true, exports: repoStub };
    delete require.cache[require.resolve('../utils/eventMgmtManager')];
    const Manager = require('../utils/eventMgmtManager');
    return {
        manager: new Manager(null),
        restore() {
            delete require.cache[require.resolve('../utils/eventMgmtManager')];
            if (prev) require.cache[repoPath] = prev;
            else delete require.cache[repoPath];
        },
    };
}

test('a failed init schedules a bounded retry instead of giving up forever', async () => {
    const repoStub = {
        ensureEventMgmtTables: async () => { throw new Error('column "recurrence_parent_id" does not exist'); },
        getAllGuildEvents: async () => [],
    };
    const { manager, restore } = loadEventManager(repoStub);
    // The manager resolves the pool through its own module instance, so stub the
    // live module rather than the one this file loaded first.
    const liveDb = require('../server/eventMgmtDb');
    const originalQuery = liveDb.eventMgmtPool.query;
    liveDb.eventMgmtPool.query = async () => ({ rows: [] });
    try {
        await manager.ready();
        assert.equal(manager._tableReady, false);
        assert.ok(manager._retryTimer, 'a retry must be scheduled after a failed boot');
        assert.equal(manager.cacheSize, 0);

        manager.stop();
        assert.equal(manager._retryTimer, null, 'stop() clears the retry timer');

        // The database comes back (schema repaired) — the retry path recovers.
        repoStub.ensureEventMgmtTables = async () => true;
        await manager._init(1);
        assert.equal(manager._tableReady, true);
    } finally {
        manager.stop();
        liveDb.eventMgmtPool.query = originalQuery;
        restore();
    }
});

test('init retries are bounded (no infinite reconnect loop)', async () => {
    const repoStub = {
        ensureEventMgmtTables: async () => { throw new Error('db down'); },
        getAllGuildEvents: async () => [],
    };
    const { manager, restore } = loadEventManager(repoStub);
    try {
        await manager.ready();
        manager.stop();
        await manager._init(5); // INIT_MAX_RETRIES
        assert.equal(manager._retryTimer, null, 'no retry after the retry budget is spent');
    } finally {
        manager.stop();
        restore();
    }
});
