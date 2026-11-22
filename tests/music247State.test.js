const { test } = require('node:test');
const assert = require('node:assert');

function loadCommandWithFakeDb() {
    const dbPath = require.resolve('../music/schema/247');
    const fake = {
        enabled: false,
        calls: [],
        async setEnabled(guildId, enabled, ids = {}) {
            this.calls.push({ guildId, enabled, ids });
            this.enabled = enabled;
            return { enabled, changed: true };
        },
        async getState() {
            return { enabled: this.enabled, textId: null, voiceId: null };
        },
    };
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: fake };
    const cmdPath = require.resolve('../music/commands/Config/247');
    delete require.cache[cmdPath];
    return { fake, cmd: require(cmdPath) };
}

function fakeMessage() {
    const replies = [];
    return {
        replies,
        guild: { id: 'g1' },
        author: { displayAvatarURL: () => 'https://cdn.discordapp.com/avatars/1/a.png' },
        reply: async (payload) => { replies.push(payload); return payload; },
    };
}

test('247 start/stop is explicit and idempotent (stop never re-enables)', async () => {
    const { fake, cmd } = loadCommandWithFakeDb();
    const client = { manager: { players: { get: () => ({ voiceId: 'v1', textId: 't1' }) } } };
    const msg = fakeMessage();

    await cmd.execute(msg, ['start'], client);
    assert.equal(fake.enabled, true);

    await cmd.execute(msg, ['stop'], client);
    assert.equal(fake.enabled, false);
    await cmd.execute(msg, ['stop'], client);
    assert.equal(fake.enabled, false);
    await cmd.execute(msg, ['stop'], client);
    assert.equal(fake.enabled, false);

    await cmd.execute(msg, ['start'], client);
    assert.equal(fake.enabled, true);

    // Stop must work with no active player.
    client.manager.players.get = () => null;
    await cmd.execute(msg, ['stop'], client);
    assert.equal(fake.enabled, false);

    assert.deepEqual(fake.calls.map(c => c.enabled), [true, false, false, false, true, false]);
});

test('247 enable without a player refuses instead of creating an empty session', async () => {
    const { fake, cmd } = loadCommandWithFakeDb();
    const client = { manager: { players: { get: () => null } } };
    const msg = fakeMessage();
    await cmd.execute(msg, ['enable'], client);
    assert.equal(fake.enabled, false);
    assert.equal(fake.calls.length, 0);
    assert.match(msg.replies[0], /play a song/i);
});


test('slash /247 uses the same explicit state operation', async () => {
    const { fake } = loadCommandWithFakeDb();
    const slashPath = require.resolve('../music/slashCommands/Music/247');
    delete require.cache[slashPath];
    const cmd = require(slashPath);
    const edits = [];
    const interaction = {
        guild: { id: 'g1' },
        member: { displayAvatarURL: () => 'https://cdn.discordapp.com/avatars/1/a.png' },
        options: { getString: () => 'stop' },
        deferReply: async () => {},
        editReply: async (payload) => { edits.push(payload); return payload; },
    };
    await cmd.run({ manager: { players: { get: () => null } } }, interaction);
    assert.equal(fake.enabled, false);
    assert.equal(fake.calls.length, 1);
    assert.equal(fake.calls[0].enabled, false);
});

test('slash /247 enable without a player refuses', async () => {
    const { fake } = loadCommandWithFakeDb();
    const slashPath = require.resolve('../music/slashCommands/Music/247');
    delete require.cache[slashPath];
    const cmd = require(slashPath);
    const edits = [];
    const interaction = {
        guild: { id: 'g1' },
        member: { displayAvatarURL: () => 'https://cdn.discordapp.com/avatars/1/a.png' },
        options: { getString: () => 'enable' },
        deferReply: async () => {},
        editReply: async (payload) => { edits.push(payload); return payload; },
    };
    await cmd.run({ manager: { players: { get: () => null } } }, interaction);
    assert.equal(fake.enabled, false);
    assert.equal(fake.calls.length, 0);
    assert.match(edits[0], /play a song/i);
});


test('restore247 never reconnects a guild with no persisted 24/7 row', async () => {
    const dbPath = require.resolve('../music/schema/247');
    const fake = { find: async () => [] };
    require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: fake };
    const restorePath = require.resolve('../music/loaders/restore247');
    delete require.cache[restorePath];
    const { restoreAutoReconnect } = require(restorePath);
    let created = 0;
    const client = {
        manager: { players: { get: () => null }, createPlayer: async () => { created++; } },
        guilds: { cache: new Map([['g1', { id: 'g1', channels: { cache: new Map([['v1', {}]]) } }]]) },
        logger: { log() {} },
    };
    assert.equal(await restoreAutoReconnect(client), 0);
    assert.equal(created, 0);
});

function fakePool() {
    const rows = new Map();
    return {
        rows,
        async query(sql, values = []) {
            const q = String(sql).replace(/\s+/g, ' ').trim();
            if (/^CREATE TABLE/i.test(q)) return { rows: [], rowCount: 0 };
            if (/^DELETE FROM music_247_sessions a/i.test(q)) return { rows: [], rowCount: 0 };
            if (/^CREATE UNIQUE INDEX/i.test(q)) return { rows: [], rowCount: 0 };
            if (/^SELECT \* FROM music_247_sessions/i.test(q)) {
                const row = rows.get(values[0]);
                return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
            }
            if (/^INSERT INTO music_247_sessions/i.test(q)) {
                const row = values.length >= 4
                    ? { id: values[0], Guild: values[1], TextId: values[2], VoiceId: values[3] }
                    : { id: rows.size + 1, Guild: values[0], TextId: values[1], VoiceId: values[2] };
                rows.set(row.Guild, row);
                return { rows: [row], rowCount: 1 };
            }
            if (/^DELETE FROM music_247_sessions WHERE/i.test(q)) {
                const had = rows.delete(values[0]);
                return { rows: [], rowCount: had ? 1 : 0 };
            }
            if (/^UPDATE music_247_sessions SET/i.test(q)) {
                const row = rows.get(values[0]);
                if (row) { row.TextId = values[1]; row.VoiceId = values[2]; }
                return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
            }
            throw new Error(`unexpected SQL: ${q}`);
        },
    };
}

function loadSchemaWithPool(pool) {
    const createPoolPath = require.resolve('../server/createPool');
    const resolvePath = require.resolve('../server/resolveDbUrl');
    const pgPath = require.resolve('../music/schema/_pg');
    const schemaPath = require.resolve('../music/schema/247');
    require.cache[createPoolPath] = { id: createPoolPath, filename: createPoolPath, loaded: true, exports: { createPool: () => pool } };
    require.cache[resolvePath] = { id: resolvePath, filename: resolvePath, loaded: true, exports: { resolveDbUrl: () => 'postgres://test' } };
    delete require.cache[pgPath];
    delete require.cache[schemaPath];
    return require(schemaPath);
}

test('247 persistent state is idempotent, guild-isolated and survives a reload', async () => {
    const pool = fakePool();
    let db = loadSchemaWithPool(pool);

    await db.setEnabled('g1', true, { textId: 't1', voiceId: 'v1' });
    assert.deepEqual(await db.getState('g1'), { enabled: true, textId: 't1', voiceId: 'v1' });

    await db.setEnabled('g1', false);
    await db.setEnabled('g1', false);
    await db.setEnabled('g1', false);
    assert.equal(await db.isEnabled('g1'), false);

    await db.setEnabled('g1', true, { textId: 't2', voiceId: 'v2' });
    await db.setEnabled('g2', true, { textId: 't3', voiceId: 'v3' });
    assert.equal(await db.isEnabled('g1'), true);
    assert.equal(await db.isEnabled('g2'), true);

    await db.setEnabled('g1', false);
    assert.equal(await db.isEnabled('g1'), false);
    assert.equal(await db.isEnabled('g2'), true);

    // Simulate a bot restart: a fresh module reads the same Postgres rows.
    db = loadSchemaWithPool(pool);
    assert.equal(await db.isEnabled('g1'), false);
    assert.equal(await db.isEnabled('g2'), true);
});
