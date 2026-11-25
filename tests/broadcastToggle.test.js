// The broadcast card's "Broadcast setting" toggle must actually switch the
// guild's broadcast reception on/off: persisted to `server_settings`, visible to
// the delivery loops, and honoured by a real `/broadcast` run.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Collection, MessageFlags } = require('discord.js');

const ROOT = path.join(__dirname, '..');

const config = require('../config');
const { pool } = require('../server/db');
const ServerSettingsManager = require('../utils/serverSettingsManager');
const { handleBroadcastButton } = require('../utils/broadcastInteractions');
const { TOGGLE_BUTTON_ID, SETTING_BUTTON_ID } = require('../utils/broadcastPayload');
const broadcastCommand = require('../commands/broadcast');

// ── fake `server_settings` table (no Postgres in CI) ──────────────────────
function installFakeDb() {
    const rows = new Map();
    const queries = [];
    const originalQuery = pool.query;

    pool.query = async (sql, params = []) => {
        const text = String(sql).replace(/\s+/g, ' ').trim();
        queries.push({ text, params });

        if (/^(CREATE|ALTER) TABLE/i.test(text)) return { rows: [], rowCount: 0 };
        if (/^SELECT \* FROM server_settings/i.test(text)) {
            return { rows: [...rows.values()], rowCount: rows.size };
        }
        if (/^INSERT INTO server_settings/i.test(text)) {
            const [
                guildId, receive, channel, levEnabled, levChannel, mult, cooldown,
                arEnabled, ar, arsEnabled, ars, noPrefix, prefix,
            ] = params;
            rows.set(guildId, {
                guild_id: guildId,
                receive_broadcasts: receive,
                broadcast_channel_id: channel,
                leveling_enabled: levEnabled,
                leveling_channel_id: levChannel,
                xp_multiplier: mult,
                xp_cooldown: cooldown,
                auto_reactions_enabled: arEnabled,
                auto_reactions: JSON.parse(ar),
                auto_responder_enabled: arsEnabled,
                auto_responder: JSON.parse(ars),
                no_prefix_users: JSON.parse(noPrefix),
                prefix,
            });
            return { rows: [], rowCount: 1 };
        }
        throw new Error(`unexpected SQL: ${text.slice(0, 90)}`);
    };

    return {
        rows,
        queries,
        restore: () => { pool.query = originalQuery; },
    };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 25));

async function makeManager(client) {
    // Never touch data/serverSettings.json from a test.
    ServerSettingsManager.prototype._migrateFromJson = async () => {};
    const manager = new ServerSettingsManager(client);
    await settle();
    await manager.loadSettings();
    return manager;
}

function fakeGuild(id, { sends } = {}) {
    const channel = {
        id: `${id}-general`,
        name: 'general',
        type: 0,
        position: 0,
        permissionsFor: () => ({ has: () => true }),
        send: async (payload) => {
            sends?.push({ guildId: id, payload });
            return { id: 'm1' };
        },
    };
    return {
        id,
        name: `Guild ${id}`,
        channels: { cache: new Collection([[channel.id, channel]]) },
        members: { me: { id: 'bot' } },
    };
}

function fakeToggleInteraction(manager, guildId, { perms = true } = {}) {
    const updates = [];
    const replies = [];
    return {
        updates,
        replies,
        interaction: {
            customId: TOGGLE_BUTTON_ID,
            guild: { id: guildId, channels: { cache: new Collection() } },
            memberPermissions: { has: () => perms },
            client: { serverSettingsManager: manager },
            replied: false,
            deferred: false,
            async reply(p) { replies.push(p); },
            async update(p) { updates.push(p); },
            async followUp(p) { replies.push(p); },
        },
    };
}

function fakeBroadcastInteraction(client, { preview = false } = {}) {
    const replies = [];
    const edits = [];
    const values = {
        message: 'Maintenance at 20:00 UTC.',
        title: 'Scheduled maintenance',
        image: null,
        color: null,
    };
    return {
        replies,
        edits,
        interaction: {
            user: { id: 'dev-user', tag: 'dev#0001' },
            client,
            createdTimestamp: Date.now(),
            replied: false,
            deferred: false,
            options: {
                getString: (name) => values[name] ?? null,
                getBoolean: () => preview,
            },
            async reply(p) { this.replied = true; replies.push(p); return { edit: async () => {} }; },
            async editReply(p) { edits.push(p); },
            async followUp(p) { replies.push(p); },
        },
    };
}

test('toggling the broadcast setting flips the guild and persists it', async () => {
    const db = installFakeDb();
    try {
        const manager = await makeManager({ guilds: { cache: new Collection([['g1', {}]]) } });

        assert.equal(manager.receivesBroadcasts('g1'), true, 'broadcasts are on by default');

        const off = fakeToggleInteraction(manager, 'g1');
        assert.equal(await handleBroadcastButton(off.interaction), true);
        assert.equal(manager.receivesBroadcasts('g1'), false, 'toggle turned it off');
        await settle();
        assert.equal(db.rows.get('g1').receive_broadcasts, false, 'written to server_settings');
        assert.match(
            JSON.stringify(off.updates[0]),
            /Your current setting is `off`/,
            'the panel shows the new state'
        );

        const on = fakeToggleInteraction(manager, 'g1');
        await handleBroadcastButton(on.interaction);
        assert.equal(manager.receivesBroadcasts('g1'), true, 'toggle turned it back on');
        await settle();
        assert.equal(db.rows.get('g1').receive_broadcasts, true);

        manager._reloadTimer?.stop?.();
    } finally {
        db.restore();
    }
});

test('"Broadcast setting" only displays; the toggle is what changes it', async () => {
    const db = installFakeDb();
    try {
        const manager = await makeManager({ guilds: { cache: new Collection([['g1', {}]]) } });
        const { interaction } = fakeToggleInteraction(manager, 'g1');
        interaction.customId = SETTING_BUTTON_ID;

        await handleBroadcastButton(interaction);
        assert.equal(manager.receivesBroadcasts('g1'), true);
        await settle();
        assert.equal(db.rows.has('g1'), false, 'showing the panel writes nothing');

        manager._reloadTimer?.stop?.();
    } finally {
        db.restore();
    }
});

test('a real /broadcast skips servers that toggled broadcasts off', async () => {
    const db = installFakeDb();
    const devIds = config.developerIds;
    config.developerIds = [...devIds, 'dev-user'];
    try {
        const sends = [];
        const g1 = fakeGuild('g1', { sends });
        const g2 = fakeGuild('g2', { sends });
        const client = {
            guilds: { cache: new Collection([['g1', g1], ['g2', g2]]) },
            user: { id: 'bot', username: 'PrimeBot', displayAvatarURL: () => 'https://cdn.discordapp.com/embed/avatars/0.png' },
        };
        const manager = await makeManager(client);
        client.serverSettingsManager = manager;

        // Both servers receive by default.
        await broadcastCommand.execute(fakeBroadcastInteraction(client).interaction);
        assert.deepEqual(sends.map((s) => s.guildId), ['g1', 'g2'], 'both servers got the card');
        assert.ok(sends.every((s) => s.payload.flags & MessageFlags.IsComponentsV2), 'delivered as Components V2');

        // g2 turns broadcasts off from the announcement card.
        await handleBroadcastButton(fakeToggleInteraction(manager, 'g2').interaction);
        assert.equal(manager.receivesBroadcasts('g2'), false);

        sends.length = 0;
        const second = fakeBroadcastInteraction(client);
        await broadcastCommand.execute(second.interaction);
        assert.deepEqual(sends.map((s) => s.guildId), ['g1'], 'opted-out server is skipped');
        assert.match(JSON.stringify(second.edits.at(-1)), /skipped due to opt-out preferences|Opted Out/);

        // Turning it back on restores delivery.
        await handleBroadcastButton(fakeToggleInteraction(manager, 'g2').interaction);
        assert.equal(manager.receivesBroadcasts('g2'), true);

        sends.length = 0;
        await broadcastCommand.execute(fakeBroadcastInteraction(client).interaction);
        assert.deepEqual(sends.map((s) => s.guildId).sort(), ['g1', 'g2'], 'delivery resumed');

        manager._reloadTimer?.stop?.();
    } finally {
        config.developerIds = devIds;
        db.restore();
    }
});

test('a dashboard-style write is picked up by the bot reload (same DB)', async () => {
    const db = installFakeDb();
    try {
        const sends = [];
        const g1 = fakeGuild('g1', { sends });
        const client = {
            guilds: { cache: new Collection([['g1', g1]]) },
            user: { id: 'bot', username: 'PrimeBot', displayAvatarURL: () => 'https://cdn.discordapp.com/avatars/0.png' },
        };
        const manager = await makeManager(client);
        client.serverSettingsManager = manager;

        await handleBroadcastButton(fakeToggleInteraction(manager, 'g1').interaction);
        await settle();
        assert.equal(db.rows.get('g1').receive_broadcasts, false);

        // The dashboard writes the column directly; the bot only sees it on reload.
        db.rows.get('g1').receive_broadcasts = true;
        assert.equal(manager.receivesBroadcasts('g1'), false, 'cache is still stale');
        const changed = await manager._refreshFromDatabase();
        assert.equal(changed, true);
        assert.equal(manager.receivesBroadcasts('g1'), true, 'reload applied the dashboard write');

        manager._reloadTimer?.stop?.();
    } finally {
        db.restore();
    }
});

test('the reception count reported to the developer follows the toggle', async () => {
    const db = installFakeDb();
    try {
        const g1 = fakeGuild('g1');
        const g2 = fakeGuild('g2');
        const client = { guilds: { cache: new Collection([['g1', g1], ['g2', g2]]) } };
        const manager = await makeManager(client);
        client.serverSettingsManager = manager;

        assert.equal(manager.getBroadcastReceptionCount(), 2);
        await handleBroadcastButton(fakeToggleInteraction(manager, 'g2').interaction);
        assert.equal(manager.getBroadcastReceptionCount(), 1);
        assert.deepEqual(manager.getOptedOutServers(), ['g2']);

        manager._reloadTimer?.stop?.();
    } finally {
        db.restore();
    }
});

test('every delivery path gates on the per-guild reception flag', () => {
    const sites = {
        'commands/broadcast.js': /!interaction\.client\.serverSettingsManager\.receivesBroadcasts\(guild\.id\)/,
        'events/messageCreate.js': /!client\.serverSettingsManager\.receivesBroadcasts\(guild\.id\)/,
        'events/interactionCreate.js': /!client\.serverSettingsManager\.receivesBroadcasts\(guild\.id\)/,
    };
    for (const [file, pattern] of Object.entries(sites)) {
        const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
        assert.match(src, pattern, `${file} must skip opted-out guilds`);
    }
});
