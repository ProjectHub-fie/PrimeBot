/**
 * Ticket-open interaction lifecycle regression tests.
 *
 * The reported bug: "Something went wrong" shown to the user even though the
 * channel was created. Root cause: `_openTicket` did ALL of its long work
 * (channel creation + message send + DB insert) before acknowledging the
 * interaction, so the ~3s component-timeout fired and the late `reply()` then
 * failed. These tests pin the fixed lifecycle: defer FIRST, answer exactly
 * once via editReply, dedupe double-clicks, and clean up when initialization
 * fails after the channel exists.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');

// Stub DB pools before requiring the manager so `_init` never hits Postgres.
const { ticketPool } = require('../server/ticketDb');
const { tclaimPool } = require('../server/tclaimDb');
const { trolePool } = require('../server/troleDb');
const { tlogPool } = require('../server/tlogDb');
ticketPool.query = async () => ({ rows: [] });
tclaimPool.query = async () => ({ rows: [] });
trolePool.query = async () => ({ rows: [] });
trolePool.connect = async () => ({ query: async () => ({}), release: () => {} });
tlogPool.query = async () => ({ rows: [] });

const { TicketPanelManager } = require('../utils/ticketManager');

async function makeManager() {
    const mgr = new TicketPanelManager({});
    await new Promise(r => setTimeout(r, 10));
    return mgr;
}

/** Mimic a discord.js interaction after `deferReply({ ephemeral: true })`. */
function deferredInteraction() {
    const calls = [];
    return {
        calls,
        id: 'inter-' + Math.random().toString(36).slice(2, 8),
        replied: false,
        deferred: false,
        guild: null,
        member: null,
        user: { id: 'u1', username: 'alice', tag: 'alice#0000' },
        channel: { id: 'ch0', threads: { create: async () => { throw new Error('no thread fallback'); } } },
        async deferReply(opts) {
            calls.push(['deferReply', opts]);
            this.deferred = true;
            this._deferOpts = opts;
        },
        async reply(payload) {
            calls.push(['reply', payload]);
            this.replied = true;
        },
        async editReply(payload) {
            calls.push(['editReply', payload]);
            this.replied = true;
        },
    };
}

function makeGuild({ channelCreate = null, maxChannels = Infinity } = {}) {
    const channels = [];
    const guild = {
        id: 'gmock',
        ownerId: 'owner',
        channels: {
            create: channelCreate || (async ({ name }) => {
                if (channels.length >= maxChannels) return null;
                const ch = {
                    id: `c-${channels.length}`,
                    name,
                    parentId: 'cat',
                    send: async () => ({ id: 'm1' }),
                    isThread: () => false,
                    delete: async (reason) => { channels.length--; },
                };
                channels.push(ch);
                return ch;
            }),
        },
        members: {
            me: { id: 'bot' },
            cache: { filter: () => new Map() },
        },
    };
    guild._channels = channels;
    return guild;
}

test('_openTicket defers BEFORE any channel work and answers once with editReply', async () => {
    const mgr = await makeManager();
    mgr._saveInstance = async () => {};
    mgr._ensureClaimRow = async () => {};
    mgr._applyRoleSettings = async () => {};

    const guild = makeGuild();
    const interaction = deferredInteraction();
    interaction.guild = guild;
    interaction.member = { id: 'u1', roles: { cache: new Set() }, permissions: { has: () => false } };
    const panel = mgr._normalizePanel({ id: 1, guildId: 'gmock', name: 'Support', ticketName: 'support', maxOpenPerUser: 0 });

    await mgr._openTicket(interaction, panel, guild, interaction.member, 'u1', null, null);

    // Deferred first, then exactly ONE final answer via editReply — never reply().
    assert.equal(interaction.calls[0][0], 'deferReply');
    assert.deepEqual(interaction.calls[0][1], { ephemeral: true });
    const answers = interaction.calls.filter(c => c[0] === 'reply' || c[0] === 'editReply');
    assert.equal(answers.length, 1, 'exactly one success/failure answer');
    assert.equal(answers[0][0], 'editReply');
    assert.match(answers[0][1].content, /Your ticket has been opened/);
    assert.equal(guild._channels.length, 1, 'channel created');
});

test('double-click on the same user+panel does not open a second channel', async () => {
    const mgr = await makeManager();
    mgr._saveInstance = async () => {};
    mgr._ensureClaimRow = async () => {};
    mgr._applyRoleSettings = async () => {};

    const guild = makeGuild();
    const panel = mgr._normalizePanel({ id: 2, guildId: 'gmock', name: 'Support', ticketName: 'support', maxOpenPerUser: 0 });

    // Simulate an in-flight open by another (duplicate) click: same key set.
    const firstOpenKey = `gmock|u1|${panel.id}`;
    mgr._pendingOpens.set(firstOpenKey, true);

    const interaction = deferredInteraction();
    interaction.guild = guild;
    interaction.member = { id: 'u1', roles: { cache: new Set() }, permissions: { has: () => false } };

    await mgr._openTicket(interaction, panel, guild, interaction.member, 'u1', null, null);

    assert.equal(guild._channels.length, 0, 'no duplicate channel while one is in flight');
    const answers = interaction.calls.filter(c => c[0] === 'reply' || c[0] === 'editReply');
    assert.equal(answers.length, 1);
    assert.match(answers[0][1].content, /already being opened/);
    mgr._pendingOpens.delete(firstOpenKey);
});

test('channel creation failure replies an accurate error (no fake success)', async () => {
    const mgr = await makeManager();
    mgr._saveInstance = async () => {};
    mgr._ensureClaimRow = async () => {};
    mgr._applyRoleSettings = async () => {};

    const guild = makeGuild({
        channelCreate: async () => { throw new Error('Missing Permissions'); },
    });
    const interaction = deferredInteraction();
    interaction.guild = guild;
    interaction.member = { id: 'u1', roles: { cache: new Set() }, permissions: { has: () => false } };
    const panel = mgr._normalizePanel({ id: 3, guildId: 'gmock', name: 'Support', ticketName: 'support', maxOpenPerUser: 0 });

    await mgr._openTicket(interaction, panel, guild, interaction.member, 'u1', null, null);

    assert.equal(interaction.calls[0][0], 'deferReply');
    const answers = interaction.calls.filter(c => c[0] === 'reply' || c[0] === 'editReply');
    assert.equal(answers.length, 1);
    assert.equal(answers[0][0], 'editReply');
    assert.match(answers[0][1].content, /error opening your ticket/);
    assert.equal(guild._channels.length, 0);
});

test('DB failure after channel creation cleans up the orphan channel and reports failure', async () => {
    const mgr = await makeManager();
    let deletions = 0;
    const guild = makeGuild();
    const origCreate = guild.channels.create;
    guild.channels.create = async (opts) => {
        const ch = await origCreate(opts);
        ch.delete = async () => { deletions++; };
        return ch;
    };
    // DB save fails after the channel is created.
    mgr._saveInstance = async () => { throw new Error('ECONNRESET'); };
    mgr._ensureClaimRow = async () => {};
    mgr._applyRoleSettings = async () => {};

    const interaction = deferredInteraction();
    interaction.guild = guild;
    interaction.member = { id: 'u1', roles: { cache: new Set() }, permissions: { has: () => false } };
    const panel = mgr._normalizePanel({ id: 4, guildId: 'gmock', name: 'Support', ticketName: 'support', maxOpenPerUser: 0 });

    await mgr._openTicket(interaction, panel, guild, interaction.member, 'u1', null, null);

    const answers = interaction.calls.filter(c => c[0] === 'reply' || c[0] === 'editReply');
    assert.equal(answers.length, 1, 'one truthful answer');
    assert.equal(answers[0][0], 'editReply');
    assert.match(answers[0][1].content, /error opening your ticket/);
    assert.equal(deletions, 1, 'orphaned channel cleaned up');
    assert.equal(mgr._pendingOpens.size, 0, 'in-flight guard released in finally');
});

test('a successfully created ticket never produces a second reply', async () => {
    const mgr = await makeManager();
    mgr._saveInstance = async () => {};
    mgr._ensureClaimRow = async () => {};
    mgr._applyRoleSettings = async () => {};

    const guild = makeGuild();
    const interaction = deferredInteraction();
    interaction.guild = guild;
    interaction.member = { id: 'u1', roles: { cache: new Set() }, permissions: { has: () => false } };
    const panel = mgr._normalizePanel({ id: 5, guildId: 'gmock', name: 'Support', ticketName: 'support', maxOpenPerUser: 0 });

    await mgr._openTicket(interaction, panel, guild, interaction.member, 'u1', null, null);

    assert.equal(interaction.calls.filter(c => c[0] === 'editReply').length, 1);
    assert.equal(interaction.calls.filter(c => c[0] === 'reply').length, 0);
    assert.equal(mgr._pendingOpens.size, 0);
});