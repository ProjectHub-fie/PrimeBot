/**
 * Private Security Audit Logger — behaviour tests.
 *
 * Everything here is pure / in-memory: a stub client, stub guilds and a stub
 * private channel that records the payloads it receives. No Discord network,
 * no database, no timers left running.
 *
 * The twelve required scenarios are covered explicitly (search for "SCENARIO").
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
    SecurityAuditLogger,
    EVENT_TYPES,
    COLORS,
    formatDuration,
    maskId,
} = require('../utils/securityAuditLogger');
const config = require('../config');

const ROOT = path.join(__dirname, '..');
const CHANNEL_ID = '123456789012345678';
const BOT_ID = '999999999999999999';
const GUILD_A = '111111111111111111';
const GUILD_B = '333333333333333333';

// ── Stubs ───────────────────────────────────────────────────────────────────

function perms(granted) {
    return { has: (name) => granted.includes(name) };
}

function makeChannel({ id = CHANNEL_ID, name = 'security-audit', granted = ['ViewChannel', 'SendMessages'], textBased = true } = {}) {
    const sent = [];
    return {
        id,
        name,
        type: textBased ? 0 : 2,
        sent,
        isTextBased: () => textBased,
        isVoiceBased: () => !textBased,
        permissionsFor: () => perms(granted),
        async send(payload) {
            sent.push(payload);
            return { id: `msg-${sent.length}` };
        },
    };
}

function makeClient({ channel = null, guilds = [], ready = true } = {}) {
    const channelCache = new Map();
    if (channel) channelCache.set(channel.id, channel);
    const guildCache = new Map();
    for (const g of guilds) guildCache.set(g.id, g);
    return {
        user: { id: BOT_ID, username: 'PrimeBot', bot: true },
        isReady: () => ready,
        channels: {
            cache: channelCache,
            async fetch(id) {
                if (channelCache.has(id)) return channelCache.get(id);
                const err = new Error('Unknown Channel');
                err.status = 404;
                err.code = 10003;
                throw err;
            },
        },
        guilds: { cache: guildCache },
    };
}

function makeGuild({ id = GUILD_A, name = 'Test Guild', ownerId = '222222222222222222', memberCount = 42, icon = 'abc123', channels = [], joinedTimestamp = null } = {}) {
    const channelCache = new Map();
    for (const c of channels) channelCache.set(c.id, c);
    return {
        id,
        name,
        ownerId,
        memberCount,
        joinedTimestamp,
        createdAt: new Date('2021-03-01T10:00:00Z'),
        iconURL: ({ size } = {}) => (icon ? `https://cdn.discordapp.com/icons/${id}/${icon}.png?size=${size || 128}` : null),
        channels: { cache: channelCache },
        members: { cache: new Map(), async fetch() { return null; } },
    };
}

function makeMember({ id = '444444444444444444', username = 'alice', displayName = 'Alice', bot = false } = {}) {
    return { id, displayName, user: { id, username, bot } };
}

function makeVoiceChannel(id, name) {
    return { id, name };
}

function voiceState({ guild, member, channelId = null, channel = null }) {
    return { id: member.id, guild, member, channelId, channel };
}

function makeLogger({ client, channelId = CHANNEL_ID, nowFn, retryDelays, maxQueue } = {}) {
    const logs = [];
    const logger = new SecurityAuditLogger({
        channelId,
        client,
        sleepFn: (resolve) => setImmediate(resolve),
        nowFn,
        retryDelays,
        maxQueue,
        logger: {
            warn: (m) => logs.push(m),
            log: (m) => logs.push(m),
            error: (m) => logs.push(m),
        },
    });
    return { logger, logs };
}

const embedOf = (payload) => (payload && payload.embeds && payload.embeds[0] ? payload.embeds[0].toJSON() : null);
const fieldValue = (embed, name) => {
    const field = (embed.fields || []).find((f) => f.name === name);
    return field ? field.value : undefined;
};

// ── Config ──────────────────────────────────────────────────────────────────

test('the destination is a hardcoded, owner-only config constant (no env var)', () => {
    assert.equal(config.securityAudit.enabled, true, 'logging is enabled by default');
    assert.ok('channelId' in config.securityAudit);
    const src = fs.readFileSync(path.join(ROOT, 'config.js'), 'utf8');
    assert.match(src, /const SECURITY_AUDIT_CHANNEL_ID = /);
    assert.match(src, /securityAudit:\s*\{/);
    assert.doesNotMatch(src, /process\.env\.[A-Z_]*SECURITY_AUDIT/);
});

test('the module requires no database / persistence client', () => {
    const src = fs.readFileSync(path.join(ROOT, 'utils', 'securityAuditLogger.js'), 'utf8');
    const requires = [...src.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map((m) => m[1]);
    for (const mod of requires) {
        assert.ok(!/(^|\/)(pg|drizzle-orm|mongoose|redis|sqlite3|better-sqlite3|sequelize)$/.test(mod), `unexpected persistence dependency: ${mod}`);
        assert.ok(!/Db$/.test(mod), `unexpected database module: ${mod}`);
    }
    assert.deepEqual(requires.sort(), ['../config', 'discord.js']);
});

// ── SCENARIO 1: PrimeBot joins another server ───────────────────────────────

test('SCENARIO 1: server join posts a green audit embed with every detail', async () => {
    const channel = makeChannel();
    const guild = makeGuild({ channels: [makeVoiceChannel('555555555555555555', 'General')] });
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });

    const ok = await logger.onGuildCreate(guild, client);

    assert.equal(ok, true);
    assert.equal(channel.sent.length, 1);
    const embed = embedOf(channel.sent[0]);
    assert.equal(embed.color, COLORS.join);
    assert.match(embed.title, /PrimeBot Joined a Server/);
    assert.match(fieldValue(embed, 'Server'), /Test Guild/);
    assert.match(fieldValue(embed, 'Server'), new RegExp(GUILD_A));
    assert.equal(fieldValue(embed, 'Server ID'), `\`${GUILD_A}\``);
    assert.equal(fieldValue(embed, 'Owner'), `<@${guild.ownerId}>`);
    assert.equal(fieldValue(embed, 'Owner ID'), `\`${guild.ownerId}\``);
    assert.equal(fieldValue(embed, 'Owner name'), 'Unavailable', 'owner name is not fetched → never invented');
    assert.equal(fieldValue(embed, 'Members'), '42');
    assert.match(fieldValue(embed, 'Server created'), /<t:\d+:F> \(<t:\d+:R>\)/);
    assert.match(fieldValue(embed, 'PrimeBot joined'), /<t:\d+:R>/);
    assert.equal(fieldValue(embed, 'Total servers'), '1');
    assert.match(fieldValue(embed, 'Event'), /server_join/);
    assert.match(embed.footer.text, /server_join/);
    assert.match(embed.thumbnail.url, /^https:\/\/cdn\.discordapp\.com\/icons\//);
    assert.deepEqual(channel.sent[0].allowedMentions, { parse: [] }, 'never pings anyone');
    // The destination is private — the payload must not leak it.
    assert.ok(!JSON.stringify(embed).includes(CHANNEL_ID));
});

test('the READY-time guildCreate burst is not logged as a join', async () => {
    const channel = makeChannel();
    const clock = 2_000_000_000_000;
    // discord.js re-emits guildCreate for every guild it is already in when it
    // hydrates the cache at READY — that membership is old, not a new join.
    const guild = makeGuild({ joinedTimestamp: clock - 60 * 60 * 1000 });
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client, nowFn: () => clock });

    const ok = await logger.onGuildCreate(guild, client);
    assert.equal(ok, false);
    assert.equal(channel.sent.length, 0, 'no audit spam on every restart');
    assert.equal(logger.getGuildSnapshot(GUILD_A).name, 'Test Guild', 'the guild is still cached for a later leave');
});

test('a genuinely new join (recent joinedTimestamp) is logged', async () => {
    const channel = makeChannel();
    const clock = 2_000_000_000_000;
    const guild = makeGuild({ joinedTimestamp: clock - 10_000 });
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client, nowFn: () => clock });

    assert.equal(await logger.onGuildCreate(guild, client), true);
    assert.equal(channel.sent.length, 1);
});

test('an unavailable guild (Discord outage) is never reported as a leave', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    logger.rememberGuild(guild);

    const ok = await logger.onGuildDelete({ id: GUILD_A, available: false }, client);
    assert.equal(ok, false);
    assert.equal(channel.sent.length, 0);
    assert.ok(logger.getGuildSnapshot(GUILD_A), 'snapshot kept for when the guild comes back');
});

test('server join reports an unknown owner name / member count as Unavailable', async () => {
    const channel = makeChannel();
    const guild = makeGuild({ ownerId: null, memberCount: null, icon: null });
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });

    await logger.onGuildCreate(guild, client);
    const embed = embedOf(channel.sent[0]);
    assert.equal(fieldValue(embed, 'Owner'), 'Unavailable');
    assert.equal(fieldValue(embed, 'Members'), 'Unavailable');
    assert.equal(embed.thumbnail, undefined);
});

// ── SCENARIO 2: PrimeBot leaves another server ──────────────────────────────

test('SCENARIO 2: server leave uses the in-memory snapshot and a red embed', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    logger.rememberGuild(guild); // known while the bot was running

    client.guilds.cache.delete(GUILD_A); // discord.js removes it before emitting
    const ok = await logger.onGuildDelete({ id: GUILD_A }, client);

    assert.equal(ok, true);
    const embed = embedOf(channel.sent[0]);
    assert.equal(embed.color, COLORS.leave);
    assert.match(embed.title, /PrimeBot Left a Server/);
    assert.match(fieldValue(embed, 'Server (last known)'), /Test Guild/);
    assert.equal(fieldValue(embed, 'Owner ID (last known)'), `\`${guild.ownerId}\``);
    assert.equal(fieldValue(embed, 'Members (last known)'), '42');
    assert.match(fieldValue(embed, 'Left at'), /<t:\d+:F>/);
    assert.equal(fieldValue(embed, 'Remaining servers'), '0');
    assert.match(fieldValue(embed, 'Event'), /server_leave/);
});

test('server leave reports data it never knew as Unavailable (no invention)', async () => {
    const channel = makeChannel();
    const client = makeClient({ channel });
    const { logger } = makeLogger({ client });

    await logger.onGuildDelete({ id: GUILD_B }, client);
    const embed = embedOf(channel.sent[0]);
    assert.equal(fieldValue(embed, 'Server (last known)'), `Unavailable (\`${GUILD_B}\`)`);
    assert.equal(fieldValue(embed, 'Owner ID (last known)'), 'Unavailable');
    assert.equal(fieldValue(embed, 'Members (last known)'), 'Unavailable');
    assert.match(embed.description, /Unavailable/);
});

test('server leave drops that guild\'s voice sessions', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const member = makeMember();
    await logger.onVoiceStateUpdate(
        voiceState({ guild, member }),
        voiceState({ guild, member, channelId: '555555555555555555', channel: makeVoiceChannel('555555555555555555', 'General') }),
        client,
    );
    assert.ok(logger.getVoiceSession(GUILD_A, member.id));

    await logger.onGuildDelete(guild, client);
    assert.equal(logger.getVoiceSession(GUILD_A, member.id), null);
});

// ── SCENARIO 3: a member joins a voice channel ──────────────────────────────

test('SCENARIO 3: member voice join posts a green embed with member/guild/channel ids', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const member = makeMember();
    const vc = makeVoiceChannel('555555555555555555', 'General');

    const ok = await logger.onVoiceStateUpdate(
        voiceState({ guild, member }),
        voiceState({ guild, member, channelId: vc.id, channel: vc }),
        client,
    );

    assert.equal(ok, true);
    const embed = embedOf(channel.sent[0]);
    assert.equal(embed.color, COLORS.join);
    assert.match(embed.title, /Voice Channel Join/);
    assert.equal(fieldValue(embed, 'Member'), `Alice (<@${member.id}>)`);
    assert.equal(fieldValue(embed, 'Username'), '@alice');
    assert.equal(fieldValue(embed, 'User ID'), `\`${member.id}\``);
    assert.match(fieldValue(embed, 'Server'), new RegExp(GUILD_A));
    assert.equal(fieldValue(embed, 'Channel'), 'General');
    assert.equal(fieldValue(embed, 'Channel ID'), `\`${vc.id}\``);
    assert.match(fieldValue(embed, 'Timestamp'), /<t:\d+:F> \(<t:\d+:R>\)/);
    assert.match(fieldValue(embed, 'Event'), /voice_join/);
    // Session is tracked for the later leave/move.
    assert.equal(logger.getVoiceSession(GUILD_A, member.id).channelId, vc.id);
});

// ── SCENARIO 4: a member leaves a voice channel ─────────────────────────────

test('SCENARIO 4: member voice leave posts a red embed with the session duration', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    let clock = 1_000_000;
    const { logger } = makeLogger({ client, nowFn: () => clock });
    const member = makeMember();
    const vc = makeVoiceChannel('555555555555555555', 'General');

    await logger.onVoiceStateUpdate(voiceState({ guild, member }), voiceState({ guild, member, channelId: vc.id, channel: vc }), client);
    clock += 125_000; // 2m 5s in voice
    const ok = await logger.onVoiceStateUpdate(voiceState({ guild, member, channelId: vc.id, channel: vc }), voiceState({ guild, member }), client);

    assert.equal(ok, true);
    const embed = embedOf(channel.sent[1]);
    assert.equal(embed.color, COLORS.leave);
    assert.match(embed.title, /Voice Channel Leave/);
    assert.equal(fieldValue(embed, 'Previous channel'), 'General');
    assert.equal(fieldValue(embed, 'Previous channel ID'), `\`${vc.id}\``);
    assert.equal(fieldValue(embed, 'Duration'), '2m 5s');
    assert.match(fieldValue(embed, 'Event'), /voice_leave/);
    assert.equal(logger.getVoiceSession(GUILD_A, member.id), null, 'completed session is removed');
});

// ── SCENARIO 5: a member moves between voice channels ───────────────────────

test('SCENARIO 5: a channel move is ONE orange move event, not leave + join', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    let clock = 5_000_000;
    const { logger } = makeLogger({ client, nowFn: () => clock });
    const member = makeMember();
    const from = makeVoiceChannel('555555555555555555', 'General');
    const to = makeVoiceChannel('666666666666666666', 'Gaming');

    await logger.onVoiceStateUpdate(voiceState({ guild, member }), voiceState({ guild, member, channelId: from.id, channel: from }), client);
    clock += 30_000;
    const ok = await logger.onVoiceStateUpdate(
        voiceState({ guild, member, channelId: from.id, channel: from }),
        voiceState({ guild, member, channelId: to.id, channel: to }),
        client,
    );

    assert.equal(ok, true);
    assert.equal(channel.sent.length, 2, 'join + move only — no extra leave/join pair');
    const embed = embedOf(channel.sent[1]);
    assert.equal(embed.color, COLORS.move);
    assert.match(embed.title, /Voice Channel Move/);
    assert.equal(fieldValue(embed, 'Previous channel'), 'General');
    assert.equal(fieldValue(embed, 'New channel'), 'Gaming');
    assert.equal(fieldValue(embed, 'Previous channel ID'), `\`${from.id}\``);
    assert.equal(fieldValue(embed, 'New channel ID'), `\`${to.id}\``);
    assert.equal(fieldValue(embed, 'Duration'), '30s', 'time spent in the previous channel');
    assert.match(fieldValue(embed, 'Event'), /voice_move/);
    assert.equal(logger.getVoiceSession(GUILD_A, member.id).channelId, to.id, 'session follows the member');
});

// ── SCENARIO 6 / 7: PrimeBot's own voice activity ───────────────────────────

test('SCENARIO 6: PrimeBot voice join is identified as a bot event', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const botMember = makeMember({ id: BOT_ID, username: 'PrimeBot', displayName: 'PrimeBot', bot: true });
    const vc = makeVoiceChannel('555555555555555555', 'Music');

    await logger.onVoiceStateUpdate(voiceState({ guild, member: botMember }), voiceState({ guild, member: botMember, channelId: vc.id, channel: vc }), client);

    const embed = embedOf(channel.sent[0]);
    assert.match(embed.title, /PrimeBot Joined Voice/);
    assert.equal(embed.color, COLORS.info);
    assert.equal(fieldValue(embed, 'Bot'), `PrimeBot (<@${BOT_ID}>)`);
    assert.equal(fieldValue(embed, 'User ID'), `\`${BOT_ID}\``);
    assert.equal(fieldValue(embed, 'Channel'), 'Music');
    assert.match(fieldValue(embed, 'Event'), /voice_bot_join/);
});

test('SCENARIO 7: PrimeBot leaving a live channel is a red bot leave', async () => {
    const channel = makeChannel();
    const vc = makeVoiceChannel('555555555555555555', 'Music');
    const guild = makeGuild({ channels: [vc] });
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const botMember = makeMember({ id: BOT_ID, username: 'PrimeBot', bot: true });

    await logger.onVoiceStateUpdate(voiceState({ guild, member: botMember }), voiceState({ guild, member: botMember, channelId: vc.id, channel: vc }), client);
    await logger.onVoiceStateUpdate(voiceState({ guild, member: botMember, channelId: vc.id, channel: vc }), voiceState({ guild, member: botMember }), client);

    const embed = embedOf(channel.sent[1]);
    assert.match(embed.title, /PrimeBot Left Voice/);
    assert.equal(embed.color, COLORS.leave);
    assert.match(fieldValue(embed, 'Event'), /voice_bot_leave/);
});

test('SCENARIO 7: a removed channel is reported as an unexpected bot disconnect', async () => {
    const channel = makeChannel();
    const vc = makeVoiceChannel('555555555555555555', 'Music');
    const guild = makeGuild({ channels: [vc] });
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const botMember = makeMember({ id: BOT_ID, username: 'PrimeBot', bot: true });

    await logger.onVoiceStateUpdate(voiceState({ guild, member: botMember }), voiceState({ guild, member: botMember, channelId: vc.id, channel: vc }), client);
    guild.channels.cache.delete(vc.id); // channel deleted while the bot was connected
    await logger.onVoiceStateUpdate(voiceState({ guild, member: botMember, channelId: vc.id, channel: vc }), voiceState({ guild, member: botMember }), client);

    const embed = embedOf(channel.sent[1]);
    assert.match(embed.title, /PrimeBot Voice Disconnect/);
    assert.equal(embed.color, COLORS.move);
    assert.match(fieldValue(embed, 'Event'), /voice_bot_disconnect/);
});

test('PrimeBot moving between channels is an orange bot move', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const botMember = makeMember({ id: BOT_ID, username: 'PrimeBot', bot: true });
    const a = makeVoiceChannel('555555555555555555', 'A');
    const b = makeVoiceChannel('666666666666666666', 'B');

    await logger.onVoiceStateUpdate(voiceState({ guild, member: botMember }), voiceState({ guild, member: botMember, channelId: a.id, channel: a }), client);
    await logger.onVoiceStateUpdate(
        voiceState({ guild, member: botMember, channelId: a.id, channel: a }),
        voiceState({ guild, member: botMember, channelId: b.id, channel: b }),
        client,
    );

    const embed = embedOf(channel.sent[1]);
    assert.match(embed.title, /PrimeBot Moved Voice Channel/);
    assert.equal(embed.color, COLORS.move);
    assert.match(fieldValue(embed, 'Event'), /voice_bot_move/);
});

// ── SCENARIO 8: several guilds at once ──────────────────────────────────────

test('SCENARIO 8: concurrent events from multiple guilds all reach the one channel', async () => {
    const channel = makeChannel();
    const guildA = makeGuild({ id: GUILD_A, name: 'Alpha' });
    const guildB = makeGuild({ id: GUILD_B, name: 'Beta' });
    const client = makeClient({ channel, guilds: [guildA, guildB] });
    const { logger } = makeLogger({ client });
    const alice = makeMember({ id: '444444444444444444', username: 'alice' });
    const bob = makeMember({ id: '777777777777777777', username: 'bob' });

    const results = await Promise.all([
        logger.onVoiceStateUpdate(voiceState({ guild: guildA, member: alice }), voiceState({ guild: guildA, member: alice, channelId: '1', channel: makeVoiceChannel('1', 'A-voice') }), client),
        logger.onVoiceStateUpdate(voiceState({ guild: guildB, member: bob }), voiceState({ guild: guildB, member: bob, channelId: '2', channel: makeVoiceChannel('2', 'B-voice') }), client),
        logger.onGuildCreate(guildA, client),
    ]);

    assert.deepEqual(results, [true, true, true]);
    assert.equal(channel.sent.length, 3, 'every event delivered exactly once');
    const guildIds = channel.sent.map((p) => {
        const embed = embedOf(p);
        return fieldValue(embed, 'Server ID');
    });
    assert.ok(guildIds.includes(`\`${GUILD_A}\``));
    assert.ok(guildIds.includes(`\`${GUILD_B}\``));
});

// ── SCENARIO 9: restart while members are in voice ──────────────────────────

test('SCENARIO 9: a session that began before the restart reports duration as unavailable', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client }); // fresh process: no sessions
    const member = makeMember();
    const vc = makeVoiceChannel('555555555555555555', 'General');

    const ok = await logger.onVoiceStateUpdate(
        voiceState({ guild, member, channelId: vc.id, channel: vc }),
        voiceState({ guild, member }),
        client,
    );

    assert.equal(ok, true);
    const embed = embedOf(channel.sent[0]);
    assert.match(embed.title, /Voice Channel Leave/);
    assert.match(fieldValue(embed, 'Duration'), /^Unavailable — .*restart/);
    assert.doesNotMatch(fieldValue(embed, 'Duration'), /\d+s|\d+m|\d+h/, 'no invented duration');
});

// ── SCENARIO 10: destination missing / inaccessible ─────────────────────────

test('SCENARIO 10: a missing destination channel is skipped with a masked diagnostic', async () => {
    const client = makeClient({ channel: null }); // nothing cached, fetch throws 404
    const guild = makeGuild();
    const { logger, logs } = makeLogger({ client });
    const member = makeMember();
    const vc = makeVoiceChannel('555555555555555555', 'General');

    const ok = await logger.onVoiceStateUpdate(voiceState({ guild, member }), voiceState({ guild, member, channelId: vc.id, channel: vc }), client);

    assert.equal(ok, false);
    assert.equal(logger.stats.failed, 1);
    assert.ok(logs.length >= 1);
    const diagnostic = logs.join('\n');
    assert.match(diagnostic, /\[SECURITY AUDIT\]/);
    assert.ok(!diagnostic.includes(CHANNEL_ID), 'the private channel id is never logged in full');
    assert.match(diagnostic, new RegExp(maskId(CHANNEL_ID)));
});

test('SCENARIO 10: a non-text destination is rejected', async () => {
    const voiceChannel = makeChannel({ textBased: false });
    const client = makeClient({ channel: voiceChannel });
    const { logger, logs } = makeLogger({ client });

    const result = await logger.verifyDestination();
    assert.equal(result.ok, false);
    assert.match(logs.join('\n'), /not a text-based channel/);
});

test('SCENARIO 10: missing View Channel / Send Messages is refused before sending', async () => {
    const channel = makeChannel({ granted: ['ViewChannel'] });
    const client = makeClient({ channel });
    const guild = makeGuild();
    const { logger, logs } = makeLogger({ client });
    const member = makeMember();

    const ok = await logger.onVoiceStateUpdate(
        voiceState({ guild, member }),
        voiceState({ guild, member, channelId: '1', channel: makeVoiceChannel('1', 'X') }),
        client,
    );

    assert.equal(ok, false);
    assert.equal(channel.sent.length, 0);
    assert.match(logs.join('\n'), /SendMessages/);
});

test('an unconfigured placeholder keeps the logger inert with one diagnostic', async () => {
    const channel = makeChannel();
    const client = makeClient({ channel });
    const { logger, logs } = makeLogger({ client, channelId: 'YOUR_LOG_CHANNEL_ID' });
    const guild = makeGuild();

    assert.equal(logger.isConfigured(), false);
    const ok = await logger.onGuildCreate(guild, client);
    const again = await logger.onGuildDelete(guild, client);

    assert.equal(ok, false);
    assert.equal(again, false);
    assert.equal(channel.sent.length, 0);
    assert.equal(logs.filter((l) => /SECURITY_AUDIT_CHANNEL_ID/.test(l)).length, 1, 'warned once');
});

// ── SCENARIO 11: rate limits / temporary API failures ───────────────────────

test('SCENARIO 11: a 429 is retried after retry_after and then delivered', async () => {
    const channel = makeChannel();
    const sleeps = [];
    const client = makeClient({ channel });
    const guild = makeGuild();
    const logger = new SecurityAuditLogger({
        channelId: CHANNEL_ID,
        client,
        sleepFn: (resolve, ms) => { sleeps.push(ms); return setImmediate(resolve); },
        logger: { warn() {}, log() {}, error() {} },
    });

    let attempts = 0;
    channel.send = async (payload) => {
        attempts++;
        if (attempts === 1) {
            const err = new Error('You are being rate limited.');
            err.status = 429;
            err.retryAfter = 750;
            throw err;
        }
        channel.sent.push(payload);
        return { id: 'ok' };
    };

    const ok = await logger.onGuildCreate(guild, client);
    assert.equal(ok, true);
    assert.equal(attempts, 2);
    assert.deepEqual(sleeps, [750], 'waits exactly the retry_after the API returned');
    assert.equal(logger.stats.sent, 1);
});

test('SCENARIO 11: a 5xx is retried, then the event is dropped without throwing', async () => {
    const channel = makeChannel();
    const client = makeClient({ channel });
    const guild = makeGuild();
    const { logger, logs } = makeLogger({ client, retryDelays: [1, 1] });
    let attempts = 0;
    channel.send = async () => {
        attempts++;
        const err = new Error('Service Unavailable');
        err.status = 503;
        throw err;
    };

    const ok = await logger.onGuildCreate(guild, client);
    assert.equal(ok, false);
    assert.equal(attempts, 3, 'initial attempt + 2 retries');
    assert.equal(logger.stats.failed, 1);
    assert.equal(logger.stats.lastError.includes('503'), true);
    assert.match(logs.join('\n'), /could not deliver server_join/);
});

test('a non-retryable error is not retried', async () => {
    const channel = makeChannel();
    const client = makeClient({ channel });
    const guild = makeGuild();
    const { logger } = makeLogger({ client });
    let attempts = 0;
    channel.send = async () => {
        attempts++;
        const err = new Error('Missing Access');
        err.status = 403;
        err.code = 50001;
        throw err;
    };

    const ok = await logger.onGuildCreate(guild, client);
    assert.equal(ok, false);
    assert.equal(attempts, 1);
});

// ── SCENARIO 12: mute / deafen / stream / camera never log ──────────────────

test('SCENARIO 12: mute, deafen, streaming and camera changes produce no events', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const member = makeMember();
    const vc = makeVoiceChannel('555555555555555555', 'General');

    await logger.onVoiceStateUpdate(voiceState({ guild, member }), voiceState({ guild, member, channelId: vc.id, channel: vc }), client);
    assert.equal(channel.sent.length, 1);

    const base = voiceState({ guild, member, channelId: vc.id, channel: vc });
    const variants = [
        { ...base, selfMute: true },
        { ...base, selfDeaf: true },
        { ...base, serverMute: true, serverDeaf: true },
        { ...base, streaming: true },
        { ...base, selfVideo: true },
        { ...base, suppress: true },
    ];
    for (const next of variants) {
        const ok = await logger.onVoiceStateUpdate(base, next, client);
        assert.equal(ok, false, 'no audit event for a non-channel state change');
    }
    assert.equal(channel.sent.length, 1, 'still only the original join');
});

// ── Privacy / delivery guarantees ───────────────────────────────────────────

test('events are only ever sent to the configured private channel', async () => {
    const privateChannel = makeChannel();
    const guildChannel = makeChannel({ id: '888888888888888888', name: 'general' });
    const client = makeClient({ channel: privateChannel });
    client.channels.cache.set(guildChannel.id, guildChannel);
    const guild = makeGuild();
    const { logger } = makeLogger({ client });
    const member = makeMember();

    await logger.onVoiceStateUpdate(
        voiceState({ guild, member }),
        voiceState({ guild, member, channelId: '1', channel: makeVoiceChannel('1', 'X') }),
        client,
    );

    assert.equal(privateChannel.sent.length, 1);
    assert.equal(guildChannel.sent.length, 0, 'never posted into the guild that generated the event');
});

test('a duplicate delivery of the same event is processed once', async () => {
    const channel = makeChannel();
    const guild = makeGuild();
    const client = makeClient({ channel, guilds: [guild] });
    const { logger } = makeLogger({ client });
    const member = makeMember();
    const vc = makeVoiceChannel('555555555555555555', 'General');

    const oldState = voiceState({ guild, member });
    const newState = voiceState({ guild, member, channelId: vc.id, channel: vc });
    const first = await logger.onVoiceStateUpdate(oldState, newState, client);
    const second = await logger.onVoiceStateUpdate(oldState, newState, client);

    assert.equal(first, true);
    assert.equal(second, false);
    assert.equal(channel.sent.length, 1);
});

test('a full delivery queue drops events instead of growing without bound', async () => {
    const channel = makeChannel();
    const client = makeClient({ channel });
    const guild = makeGuild();
    const { logger, logs } = makeLogger({ client, maxQueue: 0 });

    const ok = await logger.onGuildCreate(guild, client);
    assert.equal(ok, false);
    assert.equal(logger.stats.skipped, 1);
    assert.match(logs.join('\n'), /queue is full/);
});

test('formatDuration renders hours/minutes/seconds', () => {
    assert.equal(formatDuration(0), '0s');
    assert.equal(formatDuration(5_000), '5s');
    assert.equal(formatDuration(65_000), '1m 5s');
    assert.equal(formatDuration(3_725_000), '1h 2m 5s');
    assert.equal(formatDuration(null), null);
    assert.equal(formatDuration(-1), null);
});

// ── Event wiring ────────────────────────────────────────────────────────────

test('the gateway handlers are wired to the logger', () => {
    const guildCreate = require('../events/guildCreate');
    const guildDelete = require('../events/guildDelete');
    const voiceUpdate = require('../events/voiceStateUpdate');
    assert.equal(guildCreate.name, 'guildCreate');
    assert.equal(guildDelete.name, 'guildDelete');
    assert.equal(voiceUpdate.name, 'voiceStateUpdate');
    for (const [file, handler] of [['guildCreate.js', guildCreate], ['guildDelete.js', guildDelete], ['voiceStateUpdate.js', voiceUpdate]]) {
        const src = fs.readFileSync(path.join(ROOT, 'events', file), 'utf8');
        assert.match(src, /securityAuditLogger/, `${file} must use the audit logger`);
        assert.match(handler.execute.toString(), /try\s*\{/, `${file} swallows its own errors`);
    }
    const ready = fs.readFileSync(path.join(ROOT, 'events', 'ready.js'), 'utf8');
    assert.match(ready, /getSecurityAuditLogger\(\)/);
    assert.match(ready, /securityAudit\.attach\(client\)/);
    assert.match(ready, /securityAudit\.verifyDestination\(\)/);
});

test('end-to-end: the real gateway handlers deliver through to the private channel', async () => {
    const channel = makeChannel();
    const guild = makeGuild({ joinedTimestamp: Date.now() - 5000 });
    const client = makeClient({ channel, guilds: [guild] });
    const member = makeMember();
    const vc = makeVoiceChannel('555555555555555555', 'General');

    const audit = require('../utils/securityAuditLogger');
    const savedChannelId = config.securityAudit.channelId;
    config.securityAudit.channelId = CHANNEL_ID;
    audit.resetSecurityAuditLogger();
    try {
        const singleton = audit.getSecurityAuditLogger();
        singleton.client = client;
        singleton.logger = { warn() {}, log() {}, error() {} };

        await require('../events/guildCreate').execute(guild, client);
        await require('../events/voiceStateUpdate').execute(
            voiceState({ guild, member }),
            voiceState({ guild, member, channelId: vc.id, channel: vc }),
            client,
        );
        client.guilds.cache.delete(GUILD_A);
        await require('../events/guildDelete').execute({ id: GUILD_A }, client);

        assert.equal(channel.sent.length, 3, 'join + voice join + leave all delivered');
        const types = channel.sent.map((p) => fieldValue(embedOf(p), 'Event'));
        assert.deepEqual(types, ['`server_join`', '`voice_join`', '`server_leave`']);
    } finally {
        config.securityAudit.channelId = savedChannelId;
        audit.resetSecurityAuditLogger();
    }
});

test('a failing handler never throws into the gateway', async () => {
    const { logger } = makeLogger({ client: null });
    await assert.doesNotReject(() => logger.onGuildCreate(null, null));
    await assert.doesNotReject(() => logger.onGuildDelete({ id: GUILD_A }, null));
    await assert.doesNotReject(() => logger.onVoiceStateUpdate(null, null, null));
    await assert.doesNotReject(() => logger.verifyDestination());
});

test('attach() snapshots every cached guild in memory', () => {
    const guild = makeGuild();
    const client = makeClient({ guilds: [guild] });
    const { logger } = makeLogger({ client });
    logger.attach(client);
    const snapshot = logger.getGuildSnapshot(GUILD_A);
    assert.equal(snapshot.name, 'Test Guild');
    assert.equal(snapshot.ownerId, guild.ownerId);
    assert.equal(snapshot.memberCount, 42);
});
