// No-prefix ("sash-less") commands must be case-insensitive.
//
// A no-prefix grant lets a user type `ping` instead of `$ping`. Users type
// `Ping` / `PING` just as often, so the no-prefix path has to lowercase the
// command name before it reaches the `switch (commandName)`. This drives the
// REAL events/messageCreate.js handler with a stubbed server-settings manager
// (no Postgres in CI) and asserts the mixed-case forms all reach the same
// command — the same harness pattern as embedSendCommand.test.js.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Minimal client: enough for the `about` case (guilds.cache + prefix lookup)
// and the no-prefix gate. The settings manager is a stub so no DB is touched.
function buildClient(noPrefix) {
    return {
        user: { id: 'bot', displayAvatarURL: () => 'https://cdn.discordapp.com/embed/avatars/0.png', username: 'PrimeBot' },
        ws: { ping: 42 },
        commands: new Map(),
        guilds: { cache: { size: 3, reduce: () => 10, get: () => null } },
        serverSettingsManager: {
            getGuildPrefix: () => '$',
            hasNoPrefixMode: () => noPrefix,
            getTriggeredReactions: () => [],
            getTriggeredResponses: () => [],
        },
        // Counting/leveling are optional-chained in the handler.
        countingManager: { isCountingChannel: () => false, processCountingMessage: async () => false },
        levelingManager: { processMessage: async () => {} },
    };
}

function buildMessage(content) {
    const replies = [];
    const channel = {
        id: 'chan',
        isTextBased: () => true,
        permissionsFor: () => ({ has: () => true }),
        send: async (p) => { replies.push(p); return { id: '1', createdTimestamp: Date.now() }; },
    };
    return {
        content,
        guild: {
            id: '1',
            name: 'Test Guild',
            members: { me: { id: 'bot' } },
            channels: { cache: { get: () => channel }, fetch: async () => channel },
        },
        channel,
        member: { permissions: { has: () => true } },
        mentions: { channels: { first: () => null }, users: { first: () => null } },
        reply: async (p) => { replies.push(p); return { id: '2', delete: async () => {} }; },
        react: async () => {},
        author: { id: 'u', tag: 'u#0001', bot: false, username: 'u', displayAvatarURL: () => 'https://cdn.discordapp.com/embed/avatars/0.png' },
        _replies: replies,
    };
}

async function runNoPrefix(content) {
    global.botActive = true;
    const mcPath = require.resolve('../events/messageCreate');
    delete require.cache[mcPath];
    const mc = require(mcPath);
    const message = buildMessage(content);
    const client = buildClient(true);
    await mc.execute(message, client);
    return message._replies;
}

test('no-prefix commands work regardless of the casing the user types', async () => {
    for (const content of ['about', 'About', 'ABOUT', 'aBoUt']) {
        const replies = await runNoPrefix(content);
        assert.ok(replies.length > 0, `"${content}" produced a reply`);
        const payload = replies[0];
        const text = JSON.stringify(payload);
        assert.match(text, /About PrimeBot/, `"${content}" reached the about command`);
    }
});

test('an upper-case alias reaches the same command as its lower-case form', async () => {
    // `ab` is aliased to a different (legacy) about embed earlier in the switch,
    // so assert aliasing with `AB` vs `ab` producing identical output instead of
    // assuming which about page it renders.
    const upper = await runNoPrefix('AB');
    const lower = await runNoPrefix('ab');
    assert.ok(upper.length > 0 && lower.length > 0, 'both forms replied');
    // The embeds carry a live setTimestamp(), so compare the stable fields.
    const strip = (payload) => {
        const clone = JSON.parse(JSON.stringify(payload));
        for (const embed of clone.embeds || []) delete embed.timestamp;
        return clone;
    };
    assert.deepEqual(strip(upper[0]), strip(lower[0]), 'AB and ab produce the same payload');
});

test('the no-prefix path lowercases the command name before the switch', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'events', 'messageCreate.js'), 'utf8');
    // The no-prefix branch must lowercase before simulating the prefixed message.
    assert.match(src, /\[NO-PREFIX\] Processing command/);
    assert.match(src, /const commandName = args\.shift\(\)\.toLowerCase\(\);/);
    // The simulated message is built from the lowercased name.
    assert.match(src, /const simulatedContent = `\$\{prefix\}\$\{commandName\}/);
});

test('a prefix-less command name reaching the switch is always lowercased', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'events', 'messageCreate.js'), 'utf8');
    const lowercases = src.match(/args\.shift\(\)\.toLowerCase\(\)/g) || [];
    // The emoji-prefix path, the no-prefix path and the normal prefix path all
    // lowercase; losing any one of them reintroduces the case bug.
    assert.ok(lowercases.length >= 3, `expected ≥3 command-name lowercasings, found ${lowercases.length}`);
});

test('server settings manager is only consulted for the no-prefix grant', async () => {
    // Sanity: without a grant the same mixed-case text is NOT treated as a command.
    global.botActive = true;
    const mcPath = require.resolve('../events/messageCreate');
    delete require.cache[mcPath];
    const mc = require(mcPath);
    const message = buildMessage('ABOUT');
    await mc.execute(message, buildClient(false));
    assert.equal(message._replies.length, 0, 'no grant → no command handling');
});
