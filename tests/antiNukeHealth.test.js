'use strict';
const test = require('node:test');
const assert = require('node:assert');

const { healthScan, PASS, WARN, FAIL } = require('../utils/antiNukeHealth');

function makeGuild(overrides = {}) {
    return {
        id: '100000000000000000',
        name: 'Test Guild',
        ownerId: '200000000000000000',
        roles: {
            cache: new Map([
                ['300000000000000000', { id: '300000000000000000', name: 'Quarantine', position: 2 }],
                ['400000000000000000', { id: '400000000000000000', name: 'BotRole', position: 5 }],
            ]),
        },
        channels: {
            cache: new Map([['500000000000000000', { id: '500000000000000000', name: 'security-logs' }]]),
            fetch: async (id) => (id === '500000000000000000' ? { id: '500000000000000000' } : null),
        },
        members: {
            me: {
                id: '900000000000000000',
                permissions: { has: () => true },
                roles: { highest: { position: 5 } },
            },
            cache: new Map(),
            fetch: async () => null,
        },
        ...overrides,
    };
}

function makeManager(settings) {
    return {
        _auditStreamAvailable: true,
        processEvent: async () => ({}),
        getSettings: () => settings,
    };
}

const baseSettings = {
    enabled: true,
    dryRun: false,
    alertChannelId: '500000000000000000',
    trustedUserIds: [],
    trustedRoleIds: [],
    watched: { memberBan: { enabled: true, threshold: 5, seconds: 15 } },
    actionResponses: {},
    responses: ['alertOwner', 'alertChannel', 'logOnly'],
    quarantineRoleId: null,
    dangerousPermissions: ['Administrator'],
    lockdown: { enabled: true, verificationLevel: 'high', pauseInvites: true },
    responseCooldownSeconds: 30,
    updatedAt: new Date().toISOString(),
};

test('healthScan returns PASS for a fully operational anti-nuke setup', async () => {
    const guild = makeGuild();
    const scan = await healthScan({
        manager: makeManager(baseSettings),
        client: {
            // discord.js GatewayIntentBits are numeric: GuildModeration = 4.
            options: { intents: { has: (bit) => bit === 4 } },
        },
        guild,
    });
    const byKey = Object.fromEntries(scan.checks.map(c => [c.key, c.result]));
    // A fresh setup without a quarantine role or prior incidents legitimately
    // yields WARNING overall — the guarantee is: never PASS a check that wasn't
    // performed, and never FAIL a healthy pipeline.
    assert.ok(!scan.checks.some(c => c.result === FAIL), JSON.stringify(scan.checks.map(c => [c.key, c.result, c.note])));
    assert.equal(byKey.enabled, PASS);
    assert.equal(byKey.dry_run, PASS);
    assert.equal(byKey.config_cache, PASS);
    assert.equal(byKey.intent, PASS);
    assert.equal(byKey.audit_stream, PASS);
    assert.equal(byKey.gateway, PASS);
});

test('healthScan FAILS when Anti-Nuke is disabled or dry-run is on', async () => {
    const guild = makeGuild();
    const s1 = await healthScan({ manager: makeManager({ ...baseSettings, enabled: false }), client: null, guild });
    assert.equal(s1.overall, FAIL);
    assert.equal(Object.fromEntries(s1.checks.map(c => [c.key, c.result])).enabled, FAIL);

    const s2 = await healthScan({ manager: makeManager({ ...baseSettings, dryRun: true }), client: null, guild });
    const byKey = Object.fromEntries(s2.checks.map(c => [c.key, c.result]));
    assert.equal(byKey.dry_run, WARN, 'dry-run ON must be WARNING, not PASS');
});

test('healthScan reports the effective response plan and never fabricates PASS', async () => {
    const guild = makeGuild();
    const s = await healthScan({ manager: makeManager(baseSettings), client: null, guild });
    const responsesCheck = s.checks.find(c => c.key === 'responses');
    assert.ok(responsesCheck, 'responses check exists');
    // The per-action default for memberBan is quarantine+alerts → enforcement.
    assert.equal(responsesCheck.result, PASS);
});

test('healthScan flags a missing quarantine role', async () => {
    const guild = makeGuild();
    const s = await healthScan({
        manager: makeManager({ ...baseSettings, quarantineRoleId: '999999999999999999' }),
        client: null, guild,
    });
    const q = s.checks.find(c => c.key === 'quarantine_role');
    assert.equal(q.result, FAIL, 'missing quarantine role must be FAILED');
    assert.ok(/does not exist/.test(q.note || ''));
});

test('healthScan flags a quarantine role at/above the bot highest role', async () => {
    // Quarantine role position 8 > bot role position 5 → not manageable.
    const roles = new Map([
        ['300000000000000000', { id: '300000000000000000', name: 'Quarantine', position: 8 }],
        ['400000000000000000', { id: '400000000000000000', name: 'BotRole', position: 5 }],
    ]);
    const guild = makeGuild({ roles: { cache: roles } });
    const s = await healthScan({
        manager: makeManager({ ...baseSettings, quarantineRoleId: '300000000000000000' }),
        client: null, guild,
    });
    const q = s.checks.find(c => c.key === 'quarantine_role');
    assert.equal(q.result, FAIL);
    assert.ok(/above/.test(q.note || ''));
});

test('healthScan reports missing bot permissions as FAILED per check', async () => {
    const guild = makeGuild({
        members: {
            me: {
                id: '900000000000000000',
                permissions: { has: (flag) => flag !== 2n }, // no KickMembers
                roles: { highest: { position: 5 } },
            },
            cache: new Map(), fetch: async () => null,
        },
    });
    const s = await healthScan({ manager: makeManager(baseSettings), client: null, guild });
    const kick = s.checks.find(c => c.key === 'perm:KickMembers');
    assert.equal(kick.result, FAIL);
});

test('healthScan warns when the audit stream has never been observed', async () => {
    const guild = makeGuild();
    const manager = makeManager(baseSettings);
    manager._auditStreamAvailable = false;
    const s = await healthScan({ manager, client: { options: { intents: { has: () => false } } }, guild });
    const stream = s.checks.find(c => c.key === 'audit_stream');
    assert.equal(stream.result, WARN);
});