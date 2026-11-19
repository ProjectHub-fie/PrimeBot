/*
 * Anti-Nuke backup pipeline — real workflow tests.
 *
 * The bug these cover: the backup system reported SUCCESS the moment a row was
 * INSERTed, even when every Discord REST read had failed (the errors were
 * swallowed into `catch(() => [])`), so a snapshot could "succeed" carrying no
 * data at all. These tests drive the REAL dashboard/db.js backup SQL against an
 * in-memory pg pool stub (so the column wiring is genuinely executed) plus the
 * REAL dashboard/antiNukeActions.js capture/restore logic with a stubbed
 * Discord REST layer, and assert the honest lifecycle:
 *
 *   • a real capture persists roles/channels/guild-settings and verifies;
 *   • a failed fetch is FAILED/PARTIAL with the real reason, never SUCCESS;
 *   • an empty capture is FAILED, never SUCCESS;
 *   • a DB write failure is FAILED, never SUCCESS;
 *   • a restore applies + verifies, and reports PARTIAL/FAILED with detail;
 *   • a restore without permissions is refused, not faked;
 *   • a stale IN_PROGRESS row is reconciled to FAILED;
 *   • cross-guild access is impossible;
 *   • duplicate concurrent captures are refused.
 *
 * No Postgres / no network: the pool stub models only the SQL these functions
 * emit, and the Discord layer is injected.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

const GUILD = '111111111111111111';
const OTHER_GUILD = '222222222222222222';

// ── In-memory pg pool modelling only the backup SQL ─────────────────────────

function makeBackupPool({ failOn = null } = {}) {
    const backups = [];
    const operations = [];
    const incidents = [];
    let seq = 0;
    let opSeq = 0;
    const calls = [];

    const rowToReturn = (r) => ({
        id: r.id, guild_id: r.guild_id, name: r.name, created_by: r.created_by,
        created_at: r.created_at, counts: r.counts, notes: r.notes,
        status: r.status, operation: r.operation, started_at: r.started_at,
        completed_at: r.completed_at, resources: r.resources, errors: r.errors,
        verification: r.verification,
        has_guild_settings: r.guild_settings != null,
    });

    async function query(text, params = []) {
        const sql = String(text).replace(/\s+/g, ' ').trim();
        calls.push({ sql, params });
        if (failOn && sql.includes(failOn)) throw new Error('simulated DB failure');
        // DDL / unrelated statements: no-op.
        if (/^(CREATE|ALTER|DELETE FROM antinuke_dedup|SELECT NOW)/i.test(sql)) return { rows: [], rowCount: 0 };

        // INSERT backup
        if (/^INSERT INTO antinuke_backups/i.test(sql)) {
            const [guildId, name, createdBy, roles, channels, settings, guildSettings, counts, notes,
                status, operation, startedAt, resources, errors, verification] = params;
            const r = {
                id: ++seq, guild_id: guildId, name, created_by: createdBy,
                created_at: new Date(), roles: JSON.parse(roles), channels: JSON.parse(channels),
                settings: settings ? JSON.parse(settings) : null,
                guild_settings: guildSettings ? JSON.parse(guildSettings) : null,
                counts: JSON.parse(counts), notes,
                status, operation, started_at: startedAt || new Date(), completed_at: new Date(),
                resources: JSON.parse(resources), errors: JSON.parse(errors), verification: JSON.parse(verification),
            };
            backups.push(r);
            return { rows: [rowToReturn(r)], rowCount: 1 };
        }

        // UPDATE backup (complete) — carries the payload + status
        if (/^UPDATE antinuke_backups SET roles = \$3/i.test(sql)) {
            const [guildId, id, roles, channels, guildSettings, settings, counts, status, resources, errors, verification] = params;
            const r = backups.find(x => x.guild_id === guildId && x.id === Number(id));
            if (!r) return { rows: [], rowCount: 0 };
            r.roles = JSON.parse(roles); r.channels = JSON.parse(channels);
            r.guild_settings = guildSettings ? JSON.parse(guildSettings) : null;
            r.settings = settings ? JSON.parse(settings) : null;
            r.counts = JSON.parse(counts); r.status = status; r.completed_at = new Date();
            r.resources = JSON.parse(resources); r.errors = JSON.parse(errors); r.verification = JSON.parse(verification);
            return { rows: [rowToReturn(r)], rowCount: 1 };
        }

        // UPDATE backup status only
        if (/^UPDATE antinuke_backups SET status = COALESCE/i.test(sql)) {
            const [guildId, id, status, completedAt, resources, errors, verification] = params;
            const r = backups.find(x => x.guild_id === guildId && x.id === Number(id));
            if (!r) return { rows: [], rowCount: 0 };
            if (status) r.status = status;
            if (completedAt) r.completed_at = completedAt;
            if (resources) r.resources = JSON.parse(resources);
            if (errors) r.errors = JSON.parse(errors);
            if (verification) r.verification = JSON.parse(verification);
            return { rows: [{ id: r.id }], rowCount: 1 };
        }

        // UPDATE reconcile stale
        if (/^UPDATE antinuke_backups SET status = 'FAILED'/i.test(sql)) {
            const [guildId, mins, extra] = params;
            let n = 0;
            for (const r of backups) {
                if (r.guild_id !== guildId) continue;
                if (!['PENDING', 'IN_PROGRESS'].includes(r.status)) continue;
                const ageMin = (Date.now() - new Date(r.started_at || r.created_at).getTime()) / 60000;
                if (ageMin < Number(mins)) continue;
                r.status = 'FAILED'; r.completed_at = new Date();
                r.errors = r.errors.concat(JSON.parse(extra));
                n++;
            }
            return { rows: new Array(n).fill({ id: 1 }), rowCount: n };
        }

        // DELETE backup
        if (/^DELETE FROM antinuke_backups/i.test(sql)) {
            const [guildId, id] = params;
            const i = backups.findIndex(x => x.guild_id === guildId && x.id === Number(id));
            if (i < 0) return { rows: [], rowCount: 0 };
            backups.splice(i, 1);
            return { rows: [], rowCount: 1 };
        }

        // COUNT in-flight
        if (/^SELECT COUNT\(\*\)::int AS count FROM antinuke_backups WHERE guild_id = \$1 AND status IN/i.test(sql)) {
            const [guildId, secs] = params;
            const n = backups.filter(r => r.guild_id === guildId && ['PENDING', 'IN_PROGRESS'].includes(r.status)
                && (Date.now() - new Date(r.started_at || r.created_at).getTime()) / 1000 < Number(secs)).length;
            return { rows: [{ count: n }], rowCount: 1 };
        }

        // COUNT all
        if (/^SELECT COUNT\(\*\)::int AS count FROM antinuke_backups WHERE guild_id = \$1/i.test(sql)) {
            const [guildId] = params;
            return { rows: [{ count: backups.filter(r => r.guild_id === guildId).length }], rowCount: 1 };
        }

        // LIST
        if (/^SELECT id, guild_id, name, created_by, created_at, counts, notes, status/i.test(sql)) {
            const [guildId, lim, off] = params;
            const rows = backups.filter(r => r.guild_id === guildId)
                .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
                .slice(off, off + lim).map(rowToReturn);
            return { rows, rowCount: rows.length };
        }

        // SELECT * one backup
        if (/^SELECT \* FROM antinuke_backups WHERE guild_id = \$1 AND id = \$2/i.test(sql)) {
            const [guildId, id] = params;
            const r = backups.find(x => x.guild_id === guildId && x.id === Number(id));
            return r ? { rows: [{ ...r, ...rowToReturn(r) }], rowCount: 1 } : { rows: [], rowCount: 0 };
        }

        // INSERT operation
        if (/^INSERT INTO antinuke_backup_operations/i.test(sql)) {
            const [backupId, guildId, operation, status, actorId, startedAt, counts, errors, verification, details] = params;
            const r = {
                id: ++opSeq, backup_id: backupId, guild_id: guildId, operation, status, actor_id: actorId,
                started_at: startedAt || new Date(), completed_at: new Date(),
                counts: JSON.parse(counts), errors: JSON.parse(errors),
                verification: JSON.parse(verification), details,
            };
            operations.push(r);
            return { rows: [r], rowCount: 1 };
        }

        // LIST operations
        if (/^SELECT \* FROM antinuke_backup_operations WHERE guild_id = \$1/i.test(sql)) {
            const [guildId, lim] = params;
            const rows = operations.filter(o => o.guild_id === guildId)
                .sort((a, b) => new Date(b.started_at) - new Date(a.started_at)).slice(0, lim);
            return { rows, rowCount: rows.length };
        }

        // antinuke_settings read (used by preview for trusted roles)
        if (/FROM antinuke_settings/i.test(sql)) return { rows: [], rowCount: 0 };

        // Incident-ledger write (recordLockdownIncident). Recorded so a test can
        // prove a backup/lockdown action actually reaches the ledger.
        if (/^INSERT INTO antinuke_incidents/i.test(sql)) {
            incidents.push({ sql, params });
            return { rows: [{ id: incidents.length }], rowCount: 1 };
        }

        return { rows: [], rowCount: 0 };
    }

    return {
        query,
        connect: async () => ({ query, release: () => {} }),
        end: async () => {},
        on: () => {},
        __backups: backups,
        __operations: operations,
        __incidents: incidents,
        __calls: calls,
    };
}

// ── Module stubbing: anukeDb pool + Discord REST ────────────────────────────

let pool = null;
let discordStub = null;

function installStubs({ pool: p, discord: d }) {
    pool = p; discordStub = d;
    const anukePath = require.resolve('../server/anukeDb');
    const discordPath = require.resolve('../dashboard/discord');
    const origLoad = Module._load;
    Module._load = function (request, parent, isMain) {
        if (parent && parent.filename && parent.filename.includes(`${path.sep}server${path.sep}`) && request === './createPool') {
            return { createPool: () => pool };
        }
        return origLoad.apply(this, arguments);
    };
    Module._load = origLoad;
    // Stub the modules by replacing the require cache entries.
    require.cache[anukePath] = {
        id: anukePath, filename: anukePath, loaded: true,
        exports: {
            anukePool: pool,
            ensureAnukeTables: async () => {},
            resolveConnectionString: () => 'stub',
            claimDedupKey: async () => true,
            listAccessRows: async () => [],
        },
    };
    require.cache[discordPath] = {
        id: discordPath, filename: discordPath, loaded: true,
        exports: discordStub,
    };
    for (const key of ['../dashboard/db', '../dashboard/antiNukeActions']) {
        delete require.cache[require.resolve(key)];
    }
    return {
        restore() {
            delete require.cache[anukePath];
            delete require.cache[discordPath];
            for (const key of ['../dashboard/db', '../dashboard/antiNukeActions']) {
                delete require.cache[require.resolve(key)];
            }
        },
    };
}

/** A Discord REST stub with controllable reads + recorded writes. */
function makeDiscord({ roles = [], channels = [], guildRaw = { verification_level: 1, name: 'Test' }, permissions = 0xFFFFFFFFFFFFFn, readError = {}, strict = false } = {}) {
    const writes = [];
    let liveRoles = roles.map(r => ({ ...r }));
    let liveChannels = channels.map(c => ({ ...c }));
    // Mutable read-error state so a test can make reads start failing mid-flow.
    const readErrorState = { ...readError };
    // Mimic Discord's validation: a create whose parent_id or overwrite target
    // does not exist is rejected with `Invalid Form Body (400)`.
    const validate = (body) => {
        if (!strict) return;
        const channelIds = new Set(liveChannels.map(c => String(c.id)));
        const roleIds = new Set(liveRoles.map(r => String(r.id)));
        if (body.parent_id && !channelIds.has(String(body.parent_id))) {
            const e = new Error('Discord API error: parent_id: Channel not found (50035) (400)');
            e.status = 400; throw e;
        }
        for (const ow of body.permission_overwrites || []) {
            const id = String(ow.id);
            if (id === String(GUILD) || Number(ow.type) === 1) continue;
            if (!roleIds.has(id)) {
                const e = new Error(`Discord API error: permission_overwrites.${id}: Unknown role (50035) (400)`);
                e.status = 400; throw e;
            }
        }
    };
    const stub = {
        API_BASE: 'https://discord.com/api/v10',
        __writes: writes,
        getGuildRoles: async () => {
            if (readErrorState.roles) throw new Error(readErrorState.roles);
            return liveRoles;
        },
        getGuildChannelsRaw: async () => {
            if (readErrorState.channels) throw new Error(readErrorState.channels);
            return liveChannels;
        },
        getGuildRaw: async () => {
            if (readErrorState.guild) throw new Error(readErrorState.guild);
            return guildRaw;
        },
        getBotMember: async () => ({ roles: ['botrole'] }),
        computeBotPermissions: async () => permissions,
        createGuildRole: async (guildId, body) => {
            writes.push({ op: 'createGuildRole', body });
            const role = { id: 'new-role-' + (writes.length), ...body };
            liveRoles.push(role);
            return role;
        },
        modifyGuildRole: async (guildId, roleId, body) => {
            writes.push({ op: 'modifyGuildRole', roleId, body });
            const r = liveRoles.find(x => String(x.id) === String(roleId));
            if (r) Object.assign(r, body);
            return r || { id: roleId, ...body };
        },
        createGuildChannel: async (guildId, body) => {
            validate(body);
            writes.push({ op: 'createGuildChannel', body });
            const ch = { id: 'new-chan-' + (writes.length), ...body };
            liveChannels.push(ch);
            return ch;
        },
        patchChannel: async (channelId, body) => {
            writes.push({ op: 'patchChannel', channelId, body });
            const c = liveChannels.find(x => String(x.id) === String(channelId));
            if (c) Object.assign(c, body);
            return c || { id: channelId };
        },
        patchGuild: async (guildId, body) => {
            writes.push({ op: 'patchGuild', body });
            return body;
        },
        putChannelOverwrite: async (channelId, overwriteId, body) => {
            if (strict) {
                const roleIds = new Set(liveRoles.map(r => String(r.id)));
                const id = String(overwriteId);
                if (id !== String(GUILD) && Number(body.type) !== 1 && !roleIds.has(id)) {
                    const e = new Error(`Discord API error: Unknown role (50035) (400)`);
                    e.status = 400; throw e;
                }
            }
            writes.push({ op: 'putChannelOverwrite', channelId, overwriteId, body });
            return body;
        },
        deleteChannelOverwrite: async (channelId, overwriteId) => {
            writes.push({ op: 'deleteChannelOverwrite', channelId, overwriteId });
            return {};
        },
        __setLive({ roles: r, channels: c }) {
            if (r) liveRoles = r.map(x => ({ ...x }));
            if (c) liveChannels = c.map(x => ({ ...x }));
        },
        __setReadError(next) {
            Object.assign(readErrorState, next || {});
        },
    };
    return stub;
}

function loadModules() {
    const db = require('../dashboard/db');
    const actions = require('../dashboard/antiNukeActions');
    return { db, actions };
}

const SAMPLE_ROLES = [
    { id: 'r-admin', name: 'Admin', position: 5, permissions: '8', color: 0, managed: false },
    { id: 'r-mod', name: 'Mod', position: 3, permissions: '1024', color: 0, managed: false },
];
const SAMPLE_CHANNELS = [
    { id: 'c-cat', name: 'General', type: 4, position: 0, permission_overwrites: [] },
    { id: 'c-gen', name: 'general', type: 0, position: 1, parent_id: 'c-cat', topic: 'hi', permission_overwrites: [{ id: GUILD, type: 0, allow: '0', deny: '2048' }] },
];

// ── 1. A real capture persists + verifies ───────────────────────────────────

test('capture persists roles/channels/guild-settings, verifies, and reports SUCCESS', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { db, actions } = loadModules();
        const result = await actions.captureBackup({ guildId: GUILD, name: 'snap1', createdBy: 'user1' });

        assert.equal(result.status, 'SUCCESS', 'a fully-captured snapshot is SUCCESS');
        assert.equal(result.counts.roles, 2);
        assert.equal(result.counts.channels, 2);
        assert.equal(result.verification.ok, true, 'the stored row is verified');

        // The record really exists and is retrievable.
        const stored = await db.getAntiNukeBackup(GUILD, result.backup.id);
        assert.ok(stored, 'the backup row exists');
        assert.equal(stored.roles.length, 2, 'roles were stored');
        assert.equal(stored.channels.length, 2, 'channels were stored');
        assert.equal(stored.guildSettings.verificationLevel, 1, 'guild settings were stored');
        assert.equal(stored.status, 'SUCCESS');
        assert.equal(stored.verification.ok, true);

        // Per-resource success tracking.
        assert.equal(stored.resources.roles.ok, true);
        assert.equal(stored.resources.channels.ok, true);
        assert.equal(stored.resources.guildSettings.ok, true);

        // An operation-log row was written with the real outcome.
        const ops = await db.getAntiNukeBackupOperations(GUILD);
        assert.equal(ops.length, 1);
        assert.equal(ops[0].operation, 'create');
        assert.equal(ops[0].status, 'SUCCESS');
        assert.equal(ops[0].counts.roles, 2);
        assert.equal(ops[0].verification.ok, true);
    } finally { stubs.restore(); }
});

// ── 2. A failed fetch is never SUCCESS ──────────────────────────────────────

test('a roles fetch failure is reported as PARTIAL with the real reason — never SUCCESS', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS, readError: { roles: 'Discord API error: Missing Permissions (50013)' } });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { db, actions } = loadModules();
        const result = await actions.captureBackup({ guildId: GUILD, name: 'partial', createdBy: 'user1' });

        assert.equal(result.status, 'PARTIAL', 'one failed resource type over a successful one is PARTIAL');
        assert.ok(result.errors.some(e => /roles/.test(e) && /50013/.test(e)), 'the real reason is recorded');
        assert.equal(result.counts.roles, 0);
        assert.equal(result.counts.channels, 2);

        const stored = await db.getAntiNukeBackup(GUILD, result.backup.id);
        assert.equal(stored.status, 'PARTIAL');
        assert.equal(stored.resources.roles.ok, false);
        assert.match(stored.resources.roles.error, /50013/);
    } finally { stubs.restore(); }
});

test('when EVERY read fails the capture is FAILED', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ readError: { roles: 'boom', channels: 'boom', guild: 'boom' } });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { db, actions } = loadModules();
        const result = await actions.captureBackup({ guildId: GUILD, name: 'dead', createdBy: 'u' });
        assert.equal(result.status, 'FAILED');
        const stored = await db.getAntiNukeBackup(GUILD, result.backup.id);
        assert.equal(stored.status, 'FAILED');
        assert.ok(stored.errors.length > 0);
    } finally { stubs.restore(); }
});

// ── 3. An empty capture is FAILED ───────────────────────────────────────────

test('an empty guild capture (0 roles, 0 channels) is FAILED, never SUCCESS', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: [], channels: [] });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { db, actions } = loadModules();
        const result = await actions.captureBackup({ guildId: GUILD, name: 'empty', createdBy: 'u' });
        assert.equal(result.status, 'FAILED');
        assert.ok(result.errors.some(e => /no resources captured/.test(e)));
        const stored = await db.getAntiNukeBackup(GUILD, result.backup.id);
        assert.equal(stored.status, 'FAILED');
    } finally { stubs.restore(); }
});

// ── 4. A DB write failure is FAILED ─────────────────────────────────────────

test('a persistence failure marks the snapshot FAILED (never SUCCESS) and records the reason', async () => {
    const p = makeBackupPool({ failOn: 'UPDATE antinuke_backups SET roles = $3' });
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { db, actions } = loadModules();
        const result = await actions.captureBackup({ guildId: GUILD, name: 'dbdown', createdBy: 'u' });
        assert.equal(result.status, 'FAILED', 'a DB failure is never reported as SUCCESS');
        assert.ok(result.errors.some(e => /persist\/verify failed/.test(e)));
        const stored = await db.getAntiNukeBackup(GUILD, result.backup.id);
        assert.equal(stored.status, 'FAILED');
    } finally { stubs.restore(); }
});

// ── 5. Duplicate concurrent captures are refused ────────────────────────────

test('a second capture while one is in flight is refused with 409', async () => {
    const p = makeBackupPool();
    // Seed an IN_PROGRESS row for the guild.
    p.__backups.push({
        id: 99, guild_id: GUILD, name: 'running', created_by: 'u', created_at: new Date(),
        roles: [], channels: [], settings: null, guild_settings: null, counts: {},
        notes: '', status: 'IN_PROGRESS', operation: 'create', started_at: new Date(),
        completed_at: null, resources: {}, errors: [], verification: {},
    });
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        await assert.rejects(
            () => actions.captureBackup({ guildId: GUILD, name: 'dup', createdBy: 'u' }),
            (err) => err.status === 409 && err.reason === 'backup_in_progress',
        );
    } finally { stubs.restore(); }
});

// ── 6. Restore applies + verifies ───────────────────────────────────────────

test('restore recreates missing roles/channels, applies them and verifies — SUCCESS', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        assert.equal(captured.status, 'SUCCESS');

        // Simulate a nuke: the live guild loses a role and a channel.
        d.__setLive({
            roles: [SAMPLE_ROLES[0]],
            channels: [SAMPLE_CHANNELS[0]],
        });

        const preview = await actions.previewBackupRestore(GUILD, captured.backup.id);
        assert.ok(preview.plan.ops.some(o => o.kind === 'roleCreate'), 'the missing role is planned');
        assert.ok(preview.plan.ops.some(o => o.kind === 'channelCreate'), 'the missing channel is planned');
        assert.equal(preview.permissions.ok, true);

        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'admin' });
        assert.equal(report.status, 'SUCCESS', 'a fully applied + verified restore is SUCCESS');
        assert.equal(report.summary.rolesCreated, 1);
        assert.equal(report.summary.channelsCreated, 1);
        assert.equal(report.summary.verified, true, 'the read-back verified the restore');
        assert.ok(report.newIds.length >= 2, 'recreated resources carry NEW ids');

        // The writes really happened.
        assert.ok(d.__writes.some(w => w.op === 'createGuildRole' && w.body.name === 'Mod'));
        assert.ok(d.__writes.some(w => w.op === 'createGuildChannel' && w.body.name === 'general'));
    } finally { stubs.restore(); }
});

test('restore never deletes existing channels or roles', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        // Add an unrelated channel/role that is NOT in the snapshot.
        d.__setLive({
            roles: [...SAMPLE_ROLES, { id: 'r-extra', name: 'Extra', position: 1, permissions: '0' }],
            channels: [...SAMPLE_CHANNELS, { id: 'c-extra', name: 'unrelated', type: 0, position: 9, permission_overwrites: [] }],
        });
        await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'a' });
        assert.ok(!d.__writes.some(w => w.op === 'deleteGuildRole' || w.op === 'deleteGuildChannel'), 'no delete calls');
    } finally { stubs.restore(); }
});

// ── 7. Restore partial / failed ─────────────────────────────────────────────

test('a restore where one operation fails is PARTIAL and names the failure', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    // Fail the role creation only.
    const origCreateRole = d.createGuildRole;
    d.createGuildRole = async (guildId, body) => {
        if (body.name === 'Mod') throw new Error('Discord API error: Missing Permissions (50013)');
        return origCreateRole(guildId, body);
    };
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        d.__setLive({ roles: [SAMPLE_ROLES[0]], channels: [SAMPLE_CHANNELS[0]] });

        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'a' });
        assert.equal(report.status, 'PARTIAL', 'some applied, some failed → PARTIAL');
        assert.ok(report.failed.some(f => f.kind === 'roleCreate'), 'the failed op is named');
        assert.ok(report.errors.some(e => /50013/.test(e)), 'the real error is surfaced');
        // The applied subset is still verified (the channel was created and
        // confirmed), but the overall status stays PARTIAL because a resource
        // failed — verification never upgrades a partial restore to SUCCESS.
        assert.equal(report.summary.applied, 1);
        assert.equal(report.summary.failed, 1);
    } finally { stubs.restore(); }
});

test('a restore where every operation fails is FAILED', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    d.createGuildRole = async () => { throw new Error('Discord API error: Missing Permissions (50013)'); };
    d.createGuildChannel = async () => { throw new Error('Discord API error: Missing Permissions (50013)'); };
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        d.__setLive({ roles: [SAMPLE_ROLES[0]], channels: [SAMPLE_CHANNELS[0]] });
        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'a' });
        assert.equal(report.status, 'FAILED');
    } finally { stubs.restore(); }
});

// ── 8. Missing permissions refuse the restore ───────────────────────────────

test('a restore without Manage Roles/Channels is refused — not faked as success', async () => {
    const p = makeBackupPool();
    // Only View Channel + Manage Guild; no Manage Roles/Channels.
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS, permissions: (1n << 10n) | (1n << 5n) });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        d.__setLive({ roles: [SAMPLE_ROLES[0]], channels: [SAMPLE_CHANNELS[0]] });
        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'a' });
        assert.equal(report.status, 'FAILED');
        assert.ok(report.errors.some(e => /missing permissions/i.test(e)));
        assert.ok(report.errors.some(e => /Manage Roles/.test(e)));
        assert.equal(d.__writes.filter(w => w.op === 'createGuildRole').length, 0, 'no writes were attempted');
    } finally { stubs.restore(); }
});

test('dry-run restore applies nothing and reports PENDING', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        d.__setLive({ roles: [SAMPLE_ROLES[0]], channels: [SAMPLE_CHANNELS[0]] });
        const report = await actions.restoreBackup(GUILD, captured.backup.id, { dryRun: true });
        assert.equal(report.dryRun, true);
        assert.equal(d.__writes.length, 0, 'a dry run never writes');
    } finally { stubs.restore(); }
});

// ── 9. Invalid backup data ──────────────────────────────────────────────────

test('invalid stored backup data is refused by verification, not silently restored', async () => {
    const { verifySnapshot } = require('../utils/antiNukeBackup');
    const bad = { guildId: GUILD, roles: 'not-an-array', channels: [], counts: { roles: 5, channels: 0 } };
    const v = verifySnapshot(bad, { guildId: GUILD });
    assert.equal(v.ok, false);
    assert.ok(v.errors.some(e => /roles is not an array/.test(e)));
    assert.ok(v.errors.some(e => /counts\.roles/.test(e)));

    const wrongGuild = verifySnapshot({ guildId: OTHER_GUILD, roles: [], channels: [], counts: {} }, { guildId: GUILD });
    assert.equal(wrongGuild.ok, false);
    assert.ok(wrongGuild.errors.some(e => /guild mismatch/.test(e)));
});

test('restoring a corrupt snapshot fails cleanly instead of throwing', async () => {
    const p = makeBackupPool();
    p.__backups.push({
        id: 7, guild_id: GUILD, name: 'corrupt', created_by: 'u', created_at: new Date(),
        roles: 'CORRUPT', channels: [], settings: null, guild_settings: null,
        counts: { roles: 0, channels: 0 }, notes: '', status: 'SUCCESS', operation: 'create',
        started_at: new Date(), completed_at: new Date(), resources: {}, errors: [], verification: {},
    });
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const preview = await actions.previewBackupRestore(GUILD, 7);
        assert.ok(preview, 'the preview returns rather than throwing');
    } finally { stubs.restore(); }
});

// ── 10. Stale IN_PROGRESS reconciliation ────────────────────────────────────

test('an interrupted IN_PROGRESS snapshot is reconciled to FAILED with a reason', async () => {
    const p = makeBackupPool();
    const stale = new Date(Date.now() - 30 * 60000); // 30 min ago
    p.__backups.push({
        id: 5, guild_id: GUILD, name: 'interrupted', created_by: 'u', created_at: stale,
        roles: [], channels: [], settings: null, guild_settings: null, counts: {},
        notes: '', status: 'IN_PROGRESS', operation: 'create', started_at: stale,
        completed_at: null, resources: {}, errors: [], verification: {},
    });
    const stubs = installStubs({ pool: p, discord: makeDiscord() });
    try {
        const { db } = loadModules();
        const n = await db.reconcileStaleBackups(GUILD);
        assert.equal(n, 1);
        const stored = await db.getAntiNukeBackup(GUILD, 5);
        assert.equal(stored.status, 'FAILED');
        assert.ok(stored.errors.some(e => /interrupted/.test(e)));
    } finally { stubs.restore(); }
});

test('reconciliation leaves a genuinely fresh in-flight snapshot alone', async () => {
    const p = makeBackupPool();
    p.__backups.push({
        id: 6, guild_id: GUILD, name: 'live', created_by: 'u', created_at: new Date(),
        roles: [], channels: [], settings: null, guild_settings: null, counts: {},
        notes: '', status: 'IN_PROGRESS', operation: 'create', started_at: new Date(),
        completed_at: null, resources: {}, errors: [], verification: {},
    });
    const stubs = installStubs({ pool: p, discord: makeDiscord() });
    try {
        const { db } = loadModules();
        const n = await db.reconcileStaleBackups(GUILD);
        assert.equal(n, 0);
        const stored = await db.getAntiNukeBackup(GUILD, 6);
        assert.equal(stored.status, 'IN_PROGRESS');
    } finally { stubs.restore(); }
});

// ── 11. Cross-guild isolation ───────────────────────────────────────────────

test('a backup is never reachable from another guild', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { db, actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'mine', createdBy: 'u' });
        assert.equal(await db.getAntiNukeBackup(OTHER_GUILD, captured.backup.id), null);
        assert.equal(await actions.previewBackupRestore(OTHER_GUILD, captured.backup.id), null);
        assert.equal(await actions.restoreBackup(OTHER_GUILD, captured.backup.id), null);
    } finally { stubs.restore(); }
});

// ── 12. Hierarchy restrictions are reported, not silently dropped ───────────

test('a role above the bot\'s highest role is reported as skipped, not silently ignored', async () => {
    const { planRestore } = require('../utils/antiNukeBackup');
    const snapshot = {
        roles: [{ id: 'r-hi', name: 'Top', position: 100, permissions: '8' }],
        channels: [],
    };
    const plan = planRestore(snapshot, { roles: [], channels: [] }, { botHighestPosition: 10 });
    assert.equal(plan.ops.length, 0, 'the role is not created');
    assert.equal(plan.skipped.length, 1, 'but it is reported as skipped');
    assert.match(plan.skipped[0].reason, /above the bot/);
    assert.equal(plan.skipped[0].name, 'Top');
});

test('a protected role (trusted / @everyone) is reported as skipped', async () => {
    const { planRestore } = require('../utils/antiNukeBackup');
    const snapshot = {
        roles: [{ id: 'r-safe', name: 'Trusted', position: 1, permissions: '0' }],
        channels: [],
    };
    const plan = planRestore(snapshot, { roles: [], channels: [] }, { safeRoleIds: ['r-safe'], botHighestPosition: 100 });
    assert.equal(plan.ops.length, 0);
    assert.match(plan.skipped[0].reason, /protected/);
});

// ── 13. Stale-id remap: a nuked category's children must not 400 ─────────────
//
// Reproduces the production failure: after a nuke the categories/roles are gone,
// so the restore recreates them with NEW ids. A child channel still referenced
// the OLD parent_id (and an old role in its overwrites), so Discord rejected the
// create with `Invalid Form Body (400)`. 53 of 73 creates failed this way.

const NUKE_ROLES = [
    { id: 'r-admin', name: 'Admin', position: 5, permissions: '8', color: 0, managed: false },
];
const NUKE_CHANNELS = [
    { id: 'c-cat', name: 'General', type: 4, position: 0, permission_overwrites: [] },
    { id: 'c-gen', name: 'general', type: 0, position: 1, parent_id: 'c-cat', topic: 'hi',
      permission_overwrites: [{ id: 'r-admin', type: 0, allow: '0', deny: '2048' }] },
    { id: 'c-voice', name: 'Voice', type: 2, position: 2, parent_id: 'c-cat', permission_overwrites: [] },
];

test('restore remaps a recreated category id so child channels do not 400', async () => {
    const p = makeBackupPool();
    // strict: Discord rejects a stale parent_id / unknown overwrite role with 400.
    const d = makeDiscord({ roles: NUKE_ROLES, channels: NUKE_CHANNELS, strict: true });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        assert.equal(captured.status, 'SUCCESS');

        // Nuke: every channel AND the role are gone.
        d.__setLive({ roles: [], channels: [] });

        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'admin' });
        assert.equal(report.summary.failed, 0, 'no create was rejected with Invalid Form Body');
        assert.equal(report.summary.channelsCreated, 3, 'all three channels were created');
        assert.equal(report.summary.rolesCreated, 1, 'the role was recreated');
        assert.equal(report.status, 'SUCCESS', 'a fully applied + verified restore is SUCCESS');

        // The category was created first, then the children reference its NEW id.
        const creates = d.__writes.filter(w => w.op === 'createGuildChannel');
        const cat = creates.find(w => w.body.name === 'General');
        const gen = creates.find(w => w.body.name === 'general');
        assert.ok(cat && gen, 'category and child were both created');
        assert.match(String(gen.body.parent_id), /^new-chan-\d+$/, 'child parent_id is a NEW channel id');
        assert.notEqual(String(gen.body.parent_id), 'c-cat', 'the stale parent id is not sent');
        // The overwrite was remapped onto the recreated role (a new-role id).
        const owRole = (gen.body.permission_overwrites || []).find(o => o.deny === '2048');
        assert.ok(owRole, 'the overwrite survived');
        assert.match(String(owRole.id), /^new-role-\d+$/, 'the overwrite targets the recreated role');
        assert.notEqual(String(owRole.id), 'r-admin', 'the stale role id is not sent');
    } finally { stubs.restore(); }
});

test('an overwrite referencing a role that could not be restored is dropped, not sent to fail', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: NUKE_ROLES, channels: NUKE_CHANNELS, strict: true });
    // The role create fails, so 'r-admin' is never recreated and cannot be remapped.
    d.createGuildRole = async () => { throw new Error('Discord API error: Missing Permissions (50013)'); };
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        d.__setLive({ roles: [], channels: [] });
        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'a' });
        // The channels still get created (with the dangling overwrite dropped).
        assert.ok(report.summary.channelsCreated >= 2, 'channels are created despite the missing role');
        assert.ok(report.skipped.some(s => /unknown role/i.test(s.reason || '')), 'the dropped overwrite is reported');
        // The role failure still keeps the overall status honest.
        assert.equal(report.status, 'PARTIAL');
    } finally { stubs.restore(); }
});

// ── 14. Field-level Discord errors + remap unit behaviour ───────────────────

test('describeDiscordError surfaces the field path + code, not just "Invalid Form Body"', () => {
    const { describeDiscordError } = require('../dashboard/discord');
    const body = {
        message: 'Invalid Form Body', code: 50035,
        errors: { parent_id: { _errors: [{ code: 'CHANNEL_PARENT_INVALID', message: 'Channel not found' }] } },
    };
    const reason = describeDiscordError(body, 400);
    assert.match(reason, /parent_id/);
    assert.match(reason, /Channel not found/);
    assert.doesNotMatch(reason, /^Invalid Form Body$/);
    // A plain body still degrades sensibly.
    assert.equal(describeDiscordError(null, 500), 'HTTP 500');
    assert.equal(describeDiscordError({ message: 'boom' }, 400), 'boom');
});

test('remapRestoreOp drops a parent that was neither recreated nor live', () => {
    const { remapRestoreOp } = require('../utils/antiNukeBackup');
    const op = { kind: 'channelCreate', target: 'c1', payload: { name: 'x', type: 0, parentId: 'gone', permissionOverwrites: [] } };
    const { op: out, dropped } = remapRestoreOp(op, { idMap: {}, liveChannelIds: [], liveRoleIds: [] });
    assert.equal(out.payload.parentId, null, 'the stale parent is dropped');
    assert.match(dropped[0], /parent category gone/);
});

// ── 15. A restore must never mass-duplicate when the live read fails ─────────
//
// Regression: `readLiveStructure` returns [] on a failed read, which the diff
// could not tell apart from an empty guild — so a restore recreated EVERY
// role/channel and duplicated the whole server. A failed read must block the
// affected op kinds and refuse the restore.

test('a restore whose live roles/channels read fails is refused — it never mass-duplicates', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        assert.equal(captured.status, 'SUCCESS');

        // The live structure is UNCHANGED, but the reads now fail (a transient
        // Discord outage). A naive diff would treat the guild as empty.
        d.__setReadError({ roles: 'Discord API error: Missing Permissions (50013)', channels: 'Discord API error: Missing Permissions (50013)' });

        const preview = await actions.previewBackupRestore(GUILD, captured.backup.id);
        assert.equal(preview.plan.ops.length, 0, 'no ops are planned from an unreadable live structure');
        assert.ok(preview.blocked.length >= 2, 'both failed reads are reported');

        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'a' });
        assert.equal(report.status, 'FAILED');
        assert.equal(report.summary.applied, 0);
        assert.equal(d.__writes.filter(w => w.op === 'createGuildRole').length, 0, 'no roles were recreated');
        assert.equal(d.__writes.filter(w => w.op === 'createGuildChannel').length, 0, 'no channels were recreated');
        assert.ok(report.errors.some(e => /live server structure/i.test(e)), 'the real reason is recorded');
    } finally { stubs.restore(); }
});

test('a failed channel read blocks channel ops but a good role read still plans role ops', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        // A role is genuinely missing; the channel read alone fails.
        d.__setLive({ roles: [SAMPLE_ROLES[0]], channels: SAMPLE_CHANNELS });
        d.__setReadError({ channels: 'Discord API error: Missing Permissions (50013)' });

        const preview = await actions.previewBackupRestore(GUILD, captured.backup.id);
        assert.ok(preview.plan.ops.some(o => o.kind === 'roleCreate'), 'the genuinely-missing role is still planned');
        assert.ok(!preview.plan.ops.some(o => o.kind === 'channelCreate'), 'no channel op is planned from an unreadable read');
    } finally { stubs.restore(); }
});

test('unsafeRestoreOpKinds maps each failed read to the op kinds it invalidates', () => {
    const { unsafeRestoreOpKinds, filterUnsafePlan } = require('../utils/antiNukeBackup');
    const none = unsafeRestoreOpKinds({});
    assert.deepEqual(none.kinds, [], 'no failures → nothing blocked');
    assert.deepEqual(none.blocked, []);

    const roles = unsafeRestoreOpKinds({ roles: 'boom' });
    assert.ok(roles.kinds.includes('roleCreate') && roles.kinds.includes('roleUpdate'));
    assert.ok(roles.blocked[0].includes('roles'));

    const channels = unsafeRestoreOpKinds({ channels: 'boom' });
    assert.ok(channels.kinds.includes('channelCreate'));
    assert.ok(channels.kinds.includes('channelUpdate'));
    assert.ok(channels.kinds.includes('overwriteApply'));

    const plan = { ops: [{ kind: 'roleCreate' }, { kind: 'channelCreate' }, { kind: 'settingUpdate' }] };
    const filtered = filterUnsafePlan(plan, channels.kinds);
    assert.deepEqual(filtered.ops.map(o => o.kind), ['roleCreate', 'settingUpdate'], 'only the unsafe kinds are dropped');
});

// ── 16. recordLockdownIncident really writes the ledger ─────────────────────
//
// Regression: the function referenced an undefined `anukePool`, so every
// backup/lockdown incident write threw a ReferenceError inside its catch and
// silently recorded nothing.

test('recordLockdownIncident writes the incident ledger (no silent ReferenceError)', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        await actions.recordLockdownIncident({
            guildId: GUILD, action: 'backupCreated', startedBy: 'u1', severity: 'info', details: 'Backup #1',
        });
        assert.equal(p.__incidents.length, 1, 'the incident row is written');
        assert.match(p.__incidents[0].sql, /INSERT INTO antinuke_incidents/);
        assert.equal(p.__incidents[0].params[1], 'backupCreated');
    } finally { stubs.restore(); }
});

// ── 17. verifyRestore checks channel + guild settings ───────────────────────

test('verifyRestore flags a channel setting that was not applied', async () => {
    const p = makeBackupPool();
    const d = makeDiscord({ roles: SAMPLE_ROLES, channels: SAMPLE_CHANNELS });
    const stubs = installStubs({ pool: p, discord: d });
    try {
        const { actions } = loadModules();
        const captured = await actions.captureBackup({ guildId: GUILD, name: 'base', createdBy: 'u' });
        // The live channel differs on `topic`, so a channelUpdate is planned.
        d.__setLive({
            roles: SAMPLE_ROLES,
            channels: [{ ...SAMPLE_CHANNELS[0] }, { ...SAMPLE_CHANNELS[1], topic: 'changed' }],
        });
        // Make the update a no-op so the read-back still shows the wrong topic.
        d.patchChannel = async () => ({ ok: true });

        const report = await actions.restoreBackup(GUILD, captured.backup.id, { actorId: 'a' });
        assert.equal(report.verified, false, 'a setting that did not take effect is not verified');
        assert.ok(report.verification.mismatches.some(m => /setting topic/.test(m)), 'the unapplied setting is named');
        assert.notEqual(report.status, 'SUCCESS');
    } finally { stubs.restore(); }
});

