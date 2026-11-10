/**
 * Dashboard-side Anti-Nuke actions.
 *
 * The dashboard is a separate process from the bot, so it cannot call discord.js
 * guild methods. For the two operations the dashboard can trigger directly —
 * lockdown and its restoration — it performs the same steps over REST with the
 * bot token, mirroring utils/antiNukeContainment.js's safety rules:
 *
 *   • save what changes, so it can be reversed;
 *   • only touch channels that currently allow @everyone to create invites;
 *   • on restore, refuse to overwrite a change an administrator made after the
 *     lockdown started.
 *
 * The incident ledger records the action so the bot and dashboard agree on what
 * happened.
 */

const discord = require('./discord');
const { anukePool: pool } = require('../server/anukeDb');

// Discord permission bit for CreateInstantInvite.
const CREATE_INSTANT_INVITE = 1n;
const VERIFICATION_LEVELS = { none: 0, low: 1, medium: 2, high: 3, veryHigh: 4 };
const MAX_LOCKDOWN_CHANNELS = 50;

function inviteAllowedForEveryone(channel, guildId) {
    const ow = (channel.permission_overwrites || []).find(o => String(o.id) === String(guildId));
    if (!ow) return true; // inherited — @everyone can invite by default
    const allow = BigInt(ow.allow || 0);
    const deny = BigInt(ow.deny || 0);
    if ((deny & CREATE_INSTANT_INVITE) === CREATE_INSTANT_INVITE) return false;
    return true;
}

/** Engage lockdown over REST. Returns the saved lockdown record. */
async function engageLockdown({ guildId, settings, startedBy = null, reason = 'Manual lockdown' }) {
    const lockCfg = (settings && settings.lockdown) || {};
    const record = {
        active: true,
        startedAt: new Date().toISOString(),
        reason,
        startedBy,
        verificationLevelBefore: null,
        verificationLevelAfter: null,
        inviteChanges: [],
        pausedInvites: false,
        warnings: [],
    };

    // 1. Verification level.
    try {
        const guild = await discord.getGuildRaw(guildId);
        const before = guild && guild.verification_level != null ? Number(guild.verification_level) : null;
        const target = VERIFICATION_LEVELS[lockCfg.verificationLevel] != null
            ? VERIFICATION_LEVELS[lockCfg.verificationLevel]
            : VERIFICATION_LEVELS.high;
        record.verificationLevelBefore = before;
        if (before !== target) {
            await discord.patchGuild(guildId, { verification_level: target });
            record.verificationLevelAfter = target;
        } else {
            record.verificationLevelAfter = before;
        }
    } catch (err) {
        record.warnings.push(`verification_level: ${err.message}`);
    }

    // 2. Pause invites on the channels that currently allow them (bounded).
    if (lockCfg.pauseInvites !== false) {
        try {
            const channels = await discord.getGuildChannelsRaw(guildId);
            for (const ch of channels) {
                if (record.inviteChanges.length >= MAX_LOCKDOWN_CHANNELS) break;
                // Only guild text/voice/announcement channels carry overwrites.
                if (![0, 2, 5].includes(Number(ch.type))) continue;
                if (!inviteAllowedForEveryone(ch, guildId)) continue;
                const ow = (ch.permission_overwrites || []).find(o => String(o.id) === String(guildId));
                const before = ow ? { allow: String(ow.allow || 0), deny: String(ow.deny || 0) } : null;
                try {
                    const allow = before ? BigInt(before.allow) : 0n;
                    const deny = before ? BigInt(before.deny) : 0n;
                    await discord.putChannelOverwrite(ch.id, guildId, {
                        allow: String(allow & ~CREATE_INSTANT_INVITE),
                        deny: String(deny | CREATE_INSTANT_INVITE),
                        type: 0,
                    });
                    record.inviteChanges.push({ channelId: ch.id, before });
                } catch (err) {
                    record.warnings.push(`invite_pause:${ch.id}: ${err.message}`);
                }
            }
            record.pausedInvites = record.inviteChanges.length > 0;
        } catch (err) {
            record.warnings.push(`invite_scan: ${err.message}`);
        }
    }

    await saveLockdown(guildId, record, startedBy, reason);
    return record;
}

/** Restore a lockdown over REST, skipping anything an admin changed since. */
async function restoreLockdown({ guildId, record, reason = 'Lockdown lifted' }) {
    const warnings = [];
    const restored = { verificationLevel: false, invites: 0, skippedInvites: [] };
    if (!record) return { restored, warnings: ['no_record'] };

    // Verification level: only revert if it is still what lockdown set.
    try {
        if (record.verificationLevelAfter != null && record.verificationLevelBefore != null) {
            const guild = await discord.getGuildRaw(guildId);
            const current = guild && guild.verification_level != null ? Number(guild.verification_level) : null;
            if (current === record.verificationLevelAfter) {
                await discord.patchGuild(guildId, { verification_level: record.verificationLevelBefore });
                restored.verificationLevel = true;
            } else {
                warnings.push('verification_level_changed_by_admin');
            }
        }
    } catch (err) {
        warnings.push(`verification_level: ${err.message}`);
    }

    // Invite overwrites: only revert the ones we changed and that still match.
    const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
    const byId = new Map((channels || []).map(c => [String(c.id), c]));
    for (const change of record.inviteChanges || []) {
        try {
            const ch = byId.get(String(change.channelId));
            if (!ch) { warnings.push(`invite_restore_missing_channel:${change.channelId}`); continue; }
            const ow = (ch.permission_overwrites || []).find(o => String(o.id) === String(guildId));
            const deny = ow ? BigInt(ow.deny || 0) : 0n;
            const stillDenied = (deny & CREATE_INSTANT_INVITE) === CREATE_INSTANT_INVITE;
            if (!stillDenied) { restored.skippedInvites.push(change.channelId); continue; }
            if (change.before) {
                await discord.putChannelOverwrite(ch.id, guildId, {
                    allow: String(change.before.allow || 0),
                    deny: String(change.before.deny || 0),
                    type: 0,
                });
            } else {
                await discord.deleteChannelOverwrite(ch.id, guildId);
            }
            restored.invites++;
        } catch (err) {
            warnings.push(`invite_restore:${change.channelId}: ${err.message}`);
        }
    }

    await clearLockdown(guildId);
    return { restored, warnings };
}

async function saveLockdown(guildId, record, startedBy, reason) {
    try {
        await pool.query(`
            INSERT INTO antinuke_lockdowns (guild_id, active, started_at, started_by, reason, state, updated_at)
            VALUES ($1, true, NOW(), $2, $3, $4, NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                active = true, started_at = NOW(), started_by = EXCLUDED.started_by,
                reason = EXCLUDED.reason, state = EXCLUDED.state, updated_at = NOW()
        `, [String(guildId), startedBy ? String(startedBy) : null, String(reason || '').slice(0, 500), JSON.stringify(record || {})]);
    } catch (err) {
        console.error('[ANTINUKE] dashboard lockdown persist failed:', err.message);
    }
}

async function clearLockdown(guildId) {
    try {
        await pool.query('UPDATE antinuke_lockdowns SET active = false, updated_at = NOW() WHERE guild_id = $1', [String(guildId)]);
    } catch (err) {
        console.error('[ANTINUKE] dashboard lockdown clear failed:', err.message);
    }
}

/** Record a dashboard-triggered lockdown action in the incident ledger. */
async function recordLockdownIncident({ guildId, action, startedBy, severity, details = '', responseOk = true }) {
    try {
        await anukePool.query(`
            INSERT INTO antinuke_incidents
                (guild_id, action, module, severity, response_taken, response_ok, dry_run, attribution, details)
            VALUES ($1,$2,'server',$3,$4,$5,false,'manual',$6)
        `, [String(guildId), String(action).slice(0, 60), String(severity).slice(0, 20),
            JSON.stringify(['lockdown']), responseOk === true, String(details).slice(0, 1000)]);
    } catch (err) {
        console.error('[ANTINUKE] lockdown incident record failed:', err.message);
    }
}

// ── Setup-runner shims ──────────────────────────────────────────────────────
//
// The automatic setup runner (utils/antiNukeSetupRunner.js) is written against
// discord.js guild/manager objects, because the bot drives it from the gateway.
// The dashboard has no gateway client, so it drives the same runner through a
// small REST-backed shim: the runner's logic (and therefore the progress it
// reports) is identical on both sides — only the transport differs.

/** A Map-like channel cache with the methods the runner uses. */
function makeChannelCache(list) {
    const map = new Map((list || []).map(c => [String(c.id), c]));
    return {
        size: map.size,
        get: (id) => map.get(String(id)) || null,
        has: (id) => map.has(String(id)),
        values: () => map.values(),
        find: (fn) => { for (const v of map.values()) { if (fn(v)) return v; } return undefined; },
    };
}

function makeRoleCache(list) {
    const map = new Map((list || []).map(r => [String(r.id), r]));
    return {
        size: map.size,
        get: (id) => map.get(String(id)) || null,
        has: (id) => map.has(String(id)),
        values: () => map.values(),
    };
}

/**
 * Build a discord.js-guild-like object from REST for the setup runner. The bot's
 * permission report is derived from its role bitfield so `validateBotPermissions`
 * works unchanged.
 */
async function buildDashboardGuildShim(guildId) {
    const [raw, channels, roles, botPerms] = await Promise.all([
        discord.getBotGuild(guildId).catch(() => null),
        discord.getGuildChannelsRaw(guildId).catch(() => []),
        discord.getGuildRoles(guildId).catch(() => []),
        discord.computeBotPermissions(guildId, process.env.DISCORD_CLIENT_ID).catch(() => null),
    ]);
    const textChannels = (channels || []).map(c => ({
        id: String(c.id), name: c.name, type: c.type,
        permissionsFor: () => null,
    }));
    const channelCache = makeChannelCache(textChannels);
    const roleCache = makeRoleCache(roles);
    const bits = botPerms == null ? 0n : BigInt(botPerms);
    // The bot's highest role position, so the setup runner can gate on it and
    // place an auto-created isolation role just below it.
    let botHighestPosition = null;
    try {
        const member = await discord.getBotMember(guildId).catch(() => null);
        const botRoleIds = Array.isArray(member && member.roles) ? member.roles : [];
        const byId = new Map((roles || []).map(r => [String(r.id), r]));
        for (const id of botRoleIds) {
            const r = byId.get(String(id));
            if (r && (botHighestPosition == null || Number(r.position) > botHighestPosition)) {
                botHighestPosition = Number(r.position);
            }
        }
    } catch (_) { /* leave indeterminate */ }
    return {
        id: String(guildId),
        name: (raw && raw.name) || 'this server',
        ownerId: raw && raw.owner_id ? String(raw.owner_id) : null,
        memberCount: raw && raw.approximate_member_count != null ? raw.approximate_member_count : null,
        channels: {
            cache: channelCache,
            fetch: async (id) => channelCache.get(id) || null,
            create: async (opts = {}) => discord.createGuildChannel(guildId, {
                name: String(opts.name || 'primebot-antinuke-log'),
                type: opts.type != null ? opts.type : 0,
            }),
        },
        createChannel: async (opts = {}) => discord.createGuildChannel(guildId, {
            name: String(opts.name || 'primebot-antinuke-log'),
            type: opts.type != null ? opts.type : 0,
        }),
        roles: {
            cache: roleCache,
            create: async (opts = {}) => discord.createGuildRole(guildId, {
                name: String(opts.name || 'isolated'),
                permissions: opts.permissions != null ? opts.permissions : '0',
                hoist: opts.hoist === true,
                mentionable: opts.mentionable === true,
            }),
        },
        createRole: async (opts = {}) => discord.createGuildRole(guildId, {
            name: String(opts.name || 'isolated'),
            permissions: opts.permissions != null ? opts.permissions : '0',
            hoist: opts.hoist === true,
            mentionable: opts.mentionable === true,
        }),
        setRolePosition: async (roleId, position) => {
            // Discord requires the full role list to reorder; only the target
            // role's position is moved to keep the call minimal.
            return discord.modifyGuildRole(guildId, roleId, { position });
        },
        members: {
            me: {
                roles: { highest: { position: botHighestPosition == null ? 0 : botHighestPosition } },
                permissions: {
                    has: (flag) => {
                        try { return (bits & BigInt(flag)) === BigInt(flag); } catch (_) { return false; }
                    },
                },
            },
        },
    };
}

/** A manager-like object that persists through dashboard/db.js. */
function buildDashboardManagerShim(guildId) {
    const db = require('./db');
    return {
        getSettings: (id) => db.getAntiNukeSettings(id || guildId),
        async updateSettingsAsync(id, patch) {
            return db.upsertAntiNukeSettings(id || guildId, patch);
        },
        async _refreshFromDatabase() { return true; },
    };
}

// ── Backups (capture / compare / restore) ───────────────────────────────────
//
// A snapshot is captured from live REST reads and stored in `antinuke_backups`.
// Restore is a real operation: missing roles/channels are re-created and role
// permission bits re-applied through the Discord REST API. Discord assigns NEW
// ids to recreated roles/channels, so the report labels every recreated
// resource with its new id and never claims in-place restoration.

const {
    buildSnapshot, compareSnapshot, planRestore, serializeRole, serializeChannel,
} = require('../utils/antiNukeBackup');
const { DANGEROUS_PERMISSION_BY_KEY } = require('../utils/antiNukeRules');

const MAX_BACKUP_CHANNELS = 400;

/** Capture a snapshot of the live guild structure via REST and persist it. */
async function captureBackup({ guildId, name, createdBy, settings = null, notes = '' }) {
    const db = require('./db');
    const [roles, rawChannels] = await Promise.all([
        discord.getGuildRoles(guildId, { excludeUnassignable: false }).catch(() => []),
        discord.getGuildChannelsRaw(guildId).catch(() => []),
    ]);
    const channels = (rawChannels || []).slice(0, MAX_BACKUP_CHANNELS).map(c => ({
        id: c.id, name: c.name, type: c.type, parentId: c.parent_id || null,
        rawPosition: c.position, permissionOverwrites: (c.permission_overwrites || []).map(ow => ({
            id: ow.id, type: ow.type, allow: String(ow.allow || 0), deny: String(ow.deny || 0),
        })),
    }));
    const snapshot = buildSnapshot({ guildId, name, createdBy, reader: { roles, channels, settings } });
    const saved = await db.createAntiNukeBackup({
        guildId, name, createdBy,
        roles: snapshot.roles, channels: snapshot.channels, settings, notes,
    });
    return { backup: saved, counts: snapshot.counts };
}

/** Compare a stored snapshot against the live guild. */
async function compareBackup(guildId, id) {
    const db = require('./db');
    const snapshot = await db.getAntiNukeBackup(guildId, id);
    if (!snapshot) return null;
    const [roles, rawChannels] = await Promise.all([
        discord.getGuildRoles(guildId, { excludeUnassignable: false }).catch(() => []),
        discord.getGuildChannelsRaw(guildId).catch(() => []),
    ]);
    const live = {
        roles: (roles || []).map(serializeRole).filter(Boolean),
        channels: (rawChannels || []).map(c => serializeChannel({
            id: c.id, name: c.name, type: c.type, parentId: c.parent_id || null,
            rawPosition: c.position, permissionOverwrites: c.permission_overwrites || [],
        })).filter(Boolean),
    };
    return { diff: compareSnapshot({ roles: snapshot.roles, channels: snapshot.channels }, live), counts: snapshot.counts };
}

/** Preview the restore operations for a snapshot (no writes). */
async function previewBackupRestore(guildId, id) {
    const db = require('./db');
    const snapshot = await db.getAntiNukeBackup(guildId, id);
    if (!snapshot) return null;
    const [roles, rawChannels] = await Promise.all([
        discord.getGuildRoles(guildId, { excludeUnassignable: false }).catch(() => []),
        discord.getGuildChannelsRaw(guildId).catch(() => []),
    ]);
    const live = {
        roles: (roles || []).map(serializeRole).filter(Boolean),
        channels: (rawChannels || []).map(c => serializeChannel({
            id: c.id, name: c.name, type: c.type, parentId: c.parent_id || null,
            rawPosition: c.position, permissionOverwrites: c.permission_overwrites || [],
        })).filter(Boolean),
    };
    const settings = await db.getAntiNukeSettings(guildId);
    const trustedRoles = (settings && settings.trustedRoleIds) || [];
    const safeRoleIds = [guildId, ...trustedRoles];
    const botHighest = await botHighestRolePosition(guildId);
    const plan = planRestore({ roles: snapshot.roles, channels: snapshot.channels }, live, {
        safeRoleIds, botHighestPosition: botHighest == null ? Infinity : botHighest,
    });
    return { plan, counts: snapshot.counts };
}

/** Execute a restore. Returns a report of what really happened. */
async function restoreBackup(guildId, id, { actorId = null } = {}) {
    const preview = await previewBackupRestore(guildId, id);
    if (!preview) return null;
    const report = { created: { roles: [], channels: [] }, updated: { roles: [] }, failed: [], newIds: [] };
    for (const op of preview.plan.ops) {
        try {
            if (op.kind === 'roleCreate') {
                const role = await discord.createGuildRole(guildId, {
                    name: op.payload.name,
                    permissions: op.payload.permissions,
                    color: op.payload.color,
                    hoist: op.payload.hoist,
                    mentionable: op.payload.mentionable,
                });
                report.created.roles.push({ oldId: op.target, newId: role && role.id, name: op.payload.name });
                if (role && role.id) report.newIds.push({ kind: 'role', oldId: op.target, newId: role.id, name: op.payload.name });
            } else if (op.kind === 'roleUpdate') {
                await discord.modifyGuildRole(guildId, op.target, { permissions: op.payload.permissions });
                report.updated.roles.push({ id: op.target });
            } else if (op.kind === 'channelCreate') {
                const ch = await discord.createGuildChannel(guildId, {
                    name: op.payload.name, type: op.payload.type,
                    parent_id: op.payload.parentId || undefined,
                    permission_overwrites: (op.payload.permissionOverwrites || []).map(ow => ({
                        id: ow.id, type: ow.type, allow: ow.allow, deny: ow.deny,
                    })),
                });
                report.created.channels.push({ oldId: op.target, newId: ch && ch.id, name: op.payload.name });
                if (ch && ch.id) report.newIds.push({ kind: 'channel', oldId: op.target, newId: ch.id, name: op.payload.name });
            }
        } catch (err) {
            report.failed.push({ kind: op.kind, target: op.target, error: err.message });
        }
    }
    report.summary = {
        rolesCreated: report.created.roles.length,
        rolesUpdated: report.updated.roles.length,
        channelsCreated: report.created.channels.length,
        failed: report.failed.length,
    };
    report.note = 'Recreated roles and channels receive NEW ids — Discord never reuses ids, and deleted messages cannot be restored.';
    return report;
}

async function botHighestRolePosition(guildId) {
    try {
        const [member, roles] = await Promise.all([
            discord.getBotMember(guildId, process.env.DISCORD_CLIENT_ID).catch(() => null),
            discord.getGuildRoles(guildId).catch(() => []),
        ]);
        const botRoleIds = Array.isArray(member && member.roles) ? member.roles : [];
        const byId = new Map((roles || []).map(r => [String(r.id), r]));
        let highest = null;
        for (const id of botRoleIds) {
            const r = byId.get(String(id));
            if (r && (highest == null || Number(r.position) > highest)) highest = Number(r.position);
        }
        return highest;
    } catch (_) { return null; }
}

// ── Lockdown profiles ───────────────────────────────────────────────────────
//
// Five profiles, each a real set of REST operations. Every change is saved to
// the lockdown record so recovery restores ONLY what that lockdown changed and
// never overwrites an administrator's later edits.

const SEND_MESSAGES = 1n << 11n;
const VIEW_CHANNEL = 1n << 10n;
const TEXT_LIKE = new Set([0, 5]);      // text + announcement
const VIEWABLE_TYPES = new Set([0, 2, 5]); // text, voice, announcement

const LOCKDOWN_PROFILE_LABELS = {
    join: 'Join Lockdown',
    message: 'Message Lockdown',
    channel: 'Channel Lockdown',
    permission: 'Permission Lockdown',
    full: 'Full Emergency Lockdown',
};

function everyoneOverwrite(channel, guildId) {
    return (channel.permission_overwrites || []).find(o => String(o.id) === String(guildId));
}

/**
 * Build the exact operations a profile would perform, from live reads. Used for
 * the "Preview" button so the admin sees precisely what will change.
 */
async function planLockdownProfile(guildId, profileKey) {
    const ops = [];
    const key = String(profileKey || 'full');
    const wantsJoin = key === 'join' || key === 'full';
    const wantsMessage = key === 'message' || key === 'full';
    const wantsChannel = key === 'channel' || key === 'full';
    const wantsPermission = key === 'permission' || key === 'full';

    if (wantsJoin) {
        const guild = await discord.getGuildRaw(guildId).catch(() => null);
        ops.push({ kind: 'verification_level', from: guild ? guild.verification_level : null, to: 'high' });
        const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
        for (const ch of channels) {
            if (!VIEWABLE_TYPES.has(Number(ch.type))) continue;
            if (!inviteAllowedForEveryone(ch, guildId)) continue;
            ops.push({ kind: 'pause_invites', channelId: ch.id, name: ch.name });
        }
    }
    if (wantsMessage) {
        const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
        for (const ch of channels) {
            if (!TEXT_LIKE.has(Number(ch.type))) continue;
            const ow = everyoneOverwrite(ch, guildId);
            const deny = ow ? BigInt(ow.deny || 0) : 0n;
            if ((deny & SEND_MESSAGES) === SEND_MESSAGES) continue;
            ops.push({ kind: 'deny_send_messages', channelId: ch.id, name: ch.name });
        }
    }
    if (wantsChannel) {
        const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
        for (const ch of channels) {
            if (!VIEWABLE_TYPES.has(Number(ch.type))) continue;
            const ow = everyoneOverwrite(ch, guildId);
            const deny = ow ? BigInt(ow.deny || 0) : 0n;
            if ((deny & VIEW_CHANNEL) === VIEW_CHANNEL) continue;
            ops.push({ kind: 'hide_channel', channelId: ch.id, name: ch.name });
        }
    }
    if (wantsPermission) {
        const [roles, botHighest] = await Promise.all([
            discord.getGuildRoles(guildId).catch(() => []),
            botHighestRolePosition(guildId),
        ]);
        for (const r of roles) {
            if (!r || r.managed) continue;
            if (botHighest != null && Number(r.position) >= Number(botHighest)) continue;
            const bits = BigInt(r.permissions || 0);
            const hits = Object.keys(DANGEROUS_PERMISSION_BY_KEY).filter(k => {
                const meta = DANGEROUS_PERMISSION_BY_KEY[k];
                try { return (bits & BigInt(meta.flag)) === BigInt(meta.flag); } catch (_) { return false; }
            });
            if (hits.length) ops.push({ kind: 'strip_dangerous', roleId: r.id, name: r.name, permissions: hits });
        }
    }
    return { profile: key, label: LOCKDOWN_PROFILE_LABELS[key] || key, ops };
}

/** Engage a lockdown profile. Saves the exact changes for recovery. */
async function engageLockdownProfile({ guildId, profile, settings, startedBy = null, reason = null }) {
    const plan = await planLockdownProfile(guildId, profile);
    const record = {
        active: true,
        profile: plan.profile,
        startedAt: new Date().toISOString(),
        startedBy,
        reason: reason || `${plan.label} engaged`,
        changes: { verification: null, invites: [], messages: [], channels: [], permissions: [] },
        warnings: [],
    };

    const wantsJoin = plan.profile === 'join' || plan.profile === 'full';
    const wantsMessage = plan.profile === 'message' || plan.profile === 'full';
    const wantsChannel = plan.profile === 'channel' || plan.profile === 'full';
    const wantsPermission = plan.profile === 'permission' || plan.profile === 'full';

    if (wantsJoin) {
        try {
            const guild = await discord.getGuildRaw(guildId);
            const before = guild && guild.verification_level != null ? Number(guild.verification_level) : null;
            const target = VERIFICATION_LEVELS.high;
            if (before !== target) {
                await discord.patchGuild(guildId, { verification_level: target });
                record.changes.verification = { before, after: target };
            }
        } catch (err) { record.warnings.push(`verification_level: ${err.message}`); }

        const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
        for (const ch of channels) {
            if (record.changes.invites.length >= MAX_LOCKDOWN_CHANNELS) break;
            if (!VIEWABLE_TYPES.has(Number(ch.type))) continue;
            if (!inviteAllowedForEveryone(ch, guildId)) continue;
            const ow = everyoneOverwrite(ch, guildId);
            const before = ow ? { allow: String(ow.allow || 0), deny: String(ow.deny || 0) } : null;
            try {
                const allow = before ? BigInt(before.allow) : 0n;
                const deny = before ? BigInt(before.deny) : 0n;
                await discord.putChannelOverwrite(ch.id, guildId, {
                    allow: String(allow & ~CREATE_INSTANT_INVITE),
                    deny: String(deny | CREATE_INSTANT_INVITE), type: 0,
                });
                record.changes.invites.push({ channelId: ch.id, before });
            } catch (err) { record.warnings.push(`invite_pause:${ch.id}: ${err.message}`); }
        }
    }

    if (wantsMessage) {
        const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
        for (const ch of channels) {
            if (record.changes.messages.length >= MAX_LOCKDOWN_CHANNELS) break;
            if (!TEXT_LIKE.has(Number(ch.type))) continue;
            const ow = everyoneOverwrite(ch, guildId);
            const before = ow ? { allow: String(ow.allow || 0), deny: String(ow.deny || 0) } : null;
            const deny = before ? BigInt(before.deny) : 0n;
            if ((deny & SEND_MESSAGES) === SEND_MESSAGES) continue;
            try {
                const allow = before ? BigInt(before.allow) : 0n;
                await discord.putChannelOverwrite(ch.id, guildId, {
                    allow: String(allow & ~SEND_MESSAGES),
                    deny: String(deny | SEND_MESSAGES), type: 0,
                });
                record.changes.messages.push({ channelId: ch.id, before });
            } catch (err) { record.warnings.push(`deny_send:${ch.id}: ${err.message}`); }
        }
    }

    if (wantsChannel) {
        const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
        for (const ch of channels) {
            if (record.changes.channels.length >= MAX_LOCKDOWN_CHANNELS) break;
            if (!VIEWABLE_TYPES.has(Number(ch.type))) continue;
            const ow = everyoneOverwrite(ch, guildId);
            const before = ow ? { allow: String(ow.allow || 0), deny: String(ow.deny || 0) } : null;
            const deny = before ? BigInt(before.deny) : 0n;
            if ((deny & VIEW_CHANNEL) === VIEW_CHANNEL) continue;
            try {
                const allow = before ? BigInt(before.allow) : 0n;
                await discord.putChannelOverwrite(ch.id, guildId, {
                    allow: String(allow & ~VIEW_CHANNEL),
                    deny: String(deny | VIEW_CHANNEL), type: 0,
                });
                record.changes.channels.push({ channelId: ch.id, before });
            } catch (err) { record.warnings.push(`hide_channel:${ch.id}: ${err.message}`); }
        }
    }

    if (wantsPermission) {
        const [roles, botHighest] = await Promise.all([
            discord.getGuildRoles(guildId).catch(() => []),
            botHighestRolePosition(guildId),
        ]);
        for (const r of roles) {
            if (!r || r.managed) continue;
            if (botHighest != null && Number(r.position) >= Number(botHighest)) continue;
            const bits = BigInt(r.permissions || 0);
            let next = bits;
            const hits = [];
            for (const key of Object.keys(DANGEROUS_PERMISSION_BY_KEY)) {
                const meta = DANGEROUS_PERMISSION_BY_KEY[key];
                try {
                    if ((bits & BigInt(meta.flag)) === BigInt(meta.flag)) { next &= ~BigInt(meta.flag); hits.push(key); }
                } catch (_) { /* skip */ }
            }
            if (!hits.length) continue;
            try {
                await discord.modifyGuildRole(guildId, r.id, { permissions: String(next) });
                record.changes.permissions.push({ roleId: r.id, before: String(bits), after: String(next), hits });
            } catch (err) { record.warnings.push(`strip_dangerous:${r.id}: ${err.message}`); }
        }
    }

    await saveLockdown(guildId, record, startedBy, record.reason);
    return record;
}

/** Restore only what the active lockdown changed; skip admin edits after it. */
async function restoreLockdownProfile({ guildId, record }) {
    const warnings = [];
    const restored = { verification: false, invites: 0, messages: 0, channels: 0, permissions: 0, skipped: [] };
    if (!record || !record.changes) return { restored, warnings: ['no_record'] };

    // Verification level — only revert if unchanged since lockdown.
    const v = record.changes.verification;
    if (v && v.after != null && v.before != null) {
        try {
            const guild = await discord.getGuildRaw(guildId);
            const current = guild && guild.verification_level != null ? Number(guild.verification_level) : null;
            if (current === v.after) {
                await discord.patchGuild(guildId, { verification_level: v.before });
                restored.verification = true;
            } else { warnings.push('verification_level_changed_by_admin'); }
        } catch (err) { warnings.push(`verification_level: ${err.message}`); }
    }

    const channels = await discord.getGuildChannelsRaw(guildId).catch(() => []);
    const byId = new Map((channels || []).map(c => [String(c.id), c]));

    const revertOverwrites = async (list, flag, counter) => {
        for (const change of list || []) {
            const ch = byId.get(String(change.channelId));
            if (!ch) { warnings.push(`restore_missing_channel:${change.channelId}`); continue; }
            const ow = everyoneOverwrite(ch, guildId);
            const deny = ow ? BigInt(ow.deny || 0) : 0n;
            if ((deny & flag) !== flag) { restored.skipped.push(change.channelId); continue; }
            try {
                if (change.before) {
                    await discord.putChannelOverwrite(ch.id, guildId, {
                        allow: String(change.before.allow || 0), deny: String(change.before.deny || 0), type: 0,
                    });
                } else {
                    await discord.deleteChannelOverwrite(ch.id, guildId);
                }
                restored[counter]++;
            } catch (err) { warnings.push(`restore:${change.channelId}: ${err.message}`); }
        }
    };
    await revertOverwrites(record.changes.invites, CREATE_INSTANT_INVITE, 'invites');
    await revertOverwrites(record.changes.messages, SEND_MESSAGES, 'messages');
    await revertOverwrites(record.changes.channels, VIEW_CHANNEL, 'channels');

    for (const change of record.changes.permissions || []) {
        try {
            const roles = await discord.getGuildRoles(guildId).catch(() => []);
            const role = (roles || []).find(r => String(r.id) === String(change.roleId));
            if (!role) { warnings.push(`restore_missing_role:${change.roleId}`); continue; }
            if (String(role.permissions || 0) !== String(change.after)) { restored.skipped.push(change.roleId); continue; }
            await discord.modifyGuildRole(guildId, change.roleId, { permissions: change.before });
            restored.permissions++;
        } catch (err) { warnings.push(`restore_role:${change.roleId}: ${err.message}`); }
    }

    await clearLockdown(guildId);
    return { restored, warnings };
}

module.exports = {
    engageLockdown,
    restoreLockdown,
    saveLockdown,
    clearLockdown,
    recordLockdownIncident,
    inviteAllowedForEveryone,
    buildDashboardGuildShim,
    buildDashboardManagerShim,
    CREATE_INSTANT_INVITE,
    VERIFICATION_LEVELS,
    // Backups
    captureBackup,
    compareBackup,
    previewBackupRestore,
    restoreBackup,
    botHighestRolePosition,
    // Lockdown profiles
    LOCKDOWN_PROFILE_LABELS,
    planLockdownProfile,
    engageLockdownProfile,
    restoreLockdownProfile,
};
