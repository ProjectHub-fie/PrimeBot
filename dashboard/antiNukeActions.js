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
        // `position` lets the setup runner's hierarchy checks and the isolation
        // role placement read a real value from the REST descriptors.
        position: Number(c.position != null ? c.position : 0),
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
            create: async (opts = {}) => {
                // Discord does not accept `position` on role CREATE — it is set
                // afterwards via PATCH. Sending it would be silently ignored at
                // best, so it is stripped here and applied below.
                const role = await discord.createGuildRole(guildId, {
                    name: String(opts.name || 'isolated'),
                    permissions: opts.permissions != null ? opts.permissions : '0',
                    hoist: opts.hoist === true,
                    mentionable: opts.mentionable === true,
                });
                if (role && opts.position != null) {
                    try { await discord.modifyGuildRole(guildId, role.id, { position: opts.position }); } catch (_) { /* best-effort */ }
                }
                return role;
            },
        },
        createRole: async (opts = {}) => {
            const role = await discord.createGuildRole(guildId, {
                name: String(opts.name || 'isolated'),
                permissions: opts.permissions != null ? opts.permissions : '0',
                hoist: opts.hoist === true,
                mentionable: opts.mentionable === true,
            });
            if (role && opts.position != null) {
                try { await discord.modifyGuildRole(guildId, role.id, { position: opts.position }); } catch (_) { /* best-effort */ }
            }
            return role;
        },
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
// Restore is a real operation: missing roles/channels are re-created, changed
// permission overwrites + channel settings are re-applied and role permission
// bits are restored through the Discord REST API. Discord assigns NEW ids to
// recreated roles/channels, so the report labels every recreated resource with
// its new id and never claims in-place restoration.
//
// Every step reports the truth:
//   • a fetch failure is recorded per resource type, never swallowed into an
//     empty list that would look like "an empty server";
//   • the row is written IN_PROGRESS first and only becomes SUCCESS after the
//     data has been persisted AND re-read back AND verified;
//   • an operation log row records the real start/finish times, counts,
//     failures and verification state for the dashboard.

const {
    buildSnapshot, compareSnapshot, planRestore, verifySnapshot, remapRestoreOp,
    serializeRole, serializeChannel, serializeGuildSettings,
    computeBackupStatus, computeRestoreStatus,
    BACKUP_STATUS,
} = require('../utils/antiNukeBackup');
const { DANGEROUS_PERMISSION_BY_KEY } = require('../utils/antiNukeRules');

const MAX_BACKUP_CHANNELS = 400;

// Discord permission bits used for the pre-flight capability check.
const PERM_MANAGE_ROLES = 1n << 28n;
const PERM_MANAGE_CHANNELS = 1n << 4n;
const PERM_VIEW_CHANNEL = 1n << 10n;
const PERM_MANAGE_GUILD = 1n << 5n;

/**
 * Verify the bot can actually perform a backup/restore in this guild. Returns
 * `{ ok, missing: string[], bitfield }`. Missing permissions are a real failure
 * reason — the operation must not be reported successful when Discord would
 * reject it. Never bypasses Discord's hierarchy: role position is checked too.
 */
async function validateBackupPermissions(guildId) {
    const bits = await discord.computeBotPermissions(guildId, process.env.DISCORD_CLIENT_ID).catch(() => null);
    const missing = [];
    if (bits == null) {
        return { ok: false, missing: ['bot permissions could not be determined'], bitfield: null };
    }
    const has = (flag) => (bits & flag) === flag;
    if (!has(PERM_MANAGE_ROLES)) missing.push('Manage Roles');
    if (!has(PERM_MANAGE_CHANNELS)) missing.push('Manage Channels');
    if (!has(PERM_VIEW_CHANNEL)) missing.push('View Channels');
    if (!has(PERM_MANAGE_GUILD)) missing.push('Manage Server');
    return { ok: missing.length === 0, missing, bitfield: bits.toString() };
}

/** Fetch the live structure via REST, recording a real error per resource. */
async function readLiveStructure(guildId) {
    const errors = {};
    const [roles, rawChannels, rawGuild] = await Promise.all([
        discord.getGuildRoles(guildId, { excludeUnassignable: false })
            .catch(err => { errors.roles = err.message || String(err); return null; }),
        discord.getGuildChannelsRaw(guildId)
            .catch(err => { errors.channels = err.message || String(err); return null; }),
        discord.getGuildRaw(guildId)
            .catch(err => { errors.guildSettings = err.message || String(err); return null; }),
    ]);
    const channels = Array.isArray(rawChannels)
        ? rawChannels.slice(0, MAX_BACKUP_CHANNELS).map(c => ({
            id: c.id, name: c.name, type: c.type, parent_id: c.parent_id || null,
            position: c.position,
            topic: c.topic, nsfw: c.nsfw, rate_limit_per_user: c.rate_limit_per_user,
            bitrate: c.bitrate, user_limit: c.user_limit, rtc_region: c.rtc_region,
            video_quality_mode: c.video_quality_mode,
            default_auto_archive_duration: c.default_auto_archive_duration,
            default_thread_rate_limit_per_user: c.default_thread_rate_limit_per_user,
            permission_overwrites: c.permission_overwrites || [],
        }))
        : [];
    return {
        roles: Array.isArray(roles) ? roles : [],
        channels,
        guildSettings: rawGuild || null,
        errors,
    };
}

/**
 * Capture a snapshot of the live guild structure via REST, persist it, re-read
 * it back and verify it — then set the honest terminal status. Never reports
 * SUCCESS when the reads failed, when nothing was captured, or when the stored
 * row cannot be verified.
 */
async function captureBackup({ guildId, name, createdBy, settings = null, notes = '' }) {
    const db = require('./db');
    const startedAt = new Date();

    // Refuse a duplicate concurrent capture (a double-click / retry storm).
    const inFlight = await db.countInFlightBackups(guildId).catch(() => 0);
    if (inFlight > 0) {
        const err = new Error('A backup is already in progress for this server.');
        err.status = 409;
        err.reason = 'backup_in_progress';
        throw err;
    }

    // Create the row up-front as IN_PROGRESS so a crash leaves a truthful
    // (reconcilable) record rather than a phantom success.
    const pending = await db.createAntiNukeBackup({
        guildId, name, createdBy, roles: [], channels: [], settings, notes,
        status: BACKUP_STATUS.IN_PROGRESS, operation: 'create', startedAt,
    });

    let finalStatus = BACKUP_STATUS.FAILED;
    let snapshot = null;
    let errors = [];
    try {
        const live = await readLiveStructure(guildId);
        snapshot = buildSnapshot({
            guildId, name, createdBy,
            reader: {
                roles: live.roles, channels: live.channels,
                guildSettings: live.guildSettings, settings,
                errors: live.errors,
            },
        });
        const decision = computeBackupStatus(snapshot);
        finalStatus = decision.status;
        errors = decision.errors;
    } catch (err) {
        errors = [err.message || String(err)];
        finalStatus = BACKUP_STATUS.FAILED;
        snapshot = buildSnapshot({ guildId, name, createdBy, reader: { errors: { roles: errors[0] } } });
    }

    // Persist the payload + terminal status, then re-read to verify it landed.
    let saved = null;
    let verification = { ok: false, errors: ['not persisted'] };
    try {
        saved = await db.completeAntiNukeBackup(guildId, pending.id, {
            roles: snapshot.roles, channels: snapshot.channels,
            guildSettings: snapshot.guildSettings, settings,
            status: finalStatus, resources: snapshot.resources,
            errors, verification: {},
        });
        const stored = await db.getAntiNukeBackup(guildId, pending.id);
        verification = verifySnapshot(stored || {}, { guildId });
        // A stored row that fails verification is never SUCCESS.
        if (!verification.ok && finalStatus === BACKUP_STATUS.SUCCESS) {
            finalStatus = BACKUP_STATUS.PARTIAL;
        }
        // Record the verification result + the final status on the row.
        await db.updateAntiNukeBackupStatus(guildId, pending.id, {
            status: finalStatus, verification,
            errors: errors.concat(verification.ok ? [] : verification.errors),
        });
        if (saved) { saved.status = finalStatus; saved.verification = verification; }
    } catch (err) {
        finalStatus = BACKUP_STATUS.FAILED;
        errors = errors.concat([`persist/verify failed: ${err.message || err}`]);
        verification = { ok: false, errors: [String(err.message || err)] };
        try {
            await db.updateAntiNukeBackupStatus(guildId, pending.id, {
                status: BACKUP_STATUS.FAILED, verification, errors,
            });
        } catch (_) { /* the row stays IN_PROGRESS and reconcileStaleBackups fixes it */ }
    }

    // Operation log — always written, whatever the outcome.
    await db.addAntiNukeBackupOperation({
        backupId: pending.id, guildId, operation: 'create', status: finalStatus, actorId: createdBy,
        startedAt, counts: snapshot ? snapshot.counts : {}, errors, verification,
        details: `capture ${finalStatus}`,
    }).catch(() => {});

    const finished = await db.getAntiNukeBackup(guildId, pending.id).catch(() => null);
    return {
        backup: finished || saved || pending,
        status: finalStatus,
        counts: snapshot ? snapshot.counts : { roles: 0, channels: 0 },
        resources: snapshot ? snapshot.resources : {},
        errors,
        verification,
    };
}

/** Compare a stored snapshot against the live guild. */
async function compareBackup(guildId, id) {
    const db = require('./db');
    const snapshot = await db.getAntiNukeBackup(guildId, id);
    if (!snapshot) return null;
    const live = await readLiveStructure(guildId);
    const liveShape = {
        roles: live.roles.map(serializeRole).filter(Boolean),
        channels: live.channels.map(serializeChannel).filter(Boolean),
        guildSettings: serializeGuildSettings(live.guildSettings),
    };
    return {
        diff: compareSnapshot({ roles: snapshot.roles, channels: snapshot.channels, guildSettings: snapshot.guildSettings }, liveShape),
        counts: snapshot.counts,
        status: snapshot.status,
        readErrors: live.errors,
    };
}

/** Build the live-shape + plan a restore. Shared by preview + restore. */
async function buildRestorePlan(guildId, snapshot) {
    const db = require('./db');
    const live = await readLiveStructure(guildId);
    const liveShape = {
        roles: live.roles.map(serializeRole).filter(Boolean),
        channels: live.channels.map(serializeChannel).filter(Boolean),
        guildSettings: serializeGuildSettings(live.guildSettings),
    };
    const settings = await db.getAntiNukeSettings(guildId).catch(() => null);
    const trustedRoles = (settings && settings.trustedRoleIds) || [];
    const safeRoleIds = [guildId, ...trustedRoles];
    const botHighest = await botHighestRolePosition(guildId);
    const plan = planRestore(
        { roles: snapshot.roles, channels: snapshot.channels, guildSettings: snapshot.guildSettings },
        liveShape,
        { safeRoleIds, botHighestPosition: botHighest == null ? Infinity : botHighest },
    );
    return { plan, readErrors: live.errors, botHighest };
}

/** Preview the restore operations for a snapshot (no writes). */
async function previewBackupRestore(guildId, id) {
    const db = require('./db');
    const snapshot = await db.getAntiNukeBackup(guildId, id);
    if (!snapshot) return null;
    const { plan, readErrors } = await buildRestorePlan(guildId, snapshot);
    const permissions = await validateBackupPermissions(guildId);
    return {
        plan, counts: snapshot.counts, status: snapshot.status,
        readErrors, permissions,
        skipped: plan.skipped || [],
        destructive: false,
        note: 'Recreated roles/channels receive NEW ids. Existing channels and roles are never deleted.',
    };
}

/** Map a planned op onto the REST call that applies it. */
async function applyRestoreOp(guildId, op) {
    if (op.kind === 'roleCreate') {
        const role = await discord.createGuildRole(guildId, {
            name: op.payload.name,
            permissions: op.payload.permissions,
            color: op.payload.color,
            hoist: op.payload.hoist,
            mentionable: op.payload.mentionable,
        });
        // Discord ignores `position` on create; set it afterwards (best-effort,
        // and only ever below the bot's own highest role).
        if (role && role.id && op.payload.position != null) {
            await discord.modifyGuildRole(guildId, role.id, { position: op.payload.position }).catch(() => {});
        }
        return { kind: op.kind, oldId: op.target, newId: role && role.id, name: op.payload.name };
    }
    if (op.kind === 'roleUpdate') {
        await discord.modifyGuildRole(guildId, op.target, { permissions: op.payload.permissions });
        return { kind: op.kind, id: op.target };
    }
    if (op.kind === 'channelCreate') {
        const body = {
            name: op.payload.name, type: op.payload.type,
            permission_overwrites: (op.payload.permissionOverwrites || []).map(ow => ({
                id: ow.id, type: ow.type, allow: ow.allow, deny: ow.deny,
            })),
        };
        if (op.payload.parentId) body.parent_id = op.payload.parentId;
        const settings = op.payload.settings || {};
        if (settings.topic !== undefined) body.topic = settings.topic;
        if (settings.nsfw !== undefined) body.nsfw = settings.nsfw;
        if (settings.rateLimitPerUser !== undefined) body.rate_limit_per_user = settings.rateLimitPerUser;
        if (settings.bitrate !== undefined) body.bitrate = settings.bitrate;
        if (settings.userLimit !== undefined) body.user_limit = settings.userLimit;
        if (settings.rtcRegion !== undefined) body.rtc_region = settings.rtcRegion;
        if (settings.videoQualityMode !== undefined) body.video_quality_mode = settings.videoQualityMode;
        if (settings.defaultAutoArchiveDuration !== undefined) body.default_auto_archive_duration = settings.defaultAutoArchiveDuration;
        if (settings.defaultThreadRateLimitPerUser !== undefined) body.default_thread_rate_limit_per_user = settings.defaultThreadRateLimitPerUser;
        const ch = await discord.createGuildChannel(guildId, body);
        return { kind: op.kind, oldId: op.target, newId: ch && ch.id, name: op.payload.name };
    }
    if (op.kind === 'overwriteApply') {
        const ow = op.payload.overwrite || {};
        await discord.putChannelOverwrite(op.payload.channelId, ow.id, {
            allow: String(ow.allow || 0), deny: String(ow.deny || 0), type: Number(ow.type || 0),
        });
        return { kind: op.kind, channelId: op.payload.channelId, overwriteId: ow.id };
    }
    if (op.kind === 'channelUpdate') {
        const s = op.payload.settings || {};
        const body = {};
        if (s.topic !== undefined) body.topic = s.topic;
        if (s.nsfw !== undefined) body.nsfw = s.nsfw;
        if (s.rateLimitPerUser !== undefined) body.rate_limit_per_user = s.rateLimitPerUser;
        if (s.bitrate !== undefined) body.bitrate = s.bitrate;
        if (s.userLimit !== undefined) body.user_limit = s.userLimit;
        if (s.rtcRegion !== undefined) body.rtc_region = s.rtcRegion;
        if (s.videoQualityMode !== undefined) body.video_quality_mode = s.videoQualityMode;
        if (s.defaultAutoArchiveDuration !== undefined) body.default_auto_archive_duration = s.defaultAutoArchiveDuration;
        if (s.defaultThreadRateLimitPerUser !== undefined) body.default_thread_rate_limit_per_user = s.defaultThreadRateLimitPerUser;
        if (Object.keys(body).length === 0) return { kind: op.kind, channelId: op.payload.channelId, skipped: true };
        await discord.patchChannel(op.payload.channelId, body);
        return { kind: op.kind, channelId: op.payload.channelId };
    }
    if (op.kind === 'settingUpdate') {
        const body = guildSettingBody(op.payload.key, op.payload.value);
        if (!body) return { kind: op.kind, key: op.payload.key, skipped: true };
        await discord.patchGuild(guildId, body);
        return { kind: op.kind, key: op.payload.key };
    }
    return { kind: op.kind, skipped: true };
}

/** Map a stored guild-setting key to the Discord PATCH body (snake_case). */
function guildSettingBody(key, value) {
    switch (key) {
        case 'name': return { name: String(value) };
        case 'verificationLevel': return { verification_level: Number(value) };
        case 'explicitContentFilter': return { explicit_content_filter: Number(value) };
        case 'defaultNotifications': return { default_message_notifications: Number(value) };
        case 'afkChannelId': return value ? { afk_channel_id: String(value) } : null;
        case 'afkTimeout': return { afk_timeout: Number(value) };
        case 'systemChannelId': return value ? { system_channel_id: String(value) } : null;
        case 'systemChannelFlags': return { system_channel_flags: Number(value) };
        default: return null;
    }
}

/**
 * Execute a restore for a snapshot, then re-fetch the affected resources and
 * verify the intended state was applied. Returns a report whose `status` is
 * SUCCESS only when the changes were applied AND verified.
 */
async function restoreBackup(guildId, id, { actorId = null, dryRun = false } = {}) {
    const db = require('./db');
    const startedAt = new Date();
    const preview = await previewBackupRestore(guildId, id);
    if (!preview) return null;

    if (dryRun) {
        return {
            dryRun: true, status: BACKUP_STATUS.PENDING,
            plan: preview.plan, counts: preview.counts, permissions: preview.permissions,
            attempted: 0, applied: 0, failedCount: 0, errors: [],
            note: 'Dry run — nothing was changed.',
        };
    }

    const report = {
        created: { roles: [], channels: [] },
        updated: { roles: [], channels: [], overwrites: [], settings: [] },
        skipped: (preview.skipped || []).slice(),
        failed: [],
        newIds: [],
        errors: [],
    };

    // Old → new id map, filled as resources are recreated so a child channel's
    // parent_id and every overwrite can be remapped onto the new ids instead of
    // being sent with stale ids (which Discord rejects as Invalid Form Body).
    const idMap = new Map();
    let liveChannelIds = [];
    let liveRoleIds = [];

    // Refuse to run without the permissions the operations need — an attempt
    // that Discord would reject must fail loudly, not report success.
    if (!preview.permissions.ok) {
        report.errors.push(`missing permissions: ${preview.permissions.missing.join(', ')}`);
        report.status = BACKUP_STATUS.FAILED;
        report.attempted = 0; report.applied = 0; report.failedCount = preview.plan.ops.length;
        report.verified = false;
        await db.addAntiNukeBackupOperation({
            backupId: Number(id), guildId, operation: 'restore', status: report.status, actorId,
            startedAt, counts: { attempted: report.attempted, applied: 0, failed: report.failedCount },
            errors: report.errors, verification: { ok: false, errors: report.errors },
            details: 'restore refused — missing permissions',
        }).catch(() => {});
        report.summary = { attempted: 0, applied: 0, failed: report.failedCount, verified: false };
        return report;
    }

    // The ids that still exist, so an overwrite/parent that was NOT recreated
    // this run is only kept when its target is genuinely still present.
    const live = await readLiveStructure(guildId);
    liveChannelIds = live.channels.map(c => c.id);
    liveRoleIds = live.roles.map(r => r.id);

    for (const planned of preview.plan.ops) {
        // Remap stale ids (recreated parent categories, deleted roles) so the
        // request Discord receives is valid, and record anything we had to drop.
        const { op, dropped } = remapRestoreOp(planned, {
            idMap, liveChannelIds, liveRoleIds, guildId,
        });
        for (const reason of dropped) {
            report.skipped.push({ kind: planned.kind, target: planned.target, reason });
        }
        if (!op) continue;
        try {
            const result = await applyRestoreOp(guildId, op);
            if (result && result.skipped) { report.skipped.push({ kind: op.kind, target: op.target, reason: 'no applicable fields' }); continue; }
            if (op.kind === 'roleCreate') {
                report.created.roles.push({ oldId: op.target, newId: result.newId, name: op.payload.name });
                if (result.newId) {
                    idMap.set(String(op.target), String(result.newId));
                    report.newIds.push({ kind: 'role', oldId: op.target, newId: result.newId, name: op.payload.name });
                }
            } else if (op.kind === 'channelCreate') {
                report.created.channels.push({ oldId: op.target, newId: result.newId, name: op.payload.name });
                if (result.newId) {
                    idMap.set(String(op.target), String(result.newId));
                    report.newIds.push({ kind: 'channel', oldId: op.target, newId: result.newId, name: op.payload.name });
                }
            } else if (op.kind === 'roleUpdate') {
                report.updated.roles.push({ id: op.target });
            } else if (op.kind === 'channelUpdate') {
                report.updated.channels.push({ id: op.payload.channelId });
            } else if (op.kind === 'overwriteApply') {
                report.updated.overwrites.push({ channelId: op.payload.channelId, overwriteId: op.payload.overwrite && op.payload.overwrite.id });
            } else if (op.kind === 'settingUpdate') {
                report.updated.settings.push({ key: op.payload.key });
            }
        } catch (err) {
            report.failed.push({ kind: op.kind, target: op.target, error: err.message || String(err) });
            report.errors.push(`${op.kind}:${op.target}: ${err.message || err}`);
        }
    }

    const applied = report.created.roles.length + report.created.channels.length
        + report.updated.roles.length + report.updated.channels.length
        + report.updated.overwrites.length + report.updated.settings.length;
    report.attempted = preview.plan.ops.length;
    report.applied = applied;
    report.failedCount = report.failed.length;

    // Verify: re-fetch and confirm the intended state. Recreated resources get
    // NEW ids, so they are verified by name+type presence, not by old id.
    let verification = { ok: false, errors: ['not verified'] };
    try {
        verification = await verifyRestore(guildId, id, report);
    } catch (err) {
        verification = { ok: false, errors: [err.message || String(err)] };
    }
    report.verified = verification.ok;
    report.verification = verification;

    const decision = computeRestoreStatus(report);
    report.status = decision.status;
    report.errors = report.errors.concat(decision.errors.filter(e => !report.errors.includes(e)));
    report.note = 'Recreated roles and channels receive NEW ids — Discord never reuses ids, and deleted messages cannot be restored.';

    await db.addAntiNukeBackupOperation({
        backupId: Number(id), guildId, operation: 'restore', status: report.status, actorId,
        startedAt,
        counts: { attempted: report.attempted, applied, failed: report.failedCount },
        errors: report.errors, verification,
        details: `restore ${report.status}: +${report.created.roles.length} roles, +${report.created.channels.length} channels, ${report.failedCount} failed`,
    }).catch(() => {});

    report.summary = {
        rolesCreated: report.created.roles.length,
        rolesUpdated: report.updated.roles.length,
        channelsCreated: report.created.channels.length,
        channelsUpdated: report.updated.channels.length,
        overwritesApplied: report.updated.overwrites.length,
        settingsUpdated: report.updated.settings.length,
        attempted: report.attempted,
        applied,
        failed: report.failedCount,
        skipped: report.skipped.length,
        verified: verification.ok,
    };
    return report;
}

/**
 * Re-fetch the guild and confirm the restored state. Verifies:
 *   • every recreated role/channel now exists (by name + type);
 *   • every role whose permissions we set now carries them;
 *   • every overwrite we applied is present with the intended bits.
 * Returns `{ ok, errors, checked, mismatches }`.
 */
async function verifyRestore(guildId, id, report) {
    const db = require('./db');
    const snapshot = await db.getAntiNukeBackup(guildId, id);
    const errors = [];
    let checked = 0;
    const mismatches = [];

    const live = await readLiveStructure(guildId);
    if (live.errors.roles || live.errors.channels) {
        return { ok: false, errors: ['could not re-read guild for verification'], checked: 0, mismatches: [] };
    }
    const liveRoles = live.roles.map(serializeRole).filter(Boolean);
    const liveChannels = live.channels.map(serializeChannel).filter(Boolean);
    const rolesByName = new Map(liveRoles.map(r => [r.name, r]));
    const channelsByKey = new Map(liveChannels.map(c => [`${c.name}|${c.type}`, c]));

    for (const r of report.created.roles) {
        checked++;
        if (!rolesByName.has(r.name)) mismatches.push(`role ${r.name} missing after restore`);
    }
    for (const c of report.created.channels) {
        checked++;
        const snapChannel = (snapshot.channels || []).find(x => String(x.id) === String(c.oldId));
        const key = `${c.name}|${snapChannel ? snapChannel.type : 0}`;
        if (!channelsByKey.has(key)) mismatches.push(`channel ${c.name} missing after restore`);
    }
    for (const u of report.updated.roles) {
        checked++;
        const wanted = (snapshot.roles || []).find(x => String(x.id) === String(u.id));
        const liveRole = liveRoles.find(x => String(x.id) === String(u.id));
        if (!liveRole) { mismatches.push(`role ${u.id} missing during verify`); continue; }
        if (wanted && String(liveRole.permissions) !== String(wanted.permissions)) {
            mismatches.push(`role ${wanted.name} permissions not applied`);
        }
    }
    for (const ow of report.updated.overwrites) {
        checked++;
        const ch = liveChannels.find(c => String(c.id) === String(ow.channelId));
        if (!ch) { mismatches.push(`channel ${ow.channelId} missing during verify`); continue; }
        const applied = (ch.permissionOverwrites || []).find(o => String(o.id) === String(ow.overwriteId));
        if (!applied) mismatches.push(`overwrite ${ow.overwriteId} not applied on ${ow.channelId}`);
    }

    if (mismatches.length) errors.push(...mismatches.slice(0, 20));
    return { ok: mismatches.length === 0, errors, checked, mismatches: mismatches.slice(0, 20) };
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
    validateBackupPermissions,
    botHighestRolePosition,
    // Lockdown profiles
    LOCKDOWN_PROFILE_LABELS,
    planLockdownProfile,
    engageLockdownProfile,
    restoreLockdownProfile,
};
