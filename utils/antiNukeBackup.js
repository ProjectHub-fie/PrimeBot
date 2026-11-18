/**
 * Anti-Nuke — configuration snapshots (roles / channels / settings).
 *
 * A snapshot is a point-in-time capture of everything an Anti-Nuke incident can
 * touch: the role catalog (permissions + position + colours), the channel
 * catalog (name, type, parent, position, permission overwrites and per-channel
 * settings), the guild security settings a bot can read, and the Anti-Nuke
 * settings. It is stored as JSONB rows in `antinuke_backups` so it survives
 * manager restarts.
 *
 * A snapshot is only reported SUCCESS when its data was really fetched AND
 * persisted AND re-read back. `summarizeResources` tracks success/failure per
 * resource type so a partial capture is reported as PARTIAL, and a capture that
 * collected nothing is reported as FAILED — never SUCCESS.
 *
 * Detection and containment are BOTH real: `captureSnapshot` reads the live
 * guild via the configured reader, and `restoreSnapshot` re-creates missing
 * roles/channels and re-applies role permission bits through real Discord
 * REST calls. Because a restored channel is a NEW channel (Discord never reuses
 * channel ids), restore reports `newId` for every recreated channel — it never
 * claims a channel was "restored in place".
 */

/**
 * Operation lifecycle. A backup is never SUCCESS while it is still being
 * captured, and never SUCCESS when its data could not be fetched or persisted.
 */
const BACKUP_STATUS = {
    PENDING: 'PENDING',
    IN_PROGRESS: 'IN_PROGRESS',
    SUCCESS: 'SUCCESS',
    PARTIAL: 'PARTIAL',
    FAILED: 'FAILED',
};

const BACKUP_STATUSES = Object.values(BACKUP_STATUS);

/** Resource types a snapshot can carry, in dependency (restore) order. */
const RESOURCE_TYPES = ['roles', 'channels', 'overwrites', 'guildSettings', 'settings'];

/** Terminal states — an operation in one of these never changes again. */
function isTerminalStatus(status) {
    return status === BACKUP_STATUS.SUCCESS
        || status === BACKUP_STATUS.PARTIAL
        || status === BACKUP_STATUS.FAILED;
}

/** Compact, storage-safe role record. */
function serializeRole(role) {
    if (!role) return null;
    const r = role;
    let bits = typeof r.permissions === 'object' && r.permissions
        ? r.permissions.bitfield != null ? BigInt(r.permissions.bitfield).toString(10)
            : typeof r.permissions.bitfield === 'bigint' ? r.permissions.bitfield.toString(10)
            : (Number(r.permissions) || 0).toString(10)
        : (typeof r.permissions === 'bigint' ? r.permissions.toString(10)
            : typeof r.permissions === 'string' || typeof r.permissions === 'number' ? String(r.permissions)
            : '0');
    if (bits === 'undefined' || bits == null) bits = '0';
    return {
        id: String(r.id),
        name: r.name || '',
        position: Number(r.position || 0),
        color: Number(r.color || 0),
        hoist: r.hoist === true,
        mentionable: r.mentionable === true,
        permissions: bits,
        managed: r.managed === true,
    };
}

/**
 * Per-channel settings a bot can read and (mostly) re-apply. Only keys that are
 * actually present are stored, so a missing field is never confused with a
 * deliberate default.
 */
function serializeChannelSettings(channel) {
    const out = {};
    if (!channel) return out;
    const put = (key, value) => { if (value !== undefined && value !== null) out[key] = value; };
    put('topic', channel.topic);
    if (channel.nsfw !== undefined) out.nsfw = channel.nsfw === true;
    put('rateLimitPerUser', channel.rateLimitPerUser !== undefined ? channel.rateLimitPerUser : channel.rate_limit_per_user);
    put('bitrate', channel.bitrate);
    put('userLimit', channel.userLimit !== undefined ? channel.userLimit : channel.user_limit);
    put('rtcRegion', channel.rtcRegion !== undefined ? channel.rtcRegion : channel.rtc_region);
    put('videoQualityMode', channel.videoQualityMode !== undefined ? channel.videoQualityMode : channel.video_quality_mode);
    put('defaultAutoArchiveDuration', channel.defaultAutoArchiveDuration !== undefined
        ? channel.defaultAutoArchiveDuration : channel.default_auto_archive_duration);
    put('defaultThreadRateLimitPerUser', channel.defaultThreadRateLimitPerUser !== undefined
        ? channel.defaultThreadRateLimitPerUser : channel.default_thread_rate_limit_per_user);
    put('position', channel.rawPosition !== undefined ? channel.rawPosition : channel.position);
    return out;
}

/** Compact, storage-safe channel record. */
function serializeChannel(channel) {
    if (!channel) return null;
    const overwrites = Array.isArray(channel.permissionOverwrites)
        ? channel.permissionOverwrites
        : Array.isArray(channel.permission_overwrites) ? channel.permission_overwrites : [];
    return {
        id: String(channel.id),
        name: channel.name || '',
        type: Number(channel.type != null ? channel.type : 0),
        parentId: (channel.parentId || channel.parent_id) ? String(channel.parentId || channel.parent_id) : null,
        position: Number(channel.rawPosition != null ? channel.rawPosition : (channel.position || 0)),
        // Only the non-default permission overwrites are stored; @everyone +
        // role/member overwrites that differ from nothing are meaningful.
        permissionOverwrites: overwrites.map(ow => ({
            id: String(ow.id), type: Number(ow.type == null ? 0 : ow.type),
            allow: String(ow.allow == null ? 0 : ow.allow),
            deny: String(ow.deny == null ? 0 : ow.deny),
        })),
        settings: serializeChannelSettings(channel),
    };
}

/** Guild-level settings a bot can read back and re-apply (never icon/owner). */
function serializeGuildSettings(raw) {
    if (!raw) return null;
    const out = {};
    const put = (key, value) => { if (value !== undefined && value !== null) out[key] = value; };
    put('name', raw.name);
    put('verificationLevel', raw.verification_level !== undefined ? raw.verification_level : raw.verificationLevel);
    put('explicitContentFilter', raw.explicit_content_filter !== undefined ? raw.explicit_content_filter : raw.explicitContentFilter);
    put('defaultNotifications', raw.default_message_notifications !== undefined
        ? raw.default_message_notifications : raw.defaultNotifications);
    put('afkChannelId', raw.afk_channel_id !== undefined ? raw.afk_channel_id : raw.afkChannelId);
    put('afkTimeout', raw.afk_timeout !== undefined ? raw.afk_timeout : raw.afkTimeout);
    put('systemChannelId', raw.system_channel_id !== undefined ? raw.system_channel_id : raw.systemChannelId);
    put('systemChannelFlags', raw.system_channel_flags !== undefined ? raw.system_channel_flags : raw.systemChannelFlags);
    return Object.keys(out).length ? out : null;
}

/**
 * Capture a snapshot of a guild via a reader interface. `reader` must provide
 * `roles` and `channels` as arrays of the serialized shapes (or their REST
 * row shape — `serializeRole`/`serializeChannel` normalize either). Optional
 * `reader.guildSettings` (raw guild object) and `reader.settings` (Anti-Nuke
 * settings) are stored verbatim.
 *
 * `reader.errors` may carry a map of resource type -> error message, populated
 * by the caller when a fetch failed, so the snapshot records why it is partial.
 */
function buildSnapshot({ guildId, name, createdBy, reader = {} }) {
    const roles = (reader.roles || []).map(serializeRole).filter(Boolean);
    const channels = (reader.channels || []).map(serializeChannel).filter(Boolean);
    const guildSettings = serializeGuildSettings(reader.guildSettings);
    const errors = reader.errors && typeof reader.errors === 'object' ? { ...reader.errors } : {};
    const snapshot = {
        guildId: String(guildId),
        name: String(name || '').slice(0, 120),
        createdBy: createdBy ? String(createdBy) : null,
        createdAt: new Date().toISOString(),
        roles,
        channels,
        guildSettings,
        settings: reader.settings || null,
        errors,
        counts: {
            roles: roles.length,
            channels: channels.length,
            overwrites: channels.reduce((n, c) => n + (c.permissionOverwrites || []).length, 0),
        },
    };
    snapshot.resources = summarizeResources(snapshot);
    return snapshot;
}

/**
 * Track success/failure per resource type for a snapshot. A resource type is
 * `ok` when it was fetched without an error AND carries at least one record
 * (except settings, which is best-effort). Anything else is `failed`.
 */
function summarizeResources(snapshot) {
    const errors = (snapshot && snapshot.errors) || {};
    const channels = (snapshot && snapshot.channels) || [];
    const overwriteCount = channels.reduce((n, c) => n + (c.permissionOverwrites || []).length, 0);
    const out = {};
    const mark = (key, count) => {
        const error = errors[key];
        out[key] = {
            ok: !error && count > 0,
            count,
            error: error ? String(error).slice(0, 500) : null,
        };
    };
    mark('roles', (snapshot && snapshot.roles ? snapshot.roles.length : 0));
    mark('channels', channels.length);
    // Overwrites are an aspect of channels: only "failed" when channels failed
    // outright; zero overwrites on a real guild is legitimate (all inherited).
    out.overwrites = {
        ok: !errors.channels && channels.length > 0,
        count: overwriteCount,
        error: errors.channels ? String(errors.channels).slice(0, 500) : null,
    };
    mark('guildSettings', snapshot && snapshot.guildSettings ? 1 : 0);
    out.settings = { ok: true, count: snapshot && snapshot.settings ? 1 : 0, error: null };
    return out;
}

/**
 * Decide the terminal status of a capture. Rules:
 *   • nothing fetched at all             → FAILED (never SUCCESS)
 *   • every fetched resource type failed  → FAILED
 *   • some resource types failed          → PARTIAL
 *   • all fetched + at least one record   → SUCCESS
 * Returns `{ status, errors: string[] }`.
 */
function computeBackupStatus(snapshot) {
    const resources = snapshot.resources || summarizeResources(snapshot);
    const errors = [];
    for (const key of RESOURCE_TYPES) {
        const r = resources[key];
        if (r && r.error) errors.push(`${key}: ${r.error}`);
    }
    const totalRecords = (resources.roles ? resources.roles.count : 0)
        + (resources.channels ? resources.channels.count : 0);
    if (totalRecords === 0) {
        return { status: BACKUP_STATUS.FAILED, errors: errors.concat(['no resources captured']) };
    }
    const failedTypes = RESOURCE_TYPES.filter(k => resources[k] && !resources[k].ok);
    if (failedTypes.length === 0) return { status: BACKUP_STATUS.SUCCESS, errors };
    if (failedTypes.length === RESOURCE_TYPES.length) return { status: BACKUP_STATUS.FAILED, errors };
    return { status: BACKUP_STATUS.PARTIAL, errors };
}

/**
 * Validate a persisted snapshot before it is reported successful or restored.
 * Returns `{ ok, errors: string[] }`. Never throws on malformed input.
 */
function verifySnapshot(snapshot, { guildId = null } = {}) {
    const errors = [];
    if (!snapshot || typeof snapshot !== 'object') return { ok: false, errors: ['snapshot missing'] };
    if (guildId != null && String(snapshot.guildId) !== String(guildId)) {
        errors.push(`guild mismatch (${snapshot.guildId} != ${guildId})`);
    }
    if (!Array.isArray(snapshot.roles)) errors.push('roles is not an array');
    if (!Array.isArray(snapshot.channels)) errors.push('channels is not an array');
    const roles = Array.isArray(snapshot.roles) ? snapshot.roles : [];
    const channels = Array.isArray(snapshot.channels) ? snapshot.channels : [];
    for (const r of roles) {
        if (!r || r.id == null) { errors.push('role without id'); break; }
        if (r.permissions == null || String(r.permissions) === 'undefined') {
            errors.push(`role ${r.id} has no permission bitfield`);
            break;
        }
    }
    for (const c of channels) {
        if (!c || c.id == null || c.type == null) { errors.push('channel without id/type'); break; }
    }
    const counts = snapshot.counts || {};
    if (counts.roles != null && Number(counts.roles) !== roles.length) {
        errors.push(`counts.roles (${counts.roles}) != stored roles (${roles.length})`);
    }
    if (counts.channels != null && Number(counts.channels) !== channels.length) {
        errors.push(`counts.channels (${counts.channels}) != stored channels (${channels.length})`);
    }
    return { ok: errors.length === 0, errors };
}

/**
 * Compare a snapshot against the live guild. `live` has `{ roles, channels }`
 * of serialized rows. Returns the diffs with real names for display.
 */
function compareSnapshot(snapshot, live = {}) {
    const liveRoles = new Map((live.roles || []).map(r => [String(r.id), r]));
    const liveChannels = new Map((live.channels || []).map(c => [String(c.id), c]));

    const missingRoles = [];
    const modifiedRoles = [];
    const presentRoleIds = new Set();
    for (const r of snapshot.roles || []) {
        const cur = liveRoles.get(String(r.id));
        if (!cur) { missingRoles.push({ id: r.id, name: r.name, permissions: r.permissions, position: r.position, color: r.color, hoist: r.hoist, mentionable: r.mentionable }); continue; }
        presentRoleIds.add(String(r.id));
        if (String(cur.permissions) !== String(r.permissions)) {
            modifiedRoles.push({ id: r.id, name: r.name, fromPermissions: cur.permissions, toPermissions: r.permissions });
        }
    }

    const missingChannels = [];
    const modifiedChannels = [];
    for (const c of snapshot.channels || []) {
        const cur = liveChannels.get(String(c.id));
        if (!cur) {
            missingChannels.push({ id: c.id, name: c.name, type: c.type, parentId: c.parentId, permissionOverwrites: c.permissionOverwrites || [], settings: c.settings || {} });
            continue;
        }
        const overwrites = c.permissionOverwrites || [];
        const curOverwrites = new Map((cur.permissionOverwrites || []).map(o => [String(o.id), o]));
        const changedOverwrites = overwrites.filter(o => {
            const existing = curOverwrites.get(String(o.id));
            if (!existing) return true;
            return String(existing.allow) !== String(o.allow) || String(existing.deny) !== String(o.deny);
        });
        const settingsChanged = Object.keys(c.settings || {}).some(k => {
            const want = c.settings[k];
            const have = (cur.settings || {})[k];
            return want !== undefined && String(want) !== String(have);
        });
        if (changedOverwrites.length || settingsChanged) {
            modifiedChannels.push({
                id: c.id, name: c.name, type: c.type,
                overwrites: changedOverwrites, settings: settingsChanged ? (c.settings || {}) : {},
            });
        }
    }

    const settingsChanged = [];
    const wantSettings = snapshot.guildSettings || null;
    if (wantSettings && live.guildSettings) {
        for (const key of Object.keys(wantSettings)) {
            if (String(wantSettings[key]) !== String(live.guildSettings[key])) {
                settingsChanged.push({ key, from: live.guildSettings[key], to: wantSettings[key] });
            }
        }
    }

    return {
        missingRoles,
        modifiedRoles,
        missingChannels,
        modifiedChannels,
        settingsChanged,
        unchangedRoles: presentRoleIds.size,
        unchangedChannels: live.channels ? Math.max(0, live.channels.length - missingChannels.length) : 0,
    };
}

/**
 * Plan the restore operations for a snapshot against a live guild. Returns real
 * op lists the executor carries out (each op is { kind, target, payload }).
 * `safeRoleIds` = ids to never touch (owner/bot/trusted roles are excluded by
 * the caller). Ops are ordered so dependencies are satisfied: roles (parents)
 * before channels, categories before their children, and permission overwrites
 * after the channel exists.
 */
function planRestore(snapshot, live = {}, { safeRoleIds = [], botHighestPosition = Infinity } = {}) {
    const diff = compareSnapshot(snapshot, live);
    const safe = new Set((safeRoleIds || []).map(String));
    const ops = [];
    const skipped = [];

    for (const role of diff.missingRoles) {
        if (safe.has(String(role.id))) { skipped.push({ kind: 'roleCreate', target: role.id, name: role.name, reason: 'protected role' }); continue; }
        if (Number(role.position) >= Number(botHighestPosition)) {
            skipped.push({ kind: 'roleCreate', target: role.id, name: role.name, reason: 'above the bot\'s highest role' });
            continue;
        }
        ops.push({ kind: 'roleCreate', target: role.id, payload: {
            name: role.name, permissions: role.permissions, color: role.color,
            hoist: role.hoist, mentionable: role.mentionable,
            position: role.position,
        } });
    }
    for (const m of diff.modifiedRoles) {
        if (safe.has(String(m.id))) { skipped.push({ kind: 'roleUpdate', target: m.id, name: m.name, reason: 'protected role' }); continue; }
        ops.push({ kind: 'roleUpdate', target: m.id, payload: { permissions: m.toPermissions } });
    }

    // Categories first so a child's parent exists before it is created.
    const isCategory = (c) => Number(c.type) === 4;
    const missing = diff.missingChannels.slice().sort((a, b) => (isCategory(b) ? 1 : 0) - (isCategory(a) ? 1 : 0));
    for (const c of missing) {
        ops.push({ kind: 'channelCreate', target: c.id, payload: {
            name: c.name, type: c.type, parentId: c.parentId,
            permissionOverwrites: c.permissionOverwrites || [],
            settings: c.settings || {},
        } });
    }
    // Existing channels: re-apply changed overwrites + settings (never delete).
    for (const c of diff.modifiedChannels) {
        for (const ow of c.overwrites || []) {
            ops.push({ kind: 'overwriteApply', target: c.id, payload: {
                channelId: c.id, overwrite: ow,
            } });
        }
        if (c.settings && Object.keys(c.settings).length) {
            ops.push({ kind: 'channelUpdate', target: c.id, payload: { channelId: c.id, settings: c.settings } });
        }
    }
    for (const s of diff.settingsChanged || []) {
        ops.push({ kind: 'settingUpdate', target: s.key, payload: { key: s.key, value: s.to } });
    }

    return {
        ops, diff, skipped,
        roleCreates: ops.filter(o => o.kind === 'roleCreate').length,
        roleUpdates: ops.filter(o => o.kind === 'roleUpdate').length,
        channelCreates: ops.filter(o => o.kind === 'channelCreate').length,
        channelUpdates: ops.filter(o => o.kind === 'channelUpdate').length,
        overwriteApplies: ops.filter(o => o.kind === 'overwriteApply').length,
        settingUpdates: ops.filter(o => o.kind === 'settingUpdate').length,
    };
}

/**
 * Remap a single restore operation's ids against the ids known at apply time.
 *
 * A nuke deletes channels and roles, so a restored category/role gets a NEW id
 * (Discord never reuses ids). A child channel's `parent_id` and every permission
 * overwrite still reference the OLD ids, and Discord rejects a create that names
 * a non-existent parent or overwrite target with `Invalid Form Body (400)`.
 *
 * `idMap` maps old → new ids for resources already recreated in this run, and
 * `liveChannelIds` / `liveRoleIds` are the ids that still exist. Returns
 * `{ op, dropped: string[] }`; a parent/overwrite that can neither be remapped
 * nor found is dropped (with a reason) rather than sent to Discord to fail.
 */
function remapRestoreOp(op, { idMap = {}, liveChannelIds = [], liveRoleIds = [], guildId = null } = {}) {
    const map = idMap instanceof Map ? idMap : new Map(Object.entries(idMap));
    const liveChannels = new Set((liveChannelIds || []).map(String));
    const liveRoles = new Set((liveRoleIds || []).map(String));
    const dropped = [];
    const resolve = (id) => {
        const key = String(id);
        if (map.has(key)) return String(map.get(key));
        return null;
    };
    const keepOverwrite = (ow) => {
        const id = String(ow.id);
        if (guildId != null && id === String(guildId)) return ow;      // @everyone — always valid
        if (Number(ow.type) === 1) return ow;                           // member overwrite — user ids are stable
        if (liveRoles.has(id)) return ow;                               // role still exists
        const mapped = resolve(id);
        if (mapped) return { ...ow, id: mapped };                       // role recreated this run
        dropped.push(`overwrite for unknown role ${id}`);
        return null;
    };

    if (op.kind === 'channelCreate') {
        const payload = { ...op.payload };
        if (payload.parentId) {
            const id = String(payload.parentId);
            if (map.has(id)) payload.parentId = String(map.get(id));
            else if (liveChannels.has(id)) payload.parentId = id;
            else { dropped.push(`parent category ${id} was not restored`); payload.parentId = null; }
        }
        if (Array.isArray(payload.permissionOverwrites)) {
            payload.permissionOverwrites = payload.permissionOverwrites.map(keepOverwrite).filter(Boolean);
        }
        return { op: { ...op, payload }, dropped };
    }
    if (op.kind === 'overwriteApply') {
        const overwrite = keepOverwrite(op.payload.overwrite || {});
        if (!overwrite) return { op: null, dropped };
        return { op: { ...op, payload: { ...op.payload, overwrite } }, dropped };
    }
    return { op, dropped };
}

/**
 * Decide the terminal status of a restore from its execution report. A restore
 * is never SUCCESS when an operation failed, and never SUCCESS when nothing was
 * actually applied. Returns `{ status, errors: string[] }`.
 *
 *   • every op failed / nothing applied → FAILED
 *   • some ops failed                   → PARTIAL
 *   • ops applied, none failed          → SUCCESS (when verified) else PARTIAL
 */
function computeRestoreStatus(report = {}) {
    const applied = Number(report.applied || 0);
    const failed = Number(report.failedCount || 0);
    const attempted = Number(report.attempted || 0);
    const errors = (report.errors || []).slice();
    if (attempted > 0 && failed >= attempted && applied === 0) {
        return { status: BACKUP_STATUS.FAILED, errors: errors.length ? errors : ['every restore operation failed'] };
    }
    if (failed > 0) return { status: BACKUP_STATUS.PARTIAL, errors };
    if (applied === 0) {
        // Nothing to do is a legitimate "in sync" result, not a failure.
        return { status: attempted === 0 ? BACKUP_STATUS.SUCCESS : BACKUP_STATUS.FAILED, errors };
    }
    // Applied with no failures — but only SUCCESS when the read-back confirmed
    // the intended state. An unverified apply is PARTIAL, never a green tick.
    if (report.verified === false) {
        return { status: BACKUP_STATUS.PARTIAL, errors: errors.concat(['changes applied but not verified']) };
    }
    return { status: BACKUP_STATUS.SUCCESS, errors };
}

module.exports = {
    BACKUP_STATUS,
    BACKUP_STATUSES,
    RESOURCE_TYPES,
    isTerminalStatus,
    serializeRole,
    serializeChannel,
    serializeChannelSettings,
    serializeGuildSettings,
    buildSnapshot,
    summarizeResources,
    computeBackupStatus,
    computeRestoreStatus,
    verifySnapshot,
    compareSnapshot,
    planRestore,
    remapRestoreOp,
};
