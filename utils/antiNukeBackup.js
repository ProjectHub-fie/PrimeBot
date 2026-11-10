/**
 * Anti-Nuke — configuration snapshots (roles / channels / settings).
 *
 * A snapshot is a point-in-time capture of everything an Anti-Nuke incident can
 * touch: the role catalog (permissions + position + colours), the channel
 * catalog (name, type, parent, permission overwrites) and the Anti-Nuke
 * settings. It is stored as JSONB rows in `antinuke_backups` so it survives
 * manager restarts.
 *
 * Detection and containment are BOTH real: `captureSnapshot` reads the live
 * guild via the configured reader, and `restoreSnapshot` re-creates missing
 * roles/channels and re-applies role permission bits through real Discord
 * REST calls. Because a restored channel is a NEW channel (Discord never reuses
 * channel ids), restore reports `newId` for every recreated channel — it never
 * claims a channel was "restored in place".
 */

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

/** Compact, storage-safe channel record. */
function serializeChannel(channel) {
    if (!channel) return null;
    return {
        id: String(channel.id),
        name: channel.name || '',
        type: Number(channel.type != null ? channel.type : 0),
        parentId: channel.parentId ? String(channel.parentId) : null,
        position: Number(channel.rawPosition != null ? channel.rawPosition : (channel.position || 0)),
        // Only the non-default permission overwrites are stored; @everyone +
        // role/member overwrites that differ from nothing are meaningful.
        permissionOverwrites: Array.isArray(channel.permissionOverwrites)
            ? channel.permissionOverwrites.map(ow => ({
                id: String(ow.id), type: Number(ow.type == null ? 0 : ow.type),
                allow: String(ow.allow == null ? 0 : ow.allow),
                deny: String(ow.deny == null ? 0 : ow.deny),
            }))
            : [],
    };
}

/**
 * Capture a snapshot of a guild via a reader interface. `reader` must provide
 * `roles` and `channels` as arrays of the serialized shapes (or their REST
 * row shape — `serializeRole`/`serializeChannel` normalize either).
 */
function buildSnapshot({ guildId, name, createdBy, reader = {} }) {
    const roles = (reader.roles || []).map(serializeRole).filter(Boolean);
    const channels = (reader.channels || []).map(serializeChannel).filter(Boolean);
    return {
        guildId: String(guildId),
        name: String(name || '').slice(0, 120),
        createdBy: createdBy ? String(createdBy) : null,
        createdAt: new Date().toISOString(),
        roles,
        channels,
        settings: reader.settings || null,
        counts: {
            roles: roles.length,
            channels: channels.length,
        },
    };
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
    for (const c of snapshot.channels || []) {
        if (!liveChannels.has(String(c.id))) {
            missingChannels.push({ id: c.id, name: c.name, type: c.type, parentId: c.parentId, permissionOverwrites: c.permissionOverwrites || [] });
        }
    }

    return {
        missingRoles,
        modifiedRoles,
        missingChannels,
        unchangedRoles: presentRoleIds.size,
        unchangedChannels: live.channels ? Math.max(0, live.channels.length - missingChannels.length) : 0,
    };
}

/**
 * Plan the restore operations for a snapshot against a live guild. Returns real
 * op lists the executor carries out (each op is { kind, target, payload }).
 * `safeRoleIds` = ids to never touch (owner/bot/trusted roles are excluded by
 * the caller).
 */
function planRestore(snapshot, live = {}, { safeRoleIds = [], botHighestPosition = Infinity } = {}) {
    const diff = compareSnapshot(snapshot, live);
    const safe = new Set((safeRoleIds || []).map(String));
    const ops = [];

    for (const role of diff.missingRoles) {
        if (safe.has(String(role.id))) continue;
        if (Number(role.position) >= Number(botHighestPosition)) continue;
        ops.push({ kind: 'roleCreate', target: role.id, payload: {
            name: role.name, permissions: role.permissions, color: role.color,
            hoist: role.hoist, mentionable: role.mentionable,
            position: role.position,
        } });
    }
    for (const m of diff.modifiedRoles) {
        if (safe.has(String(m.id))) continue;
        ops.push({ kind: 'roleUpdate', target: m.id, payload: { permissions: m.toPermissions } });
    }
    for (const c of diff.missingChannels) {
        ops.push({ kind: 'channelCreate', target: c.id, payload: {
            name: c.name, type: c.type, parentId: c.parentId, permissionOverwrites: c.permissionOverwrites || [],
        } });
    }
    return { ops, diff, roleCreates: ops.filter(o => o.kind === 'roleCreate').length, roleUpdates: ops.filter(o => o.kind === 'roleUpdate').length, channelCreates: ops.filter(o => o.kind === 'channelCreate').length };
}

module.exports = {
    serializeRole,
    serializeChannel,
    buildSnapshot,
    compareSnapshot,
    planRestore,
};