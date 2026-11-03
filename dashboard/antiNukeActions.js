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
    return {
        id: String(guildId),
        name: (raw && raw.name) || 'this server',
        ownerId: raw && raw.owner_id ? String(raw.owner_id) : null,
        memberCount: raw && raw.approximate_member_count != null ? raw.approximate_member_count : null,
        channels: {
            cache: channelCache,
            fetch: async (id) => channelCache.get(id) || null,
        },
        roles: { cache: roleCache },
        members: {
            me: {
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
};
