/**
 * Event Management command layer — shared by `/event` and `$event`.
 *
 * The slash command and the prefix command both funnel into
 * `executeEventAction()`, so the two entry points can never drift in
 * behaviour, validation or authorization.
 *
 * Authorization mirrors the dashboard's eventAuth:
 *   • the server owner and members with Manage Server always pass;
 *   • a member holding the event's configured Event Manager role passes for
 *     the granular permissions the event grants (an empty list = all).
 * Every check is server-side; a hidden command is never the gate.
 */

const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const config = require('../config');
const repo = require('../server/eventMgmtRepo');
const {
    EVENT_TYPE_KEYS, EVENT_STATUSES, RECURRENCE_KEYS, REMINDER_KEYS,
    REGISTRATION_MODES, eventTypeMeta, eventStatusMeta, normalizeEventStatus,
} = require('../shared/eventConstants');
const { buildEventEmbed } = require('../shared/eventMessages');

const PERMISSION_FOR_ACTION = {
    create: 'manage_events',
    edit: 'manage_events',
    config: 'manage_events',
    reminders: 'manage_events',
    cancel: 'cancel_events',
    delete: 'cancel_events',
};

function isGuildAdmin(member, guild) {
    if (!member) return false;
    if (guild && member.id === guild.ownerId) return true;
    try {
        return member.permissions?.has?.(PermissionFlagsBits.ManageGuild) === true;
    } catch {
        return false;
    }
}

/**
 * Can this member perform `permission` on `event`? With no event (guild-level
 * create/config) only administrators pass.
 */
function canManage(member, guild, event, permission) {
    if (isGuildAdmin(member, guild)) return true;
    if (!event || !event.eventManagerRoleId) return false;
    const hasRole = member?.roles?.cache?.has?.(event.eventManagerRoleId) === true;
    if (!hasRole) return false;
    const perms = Array.isArray(event.eventPermissions) ? event.eventPermissions : [];
    return perms.length === 0 || perms.includes(permission);
}

/**
 * Parse a member-supplied time. Accepts ISO-8601 and `YYYY-MM-DD HH:MM`
 * (interpreted as UTC). Returns a Date or null — never a guessed date.
 */
function parseWhen(input) {
    if (!input) return null;
    const raw = String(input).trim();
    if (!raw) return null;
    const iso = new Date(raw);
    if (!Number.isNaN(iso.getTime()) && /[tT]|Z|[+-]\d{2}:?\d{2}$/.test(raw)) return iso;
    const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?$/);
    if (m) {
        const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4] || 0), Number(m[5] || 0)));
        return Number.isNaN(d.getTime()) ? null : d;
    }
    return Number.isNaN(iso.getTime()) ? null : iso;
}

function fmt(iso) {
    if (!iso) return 'Not scheduled';
    const ms = new Date(iso).getTime();
    if (!Number.isFinite(ms)) return 'Not scheduled';
    return `<t:${Math.floor(ms / 1000)}:F> (<t:${Math.floor(ms / 1000)}:R>)`;
}

function summaryEmbed(event, counts = null) {
    const embed = buildEventEmbed(event, counts ? {
        participants: counts.registered,
        interested: counts.interested,
        checkedIn: counts.present,
    } : {});
    embed.footer = { text: `Event #${event.id} • ${config.version}` };
    return embed;
}

function listEmbed(events, guildId, label) {
    const embed = new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle(`📅 Events — ${label}`)
        .setFooter({ text: `PrimeBot Events • ${config.version}` });
    if (!events.length) {
        embed.setDescription('No events found. Create one with `event create`.');
        return embed;
    }
    const lines = events.slice(0, 15).map(ev => {
        const status = eventStatusMeta(ev.status);
        const type = eventTypeMeta(ev.type);
        const count = ev.participantCount != null ? ` • ${ev.participantCount} going` : '';
        return `**#${ev.id}** ${type.icon} **${ev.name}**\n${status.icon} ${status.label} • ${fmt(ev.startAt)}${count}`;
    });
    embed.setDescription(lines.join('\n\n'));
    return embed;
}

function usageEmbed(prefix) {
    const p = prefix || '/';
    return new EmbedBuilder()
        .setColor(config.colors.primary)
        .setTitle('📅 Event Management')
        .setDescription('Create, run and manage community events. Premium event tools, free for everyone.')
        .addFields(
            { name: 'Members', value: `\`${p}event list\` • \`${p}event info <id>\` • \`${p}event join <id>\` • \`${p}event leave <id>\`` },
            { name: 'Organizers', value: `\`${p}event create\` • \`${p}event edit <id>\` • \`${p}event config <id>\` • \`${p}event reminders <id> 24h,1h\`` },
            { name: 'Administrators', value: `\`${p}event cancel <id> [reason]\` • \`${p}event delete <id>\`` },
            { name: 'Dashboard', value: 'Configure everything visually in the dashboard → Event Management.' },
        )
        .setFooter({ text: `Version ${config.version}` });
}

async function resolveEvent(guildId, idOrNull, { newest = false } = {}) {
    if (idOrNull) {
        const id = parseInt(idOrNull, 10);
        if (!Number.isFinite(id)) return null;
        const ev = await repo.getEvent(id);
        return ev && String(ev.guildId) === String(guildId) ? ev : null;
    }
    if (!newest) return null;
    const { events } = await repo.getGuildEvents(guildId, { limit: 1, sort: 'updated' });
    return events[0] || null;
}

function parseCsv(input, allowed) {
    if (!input) return [];
    const set = new Set(String(input).split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean));
    return allowed.filter(k => set.has(k));
}

const CHANNEL_MENTION = /^<#(\d+)>$/;
const ROLE_MENTION = /^<@&(\d+)>$/;

/**
 * Parse prefix-command arguments into the same `params` shape the slash
 * adapter produces. Supports `key=value` tokens (channel=#general, max=50,
 * start="2026-12-01 18:00", role=@Staff) plus the positional id first.
 */
function parsePrefixArgs(action, args = []) {
    const params = {};
    const kv = {};
    const positional = [];
    for (const token of args) {
        const m = /^([a-z_]+)=(.+)$/i.exec(String(token));
        if (m) kv[m[1].toLowerCase()] = m[2];
        else positional.push(String(token));
    }
    const channel = (v) => (CHANNEL_MENTION.exec(String(v || '')) || [])[1] || null;
    const role = (v) => (ROLE_MENTION.exec(String(v || '')) || [])[1] || null;

    if (action === 'create') {
        // $event create Name | 2026-12-01 18:00 | 120 | gaming | #voice | 50
        const parts = positional.join(' ').split('|').map(s => s.trim());
        params.name = parts[0] || kv.name || '';
        params.start = parts[1] || kv.start || '';
        if (parts[2] || kv.duration) params.duration = parseInt(parts[2] || kv.duration, 10);
        if (parts[3] || kv.type) params.type = (parts[3] || kv.type).toLowerCase();
        if (parts[4] || kv.channel) params.channel = channel(parts[4] || kv.channel);
        if (parts[5] || kv.max) params.max = parseInt(parts[5] || kv.max, 10);
        if (kv.announce) params.announceChannel = channel(kv.announce);
        if (kv.recurrence) params.recurrence = kv.recurrence.toLowerCase();
        if (kv.description) params.description = kv.description;
        return params;
    }

    if (['edit', 'cancel', 'delete', 'reminders', 'config', 'info', 'join', 'leave'].includes(action)) {
        const id = parseInt(positional[0] || kv.event || kv.id, 10);
        if (Number.isFinite(id)) params.eventId = id;
    }
    if (action === 'cancel') params.reason = positional.slice(1).join(' ') || kv.reason || null;
    if (action === 'reminders') params.reminders = positional[1] || kv.reminders || '';
    if (action === 'list') params.status = (positional[0] || kv.status || 'all').toLowerCase();
    if (action === 'edit' || action === 'config') {
        if (kv.name) params.name = kv.name;
        if (kv.description) params.description = kv.description;
        if (kv.start) params.start = kv.start;
        if (kv.duration) params.duration = parseInt(kv.duration, 10);
        if (kv.channel) params.channel = channel(kv.channel);
        if (kv.announce) params.announceChannel = channel(kv.announce);
        if (kv.max) params.max = parseInt(kv.max, 10);
        if (kv.recurrence) params.recurrence = kv.recurrence.toLowerCase();
        if (kv.registration) params.registrationMode = kv.registration.toLowerCase();
        if (kv.role) params.managerRole = role(kv.role);
    }
    return params;
}

/**
 * Execute one event action. Returns `{ ok, message, embed, ephemeral }`.
 *
 * `params` is a plain object supplied by the slash-command adapter or parsed by
 * the prefix adapter — never trusted for guild identity (the caller's guild is
 * always used).
 */
async function executeEventAction(client, { action, guild, member, params = {} }) {
    const mgr = client.eventMgmtManager;
    const userId = member?.id;
    const username = member?.user?.username || null;
    const needsManager = PERMISSION_FOR_ACTION[action];

    if (needsManager) {
        const event = params.eventId || params.id
            ? await resolveEvent(guild.id, params.eventId || params.id)
            : null;
        if (!canManage(member, guild, event, needsManager)) {
            return { ok: false, ephemeral: true, message: 'You do not have permission to manage events in this server.' };
        }
    }

    switch (action) {
        case 'create': {
            const startAt = parseWhen(params.start);
            if (!params.name) return { ok: false, ephemeral: true, message: 'An event name is required.' };
            if (!startAt) return { ok: false, ephemeral: true, message: 'Provide a start time, e.g. `2026-12-01 18:00` (UTC).' };
            if (!canManage(member, guild, null, 'manage_events')) {
                return { ok: false, ephemeral: true, message: 'You do not have permission to create events.' };
            }
            const duration = Number(params.duration) > 0 ? Number(params.duration) : 120;
            const endAt = new Date(startAt.getTime() + duration * 60000);
            const locationType = params.channel ? 'voice' : (params.locationType || 'none');
            const event = await repo.createEvent(guild.id, {
                name: params.name,
                description: params.description || null,
                type: params.type || 'custom',
                startAt,
                endAt,
                locationType,
                locationValue: params.channel || params.locationValue || null,
                announcementChannelId: params.announceChannel || null,
                maxParticipants: params.max ? Number(params.max) : null,
                registrationMode: params.registrationMode || 'open',
                recurrence: params.recurrence || 'none',
                syncScheduledEvent: params.syncScheduledEvent !== false,
                status: 'draft',
            }, userId);
            await repo.addActivity(event.id, guild.id, {
                userId, username, action: 'event_created', detail: event.name,
            }).catch(() => {});
            let published = false;
            if (params.publish !== false) {
                const target = event.announcementChannelId ? 'registration_open' : 'scheduled';
                await repo.updateEvent(event.id, { status: target }).catch(() => null);
                published = true;
            }
            const fresh = await repo.getEvent(event.id);
            return {
                ok: true,
                message: published
                    ? `Event **${fresh.name}** created (#${fresh.id}).`
                    : `Event **${fresh.name}** saved as a draft (#${fresh.id}).`,
                embed: summaryEmbed(fresh),
            };
        }

        case 'edit': {
            const event = await resolveEvent(guild.id, params.eventId);
            if (!event) return { ok: false, ephemeral: true, message: 'Event not found in this server.' };
            const patch = {};
            if (params.name) patch.name = params.name;
            if (params.description != null) patch.description = params.description;
            if (params.start) {
                const startAt = parseWhen(params.start);
                if (!startAt) return { ok: false, ephemeral: true, message: 'Invalid start time.' };
                patch.startAt = startAt;
                const duration = Number(params.duration) > 0 ? Number(params.duration) : null;
                if (duration) patch.endAt = new Date(startAt.getTime() + duration * 60000);
            } else if (Number(params.duration) > 0 && event.startAt) {
                patch.endAt = new Date(new Date(event.startAt).getTime() + Number(params.duration) * 60000);
            }
            if (params.channel) { patch.locationType = 'voice'; patch.locationValue = params.channel; }
            if (params.announceChannel) patch.announcementChannelId = params.announceChannel;
            if (params.max != null) patch.maxParticipants = params.max ? Number(params.max) : null;
            if (params.recurrence) patch.recurrence = params.recurrence;
            if (params.registrationMode) patch.registrationMode = params.registrationMode;
            if (!Object.keys(patch).length) {
                return { ok: false, ephemeral: true, message: 'Nothing to change. Provide at least one option.' };
            }
            const updated = await repo.updateEvent(event.id, patch);
            await repo.addActivity(event.id, guild.id, { userId, username, action: 'event_edited' }).catch(() => {});
            await mgr?.updateAnnouncement?.(event.id).catch?.(() => {});
            return { ok: true, message: `Event **${updated.name}** updated.`, embed: summaryEmbed(updated) };
        }

        case 'cancel': {
            const event = await resolveEvent(guild.id, params.eventId);
            if (!event) return { ok: false, ephemeral: true, message: 'Event not found in this server.' };
            const updated = await mgr.cancelEvent(event.id, {
                notify: true, reason: params.reason || null, userId, username,
            });
            return { ok: true, message: `Event **${updated.name}** cancelled.`, embed: summaryEmbed(updated) };
        }

        case 'delete': {
            const event = await resolveEvent(guild.id, params.eventId);
            if (!event) return { ok: false, ephemeral: true, message: 'Event not found in this server.' };
            await mgr.deleteScheduledEvent?.(event).catch?.(() => {});
            await repo.deleteEvent(event.id);
            return { ok: true, message: `Event **${event.name}** deleted.` };
        }

        case 'list': {
            const status = params.status && params.status !== 'all' ? normalizeEventStatus(params.status) : null;
            const { events } = await repo.getGuildEvents(guild.id, { status, limit: 15, sort: 'start' });
            const label = status ? eventStatusMeta(status).label : 'All';
            return { ok: true, embed: listEmbed(events, guild.id, label), ephemeral: true };
        }

        case 'info': {
            const event = await resolveEvent(guild.id, params.eventId, { newest: true });
            if (!event) return { ok: false, ephemeral: true, message: 'No events found in this server.' };
            const counts = await repo.getParticipantCounts(event.id);
            return { ok: true, embed: summaryEmbed(event, counts), ephemeral: true };
        }

        case 'join': {
            const event = await resolveEvent(guild.id, params.eventId, { newest: true });
            if (!event) return { ok: false, ephemeral: true, message: 'No events found in this server.' };
            const res = await mgr.setRsvp(event.id, member, 'going');
            return { ok: res.ok, message: res.message, ephemeral: true };
        }

        case 'leave': {
            const event = await resolveEvent(guild.id, params.eventId, { newest: true });
            if (!event) return { ok: false, ephemeral: true, message: 'No events found in this server.' };
            const res = await mgr.setRsvp(event.id, member, 'not_going');
            return { ok: res.ok, message: res.message, ephemeral: true };
        }

        case 'config': {
            const event = await resolveEvent(guild.id, params.eventId, { newest: true });
            if (!event) return { ok: false, ephemeral: true, message: 'Create an event first — there is nothing to configure.' };
            const patch = {};
            if (params.announceChannel) patch.announcementChannelId = params.announceChannel;
            if (params.managerRole) patch.eventManagerRoleId = params.managerRole;
            if (params.max != null) patch.maxParticipants = params.max ? Number(params.max) : null;
            if (params.registrationMode) patch.registrationMode = params.registrationMode;
            if (!Object.keys(patch).length) {
                const lines = [
                    `**Announcement channel:** ${event.announcementChannelId ? `<#${event.announcementChannelId}>` : 'not set'}`,
                    `**Event Manager role:** ${event.eventManagerRoleId ? `<@&${event.eventManagerRoleId}>` : 'not set'}`,
                    `**Max participants:** ${event.maxParticipants || 'unlimited'}`,
                    `**Registration:** ${event.registrationMode}`,
                    `**Manager permissions:** ${(event.eventPermissions || []).join(', ') || 'all'}`,
                ];
                return { ok: true, ephemeral: true, message: `Event #${event.id} configuration\n${lines.join('\n')}` };
            }
            const updated = await repo.updateEvent(event.id, patch);
            return { ok: true, message: `Event #${updated.id} configuration saved.`, embed: summaryEmbed(updated) };
        }

        case 'reminders': {
            const event = await resolveEvent(guild.id, params.eventId);
            if (!event) return { ok: false, ephemeral: true, message: 'Event not found in this server.' };
            const keys = parseCsv(params.reminders, REMINDER_KEYS);
            const updated = await repo.updateEvent(event.id, { reminders: keys });
            return {
                ok: true,
                message: keys.length
                    ? `Reminders set for **${updated.name}**: ${keys.join(', ')}.`
                    : `All reminders disabled for **${updated.name}**.`,
                embed: summaryEmbed(updated),
            };
        }

        default:
            return { ok: false, ephemeral: true, message: 'Unknown event action.' };
    }
}

module.exports = {
    executeEventAction,
    canManage,
    isGuildAdmin,
    parseWhen,
    summaryEmbed,
    listEmbed,
    usageEmbed,
    resolveEvent,
    parsePrefixArgs,
    EVENT_TYPE_KEYS,
    EVENT_STATUSES,
    RECURRENCE_KEYS,
    REMINDER_KEYS,
    REGISTRATION_MODES,
};
