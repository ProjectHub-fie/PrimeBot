/**
 * Shared Event Management message/component builders.
 *
 * Builds the Discord API payloads (embed + interactive component rows) used by
 * the bot's EventMgmtManager to post and update an event's announcement. Pure
 * (no discord.js, no DB) so it can be unit-tested and reused by the dashboard's
 * live preview.
 *
 * Button customIds (routed in events/interactionCreate.js):
 *   evjoin:<eventId>    — register for the event
 *   evleave:<eventId>   — leave the event
 *   evparts:<eventId>   — view the participant list (ephemeral)
 *   evinfo:<eventId>    — view event details (ephemeral)
 *   evremind:<eventId>  — toggle a personal reminder (ephemeral)
 * customIds are ≤100 chars (numeric ids only), so this is always safe.
 */

const { eventTypeMeta, eventStatusMeta } = require('./eventConstants');

const BRAND_FOOTER = 'PrimeBot Events';

function colorToInt(hex) {
    if (typeof hex === 'number' && Number.isFinite(hex)) return hex & 0xffffff;
    if (typeof hex === 'string' && /^#[0-9a-fA-F]{6}$/.test(hex)) return parseInt(hex.slice(1), 16);
    return 0x5865f2;
}

function truncate(str, max) {
    if (typeof str !== 'string') return '';
    return str.length > max ? str.slice(0, max) : str;
}

/** Discord relative timestamp, e.g. <t:1700000000:R> / :F for absolute. */
function discordTimestamp(date, style = 'F') {
    const ms = date instanceof Date ? date.getTime() : new Date(date).getTime();
    if (!Number.isFinite(ms)) return '';
    return `<t:${Math.floor(ms / 1000)}:${style}>`;
}

function locationLabel(event) {
    const type = event.locationType || 'none';
    const value = event.locationValue ? String(event.locationValue) : '';
    switch (type) {
        case 'voice':
        case 'stage':
        case 'text':
            return value ? `<#${value}>` : null;
        case 'external':
            return value ? `[${truncate(value, 100)}](${value})` : null;
        case 'custom':
            return value || null;
        default:
            return null;
    }
}

function registrationLabel(event) {
    if (event.status === 'cancelled') return '❌ Cancelled';
    if (event.status === 'completed') return '✅ Completed';
    if (event.status === 'live') return '🔴 Live now';
    if (event.registrationMode === 'closed') return '🔒 Registration closed';
    if (event.registrationMode === 'invite') return '✉️ Invite only';
    if (event.status === 'registration_open') return '🟢 Registration open';
    if (event.status === 'scheduled') return '🗓️ Scheduled';
    return '📝 Draft';
}

/**
 * Build the announcement embed (Discord API embed object).
 *
 * @param {object} event        Event config (camelCase as stored).
 * @param {object} [stats]      { participants, maxParticipants, checkedIn }
 */
function buildEventEmbed(event, stats = {}) {
    const type = eventTypeMeta(event.type);
    const status = eventStatusMeta(event.status);
    const color = event.embedColor || type.color || status.color;

    const embed = {
        title: truncate(event.embedTitle || `${type.icon} ${event.name}`, 256),
        color: colorToInt(color),
    };
    const description = event.embedDescription || event.description || '';
    if (description) embed.description = truncate(description, 4096);

    const fields = [];
    fields.push({ name: '📅 When', value: event.startAt ? `${discordTimestamp(event.startAt, 'F')}\n${discordTimestamp(event.startAt, 'R')}` : 'Not scheduled', inline: true });
    if (event.endAt) fields.push({ name: '🏁 Ends', value: `${discordTimestamp(event.endAt, 'F')}`, inline: true });
    const loc = locationLabel(event);
    fields.push({ name: '📍 Where', value: loc || 'Not set', inline: true });

    if (stats.participants != null) {
        const max = event.maxParticipants ? ` / ${event.maxParticipants}` : '';
        fields.push({ name: '👥 Participants', value: `${stats.participants}${max}`, inline: true });
    }
    if (event.trackAttendance && stats.checkedIn != null) {
        fields.push({ name: '✅ Checked in', value: String(stats.checkedIn), inline: true });
    }
    fields.push({ name: '🎟️ Registration', value: registrationLabel(event), inline: true });

    if (Array.isArray(event.embedFields)) {
        for (const f of event.embedFields.slice(0, 25 - fields.length)) {
            if (!f || (!f.name && !f.value)) continue;
            fields.push({ name: truncate(f.name, 256) || '\u200b', value: truncate(f.value, 1024) || '\u200b', inline: !!f.inline });
        }
    }
    embed.fields = fields.slice(0, 25);

    if (event.imageUrl) embed.image = { url: event.imageUrl };
    if (event.thumbnailUrl) embed.thumbnail = { url: event.thumbnailUrl };
    embed.footer = { text: event.embedFooter ? truncate(event.embedFooter, 2048) : BRAND_FOOTER };
    embed.timestamp = new Date(event.updatedAt ? new Date(event.updatedAt) : Date.now()).toISOString();
    return embed;
}

/**
 * Build the interactive component rows for an announcement.
 * Returns [] when the event is cancelled/completed (nothing to interact with).
 */
function buildEventComponents(event) {
    const id = String(event.id);
    const joinable = event.registrationMode !== 'closed'
        && event.status !== 'cancelled'
        && event.status !== 'completed';

    const row1 = [];
    if (joinable) {
        row1.push({ type: 2, style: 3, custom_id: `evjoin:${id}`, label: 'Join Event', emoji: { name: '🎟️' } });
        row1.push({ type: 2, style: 2, custom_id: `evleave:${id}`, label: 'Leave', emoji: { name: '🚪' } });
    }
    if (event.trackAttendance && event.status === 'live') {
        row1.push({ type: 2, style: 1, custom_id: `evcheckin:${id}`, label: 'Check In', emoji: { name: '✅' } });
    }
    row1.push({ type: 2, style: 2, custom_id: `evparts:${id}`, label: 'Participants', emoji: { name: '👥' } });
    row1.push({ type: 2, style: 2, custom_id: `evinfo:${id}`, label: 'Event Info', emoji: { name: 'ℹ️' } });
    row1.push({ type: 2, style: 2, custom_id: `evremind:${id}`, label: 'Remind Me', emoji: { name: '🔔' } });

    const rows = [];
    for (let i = 0; i < row1.length; i += 5) {
        rows.push({ type: 1, components: row1.slice(i, i + 5) });
    }
    return rows;
}

/** The announcement message payload. */
function buildAnnouncementPayload(event, stats = {}) {
    return {
        embeds: [buildEventEmbed(event, stats)],
        components: buildEventComponents(event),
        allowed_mentions: { parse: [] },
    };
}

/** Reminder message payload posted at (start - offsetMinutes). */
function buildReminderPayload(event, minutes) {
    const label = minutes >= 60 ? `${Math.round(minutes / 60)} hour${minutes >= 120 ? 's' : ''}` : `${minutes} minute${minutes === 1 ? '' : 's'}`;
    const when = event.startAt ? discordTimestamp(event.startAt, 'R') : 'soon';
    return {
        content: `🔔 **${event.name}** starts in ${label} (${when}).`,
        embeds: [buildEventEmbed(event, {})],
        components: buildEventComponents(event),
        allowed_mentions: { parse: [] },
    };
}

/** Participant list embed (used by the "Participants" button, ephemeral). */
function buildParticipantsEmbed(event, participants = []) {
    const type = eventTypeMeta(event.type);
    const registered = participants.filter(p => p.status === 'registered');
    const lines = registered.slice(0, 50).map((p, i) => {
        const check = p.attendanceStatus === 'present' ? ' ✅' : (p.attendanceStatus === 'absent' ? ' ❌' : '');
        return `${i + 1}. <@${p.userId}>${check}`;
    });
    const embed = {
        title: truncate(`👥 ${event.name} — Participants`, 256),
        color: colorToInt(type.color),
        description: lines.join('\n') || 'No one has registered yet.',
        footer: { text: BRAND_FOOTER },
    };
    if (event.maxParticipants) {
        embed.fields = [{ name: 'Slots', value: `${registered.length} / ${event.maxParticipants}`, inline: true }];
    }
    return embed;
}

module.exports = {
    BRAND_FOOTER,
    colorToInt,
    discordTimestamp,
    locationLabel,
    registrationLabel,
    buildEventEmbed,
    buildEventComponents,
    buildAnnouncementPayload,
    buildReminderPayload,
    buildParticipantsEmbed,
};
