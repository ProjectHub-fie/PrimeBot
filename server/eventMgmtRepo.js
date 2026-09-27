/**
 * Event Management repository — validated CRUD against the em_* tables.
 *
 * Shared by the dashboard (dashboard/db.js re-exports these) and the bot's
 * EventMgmtManager (which builds its in-memory cache from getGuildEvents).
 * Keeping all SQL + normalization here means the two sides can never drift.
 *
 * Neon notes: every list query is bounded (LIMIT/OFFSET), every write is a
 * single statement, and the reminders due-query uses the partial index
 * em_reminders_due_idx. No per-second scans.
 */

const { eventMgmtPool, ensureEventMgmtTables } = require('./eventMgmtDb');
const {
    normalizeEventType, normalizeEventStatus, canTransition,
    normalizeRegistrationMode, normalizeLocationType,
    REMINDER_PRESETS, REMINDER_KEYS,
    normalizeParticipantStatus, normalizeAttendanceStatus,
    normalizeEventPermissions,
} = require('../shared/eventConstants');

const MAX_NAME = 100;

function toIntOrNull(v) {
    const n = parseInt(v, 10);
    return Number.isFinite(n) ? n : null;
}

/** Parse a date-ish value to a Date or null. */
function toDate(v) {
    if (v == null || v === '') return null;
    const d = v instanceof Date ? v : new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
}

function sanitizeUrl(v) {
    if (!v || typeof v !== 'string') return null;
    const s = v.trim();
    if (!s) return null;
    try {
        const u = new URL(s);
        return (u.protocol === 'http:' || u.protocol === 'https:') ? s : null;
    } catch {
        return null;
    }
}

function normalizeEmbedFields(raw) {
    if (!Array.isArray(raw)) return [];
    return raw.slice(0, 25).map(f => ({
        name: String((f && f.name) || '').slice(0, 256),
        value: String((f && f.value) || '').slice(0, 1024),
        inline: !!(f && f.inline),
    }));
}

function normalizeReminders(raw) {
    if (!Array.isArray(raw)) return [];
    const seen = new Set();
    const out = [];
    for (const k of raw) {
        const key = String(k);
        if (REMINDER_KEYS.includes(key) && !seen.has(key)) { seen.add(key); out.push(key); }
    }
    return out;
}

/**
 * Normalize/validate an event config. `existing` supplies defaults for a patch;
 * for a create pass null. Never trusts client values.
 */
function normalizeEventConfig(data, existing = null) {
    const src = data && typeof data === 'object' ? data : {};
    const base = existing || {};
    const has = (k) => Object.prototype.hasOwnProperty.call(src, k);

    const name = has('name')
        ? (String(src.name || '').trim().slice(0, MAX_NAME) || base.name || 'Untitled Event')
        : (base.name || 'Untitled Event');

    const startAt = has('startAt') ? toDate(src.startAt) : (base.startAt || null);
    let endAt = has('endAt') ? toDate(src.endAt) : (base.endAt || null);
    // An end before the start is meaningless — drop it rather than store nonsense.
    if (endAt && startAt && endAt.getTime() <= startAt.getTime()) endAt = null;

    const registrationDeadline = has('registrationDeadline')
        ? toDate(src.registrationDeadline)
        : (base.registrationDeadline || null);

    const maxParticipants = has('maxParticipants')
        ? (src.maxParticipants === null || src.maxParticipants === '' ? null : Math.max(1, toIntOrNull(src.maxParticipants) || 1))
        : (base.maxParticipants || null);

    const out = {
        name,
        description: has('description') ? (src.description == null ? null : String(src.description).slice(0, 8000)) : (base.description || null),
        type: has('type') ? normalizeEventType(src.type) : (base.type || 'custom'),
        status: has('status') ? normalizeEventStatus(src.status) : (base.status || 'draft'),
        startAt,
        endAt,
        timezone: has('timezone') ? String(src.timezone || 'UTC').slice(0, 64) : (base.timezone || 'UTC'),
        locationType: has('locationType') ? normalizeLocationType(src.locationType) : (base.locationType || 'none'),
        locationValue: has('locationValue') ? (src.locationValue == null ? null : String(src.locationValue).slice(0, 500)) : (base.locationValue || null),
        registrationMode: has('registrationMode') ? normalizeRegistrationMode(src.registrationMode) : (base.registrationMode || 'open'),
        maxParticipants,
        waitlistEnabled: has('waitlistEnabled') ? !!src.waitlistEnabled : (base.waitlistEnabled !== false),
        registrationDeadline,
        trackAttendance: has('trackAttendance') ? !!src.trackAttendance : !!base.trackAttendance,
        announcementChannelId: has('announcementChannelId') ? (src.announcementChannelId || null) : (base.announcementChannelId || null),
        participantRoleId: has('participantRoleId') ? (src.participantRoleId || null) : (base.participantRoleId || null),
        staffRoleId: has('staffRoleId') ? (src.staffRoleId || null) : (base.staffRoleId || null),
        winnerRoleId: has('winnerRoleId') ? (src.winnerRoleId || null) : (base.winnerRoleId || null),
        attendanceRoleId: has('attendanceRoleId') ? (src.attendanceRoleId || null) : (base.attendanceRoleId || null),
        eventManagerRoleId: has('eventManagerRoleId') ? (src.eventManagerRoleId || null) : (base.eventManagerRoleId || null),
        eventPermissions: has('eventPermissions') ? normalizeEventPermissions(src.eventPermissions) : (base.eventPermissions || []),
        imageUrl: has('imageUrl') ? sanitizeUrl(src.imageUrl) : (base.imageUrl || null),
        thumbnailUrl: has('thumbnailUrl') ? sanitizeUrl(src.thumbnailUrl) : (base.thumbnailUrl || null),
        embedTitle: has('embedTitle') ? (src.embedTitle == null ? null : String(src.embedTitle).slice(0, 256)) : (base.embedTitle || null),
        embedDescription: has('embedDescription') ? (src.embedDescription == null ? null : String(src.embedDescription).slice(0, 4096)) : (base.embedDescription || null),
        embedColor: has('embedColor')
            ? (/^#[0-9a-fA-F]{6}$/.test(String(src.embedColor)) ? String(src.embedColor) : (base.embedColor || '#5865F2'))
            : (base.embedColor || '#5865F2'),
        embedFields: has('embedFields') ? normalizeEmbedFields(src.embedFields) : (base.embedFields || []),
        embedFooter: has('embedFooter') ? (src.embedFooter == null ? null : String(src.embedFooter).slice(0, 255)) : (base.embedFooter || null),
        reminders: has('reminders') ? normalizeReminders(src.reminders) : (base.reminders || []),
    };
    return out;
}

// ── Row mappers ─────────────────────────────────────────────────────────────
function rowToEvent(row) {
    if (!row) return null;
    return {
        id: row.id,
        guildId: row.guild_id,
        creatorId: row.creator_id || null,
        name: row.name,
        description: row.description || null,
        type: row.type || 'custom',
        status: row.status || 'draft',
        startAt: row.start_at ? new Date(row.start_at).toISOString() : null,
        endAt: row.end_at ? new Date(row.end_at).toISOString() : null,
        timezone: row.timezone || 'UTC',
        locationType: row.location_type || 'none',
        locationValue: row.location_value || null,
        registrationMode: row.registration_mode || 'open',
        maxParticipants: row.max_participants == null ? null : Number(row.max_participants),
        waitlistEnabled: row.waitlist_enabled !== false,
        registrationDeadline: row.registration_deadline ? new Date(row.registration_deadline).toISOString() : null,
        trackAttendance: row.track_attendance === true,
        announcementChannelId: row.announcement_channel_id || null,
        announcementMessageId: row.announcement_message_id || null,
        participantRoleId: row.participant_role_id || null,
        staffRoleId: row.staff_role_id || null,
        winnerRoleId: row.winner_role_id || null,
        attendanceRoleId: row.attendance_role_id || null,
        eventManagerRoleId: row.event_manager_role_id || null,
        eventPermissions: Array.isArray(row.event_permissions) ? row.event_permissions : [],
        imageUrl: row.image_url || null,
        thumbnailUrl: row.thumbnail_url || null,
        embedTitle: row.embed_title || null,
        embedDescription: row.embed_description || null,
        embedColor: row.embed_color || '#5865F2',
        embedFields: Array.isArray(row.embed_fields) ? row.embed_fields : [],
        embedFooter: row.embed_footer || null,
        reminders: Array.isArray(row.reminders) ? row.reminders : [],
        result: row.result || null,
        // Only populated by getGuildEvents (list query); null elsewhere.
        participantCount: row.participation_count == null ? null : Number(row.participation_count),
        createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
        updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
    };
}

function rowToParticipant(row) {
    if (!row) return null;
    return {
        id: row.id,
        eventId: row.event_id,
        guildId: row.guild_id,
        userId: row.user_id,
        username: row.username || null,
        status: row.status || 'registered',
        role: row.role || 'participant',
        attendanceStatus: row.attendance_status || 'unknown',
        checkedInAt: row.checked_in_at ? new Date(row.checked_in_at).toISOString() : null,
        registeredAt: row.registered_at ? new Date(row.registered_at).toISOString() : null,
        updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
    };
}

function rowToActivity(row) {
    return {
        id: row.id,
        eventId: row.event_id,
        guildId: row.guild_id,
        userId: row.user_id || null,
        username: row.username || null,
        action: row.action,
        detail: row.detail || null,
        createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
    };
}

const EVENT_COLUMNS = [
    'guild_id', 'creator_id', 'name', 'description', 'type', 'status', 'start_at', 'end_at', 'timezone',
    'location_type', 'location_value', 'registration_mode', 'max_participants', 'waitlist_enabled',
    'registration_deadline', 'track_attendance', 'announcement_channel_id', 'participant_role_id',
    'staff_role_id', 'winner_role_id', 'attendance_role_id', 'event_manager_role_id', 'event_permissions',
    'image_url', 'thumbnail_url', 'embed_title', 'embed_description', 'embed_color', 'embed_fields',
    'embed_footer', 'reminders',
];

function configToValues(guildId, cfg, creatorId) {
    return [
        guildId, creatorId || null, cfg.name, cfg.description, cfg.type, cfg.status, cfg.startAt, cfg.endAt,
        cfg.timezone, cfg.locationType, cfg.locationValue, cfg.registrationMode, cfg.maxParticipants,
        cfg.waitlistEnabled, cfg.registrationDeadline, cfg.trackAttendance, cfg.announcementChannelId,
        cfg.participantRoleId, cfg.staffRoleId, cfg.winnerRoleId, cfg.attendanceRoleId, cfg.eventManagerRoleId,
        JSON.stringify(cfg.eventPermissions || []), cfg.imageUrl, cfg.thumbnailUrl, cfg.embedTitle,
        cfg.embedDescription, cfg.embedColor, JSON.stringify(cfg.embedFields || []), cfg.embedFooter,
        JSON.stringify(cfg.reminders || []),
    ];
}

// ── Events ──────────────────────────────────────────────────────────────────
async function createEvent(guildId, data, creatorId = null) {
    await ensureEventMgmtTables();
    const cfg = normalizeEventConfig(data, { status: 'draft', eventPermissions: normalizeEventPermissions([]) });
    const placeholders = EVENT_COLUMNS.map((_, i) => `$${i + 1}`).join(',');
    const res = await eventMgmtPool.query(
        `INSERT INTO em_events (${EVENT_COLUMNS.join(',')}) VALUES (${placeholders}) RETURNING *`,
        configToValues(guildId, cfg, creatorId)
    );
    const event = rowToEvent(res.rows[0]);
    await replaceReminderRows(event);
    return event;
}

async function getEvent(id) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query('SELECT * FROM em_events WHERE id = $1', [id]);
    return rowToEvent(res.rows[0]);
}

/**
 * Bounded, filterable, sortable guild event list (server-side pagination).
 * Returns { events, total }.
 */
async function getGuildEvents(guildId, { status = null, search = null, sort = 'start', limit = 50, offset = 0 } = {}) {
    await ensureEventMgmtTables();
    const where = ['e.guild_id = $1'];
    const params = [guildId];
    if (status) { params.push(status); where.push(`e.status = $${params.length}`); }
    if (search) { params.push(`%${String(search).slice(0, 100)}%`); where.push(`e.name ILIKE $${params.length}`); }
    const whereSql = `WHERE ${where.join(' AND ')}`;

    const sortMap = {
        start: 'e.start_at ASC NULLS LAST, e.id DESC',
        created: 'e.created_at DESC, e.id DESC',
        participants: 'participation_count DESC, e.id DESC',
        updated: 'e.updated_at DESC, e.id DESC',
    };
    const orderSql = sortMap[sort] || sortMap.start;

    const totalRes = await eventMgmtPool.query(`SELECT COUNT(*)::int AS total FROM em_events e ${whereSql}`, params);

    const lim = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 100);
    const off = Math.max(parseInt(offset, 10) || 0, 0);
    params.push(lim, off);
    const res = await eventMgmtPool.query(
        `SELECT e.*, (
             SELECT COUNT(*)::int FROM em_participants p
             WHERE p.event_id = e.id AND p.status = 'registered'
         ) AS participation_count
         FROM em_events e
         ${whereSql}
         ORDER BY ${orderSql}
         LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params
    );
    return { events: res.rows.map(rowToEvent), total: totalRes.rows[0].total };
}

/** All events for a guild (bot cache load — bounded to keep Neon cheap). */
async function getAllGuildEvents(guildId, limit = 500) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        `SELECT * FROM em_events WHERE guild_id = $1 ORDER BY id DESC LIMIT $2`,
        [guildId, Math.min(Math.max(parseInt(limit, 10) || 500, 1), 1000)]
    );
    return res.rows.map(rowToEvent);
}

async function updateEvent(id, patch) {
    await ensureEventMgmtTables();
    const existing = await getEvent(id);
    if (!existing) throw new Error('Event not found.');
    const cfg = normalizeEventConfig(patch, existing);

    // A status change (if present) must respect the lifecycle transitions.
    if (patch && patch.status != null && patch.status !== existing.status) {
        if (!canTransition(existing.status, cfg.status)) {
            const err = new Error(`Cannot move event from ${existing.status} to ${cfg.status}.`);
            err.status = 409;
            throw err;
        }
    }

    const sets = [];
    const params = [];
    const push = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };
    push('name', cfg.name);
    push('description', cfg.description);
    push('type', cfg.type);
    push('status', cfg.status);
    push('start_at', cfg.startAt);
    push('end_at', cfg.endAt);
    push('timezone', cfg.timezone);
    push('location_type', cfg.locationType);
    push('location_value', cfg.locationValue);
    push('registration_mode', cfg.registrationMode);
    push('max_participants', cfg.maxParticipants);
    push('waitlist_enabled', cfg.waitlistEnabled);
    push('registration_deadline', cfg.registrationDeadline);
    push('track_attendance', cfg.trackAttendance);
    push('announcement_channel_id', cfg.announcementChannelId);
    push('participant_role_id', cfg.participantRoleId);
    push('staff_role_id', cfg.staffRoleId);
    push('winner_role_id', cfg.winnerRoleId);
    push('attendance_role_id', cfg.attendanceRoleId);
    push('event_manager_role_id', cfg.eventManagerRoleId);
    push('event_permissions', JSON.stringify(cfg.eventPermissions || []));
    push('image_url', cfg.imageUrl);
    push('thumbnail_url', cfg.thumbnailUrl);
    push('embed_title', cfg.embedTitle);
    push('embed_description', cfg.embedDescription);
    push('embed_color', cfg.embedColor);
    push('embed_fields', JSON.stringify(cfg.embedFields || []));
    push('embed_footer', cfg.embedFooter);
    push('reminders', JSON.stringify(cfg.reminders || []));
    if (patch && patch.result !== undefined) push('result', patch.result ? JSON.stringify(patch.result) : null);

    params.push(id);
    const res = await eventMgmtPool.query(
        `UPDATE em_events SET ${sets.join(', ')}, updated_at = NOW() WHERE id = $${params.length} RETURNING *`,
        params
    );
    const event = rowToEvent(res.rows[0]);
    await replaceReminderRows(event);
    return event;
}

async function setAnnouncementMessage(id, channelId, messageId) {
    await ensureEventMgmtTables();
    await eventMgmtPool.query(
        `UPDATE em_events SET announcement_channel_id = $2, announcement_message_id = $3, updated_at = NOW() WHERE id = $1`,
        [id, channelId || null, messageId || null]
    );
}

async function deleteEvent(id) {
    await ensureEventMgmtTables();
    await eventMgmtPool.query('DELETE FROM em_events WHERE id = $1', [id]);
}

/**
 * Duplicate an event: copies configuration (name/description/type/location/
 * registration/reminders/embed design) but never participants, and starts as a
 * fresh draft with no schedule.
 */
async function duplicateEvent(id, creatorId = null) {
    const src = await getEvent(id);
    if (!src) throw new Error('Event not found.');
    const copy = { ...src, status: 'draft', startAt: null, endAt: null, registrationDeadline: null };
    copy.name = `${src.name} (copy)`.slice(0, MAX_NAME);
    const created = await createEvent(src.guildId, copy, creatorId);
    await addActivity(created.id, src.guildId, { action: 'event_duplicated', detail: `Duplicated from #${src.id}` });
    return created;
}

// ── Participants ────────────────────────────────────────────────────────────
async function getParticipants(eventId, { status = null, limit = 500 } = {}) {
    await ensureEventMgmtTables();
    const params = [eventId];
    let where = 'event_id = $1';
    if (status) { params.push(status); where += ` AND status = $${params.length}`; }
    params.push(Math.min(Math.max(parseInt(limit, 10) || 500, 1), 1000));
    const res = await eventMgmtPool.query(
        `SELECT * FROM em_participants WHERE ${where} ORDER BY registered_at ASC, id ASC LIMIT $${params.length}`,
        params
    );
    return res.rows.map(rowToParticipant);
}

async function countParticipants(eventId, status = 'registered') {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        `SELECT COUNT(*)::int AS n FROM em_participants WHERE event_id = $1 AND status = $2`,
        [eventId, status]
    );
    return res.rows[0].n;
}

async function getParticipant(eventId, userId) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        'SELECT * FROM em_participants WHERE event_id = $1 AND user_id = $2',
        [eventId, userId]
    );
    return rowToParticipant(res.rows[0]);
}

/** Insert or restore a participant. `status` defaults to registered. */
async function addParticipant(eventId, guildId, userId, { username = null, status = 'registered', role = 'participant' } = {}) {
    await ensureEventMgmtTables();
    const st = normalizeParticipantStatus(status);
    const res = await eventMgmtPool.query(
        `INSERT INTO em_participants (event_id, guild_id, user_id, username, status, role, registered_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6, NOW(), NOW())
         ON CONFLICT (event_id, user_id) DO UPDATE SET
            status = EXCLUDED.status, username = COALESCE(EXCLUDED.username, em_participants.username),
            role = EXCLUDED.role, updated_at = NOW()
         RETURNING *`,
        [eventId, guildId, userId, username, st, role]
    );
    return rowToParticipant(res.rows[0]);
}

async function updateParticipant(eventId, userId, patch = {}) {
    await ensureEventMgmtTables();
    const sets = [];
    const params = [eventId, userId];
    const push = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };
    if (patch.status != null) push('status', normalizeParticipantStatus(patch.status));
    if (patch.attendanceStatus != null) {
        push('attendance_status', normalizeAttendanceStatus(patch.attendanceStatus));
        push('checked_in_at', patch.attendanceStatus === 'present' ? new Date() : null);
    }
    if (patch.role != null) push('role', String(patch.role).slice(0, 20));
    if (patch.username != null) push('username', String(patch.username).slice(0, 100));
    if (!sets.length) return getParticipant(eventId, userId);
    const res = await eventMgmtPool.query(
        `UPDATE em_participants SET ${sets.join(', ')}, updated_at = NOW()
         WHERE event_id = $1 AND user_id = $2 RETURNING *`,
        params
    );
    return rowToParticipant(res.rows[0]);
}

async function removeParticipant(eventId, userId) {
    await ensureEventMgmtTables();
    await eventMgmtPool.query('DELETE FROM em_participants WHERE event_id = $1 AND user_id = $2', [eventId, userId]);
}

/** The oldest waiting-list member (for automatic promotion). */
async function getNextWaiting(eventId) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        `SELECT * FROM em_participants WHERE event_id = $1 AND status = 'waiting'
         ORDER BY registered_at ASC, id ASC LIMIT 1`,
        [eventId]
    );
    return rowToParticipant(res.rows[0]);
}

/** Promote the next waiting-list member to registered. Returns the row or null. */
async function promoteNextWaiting(eventId) {
    const next = await getNextWaiting(eventId);
    if (!next) return null;
    return updateParticipant(eventId, next.userId, { status: 'registered' });
}

// ── Reminders ───────────────────────────────────────────────────────────────
/** Rebuild the reminder rows for an event from its enabled preset keys. */
async function replaceReminderRows(event) {
    await ensureEventMgmtTables();
    const keys = normalizeReminders(event.reminders);
    // Drop any reminder rows whose key is no longer enabled.
    if (keys.length === 0) {
        await eventMgmtPool.query('DELETE FROM em_reminders WHERE event_id = $1', [event.id]);
        return;
    }
    await eventMgmtPool.query(
        `DELETE FROM em_reminders WHERE event_id = $1 AND key <> ALL($2::text[])`,
        [event.id, keys]
    );
    if (!event.startAt) return; // no schedule yet → nothing to send
    const start = new Date(event.startAt);
    for (const key of keys) {
        const preset = REMINDER_PRESETS.find(r => r.key === key);
        if (!preset) continue;
        const sendAt = new Date(start.getTime() - preset.minutes * 60 * 1000);
        await eventMgmtPool.query(
            `INSERT INTO em_reminders (event_id, guild_id, key, offset_minutes, send_at)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (event_id, key) DO UPDATE SET
                send_at = EXCLUDED.send_at, offset_minutes = EXCLUDED.offset_minutes,
                sent_at = CASE WHEN em_reminders.send_at IS DISTINCT FROM EXCLUDED.send_at THEN NULL ELSE em_reminders.sent_at END`,
            [event.id, event.guildId, key, preset.minutes, sendAt]
        );
    }
}

/** Due, not-yet-sent reminders (indexed query, bounded). */
async function getDueReminders(now = new Date(), limit = 50) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        `SELECT r.*, e.name AS event_name FROM em_reminders r
         WHERE r.sent_at IS NULL AND r.send_at <= $1
         ORDER BY r.send_at ASC LIMIT $2`,
        [now, Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200)]
    );
    return res.rows;
}

async function markReminderSent(id) {
    await ensureEventMgmtTables();
    await eventMgmtPool.query('UPDATE em_reminders SET sent_at = NOW() WHERE id = $1 AND sent_at IS NULL', [id]);
}

async function getEventReminders(eventId) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        'SELECT * FROM em_reminders WHERE event_id = $1 ORDER BY send_at ASC',
        [eventId]
    );
    return res.rows.map(r => ({
        id: r.id, eventId: r.event_id, guildId: r.guild_id, key: r.key,
        offsetMinutes: r.offset_minutes,
        sendAt: r.send_at ? new Date(r.send_at).toISOString() : null,
        sentAt: r.sent_at ? new Date(r.sent_at).toISOString() : null,
    }));
}

// ── Personal reminders ("Remind Me" button) ─────────────────────────────────
async function toggleUserReminder(eventId, guildId, userId) {
    await ensureEventMgmtTables();
    const del = await eventMgmtPool.query(
        'DELETE FROM em_user_reminders WHERE event_id = $1 AND user_id = $2',
        [eventId, userId]
    );
    if (del.rowCount > 0) return { subscribed: false };
    await eventMgmtPool.query(
        `INSERT INTO em_user_reminders (event_id, guild_id, user_id) VALUES ($1,$2,$3)
         ON CONFLICT (event_id, user_id) DO NOTHING`,
        [eventId, guildId, userId]
    );
    return { subscribed: true };
}

async function getUserReminderSubscribers(eventId, limit = 500) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        'SELECT user_id FROM em_user_reminders WHERE event_id = $1 LIMIT $2',
        [eventId, Math.min(Math.max(parseInt(limit, 10) || 500, 1), 1000)]
    );
    return res.rows.map(r => r.user_id);
}

// ── Activity log ────────────────────────────────────────────────────────────
async function addActivity(eventId, guildId, { userId = null, username = null, action, detail = null }) {
    await ensureEventMgmtTables();
    await eventMgmtPool.query(
        `INSERT INTO em_activity (event_id, guild_id, user_id, username, action, detail)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [eventId, guildId, userId, username, action, detail]
    ).catch(err => console.error('[EVENTMGMT] activity log failed:', err.message));
}

async function getActivity(eventId, limit = 100) {
    await ensureEventMgmtTables();
    const res = await eventMgmtPool.query(
        `SELECT * FROM em_activity WHERE event_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
        [eventId, Math.min(Math.max(parseInt(limit, 10) || 100, 1), 500)]
    );
    return res.rows.map(rowToActivity);
}

// ── Analytics (cheap aggregate, called on demand — not per page render) ──────
async function getGuildEventAnalytics(guildId) {
    await ensureEventMgmtTables();
    const totals = await eventMgmtPool.query(
        `SELECT
            COUNT(*)::int AS total_events,
            COUNT(*) FILTER (WHERE status = 'cancelled')::int AS cancelled,
            COUNT(*) FILTER (WHERE status = 'live')::int AS live,
            COUNT(*) FILTER (WHERE status IN ('scheduled','registration_open','registration_closed'))::int AS upcoming,
            COUNT(*) FILTER (WHERE status = 'completed')::int AS completed,
            COUNT(*) FILTER (WHERE status = 'draft')::int AS draft
         FROM em_events WHERE guild_id = $1`,
        [guildId]
    );
    const participants = await eventMgmtPool.query(
        `SELECT
            COUNT(*) FILTER (WHERE p.status = 'registered')::int AS total_participants,
            COUNT(*) FILTER (WHERE p.attendance_status = 'present')::int AS checked_in,
            COUNT(*) FILTER (WHERE p.attendance_status = 'absent')::int AS absent
         FROM em_participants p WHERE p.guild_id = $1`,
        [guildId]
    );
    const types = await eventMgmtPool.query(
        `SELECT type, COUNT(*)::int AS n FROM em_events WHERE guild_id = $1 GROUP BY type ORDER BY n DESC`,
        [guildId]
    );
    const t = totals.rows[0];
    const p = participants.rows[0];
    const avg = t.total_events > 0 ? Math.round((p.total_participants / t.total_events) * 10) / 10 : 0;
    const attended = p.checked_in + p.absent;
    const attendanceRate = attended > 0 ? Math.round((p.checked_in / attended) * 100) : null;
    return {
        totalEvents: t.total_events,
        cancelled: t.cancelled,
        live: t.live,
        upcoming: t.upcoming,
        completed: t.completed,
        draft: t.draft,
        totalParticipants: p.total_participants,
        checkedIn: p.checked_in,
        absent: p.absent,
        averageParticipants: avg,
        attendanceRate,
        typeCounts: types.rows,
        mostPopularType: types.rows[0] ? types.rows[0].type : null,
    };
}

module.exports = {
    ensureEventMgmtTables,
    normalizeEventConfig,
    rowToEvent, rowToParticipant, rowToActivity,
    createEvent, getEvent, getGuildEvents, getAllGuildEvents, updateEvent, deleteEvent,
    duplicateEvent, setAnnouncementMessage,
    getParticipants, countParticipants, getParticipant, addParticipant,
    updateParticipant, removeParticipant, getNextWaiting, promoteNextWaiting,
    replaceReminderRows, getDueReminders, markReminderSent, getEventReminders,
    toggleUserReminder, getUserReminderSubscribers,
    addActivity, getActivity, getGuildEventAnalytics,
};
