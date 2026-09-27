/**
 * Shared Event Management catalogs + pure helpers.
 *
 * Single source of truth for the Event Management feature (dashboard's
 * Server features → Event Management, plus the bot's EventMgmtManager). The
 * dashboard renders the catalogs directly; the bot validates against them.
 *
 * Pure + dependency-free (no discord.js, no DB) so it is safe to require from
 * the bot, the dashboard, and tests.
 */

// ── Event types ─────────────────────────────────────────────────────────────
// `icon` is an emoji (used inside Discord embeds for flavour), `iconName` is an
// SVG icon name from dashboard/public/js/icons.js (dashboard chrome only).
const EVENT_TYPES = [
    { key: 'community', label: 'Community Event', icon: '🌍', iconName: 'users',    color: '#5865F2', description: 'A general community gathering.' },
    { key: 'gaming',    label: 'Gaming Event',    icon: '🎮', iconName: 'gamepad',  color: '#57F287', description: 'A gaming session with the server.' },
    { key: 'tournament',label: 'Tournament',      icon: '🏆', iconName: 'trophy',   color: '#FFD700', description: 'A competitive bracket with winners.' },
    { key: 'giveaway',  label: 'Giveaway Event',  icon: '🎁', iconName: 'gift',     color: '#EB459E', description: 'An event where prizes are given out.' },
    { key: 'meeting',   label: 'Meeting',         icon: '🗣️', iconName: 'message',  color: '#FEE75C', description: 'A staff or community meeting.' },
    { key: 'watchparty',label: 'Watch Party',     icon: '🍿', iconName: 'playCircle',color: '#ED4245', description: 'Watch something together.' },
    { key: 'custom',    label: 'Custom Event',    icon: '✨', iconName: 'star',     color: '#9B59B6', description: 'Anything that does not fit a category.' },
];

const EVENT_TYPE_KEYS = EVENT_TYPES.map(t => t.key);

function normalizeEventType(key) {
    return EVENT_TYPE_KEYS.includes(key) ? key : 'custom';
}

function eventTypeMeta(key) {
    return EVENT_TYPES.find(t => t.key === normalizeEventType(key)) || EVENT_TYPES[EVENT_TYPES.length - 1];
}

// ── Event statuses ──────────────────────────────────────────────────────────
// Ordered lifecycle: draft → scheduled → registration_open → registration_closed
// → live → completed, with `cancelled` reachable from anywhere except a
// completed event.
const EVENT_STATUSES = [
    { key: 'draft',                label: 'Draft',               icon: 'fileText',    color: '#95A5A6' },
    { key: 'scheduled',            label: 'Scheduled',           icon: 'calendar',    color: '#5865F2' },
    { key: 'registration_open',    label: 'Registration Open',   icon: 'userCheck',   color: '#57F287' },
    { key: 'registration_closed',  label: 'Registration Closed', icon: 'userX',       color: '#FEE75C' },
    { key: 'live',                 label: 'Live',                icon: 'activity',    color: '#ED4245' },
    { key: 'completed',            label: 'Completed',           icon: 'check',       color: '#2ECC71' },
    { key: 'cancelled',            label: 'Cancelled',           icon: 'ban',         color: '#95A5A6' },
];

const EVENT_STATUS_KEYS = EVENT_STATUSES.map(s => s.key);

function normalizeEventStatus(key) {
    return EVENT_STATUS_KEYS.includes(key) ? key : 'draft';
}

function eventStatusMeta(key) {
    return EVENT_STATUSES.find(s => s.key === normalizeEventStatus(key)) || EVENT_STATUSES[0];
}

// Allowed status transitions. `cancelled` is allowed from everything except
// `completed`; nothing may leave `cancelled` or `completed` (a duplicate is the
// way to run a completed event again).
const STATUS_TRANSITIONS = {
    draft:               ['scheduled', 'registration_open', 'cancelled'],
    scheduled:           ['registration_open', 'registration_closed', 'live', 'cancelled', 'draft'],
    registration_open:   ['registration_closed', 'live', 'cancelled', 'scheduled'],
    registration_closed: ['live', 'registration_open', 'cancelled', 'scheduled'],
    live:                ['completed', 'cancelled'],
    completed:           [],
    cancelled:           [],
};

function canTransition(from, to) {
    const a = normalizeEventStatus(from);
    const b = normalizeEventStatus(to);
    if (a === b) return true;
    return (STATUS_TRANSITIONS[a] || []).includes(b);
}

// ── Registration ────────────────────────────────────────────────────────────
const REGISTRATION_MODES = [
    { key: 'open',   label: 'Open',        description: 'Anyone can join.' },
    { key: 'closed', label: 'Closed',      description: 'No new registrations.' },
    { key: 'invite', label: 'Invite Only', description: 'Only staff can add participants.' },
];

const REGISTRATION_MODE_KEYS = REGISTRATION_MODES.map(r => r.key);

function normalizeRegistrationMode(key) {
    return REGISTRATION_MODE_KEYS.includes(key) ? key : 'open';
}

/** Does this status allow member self-registration? */
function statusAllowsRegistration(status) {
    return normalizeEventStatus(status) === 'registration_open';
}

// ── Location ────────────────────────────────────────────────────────────────
const LOCATION_TYPES = [
    { key: 'none',     label: 'No location',      iconName: 'x' },
    { key: 'voice',    label: 'Voice channel',    iconName: 'mute' },
    { key: 'stage',    label: 'Stage channel',    iconName: 'megaphone' },
    { key: 'text',     label: 'Text channel',     iconName: 'hash' },
    { key: 'external', label: 'External URL',     iconName: 'link' },
    { key: 'custom',   label: 'Custom location',  iconName: 'pencil' },
];

const LOCATION_TYPE_KEYS = LOCATION_TYPES.map(l => l.key);

function normalizeLocationType(key) {
    return LOCATION_TYPE_KEYS.includes(key) ? key : 'none';
}

// ── Reminders ───────────────────────────────────────────────────────────────
// Preset offsets (minutes before the event start). Organizers toggle each on/off;
// each enabled reminder stores its own `sent_at` so it can never double-send.
const REMINDER_PRESETS = [
    { key: '24h',  minutes: 24 * 60, label: '24 hours before' },
    { key: '1h',   minutes: 60,      label: '1 hour before' },
    { key: '15m',  minutes: 15,      label: '15 minutes before' },
    { key: '5m',   minutes: 5,       label: '5 minutes before' },
];

const REMINDER_KEYS = REMINDER_PRESETS.map(r => r.key);

// ── Participant statuses ────────────────────────────────────────────────────
const PARTICIPANT_STATUSES = [
    { key: 'registered', label: 'Registered', color: '#5865F2' },
    { key: 'waiting',    label: 'Waiting list', color: '#FEE75C' },
    { key: 'removed',    label: 'Removed',     color: '#ED4245' },
];

const PARTICIPANT_STATUS_KEYS = PARTICIPANT_STATUSES.map(p => p.key);

function normalizeParticipantStatus(key) {
    return PARTICIPANT_STATUS_KEYS.includes(key) ? key : 'registered';
}

// ── Attendance ──────────────────────────────────────────────────────────────
const ATTENDANCE_STATUSES = [
    { key: 'unknown', label: 'Not checked in', color: '#95A5A6' },
    { key: 'present', label: 'Checked in',     color: '#57F287' },
    { key: 'absent',  label: 'Absent',         color: '#ED4245' },
];

function normalizeAttendanceStatus(key) {
    return ATTENDANCE_STATUSES.some(a => a.key === key) ? key : 'unknown';
}

// ── Permissions ─────────────────────────────────────────────────────────────
// Granular Event Manager permissions. Server owner / Administrators always have
// all of them; the configured event-manager role gets exactly the checked set.
const EVENT_PERMISSIONS = [
    { key: 'manage_events',    label: 'Create & edit events',    description: 'Create, edit, duplicate and publish events.' },
    { key: 'manage_participants', label: 'Manage participants',  description: 'Add / remove participants and promote from the waiting list.' },
    { key: 'manage_attendance', label: 'Mark attendance',        description: 'Check members in or mark them absent.' },
    { key: 'send_announcements', label: 'Send announcements',    description: 'Post and update the event announcement.' },
    { key: 'cancel_events',    label: 'Cancel events',           description: 'Cancel or delete events.' },
];

const EVENT_PERMISSION_KEYS = EVENT_PERMISSIONS.map(p => p.key);

function defaultEventPermissions() {
    return EVENT_PERMISSION_KEYS.slice();
}

function normalizeEventPermissions(raw) {
    if (!Array.isArray(raw)) return defaultEventPermissions();
    const set = new Set(raw.filter(k => EVENT_PERMISSION_KEYS.includes(k)));
    return EVENT_PERMISSION_KEYS.filter(k => set.has(k));
}

// ── Templates ───────────────────────────────────────────────────────────────
// Selecting a template prefills the wizard; it never auto-publishes.
const EVENT_TEMPLATES = [
    {
        key: 'gaming-night',
        label: 'Gaming Night',
        icon: '🎮',
        description: 'A casual gaming session with voice chat and a participant role.',
        patch: {
            name: 'Community Gaming Night',
            type: 'gaming',
            description: 'Join us for a community gaming session! Hop in, team up, and have fun.',
            locationType: 'voice',
            registrationMode: 'open',
            durationMinutes: 120,
            reminders: ['1h', '15m'],
        },
    },
    {
        key: 'tournament',
        label: 'Tournament',
        icon: '🏆',
        description: 'A competitive bracket with winners and a winner role.',
        patch: {
            name: 'Community Tournament',
            type: 'tournament',
            description: 'Compete against the community for glory. Winners are recorded at the end.',
            registrationMode: 'open',
            durationMinutes: 180,
            reminders: ['24h', '1h', '15m'],
            trackAttendance: true,
        },
    },
    {
        key: 'meetup',
        label: 'Community Meetup',
        icon: '🌍',
        description: 'A general community meetup in a stage channel.',
        patch: {
            name: 'Community Meetup',
            type: 'community',
            description: 'Come hang out and meet the community!',
            locationType: 'stage',
            registrationMode: 'open',
            durationMinutes: 60,
            reminders: ['1h'],
        },
    },
    {
        key: 'watch-party',
        label: 'Watch Party',
        icon: '🍿',
        description: 'Watch something together with an external link.',
        patch: {
            name: 'Watch Party',
            type: 'watchparty',
            description: 'Grab a snack and watch along with us!',
            locationType: 'external',
            registrationMode: 'open',
            durationMinutes: 150,
            reminders: ['1h', '5m'],
        },
    },
    {
        key: 'giveaway',
        label: 'Giveaway',
        icon: '🎁',
        description: 'A giveaway event with attendance tracking to pick winners.',
        patch: {
            name: 'Community Giveaway',
            type: 'giveaway',
            description: 'Register to enter, then check in to be eligible for the prize.',
            registrationMode: 'open',
            maxParticipants: 100,
            durationMinutes: 45,
            reminders: ['24h', '15m'],
            trackAttendance: true,
        },
    },
    {
        key: 'custom',
        label: 'Custom',
        icon: '✨',
        description: 'Start from a blank event and configure everything yourself.',
        patch: {},
    },
];

function eventTemplateMeta(key) {
    return EVENT_TEMPLATES.find(t => t.key === key) || EVENT_TEMPLATES[EVENT_TEMPLATES.length - 1];
}

module.exports = {
    EVENT_TYPES, EVENT_TYPE_KEYS, normalizeEventType, eventTypeMeta,
    EVENT_STATUSES, EVENT_STATUS_KEYS, normalizeEventStatus, eventStatusMeta,
    STATUS_TRANSITIONS, canTransition,
    REGISTRATION_MODES, REGISTRATION_MODE_KEYS, normalizeRegistrationMode, statusAllowsRegistration,
    LOCATION_TYPES, LOCATION_TYPE_KEYS, normalizeLocationType,
    REMINDER_PRESETS, REMINDER_KEYS,
    PARTICIPANT_STATUSES, PARTICIPANT_STATUS_KEYS, normalizeParticipantStatus,
    ATTENDANCE_STATUSES, normalizeAttendanceStatus,
    EVENT_PERMISSIONS, EVENT_PERMISSION_KEYS, defaultEventPermissions, normalizeEventPermissions,
    EVENT_TEMPLATES, eventTemplateMeta,
};
