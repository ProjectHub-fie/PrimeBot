/**
 * Canonical logging event types + metadata.
 *
 * Shared by the bot (utils/serverLogger.js), the dashboard (constants + UI),
 * and tests so they all agree on which events exist, their labels, icons and
 * default colors. Adding a new loggable event is a one-line change here.
 */

/**
 * @typedef {Object} LogEventMeta
 * @property {string} key     - Stable identifier stored in settings.events.
 * @property {string} label   - Human label shown in the dashboard toggles.
 * @property {string} icon    - Emoji prefix for the embed title.
 * @property {string} color   - Default embed color (hex) for this event.
 * @property {string} category- Grouping for the dashboard UI.
 */
const LOG_EVENTS = [
    { key: 'memberJoin',    label: 'Member joined',          icon: '🟢', color: '#57F287', category: 'Members' },
    { key: 'memberLeave',   label: 'Member left',            icon: '🔴', color: '#ED4245', category: 'Members' },
    { key: 'memberBan',     label: 'Member banned',          icon: '🔨', color: '#ED4245', category: 'Members' },
    { key: 'memberUnban',   label: 'Member unbanned',        icon: '🕊️', color: '#57F287', category: 'Members' },
    { key: 'memberUpdate',  label: 'Member updated (roles / nickname)', icon: '📝', color: '#FEE75C', category: 'Members' },
    { key: 'messageDelete', label: 'Message deleted',        icon: '🗑️', color: '#ED4245', category: 'Messages' },
    { key: 'messageUpdate', label: 'Message edited',         icon: '✏️', color: '#FEE75C', category: 'Messages' },
    { key: 'commandUse',    label: 'Slash command used',     icon: '⚙️', color: '#5865F2', category: 'Activity' },
];

const LOG_EVENT_KEYS = LOG_EVENTS.map(e => e.key);
const LOG_EVENT_BY_KEY = Object.fromEntries(LOG_EVENTS.map(e => [e.key, e]));

/** Default enabled events when a guild turns logging on without specifying any. */
const DEFAULT_ENABLED_EVENTS = ['memberJoin', 'memberLeave', 'memberBan', 'messageDelete'];

/** Normalize an arbitrary events value into an array of known keys. */
function normalizeEvents(events) {
    if (!Array.isArray(events)) return [];
    const seen = new Set();
    const out = [];
    for (const e of events) {
        if (typeof e !== 'string') continue;
        const key = e.trim();
        if (LOG_EVENT_BY_KEY[key] && !seen.has(key)) {
            seen.add(key);
            out.push(key);
        }
    }
    return out;
}

/** True when the given event key is enabled for the given (normalized) settings. */
function isEventEnabled(settings, eventKey) {
    if (!settings || !settings.enabled) return false;
    const events = normalizeEvents(settings.events);
    return events.includes(eventKey);
}

function metaFor(eventKey) {
    return LOG_EVENT_BY_KEY[eventKey] || { key: eventKey, label: eventKey, icon: '📜', color: '#5865F2', category: 'Other' };
}

module.exports = {
    LOG_EVENTS,
    LOG_EVENT_KEYS,
    LOG_EVENT_BY_KEY,
    DEFAULT_ENABLED_EVENTS,
    normalizeEvents,
    isEventEnabled,
    metaFor,
};
