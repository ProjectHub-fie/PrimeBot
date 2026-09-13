/**
 * Ticket Logging — shared catalog + normalizers.
 *
 * Single source of truth for:
 *   • the event keys that ticket logging supports (TICKET_LOG_EVENTS),
 *   • default settings,
 *   • normalization of the per-panel `ticket_logging_settings` row,
 *   • the human-friendly labels/icons/colors used by the dashboard editor
 *     AND the bot's embed builder (utils/ticketLogger.js).
 *
 * Both the dashboard (Logging bar of the ticket editor) and the bot
 * (utils/ticketLogger.js) import these helpers so the UI and the embeds
 * never drift apart.
 */

// Event keys — only events the ticket system actually emits are listed.
const TICKET_LOG_EVENTS = [
    { key: 'created',    label: 'Ticket Created',       icon: '🎫',  color: '#57F287', desc: 'A new support ticket has been created.' },
    { key: 'closed',     label: 'Ticket Closed',        icon: '🔒',  color: '#ED4245', desc: 'This support ticket was closed.' },
    { key: 'reopened',   label: 'Ticket Reopened',      icon: '🔓',  color: '#57F287', desc: 'This support ticket was reopened.' },
    { key: 'claimed',    label: 'Ticket Claimed',       icon: '🙋',  color: '#5865F2', desc: 'A support staff member claimed this ticket.' },
    { key: 'unclaimed',  label: 'Ticket Unclaimed',     icon: '↩️',  color: '#FEE75C', desc: 'This ticket was unclaimed.' },
    { key: 'transferred',label: 'Ticket Transferred',   icon: '🔄',  color: '#5865F2', desc: 'This ticket was transferred to another staff member.' },
    { key: 'renamed',    label: 'Ticket Renamed',       icon: '✏️',  color: '#FEE75C', desc: 'This ticket channel was renamed.' },
    { key: 'deleted',    label: 'Ticket Deleted',       icon: '🗑️',  color: '#ED4245', desc: 'This ticket was deleted.' },
];

const TICKET_LOG_EVENT_KEYS = TICKET_LOG_EVENTS.map(e => e.key);
const DEFAULT_TICKET_LOG_EVENTS = ['created', 'closed', 'reopened', 'claimed', 'unclaimed', 'transferred'];

const DEFAULT_TICKET_LOGGING_SETTINGS = {
    enabled: false,
    channelId: null,
    events: DEFAULT_TICKET_LOG_EVENTS.slice(),
};

function _safeEventArray(raw) {
    if (!raw) return [];
    const arr = Array.isArray(raw) ? raw : (() => { try { const p = JSON.parse(String(raw)); return Array.isArray(p) ? p : []; } catch { return []; } })();
    return arr.filter(k => TICKET_LOG_EVENT_KEYS.includes(k));
}

/**
 * Normalize a stored/raw ticket-logging config into { enabled, channelId, events }.
 * Missing/invalid keys fall back to defaults. Any valid event the caller didn't
 * list stays enabled (so we never silently disable events after an upgrade).
 */
function normalizeTicketLogging(raw, defaults = DEFAULT_TICKET_LOGGING_SETTINGS) {
    const src = (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
    const storedEvents = _safeEventArray(src.events != null ? src.events : defaults.events);
    const base = Array.isArray(defaults.events) ? defaults.events : DEFAULT_TICKET_LOG_EVENTS;
    // Default-enable events the admin never explicitly disabled.
    const merged = new Set(storedEvents);
    for (const k of base) merged.add(k);
    return {
        enabled: src.enabled === true,
        channelId: (src.channelId != null ? String(src.channelId).trim() : null) || null,
        events: TICKET_LOG_EVENTS.map(e => e.key).filter(k => merged.has(k)),
    };
}

function metaFor(eventKey) {
    return TICKET_LOG_EVENTS.find(e => e.key === eventKey) || null;
}

module.exports = {
    TICKET_LOG_EVENTS,
    TICKET_LOG_EVENT_KEYS,
    DEFAULT_TICKET_LOG_EVENTS,
    DEFAULT_TICKET_LOGGING_SETTINGS,
    normalizeTicketLogging,
    metaFor,
};