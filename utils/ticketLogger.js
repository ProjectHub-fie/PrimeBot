/**
 * ticketLogger.js
 *
 * Delivers premium Discord log embeds for per-panel ticket events.
 *
 * Design goals (see the Ticket Logging spec):
 *   • Logging is SECONDARY — a failure here must never break a ticket
 *     operation. Every path is fire-and-forget and wrapped in try/catch.
 *   • Config comes from the persistent `ticket_logging_settings` table via
 *     the ticket-manager cache (TLOG_DATABASE_URL) so it survives restarts.
 *   • One ticket event → one log. The manager exposes a small
 *     subscribe(handler) bus; handlers receive a strongly-serialized event
 *     object (a stringified JSON snapshot) so identical events never double
 *     POST even if listeners/reconnects fire more than once.
 *   • Embeds use the shared TICKET_LOG_EVENTS catalog (shared/ticketLogging.js)
 *     for the icon/label/color of each event, keeping the dashboard editor and
 *     the embed output in sync.
 */

const { EmbedBuilder } = require('discord.js');
const {
    TICKET_LOG_EVENTS,
    metaFor,
} = require('../shared/ticketLogging');

const FOOTER_TEXT = 'PrimeBot • Ticket Logs';

function colorInt(hex) {
    if (!hex) return 0x5865F2;
    const m = /^#?([0-9a-fA-F]{6})$/.exec(String(hex));
    return m ? parseInt(m[1], 16) : 0x5865F2;
}

function _mentionId(id) {
    return id != null && String(id) ? `<@${id}>` : '—';
}

function _channelMention(ctx, fallback = '') {
    // The ticket channel itself (contextual, more useful than the log channel).
    const id = ctx.channelId;
    return id ? `<#${id}>` : (fallback || '—');
}

function _ts(epochMs) {
    const ms = Number(epochMs);
    if (!ms) return null;
    return Math.floor(ms / 1000);
}

function _dt(epochMs) {
    const ms = Number(epochMs);
    if (!ms) return null;
    const d = new Date(ms);
    return d.toLocaleString('en-US', {
        day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
    });
}

function _addField(embed, name, value, inline = false) {
    if (!name) return;
    if (value == null || String(value).trim() === '') return;
    embed.addFields({ name: String(name).slice(0, 256), value: String(value).slice(0, 1024), inline: !!inline });
}

/**
 * Build the event-specific embed for a ticket log.
 *
 * @param {string} eventKey - one of shared/ticketLogging TICKET_LOG_EVENTS keys
 * @param {object} ctx      - normalized event context (see makeEventContext)
 */
function buildTicketLogEmbed(eventKey, ctx = {}) {
    const meta = metaFor(eventKey) || { icon: '🎫', label: 'Ticket Event', color: '#5865F2', desc: '' };
    const embed = new EmbedBuilder()
        .setColor(colorInt(meta.color))
        .setTitle(`${meta.icon} ${meta.label}`)
        .setDescription(meta.desc || (ctx.ticket ? `Ticket \`${ctx.ticket}\`` : ''))
        .setTimestamp(ctx.timestamp || new Date());

    const panelName = ctx.panelName || null;
    const ticketName = ctx.ticket || 'ticket';

    switch (eventKey) {
        case 'created': {
            _addField(embed, 'Ticket', _channelMention(ctx, `#${ctx.ticket}`));
            _addField(embed, 'Created By', _mentionId(ctx.userId), true);
            if (ctx.category) _addField(embed, 'Category', ctx.category, true);
            if (panelName) _addField(embed, 'Panel', panelName, true);
            if (ctx.reason) _addField(embed, 'Reason', ctx.reason);
            break;
        }
        case 'closed': {
            _addField(embed, 'Ticket', _channelMention(ctx, `#${ticketName}`));
            _addField(embed, 'Closed By', _mentionId(ctx.actorId), true);
            if (ctx.reason) _addField(embed, 'Reason', ctx.reason);
            else _addField(embed, 'Reason', '—');
            if (ctx.openedAt) _addField(embed, 'Opened At', `<t:${_ts(ctx.openedAt)}:F>`, true);
            _addField(embed, 'Closed At', `<t:${_ts(ctx.timestamp || ctx.closedAt)}:F>`, true);
            if (ctx.openedAt && ctx.timestamp) {
                const hours = Math.max(0, Math.round((ctx.timestamp - ctx.openedAt) / 60000 / 60 * 10) / 10);
                _addField(embed, 'Duration', `${hours} hour${hours === 1 ? '' : 's'}`, true);
            }
            break;
        }
        case 'reopened': {
            _addField(embed, 'Ticket', _channelMention(ctx, `#${ticketName}`));
            _addField(embed, 'Reopened By', _mentionId(ctx.actorId), true);
            if (ctx.openedAt) _addField(embed, 'Opened At', `<t:${_ts(ctx.openedAt)}:F>`, true);
            break;
        }
        case 'claimed': {
            _addField(embed, 'Ticket', _channelMention(ctx, `#${ticketName}`));
            _addField(embed, 'Claimed By', _mentionId(ctx.actorId), true);
            break;
        }
        case 'unclaimed': {
            _addField(embed, 'Ticket', _channelMention(ctx, `#${ticketName}`));
            _addField(embed, 'Unclaimed By', _mentionId(ctx.actorId), true);
            break;
        }
        case 'transferred': {
            _addField(embed, 'Ticket', _channelMention(ctx, `#${ticketName}`));
            _addField(embed, 'Previous Moderator', _mentionId(ctx.previousModeratorId), true);
            _addField(embed, 'New Moderator', _mentionId(ctx.newModeratorId), true);
            break;
        }
        case 'renamed': {
            _addField(embed, 'Ticket', _channelMention(ctx, `#${ticketName}`));
            _addField(embed, 'Old Name', ctx.oldName || '—', true);
            _addField(embed, 'New Name', ctx.newName || '—', true);
            _addField(embed, 'Renamed By', _mentionId(ctx.actorId));
            break;
        }
        case 'deleted': {
            _addField(embed, 'Ticket', `#${ticketName}`);
            _addField(embed, 'Deleted By', _mentionId(ctx.actorId), true);
            if (ctx.reason) _addField(embed, 'Reason', ctx.reason);
            break;
        }
        default:
            _addField(embed, 'Ticket', ctx.ticket || '—');
    }

    const footer = panelName ? `${panelName} • ${FOOTER_TEXT}` : FOOTER_TEXT;
    embed.setFooter({ text: footer });
    return embed;
}

function buildTicketLogEmbedObject(eventKey, ctx) {
    return buildTicketLogEmbed(eventKey, ctx).toJSON();
}

/**
 * Normalize arbitrary event data into a stable context for embed building.
 * Fields a specific event doesn't use are simply ignored by buildTicketLogEmbed.
 */
function makeEventContext(eventKey, data = {}) {
    return {
        panelId: data.panelId != null ? String(data.panelId) : null,
        guildId: data.guildId != null ? String(data.guildId) : null,
        channelId: data.channelId != null ? String(data.channelId) : null,
        ticket: data.ticket || data.channelName || null,
        userId: data.userId != null ? String(data.userId) : null,
        actorId: data.actorId != null ? String(data.actorId) : (data.userId != null ? String(data.userId) : null),
        panelName: data.panelName || null,
        category: data.category || null,
        reason: data.reason || null,
        openedAt: data.openedAt ? Number(data.openedAt) : null,
        closedAt: data.closedAt ? Number(data.closedAt) : null,
        timestamp: data.timestamp ? Number(data.timestamp) : Date.now(),
        previousModeratorId: data.previousModeratorId != null ? String(data.previousModeratorId) : null,
        newModeratorId: data.newModeratorId != null ? String(data.newModeratorId) : null,
        oldName: data.oldName || null,
        newName: data.newName || null,
    };
}

// In-flight dedup: one event occurrence may be observed by multiple code paths
// (listeners, reconnects, interaction handlers firing twice). The manager stamps
// each emitted event with a stable `_id` (key + ids + actor + timestamp); any
// send attempt with the same `_id` within the window is skipped, so one ticket
// event can never generate multiple identical logs.
const _sentLogIds = new Map();
const LOG_DEDUP_MS = 5000;

function _isDuplicateLog(id) {
    if (!id) return false;
    const last = _sentLogIds.get(id);
    const now = Date.now();
    if (last && (now - last) < LOG_DEDUP_MS) return true;
    _sentLogIds.set(id, now);
    return false;
}

/**
 * Deliver a ticket log for one panel/event. Reads settings from the manager
 * cache, checks the event toggle + channel, builds the embed, sends it.
 * Returns a promise that never rejects.
 */
async function sendTicketLog(manager, instance, eventKey, eventData = {}) {
    try {
        if (!manager || !manager.client) return false;

        const panel = (instance && instance.panelId)
            ? (manager.getPanelById ? manager.getPanelById(instance.panelId) : null)
            : null;

        const settings = await manager.getTicketLoggingSettings(instance.guildId, panel);
        if (!settings || !settings.enabled) return false;
        if (settings.events && !settings.events.includes(eventKey)) return false;
        if (!settings.channelId) return false;

        // Duplicate protection (stable per-occurrence id from the manager bus).
        if (instance && instance._id && _isDuplicateLog(instance._id)) return false;

        // A channel that is deleted/inaccessible should never break anything.
        const channel = await manager.client.channels.fetch(settings.channelId).catch(() => null);
        if (!channel || typeof channel.send !== 'function') {
            console.error(`[TICKET-LOGGER] Log channel ${settings.channelId} unavailable — skipping ${eventKey} log.`);
            return false;
        }

        // Merge the instance-level ids (the manager emits them at the top level
        // of the event descriptor) into the per-event context so embed builders
        // can reference the ticket channel even when eventData omits them.
        const ctx = makeEventContext(eventKey, {
            ...(instance ? {
                panelId: instance.panelId || eventData.panelId,
                guildId: instance.guildId || eventData.guildId,
                channelId: instance.channelId || eventData.channelId,
                ticket: instance.ticket || eventData.ticket,
            } : {}),
            ...eventData,
        });
        const embed = buildTicketLogEmbed(eventKey, ctx);
        await channel.send({ embeds: [embed] });
        return true;
    } catch (err) {
        console.error('[TICKET-LOGGER] sendTicketLog failed (ticket operation NOT affected):', err.message);
        return false;
    }
}

module.exports = {
    sendTicketLog,
    buildTicketLogEmbed,
    buildTicketLogEmbedObject,
    makeEventContext,
    colorInt,
    _isDuplicateLog,
    TICKET_LOG_EVENTS,
    FOOTER_TEXT,
};