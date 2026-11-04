/**
 * Anti-Nuke — the primary detection entry point.
 *
 * Discord's `guildAuditLogEntryCreate` gateway event delivers the audit entry
 * as it is written, so the executor is known directly (no correlation delay, no
 * ambiguity). This is the most reliable attribution source, which is why the
 * Anti-Nuke executor is driven from here first and only falls back to
 * `guild.fetchAuditLogs()` correlation for events that don't carry a matching
 * audit entry shape.
 *
 * Requires the GuildModeration gateway intent (see index.js).
 *
 * The handler is deliberately thin: it maps the entry to one or more watched
 * actions (utils/antiNukeEntry.js) and hands each to the manager, which owns the
 * trust check, the burst detector and the response plan. Every failure is
 * swallowed — detection must never break the event pipeline.
 */

const { evaluateAuditEntry } = require('../utils/antiNukeEntry');

module.exports = {
    name: 'guildAuditLogEntryCreate',
    once: false,
    async execute(entry, guild, client) {
        try {
            const manager = client && client.antiNukeManager;
            if (!manager || typeof manager.processEvent !== 'function') return;
            if (!entry || !guild) return;

            // The bot's own actions are never threats (and the manager's trust
            // gate covers this too — this is just an early exit).
            const botId = client.user ? client.user.id : null;
            if (botId && entry.executorId === botId) return;

            // A guild this node owns must be cached; if it is not, another node
            // owns it and will process the event.
            if (client.guilds && client.guilds.cache && !client.guilds.cache.has(guild.id)) return;

            // The live stream is available on this node — the per-event
            // correlation fallback is no longer needed.
            if (typeof manager.noteAuditStream === 'function') manager.noteAuditStream();

            const matched = evaluateAuditEntry(entry, guild);
            if (matched.length === 0) return;

            for (const { actionKey, details } of matched) {
                // The executor is already known from the entry, so skip the
                // audit-log round trip entirely.
                await manager.processEvent({
                    guild,
                    actionKey,
                    knownExecutorId: entry.executorId ? String(entry.executorId) : null,
                    details: { summary: details, auditEntryId: entry.id, targetId: entry.targetId || null },
                }).catch(err => {
                    console.error('[ANTINUKE] processEvent (audit entry) failed:', err.message);
                });
            }
        } catch (err) {
            console.error('[ANTINUKE] guildAuditLogEntryCreate handler failed:', err.message);
        }
    },
};
