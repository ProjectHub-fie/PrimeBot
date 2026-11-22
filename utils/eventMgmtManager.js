/**
 * EventMgmtManager — Event Management runtime for the bot.
 *
 * Bridges the dashboard (which writes em_events via server/eventMgmtRepo.js)
 * and Discord (announcements, registration buttons, reminders, attendance and
 * role assignment). Follows the same pattern as the other premium managers:
 *
 *   • in-memory cache of the guilds' events, rebuilt by an AdaptivePoller that
 *     backs off while nothing changes (Neon stays cheap when idle);
 *   • a self-driving scheduler tick (AdaptivePoller, ~60s) that advances the
 *     event lifecycle (scheduled → live → completed) and fires due reminders
 *     via the indexed `em_reminders` partial index — never a full-table scan;
 *   • serial queues for role operations and DMs so a 500-participant event
 *     can never burst the Discord API.
 *
 * The dashboard is the only place events are configured; the bot only reacts.
 */

const { EmbedBuilder, GuildScheduledEventPrivacyLevel, GuildScheduledEventEntityType } = require('discord.js');
const { AdaptivePoller } = require('./adaptivePoller');
const { getCacheScheduler } = require('./cacheScheduler');
const repo = require('../server/eventMgmtRepo');
const {
    buildAnnouncementPayload, buildEventComponents, buildParticipantsEmbed,
    buildReminderPayload,
} = require('../shared/eventMessages');
const {
    normalizeEventStatus, canTransition, statusAllowsRegistration,
    eventTypeMeta, eventStatusMeta, normalizeRsvp,
} = require('../shared/eventConstants');
const { SerialQueue, applyRole, DedupSender, isSendableChannel } = require('./eventDiscord');

// How often the scheduler wakes to advance statuses / fire reminders.
const SCHED_INTERVAL_MS = parseInt(process.env.EVENTMGMT_TICK_INTERVAL_MS, 10) || 60000;

function sameSnapshot(prev, next) {
    if (prev.size !== next.size) return false;
    for (const [id, ev] of next) {
        const p = prev.get(id);
        if (!p || JSON.stringify(p) !== JSON.stringify(ev)) return false;
    }
    return true;
}

class EventMgmtManager {
    constructor(client = null) {
        this.client = client;
        this._byId = new Map();       // eventId -> event
        this._byGuild = new Map();    // guildId -> Set<eventId>
        this._tableReady = false;
        this._dedup = new DedupSender();
        this._roleQueue = new SerialQueue({
            delayMs: parseInt(process.env.EVENT_ROLE_OP_DELAY_MS, 10) || 1100,
            name: 'event-roles',
            onError: (err) => console.warn('[EVENTMGMT] role queue error:', err.message),
        });
        this._dmQueue = new SerialQueue({
            delayMs: parseInt(process.env.EVENT_DM_DELAY_MS, 10) || 150,
            name: 'event-dms',
            onError: (err) => console.warn('[EVENTMGMT] dm queue error:', err.message),
        });
        this._initPromise = this._init();
        // Ids whose recurring child has already been checked this process
        // (avoids a query every scheduler tick for a completed event).
        this._recurrenceChecked = new Set();
    }

    async _init() {
        try {
            await repo.ensureEventMgmtTables();
            this._tableReady = true;
            await this._loadAll();
            this._startReload();
            this._startScheduler();
            console.log('✅ EventMgmtManager database connection established');
        } catch (err) {
            this._tableReady = false;
            console.error('❌ EventMgmtManager initialization failed:', err.message);
            console.log('⚠️ Event Management will use fallback mode (no events loaded)');
        }
    }

    ready() { return this._initPromise; }

    _startReload() {
        if (this._reloadTimer) return;
        this._reloadTimer = getCacheScheduler().register('EVENTS', () => this._reloadAll());
    }

    _startScheduler() {
        if (this._schedTimer) return;
        this._schedTimer = new AdaptivePoller({
            name: 'EVENT SCHEDULER',
            task: () => this._tick(),
            initialMs: SCHED_INTERVAL_MS,
            // Idle floor must clear Neon's ~5-minute suspend window, so an idle
            // deployment (no live/relevant events) stops waking the endpoint.
            maxMs: Math.max(SCHED_INTERVAL_MS, 10 * 60 * 1000),
        });
        this._schedTimer.start();
    }

    /**
     * Reload every guild's events. One cheap DISTINCT-guild query plus one
     * bounded query per guild (guilds with events are few); returns true when
     * anything changed so the poller can back off while idle.
     */
    async _reloadAll() {
        return this._loadAll();
    }

    /** Full load: discover every guild that has events, then load them. */
    async _loadAll() {
        if (!this._tableReady) return false;
        // A cheap DISTINCT-guild query, then one bounded query per guild.
        const pool = require('../server/eventMgmtDb').eventMgmtPool;
        const guildRes = await pool.query('SELECT DISTINCT guild_id FROM em_events');
        const next = new Map();
        for (const row of guildRes.rows) {
            const events = await repo.getAllGuildEvents(row.guild_id);
            for (const ev of events) next.set(ev.id, ev);
        }
        return this._swapCache(next);
    }

    _swapCache(next) {
        const changed = !sameSnapshot(this._byId, next);
        const byGuild = new Map();
        for (const ev of next.values()) {
            if (!byGuild.has(ev.guildId)) byGuild.set(ev.guildId, new Set());
            byGuild.get(ev.guildId).add(ev.id);
        }
        this._byId = next;
        this._byGuild = byGuild;
        return changed;
    }

    /** Invalidate one event in the cache after a bot-side write. */
    _invalidate(eventId) {
        this._byId.delete(eventId);
    }

    // ── Reads ───────────────────────────────────────────────────────────────
    getEvent(id) {
        return this._byId.get(Number(id)) || this._byId.get(id) || null;
    }

    getGuildEvents(guildId) {
        const ids = this._byGuild.get(String(guildId));
        if (!ids) return [];
        return Array.from(ids).map(id => this._byId.get(id)).filter(Boolean);
    }

    // ── Scheduler tick ──────────────────────────────────────────────────────
    async _tick() {
        if (!this._tableReady) return false;
        let changed = false;
        try {
            changed = await this._autoAdvanceStatuses() || changed;
        } catch (err) {
            console.error('[EVENTMGMT] status advance failed:', err.message);
        }
        try {
            changed = await this._sendDueReminders() || changed;
        } catch (err) {
            console.error('[EVENTMGMT] reminder tick failed:', err.message);
        }
        try {
            changed = await this._spawnRecurrences() || changed;
        } catch (err) {
            console.error('[EVENTMGMT] recurrence spawn failed:', err.message);
        }
        try {
            changed = await this._syncScheduledEvents() || changed;
        } catch (err) {
            console.error('[EVENTMGMT] scheduled event sync failed:', err.message);
        }
        this._dedup.prune();
        return changed;
    }

    /**
     * Spawn the next occurrence of a completed recurring event.
     *
     * Idempotent: the child carries `recurrenceParentId`, so a restart or a
     * second tick can never create a duplicate. The in-memory guard keeps the
     * check to ONE query per event per process.
     */
    async _spawnRecurrences() {
        let changed = false;
        for (const ev of Array.from(this._byId.values())) {
            if (!ev.recurrence || ev.recurrence === 'none') continue;
            if (ev.status !== 'completed') continue;
            if (!ev.startAt) continue;
            if (this._recurrenceChecked.has(ev.id)) continue;
            this._recurrenceChecked.add(ev.id);
            const created = await repo.createNextOccurrence(ev);
            if (created) {
                this._byId.set(created.id, created);
                if (!this._byGuild.has(created.guildId)) this._byGuild.set(created.guildId, new Set());
                this._byGuild.get(created.guildId).add(created.id);
                changed = true;
                console.log(`[EVENTMGMT] Spawned recurring occurrence #${created.id} for #${ev.id}`);
            }
        }
        return changed;
    }

    /**
     * Create the Discord Scheduled Event for upcoming events that support one
     * (voice / stage / external). Only events without a scheduled id are
     * created, so a restart never duplicates a scheduled event.
     */
    async _syncScheduledEvents() {
        if (!this.client) return false;
        const now = Date.now();
        let changed = false;
        for (const ev of Array.from(this._byId.values())) {
            if (!ev.syncScheduledEvent || ev.scheduledEventId) continue;
            if (!ev.startAt || new Date(ev.startAt).getTime() <= now) continue;
            if (['cancelled', 'completed', 'draft'].includes(ev.status)) continue;
            if (!['voice', 'stage', 'external'].includes(ev.locationType)) continue;
            const guild = this.client.guilds.cache.get(ev.guildId)
                || await this.client.guilds.fetch(ev.guildId).catch(() => null);
            if (!guild || !guild.scheduledEvents) continue;
            const created = await this._createScheduledEvent(guild, ev);
            if (created) {
                await repo.setScheduledEventId(ev.id, created.id);
                ev.scheduledEventId = created.id;
                changed = true;
            }
        }
        return changed;
    }

    async _createScheduledEvent(guild, event) {
        const start = new Date(event.startAt);
        const end = event.endAt ? new Date(event.endAt) : new Date(start.getTime() + 2 * 60 * 60 * 1000);
        const payload = {
            name: String(event.name).slice(0, 100),
            description: (event.description || undefined),
            scheduledStartTime: start,
            scheduledEndTime: end,
            privacyLevel: GuildScheduledEventPrivacyLevel.GuildOnly,
        };
        if (event.locationType === 'external') {
            payload.entityType = GuildScheduledEventEntityType.External;
            payload.entityMetadata = { location: String(event.locationValue || 'Online').slice(0, 100) };
        } else {
            payload.entityType = event.locationType === 'stage'
                ? GuildScheduledEventEntityType.StageInstance
                : GuildScheduledEventEntityType.Voice;
            const channel = guild.channels.cache.get(event.locationValue)
                || await guild.channels.fetch(event.locationValue).catch(() => null);
            if (!channel) return null;
            payload.channel = channel;
        }
        return guild.scheduledEvents.create(payload).catch(err => {
            console.warn('[EVENTMGMT] scheduled event create failed:', err.message);
            return null;
        });
    }

    /** Delete the Discord Scheduled Event attached to an event (best-effort). */
    async deleteScheduledEvent(event) {
        if (!event || !event.scheduledEventId || !this.client) return false;
        const guild = this.client.guilds.cache.get(event.guildId)
            || await this.client.guilds.fetch(event.guildId).catch(() => null);
        if (!guild || !guild.scheduledEvents) return false;
        const ok = await guild.scheduledEvents.delete(event.scheduledEventId)
            .then(() => true)
            .catch(err => { console.warn('[EVENTMGMT] scheduled event delete failed:', err.message); return false; });
        await repo.setScheduledEventId(event.id, null).catch(() => {});
        event.scheduledEventId = null;
        return ok;
    }

    /**
     * Advance events whose start/end has passed. Only writes when a transition
     * is actually due (Neon-friendly: idle events cost nothing).
     */
    async _autoAdvanceStatuses() {
        const now = Date.now();
        let changed = false;
        for (const ev of Array.from(this._byId.values())) {
            if (ev.status === 'cancelled' || ev.status === 'completed' || ev.status === 'draft') continue;
            if (ev.startAt && now >= new Date(ev.startAt).getTime()
                && ['scheduled', 'registration_open', 'registration_closed'].includes(ev.status)) {
                await this._transition(ev, 'live', { silent: true });
                changed = true;
                continue;
            }
            if (ev.status === 'live' && ev.endAt && now >= new Date(ev.endAt).getTime()) {
                await this._transition(ev, 'completed', { silent: true });
                changed = true;
            }
        }
        return changed;
    }

    /**
     * Send any due reminders (single indexed query via the partial index on
     * `em_reminders (send_at) WHERE sent_at IS NULL`). Also DMs personal
     * "Remind Me" subscribers on the final (closest) reminder, queued.
     */
    async _sendDueReminders() {
        // Skip the due-reminders query entirely when no event can have a
        // pending reminder. Reminders belong to events, so with every cached
        // event terminal (or no events at all) the query can only ever return
        // zero rows — previously it still ran a `SELECT ... WHERE send_at <= now`
        // on the reminder table every scheduler tick, waking Neon for nothing.
        const hasLiveEvent = Array.from(this._byId.values()).some(
            (ev) => ev.status !== 'completed' && ev.status !== 'cancelled' && ev.status !== 'draft'
        );
        if (!hasLiveEvent) return false;

        const due = await repo.getDueReminders(new Date(), 50);
        if (due.length === 0) return false;
        let sent = false;
        for (const r of due) {
            const event = this.getEvent(r.event_id) || await repo.getEvent(r.event_id);
            if (!event) { await repo.markReminderSent(r.id); continue; }
            // Never remind for an event that will not happen.
            if (event.status === 'cancelled' || event.status === 'completed') {
                await repo.markReminderSent(r.id);
                continue;
            }
            await this._dispatchReminder(event, Number(r.offset_minutes));
            await repo.markReminderSent(r.id);
            sent = true;
        }
        return sent;
    }

    async _dispatchReminder(event, offsetMinutes) {
        const channel = await this._fetchChannel(event.announcementChannelId);
        if (isSendableChannel(channel)) {
            const key = `reminder:${event.id}:${offsetMinutes}`;
            if (!this._dedup.has(key)) {
                this._dedup.mark(key);
                await channel.send(buildReminderPayload(event, offsetMinutes)).catch(err =>
                    console.warn('[EVENTMGMT] reminder send failed:', err.message));
                await repo.addActivity(event.id, event.guildId, {
                    action: 'reminder_sent', detail: `${offsetMinutes} minute reminder`,
                });
            }
        }
        // Personal DMs only on the closest enabled reminder (least spammy).
        if (offsetMinutes === this._closestReminderOffset(event)) {
            const subs = await repo.getUserReminderSubscribers(event.id);
            for (const userId of subs) {
                this._dmQueue.push(async () => {
                    const user = await this.client?.users?.fetch(userId).catch(() => null);
                    if (!user) return;
                    await user.send({
                        content: `🔔 Reminder: **${event.name}** starts ${offsetMinutes >= 60 ? `in ${Math.round(offsetMinutes / 60)}h` : `in ${offsetMinutes}m`}!`,
                    }).catch(() => {});
                });
            }
        }
    }

    _closestReminderOffset(event) {
        const ev = this.getEvent(event.id) || event;
        const offsets = (ev.reminders || []).map(k => {
            const m = { '24h': 1440, '1h': 60, '15m': 15, '5m': 5 }[k];
            return m == null ? null : m;
        }).filter(v => v != null);
        return offsets.length ? Math.min(...offsets) : null;
    }

    // ── Status transitions ──────────────────────────────────────────────────
    async _transition(event, to, { silent = false, reason = null, userId = null, username = null } = {}) {
        const target = normalizeEventStatus(to);
        if (!canTransition(event.status, target)) {
            const err = new Error(`Cannot move event from ${event.status} to ${target}.`);
            err.status = 409;
            throw err;
        }
        await repo.updateEvent(event.id, { status: target });
        event.status = target;
        this._byId.set(event.id, event);
        if (!silent) {
            await repo.addActivity(event.id, event.guildId, {
                action: `status_${target}`, userId, username,
                detail: reason || `Status → ${eventStatusMeta(target).label}`,
            });
        }
        // Keep the announcement in sync (best-effort, deduped).
        if (['live', 'completed', 'cancelled', 'registration_closed'].includes(target)) {
            await this.updateAnnouncement(event.id).catch(() => {});
        }
        return event;
    }

    async transitionStatus(eventId, to, opts = {}) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) throw new Error('Event not found.');
        return this._transition(event, to, opts);
    }

    // ── Publish + announcement ──────────────────────────────────────────────
    async publish(eventId, { announce = true, userId = null, username = null } = {}) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) throw new Error('Event not found.');
        if (event.status === 'draft') {
            // Open registration when the schedule is set and registration is open.
            const target = (event.startAt && event.registrationMode === 'open') ? 'registration_open' : 'scheduled';
            await this._transition(event, target, { silent: true });
        }
        if (announce) await this.announceEvent(eventId);
        await repo.addActivity(event.id, event.guildId, { action: 'event_published', userId, username });
        return this.getEvent(eventId);
    }

    /** Post a fresh announcement. Stores the message id for later edits. */
    async announceEvent(eventId) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) throw new Error('Event not found.');
        const channel = await this._fetchChannel(event.announcementChannelId);
        if (!isSendableChannel(channel)) {
            const err = new Error('No announcement channel configured (or the bot cannot post there).');
            err.status = 400;
            throw err;
        }
        const participants = await repo.getParticipantCounts(event.id);
        const message = await channel.send(buildAnnouncementPayload(event, {
            participants: participants.registered,
            interested: participants.interested,
        }));
        await repo.setAnnouncementMessage(event.id, channel.id, message.id);
        event.announcementChannelId = channel.id;
        event.announcementMessageId = message.id;
        this._byId.set(event.id, event);
        await repo.addActivity(event.id, event.guildId, { action: 'announcement_sent', detail: `Posted to #${channel.name || channel.id}` });
        return { channelId: channel.id, messageId: message.id };
    }

    /**
     * Edit the existing announcement in place (no duplicate message). Falls back
     * to posting a new one when the original is gone.
     */
    async updateAnnouncement(eventId) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) return null;
        const channel = await this._fetchChannel(event.announcementChannelId);
        if (!isSendableChannel(channel)) return null;
        const counts = await repo.getParticipantCounts(event.id);
        const payload = buildAnnouncementPayload(event, {
            participants: counts.registered,
            interested: counts.interested,
        });
        if (event.announcementMessageId) {
            const msg = await channel.messages.fetch(event.announcementMessageId).catch(() => null);
            if (msg) {
                await msg.edit(payload).catch(err => console.warn('[EVENTMGMT] announcement edit failed:', err.message));
                return { channelId: channel.id, messageId: msg.id, edited: true };
            }
        }
        return this.announceEvent(eventId);
    }

    async _fetchChannel(channelId) {
        if (!channelId || !this.client) return null;
        return this.client.channels.fetch(channelId).catch(() => null);
    }

    // ── Cancellation / completion ───────────────────────────────────────────
    async cancelEvent(eventId, { notify = true, reason = null, userId = null, username = null } = {}) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) throw new Error('Event not found.');
        if (event.status === 'cancelled') return event;
        await this._transition(event, 'cancelled', { reason, userId, username });
        await this.deleteScheduledEvent(event).catch(() => {});
        // Best-effort announcement update (edit, never a new message).
        await this.updateAnnouncement(event.id).catch(() => {});
        if (notify) {
            const participants = await repo.getParticipants(event.id, { status: 'registered' });
            for (const p of participants) {
                this._dmQueue.push(async () => {
                    const user = await this.client?.users?.fetch(p.userId).catch(() => null);
                    if (!user) return;
                    await user.send({
                        content: `❌ The event **${event.name}** has been cancelled.${reason ? `\nReason: ${reason}` : ''}`,
                    }).catch(() => {});
                });
            }
        }
        return this.getEvent(eventId);
    }

    async completeEvent(eventId, { userId = null, username = null } = {}) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) throw new Error('Event not found.');
        await this._transition(event, 'completed', { userId, username });
        return this.getEvent(eventId);
    }

    // ── Participation (Discord buttons) ─────────────────────────────────────
    async joinEvent(eventId, member) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) return { ok: false, message: 'This event could not be found.' };
        const userId = member.id;
        const guildId = event.guildId;

        if (event.status === 'cancelled') return { ok: false, message: 'This event has been cancelled.' };
        if (event.status === 'completed') return { ok: false, message: 'This event has already finished.' };
        if (event.registrationMode === 'closed' || event.registrationMode === 'invite') {
            return { ok: false, message: 'Registration for this event is closed.' };
        }
        if (!statusAllowsRegistration(event.status) && event.status !== 'scheduled') {
            return { ok: false, message: 'Registration is not open yet.' };
        }
        if (event.registrationDeadline && Date.now() > new Date(event.registrationDeadline).getTime()) {
            return { ok: false, message: 'The registration deadline has passed.' };
        }

        const existing = await repo.getParticipant(event.id, userId);
        if (existing && existing.status === 'registered') {
            return { ok: true, message: 'You are already registered for this event.', status: 'registered' };
        }
        if (existing && existing.status === 'waiting') {
            return { ok: true, message: 'You are already on the waiting list.', status: 'waiting' };
        }

        const registered = await repo.countParticipants(event.id, 'registered');
        let status = 'registered';
        if (event.maxParticipants && registered >= event.maxParticipants) {
            if (!event.waitlistEnabled) return { ok: false, message: 'This event is full.' };
            status = 'waiting';
        }

        await repo.addParticipant(event.id, guildId, userId, {
            username: member.user ? member.user.username : null,
            status,
        });
        if (status === 'registered') {
            this._queueRole(guildId, userId, event.participantRoleId, true, `Joined event: ${event.name}`);
        }
        await repo.addActivity(event.id, guildId, {
            action: status === 'waiting' ? 'participant_waitlisted' : 'participant_joined',
            userId, username: member.user ? member.user.username : null,
        });
        this._refreshAnnouncementLater(event.id);
        return {
            ok: true,
            status,
            message: status === 'waiting'
                ? 'This event is full — you have been added to the waiting list.'
                : 'You are registered! See you there. 🎉',
        };
    }

    /**
     * RSVP dispatcher used by the announcement buttons.
     *   going      → join (capacity + waitlist rules apply)
     *   interested → record interest WITHOUT consuming a slot or granting a role
     *   not_going  → leave / clear the RSVP
     */
    async setRsvp(eventId, member, rsvp) {
        const choice = normalizeRsvp(rsvp);
        if (choice === 'going') return this.joinEvent(eventId, member);
        if (choice === 'not_going') return this.leaveEvent(eventId, member);

        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) return { ok: false, message: 'This event could not be found.' };
        if (event.status === 'cancelled') return { ok: false, message: 'This event has been cancelled.' };
        if (event.status === 'completed') return { ok: false, message: 'This event has already finished.' };

        const existing = await repo.getParticipant(event.id, member.id);
        if (existing && existing.status === 'registered') {
            return { ok: true, status: 'registered', message: 'You are going to this event. Use **Not going** to change that.' };
        }
        if (existing && existing.status === 'interested') {
            return { ok: true, status: 'interested', message: 'You are already marked as interested.' };
        }
        await repo.addParticipant(event.id, event.guildId, member.id, {
            username: member.user ? member.user.username : null,
            status: 'interested',
        });
        await repo.addActivity(event.id, event.guildId, {
            action: 'participant_interested', userId: member.id,
            username: member.user ? member.user.username : null,
        });
        this._refreshAnnouncementLater(event.id);
        return { ok: true, status: 'interested', message: '⭐ You are marked as interested. Use **Going** to reserve a spot.' };
    }

    async leaveEvent(eventId, member) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) return { ok: false, message: 'This event could not be found.' };
        const userId = member.id;
        const existing = await repo.getParticipant(event.id, userId);
        if (!existing || existing.status === 'removed') {
            return { ok: false, message: 'You are not registered for this event.' };
        }
        await repo.removeParticipant(event.id, userId);
        this._queueRole(event.guildId, userId, event.participantRoleId, false, `Left event: ${event.name}`);
        await repo.addActivity(event.id, event.guildId, {
            action: 'participant_left', userId, username: member.user ? member.user.username : null,
        });
        // Automatic waiting-list promotion.
        let promoted = null;
        if (event.waitlistEnabled && existing.status === 'registered') {
            promoted = await repo.promoteNextWaiting(event.id);
            if (promoted) {
                this._queueRole(event.guildId, promoted.userId, event.participantRoleId, true, `Promoted from waitlist: ${event.name}`);
                await repo.addActivity(event.id, event.guildId, {
                    action: 'participant_promoted', userId: promoted.userId, detail: 'Promoted from the waiting list',
                });
                this._dmQueue.push(async () => {
                    const user = await this.client?.users?.fetch(promoted.userId).catch(() => null);
                    if (user) await user.send({ content: `🎉 You've been promoted from the waiting list for **${event.name}**!` }).catch(() => {});
                });
            }
        }
        this._refreshAnnouncementLater(event.id);
        return { ok: true, promoted, message: 'You have left the event.' };
    }

    async checkIn(eventId, member) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) return { ok: false, message: 'This event could not be found.' };
        if (!event.trackAttendance) return { ok: false, message: 'Attendance is not tracked for this event.' };
        const existing = await repo.getParticipant(event.id, member.id);
        if (!existing || existing.status !== 'registered') {
            return { ok: false, message: 'You must be registered to check in.' };
        }
        await repo.updateParticipant(event.id, member.id, { attendanceStatus: 'present' });
        this._queueRole(event.guildId, member.id, event.attendanceRoleId, true, `Checked in: ${event.name}`);
        await repo.addActivity(event.id, event.guildId, {
            action: 'participant_checked_in', userId: member.id,
            username: member.user ? member.user.username : null,
        });
        return { ok: true, message: '✅ You are checked in!' };
    }

    async setResult(eventId, { winnerId = null, runnerUpId = null, notes = null, userId = null, username = null } = {}) {
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        if (!event) throw new Error('Event not found.');
        const result = { winnerId, runnerUpId, notes, recordedAt: new Date().toISOString() };
        await repo.updateEvent(event.id, { result });
        event.result = result;
        this._byId.set(event.id, event);
        if (winnerId && event.winnerRoleId) {
            this._queueRole(event.guildId, winnerId, event.winnerRoleId, true, `Event winner: ${event.name}`);
        }
        await repo.addActivity(event.id, event.guildId, {
            action: 'result_recorded', userId, username,
            detail: winnerId ? `Winner: <@${winnerId}>` : 'Results recorded',
        });
        return event;
    }

    _queueRole(guildId, userId, roleId, add, reason) {
        if (!roleId || !this.client) return;
        this._roleQueue.push(async () => {
            const guild = this.client.guilds.cache.get(guildId) || await this.client.guilds.fetch(guildId).catch(() => null);
            if (!guild) return;
            await applyRole(guild, userId, roleId, { add, reason });
        });
    }

    /** Debounced announcement refresh — an edit, never a new message. */
    _refreshAnnouncementLater(eventId) {
        if (!this.client) return;
        this._refreshTimers = this._refreshTimers || new Map();
        clearTimeout(this._refreshTimers.get(eventId));
        this._refreshTimers.set(eventId, setTimeout(() => {
            this._refreshTimers.delete(eventId);
            this.updateAnnouncement(eventId).catch(() => {});
        }, 4000));
        this._refreshTimers.get(eventId).unref?.();
    }

    // ── Button routing ──────────────────────────────────────────────────────
    /**
     * Handle an `ev*:<eventId>` button interaction. Returns true when handled.
     * All responses are ephemeral except none (announcement edits are silent).
     */
    async handleButton(interaction) {
        const customId = interaction.customId || '';
        const [action, idStr] = customId.split(':');
        const eventId = parseInt(idStr, 10);
        if (!Number.isFinite(eventId)) return false;
        const event = this.getEvent(eventId) || await repo.getEvent(eventId);
        const guildOk = event && String(event.guildId) === String(interaction.guildId);
        if (!event || !guildOk) {
            await interaction.reply({ content: 'This event could not be found.', ephemeral: true }).catch(() => {});
            return true;
        }
        const member = interaction.member;

        if (action === 'evjoin') {
            await interaction.deferReply({ ephemeral: true }).catch(() => {});
            const res = await this.setRsvp(eventId, member, 'going');
            await interaction.editReply({ content: res.message }).catch(() => {});
            return true;
        }
        if (action === 'evinterest') {
            await interaction.deferReply({ ephemeral: true }).catch(() => {});
            const res = await this.setRsvp(eventId, member, 'interested');
            await interaction.editReply({ content: res.message }).catch(() => {});
            return true;
        }
        if (action === 'evleave') {
            await interaction.deferReply({ ephemeral: true }).catch(() => {});
            const res = await this.setRsvp(eventId, member, 'not_going');
            await interaction.editReply({ content: res.message }).catch(() => {});
            return true;
        }
        if (action === 'evcheckin') {
            await interaction.deferReply({ ephemeral: true }).catch(() => {});
            const res = await this.checkIn(eventId, member);
            await interaction.editReply({ content: res.message }).catch(() => {});
            return true;
        }
        if (action === 'evparts') {
            const participants = await repo.getParticipants(eventId, {});
            await interaction.reply({ embeds: [buildParticipantsEmbed(event, participants)], ephemeral: true }).catch(() => {});
            return true;
        }
        if (action === 'evinfo') {
            const counts = await repo.getParticipantCounts(eventId);
            const type = eventTypeMeta(event.type);
            await interaction.reply({
                embeds: [buildAnnouncementPayload(event, {
                    participants: counts.registered,
                    interested: counts.interested,
                    checkedIn: counts.present,
                }).embeds[0]],
                ephemeral: true,
            }).catch(() => {});
            void type;
            return true;
        }
        if (action === 'evremind') {
            const res = await repo.toggleUserReminder(eventId, event.guildId, interaction.user.id);
            await interaction.reply({
                content: res.subscribed
                    ? `🔔 You will be reminded before **${event.name}** starts.`
                    : `🔕 You will no longer be reminded about **${event.name}**.`,
                ephemeral: true,
            }).catch(() => {});
            return true;
        }
        return false;
    }

    // ── Startup ─────────────────────────────────────────────────────────────
    async restore() {
        await this._initPromise;
        console.log(`[EVENTMGMT] Restored ${this._byId.size} event(s).`);
    }

    /** Exposed for tests/diagnostics. */
    get cacheSize() { return this._byId.size; }
}

module.exports = EventMgmtManager;
module.exports.buildAnnouncementPayload = buildAnnouncementPayload;
module.exports.buildEventComponents = buildEventComponents;
