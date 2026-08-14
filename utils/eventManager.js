const { EmbedBuilder, ChannelType, PermissionFlagsBits } = require('discord.js');
const config = require('../config');
const { eventPool } = require('../server/eventDb');

/**
 * EventManager — premium-style event management.
 *
 * A per-guild "event schedule" has a countdown (seconds until start) and a
 * list of "tasks" (actions) each carried out at a relative offset (seconds
 * from the event's start). Supported task actions:
 *
 *   • lock      — set Send Messages off for @everyone in the target channels
 *   • unlock    — re-enable Send Messages for @everyone in those channels
 *   • hide      — set View Channel off for @everyone in the target channels
 *   • unhide    — re-enable View Channel for @everyone in those channels
 *   • addrole   — grant target role(s) to target user(s)
 *   • removerole— remove target role(s) from target user(s)
 *   • sendtext  — post a plain-text message to target channel(s)
 *   • sendembed — post an embed to target channel(s)
 *
 * Backed by the dedicated EVENT_DATABASE_URL pool (server/eventDb.js, falls
 * back to DATABASE_URL). Caching pattern mirrors the other managers: in-memory
 * cache, write-through to DB, and a setInterval re-read (~30s + 5s) so
 * dashboard edits take effect without a bot restart. The execution loop polls
 * every few seconds for schedules whose start time / task offsets have arrived.
 *
 * Configured ONLY from the dashboard's 📅 Events tab.
 */

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS event_schedules (
        id                SERIAL PRIMARY KEY,
        guild_id          VARCHAR(50) NOT NULL,
        name              VARCHAR(100) NOT NULL,
        description       TEXT,
        status            VARCHAR(20) NOT NULL DEFAULT 'scheduled',
        countdown_seconds INTEGER NOT NULL DEFAULT 0,
        start_at          TIMESTAMP,
        triggered         BOOLEAN NOT NULL DEFAULT false,
        enabled           BOOLEAN NOT NULL DEFAULT true,
        created_by_id     VARCHAR(50),
        created_at        TIMESTAMP DEFAULT NOW(),
        updated_at        TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS event_schedules_guild_idx ON event_schedules (guild_id);
    CREATE TABLE IF NOT EXISTS event_tasks (
        id                SERIAL PRIMARY KEY,
        schedule_id       INTEGER NOT NULL REFERENCES event_schedules(id) ON DELETE CASCADE,
        offset_seconds    INTEGER NOT NULL DEFAULT 0,
        action            VARCHAR(30) NOT NULL,
        target_type       VARCHAR(20) NOT NULL DEFAULT 'channel',
        target_ids        JSONB NOT NULL DEFAULT '[]',
        message_content   TEXT,
        embed_title       VARCHAR(255),
        embed_description TEXT,
        embed_color       VARCHAR(20) DEFAULT '#5865F2',
        embed_image_url   TEXT,
        channel_id        VARCHAR(50),
        executed_at       TIMESTAMP,
        created_at        TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS event_tasks_schedule_idx ON event_tasks (schedule_id);
`;

const VALID_ACTIONS = new Set([
    'lock', 'unlock', 'hide', 'unhide',
    'addrole', 'removerole', 'sendtext', 'sendembed',
]);
const VALID_TARGET_TYPES = new Set(['channel', 'role', 'user']);

// How often the scheduler wakes to fire due tasks / start events.
const EXEC_INTERVAL_MS = parseInt(process.env.EVENT_EXEC_INTERVAL_MS, 10) || 5000;

class EventManager {
    constructor(client = null) {
        this.client = client;
        this._byId = new Map();        // id -> schedule
        this._byGuild = new Map();     // guildId -> Set<scheduleId>
        this._tableReady = false;
        this._initPromise = this._init();
    }

    async _init() {
        try {
            await eventPool.query(CREATE_TABLE_SQL);
            this._tableReady = true;
            await this._loadAll();
            this._startReloadInterval();
            this._startExecLoop();
            console.log('✅ EventManager database connection established');
        } catch (error) {
            this._tableReady = false;
            console.error('❌ EventManager database initialization failed:', error.message);
            console.log('⚠️ Events will use fallback mode (memory only)');
        }
    }

    _startReloadInterval() {
        const ms = parseInt(process.env.SETTINGS_RELOAD_INTERVAL_MS, 10) || 30000;
        this._reloadTimer = setInterval(() => {
            this._loadAll().catch(err => console.error('[EVENTS] Background reload failed:', err.message));
        }, ms);
        this._reloadTimer.unref?.();
    }

    _startExecLoop() {
        this._execTimer = setInterval(() => {
            this._tick().catch(err => console.error('[EVENTS] Exec tick failed:', err.message));
        }, EXEC_INTERVAL_MS);
        this._execTimer.unref?.();
    }

    async _loadAll() {
        if (!this._tableReady) return;
        const { rows: schedules } = await eventPool.query(
            `SELECT * FROM event_schedules WHERE enabled = true ORDER BY id`
        );
        this._byId.clear();
        this._byGuild.clear();
        for (const s of schedules) {
            const { rows: tasks } = await eventPool.query(
                `SELECT * FROM event_tasks WHERE schedule_id = $1 ORDER BY offset_seconds, id`, [s.id]
            );
            const schedule = this._rowToSchedule(s, tasks);
            this._byId.set(s.id, schedule);
            if (!this._byGuild.has(s.guild_id)) this._byGuild.set(s.guild_id, new Set());
            this._byGuild.get(s.guild_id).add(s.id);
        }
    }

    _rowToSchedule(row, taskRows = []) {
        return {
            id: row.id,
            guildId: row.guild_id,
            name: row.name,
            description: row.description || null,
            status: row.status || 'scheduled',
            countdownSeconds: Number(row.countdown_seconds) || 0,
            startAt: row.start_at ? new Date(row.start_at) : null,
            triggered: row.triggered === true,
            enabled: row.enabled !== false,
            createdById: row.created_by_id || null,
            createdAt: row.created_at ? new Date(row.created_at) : new Date(),
            updatedAt: row.updated_at ? new Date(row.updated_at) : new Date(),
            tasks: (taskRows || []).map(t => this._rowToTask(t)),
        };
    }

    _rowToTask(row) {
        return {
            id: row.id,
            scheduleId: row.schedule_id,
            offsetSeconds: Number(row.offset_seconds) || 0,
            action: row.action,
            targetType: row.target_type || 'channel',
            targetIds: Array.isArray(row.target_ids) ? row.target_ids.map(String) : [],
            messageContent: row.message_content || null,
            embedTitle: row.embed_title || null,
            embedDescription: row.embed_description || null,
            embedColor: row.embed_color || '#5865F2',
            embedImageUrl: row.embed_image_url || null,
            channelId: row.channel_id || null,
            executedAt: row.executed_at ? new Date(row.executed_at) : null,
        };
    }

    normalizeTask(data, keepUndefined = false) {
        const out = keepUndefined ? { ...(data || {}) } : {
            offsetSeconds: 0, action: 'sendtext', targetType: 'channel',
            targetIds: [], messageContent: null, embedTitle: null,
            embedDescription: null, embedColor: '#5865F2', embedImageUrl: null,
            channelId: null, ...(data || {}),
        };
        out.offsetSeconds = Math.max(0, parseInt(out.offsetSeconds, 10) || 0);
        out.action = VALID_ACTIONS.has(out.action) ? out.action : 'sendtext';
        out.targetType = VALID_TARGET_TYPES.has(out.targetType) ? out.targetType : 'channel';
        out.targetIds = Array.isArray(out.targetIds) ? out.targetIds.map(String) : [];
        if (out.embedColor && !/^#[0-9a-fA-F]{6}$/.test(out.embedColor)) out.embedColor = '#5865F2';
        return out;
    }

    // ── Public read API (used by the bot + dashboard indirectly via reload) ──

    getGuildSchedules(guildId) {
        const ids = this._byGuild.get(guildId);
        if (!ids) return [];
        return Array.from(ids).map(id => this._byId.get(id)).filter(Boolean);
    }

    getSchedule(id) {
        return this._byId.get(id) || null;
    }

    // ── Scheduling: start an event now / at a future time ──────────────────────
    //
    // The dashboard creates a schedule (status 'scheduled', start_at set to
    // now + countdownSeconds). The exec loop fires `start` when start_at has
    // arrived and runs each task when its offset has elapsed, marking tasks
    // executed_at so restarts resume.

    async startNow(scheduleId) {
        if (!this._tableReady) throw new Error('Event database not available');
        const startAt = new Date();
        await eventPool.query(
            `UPDATE event_schedules SET status = 'running', start_at = $2, triggered = true, updated_at = NOW() WHERE id = $1`,
            [scheduleId, startAt]
        );
        const schedule = this._byId.get(scheduleId);
        if (schedule) {
            schedule.status = 'running';
            schedule.startAt = startAt;
            schedule.triggered = true;
        }
        // Fire immediately rather than waiting for the next tick.
        this._tick().catch(() => {});
        return true;
    }

    async cancelSchedule(scheduleId) {
        if (!this._tableReady) throw new Error('Event database not available');
        await eventPool.query(
            `UPDATE event_schedules SET status = 'cancelled', enabled = false, updated_at = NOW() WHERE id = $1`,
            [scheduleId]
        );
        const schedule = this._byId.get(scheduleId);
        if (schedule) { schedule.status = 'cancelled'; schedule.enabled = false; }
        return true;
    }

    // ── The scheduler tick ─────────────────────────────────────────────────────

    async _tick() {
        if (!this._tableReady || !this.client) return;
        const now = Date.now();
        for (const schedule of this._byId.values()) {
            if (!schedule.enabled) continue;
            if (schedule.status === 'completed' || schedule.status === 'cancelled') continue;
            // Start the event when its countdown elapses (if it hasn't fired yet).
            if (!schedule.triggered && schedule.startAt) {
                if (now >= schedule.startAt.getTime()) {
                    schedule.triggered = true;
                    schedule.status = 'running';
                    await eventPool.query(
                        `UPDATE event_schedules SET triggered = true, status = 'running', updated_at = NOW() WHERE id = $1`,
                        [schedule.id]
                    ).catch(() => {});
                    console.log(`[EVENTS] Started schedule "${schedule.name}" (${schedule.id})`);
                } else {
                    continue; // not time yet
                }
            }
            if (!schedule.triggered) continue;

            const startMs = schedule.startAt ? schedule.startAt.getTime() : now;
            let allDone = true;
            for (const task of schedule.tasks) {
                if (task.executedAt) continue;
                const dueAt = startMs + task.offsetSeconds * 1000;
                if (now < dueAt) { allDone = false; continue; }
                try {
                    await this._executeTask(schedule, task);
                    task.executedAt = new Date();
                    await eventPool.query(
                        `UPDATE event_tasks SET executed_at = NOW() WHERE id = $1`, [task.id]
                    ).catch(() => {});
                } catch (err) {
                    console.error(`[EVENTS] Task ${task.id} (${task.action}) failed:`, err.message);
                    // Mark executed to avoid retrying forever on a broken task.
                    task.executedAt = new Date();
                    await eventPool.query(
                        `UPDATE event_tasks SET executed_at = NOW() WHERE id = $1`, [task.id]
                    ).catch(() => {});
                }
            }
            if (allDone && schedule.tasks.length > 0) {
                schedule.status = 'completed';
                await eventPool.query(
                    `UPDATE event_schedules SET status = 'completed', updated_at = NOW() WHERE id = $1`, [schedule.id]
                ).catch(() => {});
                console.log(`[EVENTS] Completed schedule "${schedule.name}" (${schedule.id})`);
            }
        }
    }

    // ── Task execution ─────────────────────────────────────────────────────────

    async _executeTask(schedule, task) {
        const guild = await this.client.guilds.fetch(schedule.guildId).catch(() => null);
        if (!guild) throw new Error('Guild not found');

        switch (task.action) {
            case 'lock':
            case 'unlock':
            case 'hide':
            case 'unhide':
                return this._applyChannelPerm(guild, task);
            case 'addrole':
                return this._applyRole(guild, task, true);
            case 'removerole':
                return this._applyRole(guild, task, false);
            case 'sendtext':
                return this._sendMessage(guild, task, false);
            case 'sendembed':
                return this._sendMessage(guild, task, true);
            default:
                throw new Error(`Unknown event action: ${task.action}`);
        }
    }

    async _applyChannelPerm(guild, task) {
        const channels = this._resolveChannels(guild, task.targetIds);
        const lock = task.action === 'lock';
        const hide = task.action === 'hide';
        const unlock = task.action === 'unlock';
        const unhide = task.action === 'unhide';
        for (const channel of channels) {
            const overwrites = channel.permissionOverwrites;
            const allow = [];
            const deny = [];
            // lock/hide => deny; unlock/unhide => allow (revert).
            const send = PermissionFlagsBits.SendMessages;
            const view = PermissionFlagsBits.ViewChannel;
            if (lock) deny.push(send);
            if (unlock) allow.push(send);
            if (hide) deny.push(view);
            if (unhide) allow.push(view);
            try {
                await overwrites.edit(guild.roles.everyone.id, {
                    SendMessages: lock ? false : (unlock ? true : undefined),
                    ViewChannel: hide ? false : (unhide ? true : undefined),
                }, { reason: `Event "${task.action}" by EventManager` });
            } catch (err) {
                console.error(`[EVENTS] ${task.action} on channel ${channel.id} failed:`, err.message);
            }
        }
    }

    _resolveChannels(guild, ids) {
        const out = [];
        for (const id of ids) {
            const ch = guild.channels.cache.get(id) || guild.channels.cache.find(c => c.name === id);
            if (ch) out.push(ch);
        }
        return out;
    }

    async _applyRole(guild, task, add) {
        const roles = [];
        for (const id of task.targetIds) {
            const r = guild.roles.cache.get(id) || guild.roles.cache.find(x => x.name === id);
            if (r) roles.push(r);
        }
        if (roles.length === 0) return;
        // For addrole/removerole targetIds may be role ids; users are resolved
        // via task.channelId? No — apply to all members with the role is odd.
        // Convention: targetIds are ROLE ids to apply to ALL members, OR
        // targetType 'user' => targetIds are user ids.
        const members = [];
        if (task.targetType === 'user') {
            for (const id of task.targetIds) {
                const m = await guild.members.fetch(id).catch(() => null);
                if (m) members.push(m);
            }
            for (const m of members) {
                for (const role of roles) {
                    if (add) await m.roles.add(role, `Event addrole by EventManager`).catch(() => {});
                    else await m.roles.remove(role, `Event removerole by EventManager`).catch(() => {});
                }
            }
        } else {
            // Apply role to all members — generally only addrole to a role is meaningful;
            // for removerole we skip mass removal to avoid destructive surprises.
            if (add) {
                for (const role of roles) {
                    for (const [, m] of guild.members.cache) {
                        await m.roles.add(role, `Event addrole by EventManager`).catch(() => {});
                    }
                }
            }
        }
    }

    async _sendMessage(guild, task, isEmbed) {
        const channelIds = task.targetIds && task.targetIds.length > 0 ? task.targetIds : (task.channelId ? [task.channelId] : []);
        const channels = this._resolveChannels(guild, channelIds);
        for (const channel of channels) {
            try {
                if (isEmbed) {
                    const embed = new EmbedBuilder()
                        .setColor(task.embedColor || '#5865F2')
                        .setTitle(task.embedTitle || null)
                        .setDescription(task.embedDescription || null)
                        .setTimestamp();
                    if (task.embedImageUrl) {
                        try { embed.setImage(task.embedImageUrl); } catch {}
                    }
                    await channel.send({ embeds: [embed] });
                } else {
                    await channel.send(task.messageContent || ' ');
                }
            } catch (err) {
                console.error(`[EVENTS] sendmessage to ${channel.id} failed:`, err.message);
            }
        }
    }

    // ── Restore on startup (called from events/ready.js) ──────────────────────
    async restore() {
        await this._initPromise;
        // _loadAll already ran in _init; just log.
        console.log('[EVENTS] Restored schedules from database.');
    }
}

module.exports = EventManager;
