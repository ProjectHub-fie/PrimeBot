/**
 * securityAuditLogger.js
 *
 * PRIVATE, owner-controlled security audit log.
 *
 * Records, for every server PrimeBot is installed in:
 *   • server join / leave (the bot's own membership changes),
 *   • voice-channel joins, leaves and moves,
 *   • PrimeBot's own voice activity (join / leave / move / disconnect).
 *
 * Every event is delivered as a Discord embed to ONE hardcoded private channel
 * (`config.securityAudit.channelId` → `SECURITY_AUDIT_CHANNEL_ID` in config.js).
 * There is no slash command, no dashboard page, no per-guild setting and no
 * environment variable: only the bot owner can change the destination, and only
 * by editing the source. The channel id is never echoed in a user-facing
 * response or a full-form log line (diagnostics mask it).
 *
 * ARCHITECTURE — NO DATABASE.
 * The only persistence is the Discord message itself. Everything else is
 * in-memory and rebuilt on boot:
 *   • `guildCache`    — last-known guild name / owner / member count, so a
 *                       guildDelete (which arrives with partial data) can still
 *                       report what was known while the bot was running.
 *   • `voiceSessions` — join timestamps per (guild, user) for duration math.
 * A restart empties both: a session that started before the restart is reported
 * as "duration unavailable" rather than invented.
 *
 * Every public method is fire-and-forget and swallows its own errors — an audit
 * failure can never crash the bot or block the event that triggered it.
 */

const { EmbedBuilder } = require('discord.js');
const config = require('../config');

const COLORS = {
    join: 0x2ECC71,   // green  — server join, voice join
    leave: 0xE74C3C,  // red    — server leave, voice leave
    move: 0xE67E22,   // orange — voice move, unexpected disconnect
    info: 0x3498DB,   // blue   — informational security events
};

const EVENT_TYPES = {
    SERVER_JOIN: 'server_join',
    SERVER_LEAVE: 'server_leave',
    VOICE_JOIN: 'voice_join',
    VOICE_LEAVE: 'voice_leave',
    VOICE_MOVE: 'voice_move',
    BOT_VOICE_JOIN: 'voice_bot_join',
    BOT_VOICE_LEAVE: 'voice_bot_leave',
    BOT_VOICE_MOVE: 'voice_bot_move',
    BOT_VOICE_DISCONNECT: 'voice_bot_disconnect',
};

const UNAVAILABLE = 'Unavailable';
const FOOTER = 'PrimeBot Security Audit';

const DEDUPE_WINDOW_MS = 10000;
const DEDUPE_BUCKET_MS = 2000;
const MAX_GUILD_CACHE = 10000;
const MAX_VOICE_SESSIONS = 50000;
const MAX_SEEN = 2000;
const MAX_QUEUE = 200;
const DEFAULT_RETRY_DELAYS = [500, 1500];
const MAX_RETRY_WAIT_MS = 30000;
const SNOWFLAKE = /^\d{15,22}$/;
// A guildCreate whose membership is older than this is the READY-time cache
// hydration burst, not a real join.
const JOIN_FRESHNESS_MS = 5 * 60 * 1000;
const READY_GRACE_MS = 60000;

// ── Pure formatting helpers ─────────────────────────────────────────────────

/** Absolute + relative Discord timestamp, or "Unavailable". */
function discordTime(value) {
    let ms = NaN;
    if (value instanceof Date) ms = value.getTime();
    else if (typeof value === 'number') ms = value;
    else if (typeof value === 'string') ms = Date.parse(value);
    if (!Number.isFinite(ms)) return UNAVAILABLE;
    const seconds = Math.floor(ms / 1000);
    return `<t:${seconds}:F> (<t:${seconds}:R>)`;
}

function formatDuration(ms) {
    if (!Number.isFinite(ms) || ms < 0) return null;
    const total = Math.floor(ms / 1000);
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const seconds = total % 60;
    if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}

/** Mask an id for diagnostics — the private destination never appears in full. */
function maskId(id) {
    const value = String(id == null ? '' : id);
    return value.length <= 4 ? '••••' : `••••${value.slice(-4)}`;
}

/** Make a user/guild supplied string safe for an embed value. */
function clean(text, max = 100) {
    if (text == null) return '';
    const flat = String(text).replace(/[`\r\n]+/g, ' ').trim();
    return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

function idValue(id) {
    return id ? `\`${id}\`` : UNAVAILABLE;
}

function channelName(channel) {
    return channel && channel.name ? clean(channel.name) : UNAVAILABLE;
}

// ── Embed builders (pure) ───────────────────────────────────────────────────

function buildGuildJoinEmbed({ guild, botGuildCount, ownerName, now = new Date() }) {
    const name = guild && guild.name ? clean(guild.name) : UNAVAILABLE;
    const id = guild && guild.id ? guild.id : null;
    const ownerId = guild && guild.ownerId ? guild.ownerId : null;
    const memberCount = guild && Number.isFinite(guild.memberCount) ? guild.memberCount : null;

    const embed = new EmbedBuilder()
        .setColor(COLORS.join)
        .setTitle('🟢 PrimeBot Joined a Server')
        .setFooter({ text: `${FOOTER} · ${EVENT_TYPES.SERVER_JOIN}` })
        .setTimestamp(now)
        .addFields(
            { name: 'Server', value: `${name} (${idValue(id)})`, inline: false },
            { name: 'Server ID', value: idValue(id), inline: true },
            { name: 'Owner', value: ownerId ? `<@${ownerId}>` : UNAVAILABLE, inline: true },
            { name: 'Owner ID', value: idValue(ownerId), inline: true },
            { name: 'Owner name', value: ownerName ? `@${clean(ownerName)}` : UNAVAILABLE, inline: true },
            { name: 'Members', value: memberCount != null ? String(memberCount) : UNAVAILABLE, inline: true },
            { name: 'Server created', value: guild && guild.createdAt ? discordTime(guild.createdAt) : UNAVAILABLE, inline: false },
            { name: 'PrimeBot joined', value: discordTime(now), inline: false },
            { name: 'Total servers', value: botGuildCount != null ? String(botGuildCount) : UNAVAILABLE, inline: true },
            { name: 'Event', value: `\`${EVENT_TYPES.SERVER_JOIN}\``, inline: true },
        );

    const icon = safeIconUrl(guild);
    if (icon) embed.setThumbnail(icon);
    return embed;
}

function buildGuildLeaveEmbed({ snapshot, remainingServers, now = new Date() }) {
    const s = snapshot || {};
    const missing = !s.name || !s.ownerId || s.memberCount == null;

    const embed = new EmbedBuilder()
        .setColor(COLORS.leave)
        .setTitle('🔴 PrimeBot Left a Server')
        .setFooter({ text: `${FOOTER} · ${EVENT_TYPES.SERVER_LEAVE}` })
        .setTimestamp(now)
        .addFields(
            { name: 'Server (last known)', value: `${s.name ? clean(s.name) : UNAVAILABLE} (${idValue(s.id)})`, inline: false },
            { name: 'Server ID', value: idValue(s.id), inline: true },
            { name: 'Owner ID (last known)', value: idValue(s.ownerId), inline: true },
            { name: 'Members (last known)', value: s.memberCount != null ? String(s.memberCount) : UNAVAILABLE, inline: true },
            { name: 'Left at', value: discordTime(now), inline: false },
            { name: 'Remaining servers', value: remainingServers != null ? String(remainingServers) : UNAVAILABLE, inline: true },
            { name: 'Event', value: `\`${EVENT_TYPES.SERVER_LEAVE}\``, inline: true },
        );

    if (missing) {
        embed.setDescription(
            'Discord can deliver partial guild data when the bot is removed. Values that were not '
            + 'available are reported as **Unavailable** — nothing is inferred.'
        );
    }
    if (typeof s.iconURL === 'string' && /^https?:\/\//.test(s.iconURL)) embed.setThumbnail(s.iconURL);
    return embed;
}

const VOICE_META = {
    [EVENT_TYPES.VOICE_JOIN]: { title: '🟢 Voice Channel Join', color: COLORS.join },
    [EVENT_TYPES.VOICE_LEAVE]: { title: '🔴 Voice Channel Leave', color: COLORS.leave },
    [EVENT_TYPES.VOICE_MOVE]: { title: '🟠 Voice Channel Move', color: COLORS.move },
    [EVENT_TYPES.BOT_VOICE_JOIN]: { title: '🤖 PrimeBot Joined Voice', color: COLORS.info },
    [EVENT_TYPES.BOT_VOICE_LEAVE]: { title: '🤖 PrimeBot Left Voice', color: COLORS.leave },
    [EVENT_TYPES.BOT_VOICE_MOVE]: { title: '🤖 PrimeBot Moved Voice Channel', color: COLORS.move },
    [EVENT_TYPES.BOT_VOICE_DISCONNECT]: { title: '🤖 PrimeBot Voice Disconnect', color: COLORS.move },
};

function buildVoiceEmbed({
    type,
    guild,
    member,
    fromChannel,
    toChannel,
    durationMs,
    durationUnavailableReason,
    isBot = false,
    now = new Date(),
}) {
    const meta = VOICE_META[type] || { title: '🔵 Security Event', color: COLORS.info };
    const embed = new EmbedBuilder()
        .setColor(meta.color)
        .setTitle(meta.title)
        .setFooter({ text: `${FOOTER} · ${type}` })
        .setTimestamp(now);

    if (guild) {
        embed.addFields(
            { name: 'Server', value: `${guild.name ? clean(guild.name) : UNAVAILABLE} (${idValue(guild.id)})`, inline: false },
            { name: 'Server ID', value: idValue(guild.id), inline: true },
        );
    }

    if (member) {
        const username = member.user && member.user.username ? member.user.username : null;
        const display = member.displayName || (member.user && member.user.globalName) || username || null;
        embed.addFields(
            {
                name: isBot ? 'Bot' : 'Member',
                value: `${display ? clean(display) : UNAVAILABLE} (<@${member.id}>)`,
                inline: true,
            },
            { name: 'Username', value: username ? `@${clean(username)}` : UNAVAILABLE, inline: true },
            { name: 'User ID', value: idValue(member.id), inline: true },
        );
    }

    if (fromChannel) {
        embed.addFields(
            { name: 'Previous channel', value: channelName(fromChannel), inline: true },
            { name: 'Previous channel ID', value: idValue(fromChannel.id), inline: true },
        );
    }
    if (toChannel) {
        embed.addFields(
            { name: fromChannel ? 'New channel' : 'Channel', value: channelName(toChannel), inline: true },
            { name: fromChannel ? 'New channel ID' : 'Channel ID', value: idValue(toChannel.id), inline: true },
        );
    }

    if (durationMs != null) {
        embed.addFields({ name: 'Duration', value: formatDuration(durationMs) || UNAVAILABLE, inline: true });
    } else if (durationUnavailableReason) {
        embed.addFields({ name: 'Duration', value: `${UNAVAILABLE} — ${clean(durationUnavailableReason, 180)}`, inline: true });
    }

    embed.addFields(
        { name: 'Event', value: `\`${type}\``, inline: true },
        { name: 'Timestamp', value: discordTime(now), inline: false },
    );
    return embed;
}

function safeIconUrl(guild) {
    try {
        if (!guild || typeof guild.iconURL !== 'function') return null;
        const url = guild.iconURL({ size: 256 });
        return typeof url === 'string' && /^https?:\/\//.test(url) ? url : null;
    } catch (_) {
        return null;
    }
}

// ── Delivery error classification ───────────────────────────────────────────

function errorStatus(err) {
    if (!err) return null;
    if (Number.isFinite(err.status)) return err.status;
    if (Number.isFinite(err.httpStatus)) return err.httpStatus;
    if (err.rawError && Number.isFinite(err.rawError.status)) return err.rawError.status;
    return null;
}

function isRetryable(err) {
    const status = errorStatus(err);
    if (status === 429) return true;
    if (status != null && status >= 500 && status <= 599) return true;
    const code = err && err.code;
    if (code === 'ECONNRESET' || code === 'ETIMEDOUT' || code === 'ENOTFOUND' || code === 'EAI_AGAIN') return true;
    return Boolean(err && err.name === 'AbortError');
}

function retryAfterMs(err) {
    if (!err) return null;
    // discord.js RateLimitError exposes `retryAfter` in milliseconds.
    if (Number.isFinite(err.retryAfter)) return Math.min(Math.max(err.retryAfter, 0), MAX_RETRY_WAIT_MS);
    if (err.rawError && Number.isFinite(err.rawError.retry_after)) {
        return Math.min(Math.max(err.rawError.retry_after * 1000, 0), MAX_RETRY_WAIT_MS);
    }
    if (Number.isFinite(err.retry_after)) return Math.min(Math.max(err.retry_after * 1000, 0), MAX_RETRY_WAIT_MS);
    return null;
}

function describeError(err) {
    if (!err) return 'unknown error';
    const status = errorStatus(err);
    const code = err.code || (status != null ? `HTTP ${status}` : err.name) || 'error';
    const message = err.message ? String(err.message) : '';
    return clean(`${code}${message ? `: ${message}` : ''}`, 200);
}

// ── Logger ──────────────────────────────────────────────────────────────────

class SecurityAuditLogger {
    constructor(options = {}) {
        const auditConfig = (config && config.securityAudit) || {};
        this.channelId = options.channelId !== undefined ? options.channelId : auditConfig.channelId;
        this.enabled = options.enabled !== undefined ? options.enabled : auditConfig.enabled !== false;
        this.client = options.client || null;
        this.logger = options.logger || console;

        this.guildCache = new Map();
        this.voiceSessions = new Map();
        this.stats = { sent: 0, failed: 0, skipped: 0, lastError: null };

        this._retryDelays = Array.isArray(options.retryDelays) ? options.retryDelays : DEFAULT_RETRY_DELAYS;
        this._maxQueue = Number.isFinite(options.maxQueue) ? options.maxQueue : MAX_QUEUE;
        this._now = typeof options.nowFn === 'function' ? options.nowFn : () => Date.now();
        this._sleepFn = typeof options.sleepFn === 'function'
            ? options.sleepFn
            : (resolve, ms) => setTimeout(resolve, ms);

        this._queue = Promise.resolve();
        this._queueDepth = 0;
        this._seen = new Map();
        this._fetchCooldownUntil = 0;
        this._warnedUnconfigured = false;
    }

    // ── configuration ──────────────────────────────────────────────────────

    isConfigured() {
        return SNOWFLAKE.test(String(this.channelId == null ? '' : this.channelId).trim());
    }

    // ── lifecycle ──────────────────────────────────────────────────────────

    /** Attach the client and snapshot every guild we can see (in memory only). */
    attach(client) {
        if (client) this.client = client;
        try {
            const cache = this.client && this.client.guilds && this.client.guilds.cache;
            if (cache && typeof cache.values === 'function') {
                for (const guild of cache.values()) this.rememberGuild(guild);
            }
        } catch (err) {
            this._diagnose('could not snapshot guild cache', err);
        }
        return this;
    }

    /** Resolve the destination once and report a safe diagnostic on failure. */
    async verifyDestination() {
        if (!this.enabled) return { ok: false, reason: 'disabled' };
        if (!this.isConfigured()) {
            this._warnUnconfigured();
            return { ok: false, reason: 'not_configured' };
        }
        const channel = await this.resolveChannel();
        if (!channel) return { ok: false, reason: 'unreachable' };
        const perms = this.checkPermissions(channel);
        if (!perms.ok) {
            this._diagnose(
                `destination ${maskId(this.channelId)} is missing permission(s): ${perms.missing.join(', ')}`
            );
            return { ok: false, reason: 'missing_permissions', missing: perms.missing };
        }
        this._diagnose(`destination verified (${maskId(this.channelId)})`, null, 'log');
        return { ok: true };
    }

    // ── in-memory guild cache ──────────────────────────────────────────────

    rememberGuild(guild) {
        if (!guild || !guild.id) return null;
        const prev = this.guildCache.get(guild.id) || {};
        const snapshot = {
            id: guild.id,
            name: guild.name || prev.name || null,
            iconURL: safeIconUrl(guild) || prev.iconURL || null,
            ownerId: guild.ownerId || prev.ownerId || null,
            memberCount: Number.isFinite(guild.memberCount) ? guild.memberCount : (prev.memberCount ?? null),
            knownAt: this._now(),
        };
        this.guildCache.set(guild.id, snapshot);
        if (this.guildCache.size > MAX_GUILD_CACHE) {
            this.guildCache.delete(this.guildCache.keys().next().value);
        }
        return snapshot;
    }

    getGuildSnapshot(guildId) {
        return this.guildCache.get(guildId) || null;
    }

    getVoiceSession(guildId, userId) {
        return this.voiceSessions.get(`${guildId}:${userId}`) || null;
    }

    // ── server join / leave ────────────────────────────────────────────────

    async onGuildCreate(guild, client) {
        try {
            if (client) this.client = client;
            if (!guild || !guild.id) return false;
            this.rememberGuild(guild);
            // discord.js re-emits `guildCreate` for EVERY guild it is already in
            // while it hydrates the cache at READY. Only a genuinely recent
            // membership change is an audit-worthy join.
            if (!this._isRecentJoin(guild)) return false;
            if (this._isDuplicate(`${EVENT_TYPES.SERVER_JOIN}|${guild.id}|${this._bucket()}`)) return false;

            const ownerName = await this._withTimeout(this._resolveOwnerName(guild), 5000);
            const embed = buildGuildJoinEmbed({
                guild,
                botGuildCount: this._guildCount(),
                ownerName,
                now: new Date(this._now()),
            });
            return await this._deliver(embed, { type: EVENT_TYPES.SERVER_JOIN, guildId: guild.id });
        } catch (err) {
            this._diagnose('server join audit failed', err);
            return false;
        }
    }

    async onGuildDelete(guild, client) {
        try {
            if (client) this.client = client;
            if (!guild || !guild.id) return false;
            // A guild marked unavailable is a Discord outage, NOT a removal —
            // never report it as "PrimeBot left a server".
            if (guild.available === false) return false;

            const cached = this.guildCache.get(guild.id) || {};
            const snapshot = {
                id: guild.id,
                name: guild.name || cached.name || null,
                ownerId: guild.ownerId || cached.ownerId || null,
                memberCount: Number.isFinite(guild.memberCount) ? guild.memberCount : (cached.memberCount ?? null),
                iconURL: cached.iconURL || null,
            };
            this.guildCache.delete(guild.id);
            for (const key of Array.from(this.voiceSessions.keys())) {
                if (key.startsWith(`${guild.id}:`)) this.voiceSessions.delete(key);
            }

            if (this._isDuplicate(`${EVENT_TYPES.SERVER_LEAVE}|${guild.id}|${this._bucket()}`)) return false;

            const embed = buildGuildLeaveEmbed({
                snapshot,
                remainingServers: this._guildCount(),
                now: new Date(this._now()),
            });
            return await this._deliver(embed, { type: EVENT_TYPES.SERVER_LEAVE, guildId: guild.id });
        } catch (err) {
            this._diagnose('server leave audit failed', err);
            return false;
        }
    }

    // ── voice activity ─────────────────────────────────────────────────────

    async onVoiceStateUpdate(oldState, newState, client) {
        try {
            if (client) this.client = client;
            const guild = (newState && newState.guild) || (oldState && oldState.guild) || null;
            const member = (newState && newState.member) || (oldState && oldState.member) || null;
            const guildId = guild && guild.id;
            const userId = (newState && newState.id) || (member && member.id) || (oldState && oldState.id);
            if (!guildId || !userId) return false;

            const from = (oldState && oldState.channelId) || null;
            const to = (newState && newState.channelId) || null;
            // Mute / deafen / streaming / camera / status changes never move the
            // member between channels — they must not produce join/leave logs.
            if (from === to) return false;

            const botId = this.client && this.client.user ? this.client.user.id : null;
            const isBot = Boolean((member && member.user && member.user.bot) || (botId && userId === botId));
            const key = `${guildId}:${userId}`;
            const session = this.voiceSessions.get(key) || null;
            const now = this._now();
            const fromChannel = (oldState && oldState.channel) || (session ? { id: session.channelId, name: session.channelName } : null);
            const toChannel = (newState && newState.channel) || null;

            if (!from && to) {
                this._setSession(key, { channelId: to, channelName: toChannel && toChannel.name ? toChannel.name : null, joinedAt: now });
                return await this._emitVoice(isBot ? EVENT_TYPES.BOT_VOICE_JOIN : EVENT_TYPES.VOICE_JOIN, {
                    guild, member, toChannel, isBot, now,
                });
            }

            if (from && !to) {
                this.voiceSessions.delete(key);
                const durationMs = session && Number.isFinite(session.joinedAt) ? now - session.joinedAt : null;
                const reason = durationMs == null
                    ? (session
                        ? 'the session timestamp was not recorded'
                        : 'the session began before the latest bot restart')
                    : null;
                const type = isBot
                    ? (this._channelStillExists(guild, from) ? EVENT_TYPES.BOT_VOICE_LEAVE : EVENT_TYPES.BOT_VOICE_DISCONNECT)
                    : EVENT_TYPES.VOICE_LEAVE;
                return await this._emitVoice(type, {
                    guild, member, fromChannel, durationMs, durationUnavailableReason: reason, isBot, now,
                });
            }

            if (from && to) {
                const durationMs = session && Number.isFinite(session.joinedAt) ? now - session.joinedAt : null;
                const reason = durationMs == null
                    ? (session
                        ? 'the session timestamp was not recorded'
                        : 'the session began before the latest bot restart')
                    : null;
                this._setSession(key, { channelId: to, channelName: toChannel && toChannel.name ? toChannel.name : null, joinedAt: now });
                return await this._emitVoice(isBot ? EVENT_TYPES.BOT_VOICE_MOVE : EVENT_TYPES.VOICE_MOVE, {
                    guild, member, fromChannel, toChannel, durationMs, durationUnavailableReason: reason, isBot, now,
                });
            }

            return false;
        } catch (err) {
            this._diagnose('voice audit failed', err);
            return false;
        }
    }

    async _emitVoice(type, payload) {
        const guildId = payload.guild && payload.guild.id;
        const memberId = payload.member && payload.member.id;
        const fromId = payload.fromChannel && payload.fromChannel.id;
        const toId = payload.toChannel && payload.toChannel.id;
        if (this._isDuplicate(`${type}|${guildId}|${memberId}|${fromId || '-'}|${toId || '-'}|${this._bucket()}`)) {
            return false;
        }
        const embed = buildVoiceEmbed({
            type,
            guild: payload.guild,
            member: payload.member,
            fromChannel: payload.fromChannel,
            toChannel: payload.toChannel,
            durationMs: payload.durationMs,
            durationUnavailableReason: payload.durationUnavailableReason,
            isBot: payload.isBot,
            now: new Date(payload.now != null ? payload.now : this._now()),
        });
        return this._deliver(embed, { type, guildId });
    }

    _setSession(key, session) {
        this.voiceSessions.set(key, session);
        if (this.voiceSessions.size > MAX_VOICE_SESSIONS) {
            this.voiceSessions.delete(this.voiceSessions.keys().next().value);
        }
    }

    _channelStillExists(guild, channelId) {
        try {
            if (!guild || !guild.channels || !guild.channels.cache) return true;
            if (typeof guild.channels.cache.has === 'function') return guild.channels.cache.has(channelId);
            return true;
        } catch (_) {
            return true;
        }
    }

    // ── delivery ───────────────────────────────────────────────────────────

    async resolveChannel() {
        const client = this.client;
        if (!client || !client.channels) {
            this._diagnose('cannot resolve the destination channel: client is not ready');
            return null;
        }
        let channel = null;
        try {
            if (client.channels.cache && typeof client.channels.cache.get === 'function') {
                channel = client.channels.cache.get(this.channelId) || null;
            }
        } catch (_) { /* fall through to fetch */ }

        if (!channel) {
            const now = this._now();
            if (now < this._fetchCooldownUntil) return null;
            if (typeof client.channels.fetch !== 'function') {
                this._diagnose(`destination channel ${maskId(this.channelId)} is not cached and cannot be fetched`);
                return null;
            }
            try {
                channel = await client.channels.fetch(this.channelId);
            } catch (err) {
                this._fetchCooldownUntil = now + 60000;
                this._diagnose(`destination channel ${maskId(this.channelId)} is missing or inaccessible (${describeError(err)})`);
                return null;
            }
        }

        if (!channel) {
            this._diagnose(`destination channel ${maskId(this.channelId)} is missing`);
            return null;
        }
        // Never deliver anywhere but the configured private channel.
        if (String(channel.id) !== String(this.channelId)) {
            this._diagnose('resolved channel does not match the configured audit destination');
            return null;
        }
        if (!this._isTextBased(channel)) {
            this._diagnose(`destination ${maskId(this.channelId)} is not a text-based channel`);
            return null;
        }
        return channel;
    }

    _isTextBased(channel) {
        if (!channel) return false;
        if (typeof channel.isTextBased === 'function') {
            try {
                return channel.isTextBased() === true;
            } catch (_) { return false; }
        }
        if (typeof channel.isVoiceBased === 'function') {
            try {
                if (channel.isVoiceBased() === true) return false;
            } catch (_) { /* ignore */ }
        }
        return typeof channel.send === 'function';
    }

    checkPermissions(channel) {
        const me = this.client && this.client.user;
        if (!channel || typeof channel.permissionsFor !== 'function' || !me) {
            // Cannot verify (e.g. a DM-less stub) — let the send itself decide.
            return { ok: true, missing: [] };
        }
        let perms;
        try {
            perms = channel.permissionsFor(me);
        } catch (_) {
            return { ok: true, missing: [] };
        }
        if (!perms || typeof perms.has !== 'function') {
            // Cannot verify (bot member not cached) — attempt the send and let
            // the API reject it rather than silently dropping an audit event.
            return { ok: true, missing: [], unverified: true };
        }
        const missing = [];
        try {
            if (!perms.has('ViewChannel')) missing.push('ViewChannel');
            if (!perms.has('SendMessages')) missing.push('SendMessages');
        } catch (_) {
            return { ok: true, missing: [] };
        }
        return { ok: missing.length === 0, missing };
    }

    async _deliver(embed, meta = {}) {
        if (!this.enabled) {
            this.stats.skipped++;
            return false;
        }
        if (!this.isConfigured()) {
            this._warnUnconfigured();
            this.stats.skipped++;
            return false;
        }
        const channel = await this.resolveChannel();
        if (!channel) {
            this.stats.failed++;
            return false;
        }
        const perms = this.checkPermissions(channel);
        if (!perms.ok) {
            this.stats.failed++;
            this._diagnose(`cannot post to ${maskId(this.channelId)} — missing permission(s): ${perms.missing.join(', ')}`);
            return false;
        }
        const payload = { embeds: [embed], allowedMentions: { parse: [] } };
        return this._enqueue(() => this._sendWithRetry(channel, payload, meta));
    }

    _enqueue(task) {
        if (this._queueDepth >= this._maxQueue) {
            this.stats.skipped++;
            this._diagnose('audit delivery queue is full — event dropped');
            return Promise.resolve(false);
        }
        this._queueDepth++;
        const result = this._queue
            .then(task, task)
            .catch((err) => {
                this.stats.failed++;
                this._diagnose('audit delivery failed', err);
                return false;
            })
            .then((value) => {
                this._queueDepth--;
                return value;
            });
        this._queue = result.then(() => {}, () => {});
        return result;
    }

    async _sendWithRetry(channel, payload, meta = {}) {
        for (let attempt = 0; attempt <= this._retryDelays.length; attempt++) {
            try {
                await channel.send(payload);
                this.stats.sent++;
                this.stats.lastError = null;
                return true;
            } catch (err) {
                this.stats.lastError = describeError(err);
                const retryable = isRetryable(err);
                if (!retryable || attempt === this._retryDelays.length) {
                    this.stats.failed++;
                    this._diagnose(`could not deliver ${meta.type || 'audit event'} (${this.stats.lastError})`);
                    return false;
                }
                const wait = retryAfterMs(err);
                await this._sleep(wait != null ? wait : this._retryDelays[attempt]);
            }
        }
        return false;
    }

    // ── internals ──────────────────────────────────────────────────────────

    /**
     * A `guildCreate` is a real join only when the bot's membership is recent.
     * `guild.joinedTimestamp` is Discord's own join time; the startup burst has
     * an old one. When it is missing, fall back to the ready-grace window (the
     * burst always arrives within a few seconds of READY).
     */
    _isRecentJoin(guild) {
        const joined = Number(guild && guild.joinedTimestamp);
        if (Number.isFinite(joined) && joined > 0) return this._now() - joined <= JOIN_FRESHNESS_MS;
        const readyAt = this.client && Number(this.client.readyAt);
        if (Number.isFinite(readyAt) && readyAt > 0) return this._now() - readyAt > READY_GRACE_MS;
        return true;
    }

    _guildCount() {
        const client = this.client;
        if (!client || !client.guilds || !client.guilds.cache) return null;
        if (typeof client.isReady === 'function' && client.isReady() === false) return null;
        const size = client.guilds.cache.size;
        return Number.isFinite(size) ? size : null;
    }

    async _resolveOwnerName(guild) {
        const ownerId = guild && guild.ownerId;
        if (!ownerId) return null;
        try {
            const cached = guild.members && guild.members.cache && typeof guild.members.cache.get === 'function'
                ? guild.members.cache.get(ownerId)
                : null;
            if (cached) return (cached.user && cached.user.username) || cached.displayName || null;
            if (guild.members && typeof guild.members.fetch === 'function') {
                const fetched = await guild.members.fetch(ownerId);
                if (fetched && fetched.user && fetched.user.username) return fetched.user.username;
            }
        } catch (_) { /* owner name is optional */ }
        return null;
    }

    _withTimeout(promise, ms) {
        if (!promise || typeof promise.then !== 'function') return Promise.resolve(null);
        let timer = null;
        const timeout = new Promise((resolve) => {
            timer = setTimeout(() => resolve(null), ms);
            if (timer && typeof timer.unref === 'function') timer.unref();
        });
        return Promise.race([promise, timeout]).finally(() => {
            if (timer) clearTimeout(timer);
        });
    }

    _bucket() {
        return Math.floor(this._now() / DEDUPE_BUCKET_MS);
    }

    _isDuplicate(key) {
        const now = this._now();
        const seenAt = this._seen.get(key);
        if (seenAt != null && now - seenAt < DEDUPE_WINDOW_MS) return true;
        this._seen.set(key, now);
        if (this._seen.size > MAX_SEEN) {
            for (const [k, at] of this._seen) {
                if (now - at >= DEDUPE_WINDOW_MS) this._seen.delete(k);
                if (this._seen.size <= MAX_SEEN) break;
            }
            while (this._seen.size > MAX_SEEN) this._seen.delete(this._seen.keys().next().value);
        }
        return false;
    }

    _sleep(ms) {
        const wait = Number.isFinite(ms) ? Math.max(0, ms) : 0;
        return new Promise((resolve) => {
            const handle = this._sleepFn(resolve, wait);
            if (handle && typeof handle.unref === 'function') handle.unref();
        });
    }

    _warnUnconfigured() {
        if (this._warnedUnconfigured) return;
        this._warnedUnconfigured = true;
        this._diagnose(
            'no destination channel configured — set SECURITY_AUDIT_CHANNEL_ID in config.js. '
            + 'Security audit events are being skipped.'
        );
    }

    _diagnose(message, err, level = 'warn') {
        try {
            const line = `[SECURITY AUDIT] ${message}${err ? ` — ${describeError(err)}` : ''}`;
            const log = this.logger && typeof this.logger[level] === 'function'
                ? this.logger[level].bind(this.logger)
                : (this.logger && this.logger.log ? this.logger.log.bind(this.logger) : null);
            if (log) log(line);
        } catch (_) { /* a diagnostic must never throw */ }
    }
}

// ── Process-wide singleton (no DB, no client at require time) ────────────────

let _instance = null;

function getSecurityAuditLogger() {
    if (!_instance) _instance = new SecurityAuditLogger();
    return _instance;
}

/** Test helper: drop the singleton so a fresh one is built. */
function resetSecurityAuditLogger() {
    _instance = null;
}

module.exports = {
    SecurityAuditLogger,
    getSecurityAuditLogger,
    resetSecurityAuditLogger,
    buildGuildJoinEmbed,
    buildGuildLeaveEmbed,
    buildVoiceEmbed,
    discordTime,
    formatDuration,
    maskId,
    COLORS,
    EVENT_TYPES,
    UNAVAILABLE,
};
