/**
 * Central custom-emoji manager.
 *
 * Responsibilities
 *  - Discover the emoji guilds PrimeBot is already a member of (three by
 *    default, see `shared/emojiCatalog.js`).
 *  - Read each guild's `emoji list` channel (read-only) to learn names, ids,
 *    animated flags and category headings.
 *  - Validate every candidate against the live `guild.emojis` collection —
 *    being a member of the guild is NOT proof an emoji is usable.
 *  - Cache the resolved map in memory (no per-message API calls), refresh on
 *    Discord emoji events and on a long TTL.
 *  - Expose semantic access: `emoji('success')`, `emoji('music')`, …
 *  - Fall back to Unicode (or the caller's fallback) when an emoji is missing,
 *    renamed, deleted, unavailable or inaccessible.
 *  - Never log a token: diagnostics only carry guild ids, emoji ids/names and
 *    sanitized error text.
 *
 * The legacy `$emoji add/remove/list` store (`data/emojis.json`) is preserved
 * unchanged; the guild catalog lives alongside it in separate maps.
 */

const fs = require('fs');
const path = require('path');
const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const {
    DEFAULT_EMOJI_GUILDS,
    EMOJI_LIST_CHANNEL_NAMES,
    LINIX_EMOJI_CATALOG,
    SEMANTIC_ALIASES,
    UNICODE_TO_SEMANTIC,
    EMOJI_FALLBACKS,
} = require('../shared/emojiCatalog');

const CUSTOM_EMOJI_RE = /<(a?):([A-Za-z0-9_~]+):(\d{15,22})>/g;
const PROTECTED_RE = /(<a?:[A-Za-z0-9_~]+:\d{15,22}>|https?:\/\/\S+|www\.\S+)/g;
const CODE_SPLIT_RE = /(```[\s\S]*?```|`[^`]*`)/g;
const LABEL_EMOJI_RE = /^\s*([A-Za-z0-9][A-Za-z0-9 _-]{0,39})\s*[:=-]\s*(<a?:[A-Za-z0-9_~]+:\d{15,22}>)/gm;
const SHORTCODE_RE = /^\s*:([a-z0-9_+-]{1,40}):\s*(<a?:[A-Za-z0-9_~]+:\d{15,22}>)/gim;

const DEFAULTS = {
    maxRetries: 3,
    retryBaseMs: 500,
    fetchTimeoutMs: 8000,
    cacheTtlMs: 6 * 60 * 60 * 1000,
    maxMessagesPerChannel: 500,
    refreshDebounceMs: 5000,
};

function parseGuildIds(value) {
    if (Array.isArray(value)) return value.map(String).filter(Boolean);
    if (typeof value === 'string') return value.split(',').map(s => s.trim()).filter(Boolean);
    return [];
}

function normalizeKey(name) {
    return String(name || '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, '_')
        .replace(/[^a-z0-9_]/g, '');
}

function resolveKey(name) {
    const key = normalizeKey(name);
    return SEMANTIC_ALIASES[key] || key;
}

function fallbackFor(name) {
    const unicodeKey = typeof name === 'string' ? UNICODE_TO_SEMANTIC[name] : null;
    const key = resolveKey(unicodeKey || name);
    return EMOJI_FALLBACKS[key] || '';
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function intEnv(value, fallback) {
    const n = parseInt(value, 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Redact anything token-shaped from a diagnostic message. */
function sanitizeError(err) {
    const raw = err && (err.message || err.stack || String(err));
    return String(raw || 'unknown error')
        .replace(/Bot\s+[A-Za-z0-9._-]+/gi, 'Bot <redacted>')
        .replace(/mfa\.[A-Za-z0-9_-]+/g, 'mfa.<redacted>')
        .replace(/\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}\b/g, '<redacted-token>')
        .slice(0, 500);
}

function isRetryable(err) {
    if (!err) return false;
    if (err.status === 429) return true;
    if (typeof err.status === 'number' && err.status >= 500) return true;
    return ['ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'UND_ERR_CONNECT_TIMEOUT']
        .includes(err.code);
}

class EmojiManager {
    constructor(options = {}) {
        this.emojis = new Map(); // legacy user-added emojis ($emoji add)
        this.dataPath = path.join(__dirname, '../data/emojis.json');

        const dataDir = path.join(__dirname, '../data');
        if (!fs.existsSync(dataDir)) {
            try { fs.mkdirSync(dataDir, { recursive: true }); } catch (_) {}
        }
        this.loadEmojis();

        this.options = {
            ...DEFAULTS,
            ...options,
            maxRetries: intEnv(options.maxRetries ?? process.env.EMOJI_MAX_RETRIES, DEFAULTS.maxRetries),
            retryBaseMs: intEnv(options.retryBaseMs ?? process.env.EMOJI_RETRY_BASE_MS, DEFAULTS.retryBaseMs),
            fetchTimeoutMs: intEnv(options.fetchTimeoutMs ?? process.env.EMOJI_FETCH_TIMEOUT_MS, DEFAULTS.fetchTimeoutMs),
            cacheTtlMs: intEnv(options.cacheTtlMs ?? process.env.EMOJI_CACHE_TTL_MS, DEFAULTS.cacheTtlMs),
            maxMessagesPerChannel: intEnv(options.maxMessagesPerChannel ?? process.env.EMOJI_LIST_MAX_MESSAGES, DEFAULTS.maxMessagesPerChannel),
        };
        this.guildIds = parseGuildIds(
            options.guildIds ||
            process.env.EMOJI_GUILD_IDS ||
            process.env.EMOJI_GUILD_ID ||
            DEFAULT_EMOJI_GUILDS
        );
        this.priority = new Map(this.guildIds.map((id, i) => [id, i]));

        this.client = null;
        this.ready = false;
        this.fetching = null;
        this.lastFetchAt = 0;
        this._refreshTimer = null;
        this._listenersAttached = false;

        this.byName = new Map();      // emoji name -> entry
        this.bySemantic = new Map();  // semantic key -> entry
        this.byId = new Map();        // emoji id -> entry
        this.guilds = new Map();      // guildId -> report row
        this.conflicts = [];
        this.unavailable = [];
        this._liveById = new Map();
        this._unicodeEntries = Object.entries(UNICODE_TO_SEMANTIC)
            .sort((a, b) => b[0].length - a[0].length);

        if (options.global !== false) {
            globalThis.__primebotEmojiManager = this;
        }
    }

    // ── legacy user-emoji store (unchanged behaviour) ──────────────────────
    loadEmojis() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                this.emojis.clear();
                for (const [name, emoji] of Object.entries(data)) this.emojis.set(name, emoji);
                console.log(`Loaded ${this.emojis.size} custom emojis.`);
            } else {
                this.saveEmojis();
            }
        } catch (error) {
            console.error('Error loading emojis:', sanitizeError(error));
            this.emojis = new Map();
        }
    }

    saveEmojis() {
        try {
            const data = {};
            for (const [name, emoji] of this.emojis.entries()) data[name] = emoji;
            fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving emojis:', sanitizeError(error));
        }
    }

    addEmoji(name, emoji) {
        if (this.emojis.has(name)) return false;
        this.emojis.set(name, emoji);
        this.saveEmojis();
        return true;
    }

    removeEmoji(name) {
        if (!this.emojis.has(name)) return false;
        this.emojis.delete(name);
        this.saveEmojis();
        return true;
    }

    getAllEmojis() {
        return this.emojis;
    }

    /** Legacy `$emoji <name>` accessor: user store first, then the catalog. */
    getEmoji(name) {
        return this.emojis.get(name) || this.custom(name) || null;
    }

    // ── catalog lifecycle ──────────────────────────────────────────────────
    /**
     * Attach a Discord client and load the catalog. Idempotent and safe to call
     * before the client is ready (the fetch is deferred until it is).
     */
    async start(client, opts = {}) {
        if (client) this.client = client;
        if (!this.client) return this.report();

        this._attachListeners();
        try {
            await this.refresh({ force: true, ...opts });
        } catch (err) {
            console.warn('[EMOJI] Catalog load failed:', sanitizeError(err));
        }
        return this.report();
    }

    _attachListeners() {
        if (this._listenersAttached || !this.client || !this.client.on) return;
        this._listenersAttached = true;

        const schedule = () => this._scheduleRefresh();
        this.client.on('emojiCreate', schedule);
        this.client.on('emojiDelete', schedule);
        this.client.on('emojiUpdate', schedule);
        this.client.on('guildCreate', schedule);
        this.client.on('guildDelete', schedule);
    }

    _scheduleRefresh() {
        if (this._refreshTimer) return;
        this._refreshTimer = setTimeout(() => {
            this._refreshTimer = null;
            this.refresh({ force: true }).catch(err =>
                console.warn('[EMOJI] Background refresh failed:', sanitizeError(err))
            );
        }, this.options.refreshDebounceMs);
        if (this._refreshTimer.unref) this._refreshTimer.unref();
    }

    isStale() {
        return !this.lastFetchAt || (Date.now() - this.lastFetchAt) > this.options.cacheTtlMs;
    }

    /**
     * Fetch all emoji guilds and rebuild the cache. Concurrent callers share
     * the same promise, so a burst of events never opens parallel API storms.
     */
    async refresh({ force = false } = {}) {
        if (!this.client) return this.report();
        if (!force && !this.isStale() && this.ready) return this.report();
        if (this.fetching) return this.fetching;

        this.fetching = this._refresh().finally(() => { this.fetching = null; });
        return this.fetching;
    }

    async _refresh() {
        this.guilds.clear();
        this._liveById.clear();
        this.conflicts = [];
        this.unavailable = [];

        const candidates = [];
        for (const guildId of this.guildIds) {
            const row = await this._loadGuild(guildId);
            this.guilds.set(guildId, row.report);
            for (const c of row.candidates) candidates.push(c);
        }

        // Catalog entries are candidates too, but only survive if their id was
        // actually present in a live guild collection. Resolve the source guild
        // up front so priority sorting sees the real guild.
        for (const [key, entry] of Object.entries(LINIX_EMOJI_CATALOG)) {
            const live = this._liveById.get(entry.id);
            candidates.push({
                key,
                name: entry.name,
                id: entry.id,
                animated: entry.animated,
                sourceGuildId: live ? live.guildId : null,
                source: 'catalog',
                category: null,
            });
        }

        this._finalize(candidates);
        this.lastFetchAt = Date.now();
        this.ready = this.bySemantic.size > 0 || this.byName.size > 0;

        console.log(
            `[EMOJI] Catalog ready: ${this.bySemantic.size} semantic emoji(s) from ` +
            `${this.guildIds.length} configured guild(s) ` +
            `(${this.unavailable.length} unavailable, ${this.conflicts.length} duplicate name(s)).`
        );
        return this.report();
    }

    async _loadGuild(guildId) {
        const report = {
            id: guildId,
            ok: false,
            emojiCount: 0,
            channelFound: false,
            channelId: null,
            discoveredCount: 0,
            error: null,
        };
        const candidates = [];

        const guild = await this._fetchGuild(guildId);
        if (!guild) {
            report.error = 'guild_unavailable';
            return { report, candidates };
        }
        if (guild.available === false) {
            report.error = 'guild_temporarily_unavailable';
            return { report, candidates };
        }

        // Emoji collection — the authoritative "can PrimeBot use it" list.
        let collection = guild.emojis && guild.emojis.cache;
        try {
            if (guild.emojis && typeof guild.emojis.fetch === 'function') {
                collection = await guild.emojis.fetch();
            }
        } catch (err) {
            report.error = `emoji_fetch_failed:${sanitizeError(err)}`;
            collection = (guild.emojis && guild.emojis.cache) || collection;
        }
        if (!collection) collection = new Map();

        for (const emoji of collection.values()) {
            if (!emoji || !emoji.id) continue;
            if (emoji.available === false) {
                this.unavailable.push({
                    name: emoji.name,
                    id: emoji.id,
                    sourceGuildId: guildId,
                    reason: 'emoji_unavailable',
                });
                continue;
            }
            this._liveById.set(emoji.id, {
                id: emoji.id,
                name: emoji.name,
                animated: Boolean(emoji.animated),
                guildId,
            });
            // Every live emoji is name-addressable, not only the ones listed in
            // the `emoji list` channel or the Linix catalog.
            candidates.push({
                name: emoji.name,
                id: emoji.id,
                animated: Boolean(emoji.animated),
                category: null,
                semanticName: normalizeKey(emoji.name),
                sourceGuildId: guildId,
                source: 'guild',
            });
        }
        report.emojiCount = [...this._liveById.values()].filter(e => e.guildId === guildId).length;
        report.ok = true;

        // `emoji list` channel — discovery only, never modified.
        try {
            const channel = await this._findEmojiListChannel(guild);
            if (channel) {
                report.channelFound = true;
                report.channelId = channel.id;
                const parsed = await this._readEmojiListChannel(channel);
                report.discoveredCount = parsed.length;
                for (const p of parsed) {
                    candidates.push({
                        ...p,
                        sourceGuildId: guildId,
                        source: 'channel',
                    });
                }
            }
        } catch (err) {
            report.error = report.error || `channel_read_failed:${sanitizeError(err)}`;
        }

        return { report, candidates };
    }

    async _fetchGuild(guildId) {
        if (!this.client || !this.client.guilds) return null;
        const cached = this.client.guilds.cache && this.client.guilds.cache.get(guildId);
        if (cached) return cached;

        let lastErr;
        for (let attempt = 1; attempt <= this.options.maxRetries; attempt++) {
            try {
                return await this._withTimeout(
                    this.client.guilds.fetch(guildId),
                    this.options.fetchTimeoutMs
                );
            } catch (err) {
                lastErr = err;
                if (!isRetryable(err) || attempt === this.options.maxRetries) break;
                await sleep(this.options.retryBaseMs * Math.pow(2, attempt - 1));
            }
        }
        console.warn(`[EMOJI] Guild ${guildId} unavailable:`, sanitizeError(lastErr));
        return null;
    }

    _withTimeout(promise, ms) {
        let timer;
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(() => {
                const err = new Error('emoji fetch timed out');
                err.code = 'ETIMEDOUT';
                reject(err);
            }, ms);
            if (timer.unref) timer.unref();
        });
        return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
    }

    async _findEmojiListChannel(guild) {
        if (!guild || !guild.channels) return null;
        const names = EMOJI_LIST_CHANNEL_NAMES;
        const match = (channel) => {
            if (!channel || !channel.name) return false;
            const n = String(channel.name).trim().toLowerCase().replace(/\s+/g, ' ');
            return names.includes(n) || names.includes(n.replace(/\s/g, '-'));
        };

        let channel = guild.channels.cache && [...guild.channels.cache.values()].find(match);
        if (channel) return channel;
        if (typeof guild.channels.fetch === 'function') {
            try {
                const fetched = await guild.channels.fetch();
                channel = [...fetched.values()].find(match);
            } catch (_) { /* no permission / unavailable */ }
        }
        return channel || null;
    }

    async _readEmojiListChannel(channel) {
        const out = [];
        if (!channel || !channel.messages || typeof channel.messages.fetch !== 'function') return out;

        let before;
        let read = 0;
        const limit = this.options.maxMessagesPerChannel;

        while (read < limit) {
            const batch = await channel.messages.fetch({
                limit: Math.min(100, limit - read),
                ...(before ? { before } : {}),
            });
            if (!batch || batch.size === 0) break;
            for (const message of batch.values()) {
                out.push(...this._parseEmojiListMessage(message));
            }
            read += batch.size;
            before = batch.last() ? batch.last().id : null;
            if (!before) break;
        }
        return out;
    }

    _parseEmojiListMessage(message) {
        const found = [];
        if (!message) return found;

        const category = this._messageCategory(message);
        const text = String(message.content || '');

        // 1) Every custom emoji token in the message.
        for (const m of text.matchAll(CUSTOM_EMOJI_RE)) {
            found.push({
                name: m[2],
                id: m[3],
                animated: m[1] === 'a',
                category,
                semanticName: null,
            });
        }

        // 2) `label : <:name:id>` / `label = <:name:id>` lines give a semantic
        //    alias in addition to the emoji's own name.
        for (const m of text.matchAll(LABEL_EMOJI_RE)) {
            const token = new RegExp(CUSTOM_EMOJI_RE.source).exec(m[2]);
            if (!token) continue;
            found.push({
                name: token[2],
                id: token[3],
                animated: token[1] === 'a',
                category,
                semanticName: normalizeKey(m[1]),
            });
        }

        // 3) `:shortcode: <:name:id>` lines.
        for (const m of text.matchAll(SHORTCODE_RE)) {
            const token = new RegExp(CUSTOM_EMOJI_RE.source).exec(m[2]);
            if (!token) continue;
            found.push({
                name: token[2],
                id: token[3],
                animated: token[1] === 'a',
                category,
                semanticName: normalizeKey(m[1]),
            });
        }

        // 4) Embeds often carry the grouped list. Read them too.
        for (const embed of message.embeds || []) {
            const embedCategory = embed.title || category;
            const chunks = [embed.description, embed.footer && embed.footer.text];
            for (const field of embed.fields || []) chunks.push(field.name, field.value);
            for (const chunk of chunks) {
                if (!chunk) continue;
                for (const m of String(chunk).matchAll(CUSTOM_EMOJI_RE)) {
                    found.push({
                        name: m[2],
                        id: m[3],
                        animated: m[1] === 'a',
                        category: embedCategory || null,
                        semanticName: null,
                    });
                }
            }
        }

        return found;
    }

    _messageCategory(message) {
        const embed = (message.embeds || [])[0];
        if (embed && embed.title) return embed.title;
        const first = String(message.content || '').split('\n')[0].trim();
        if (first.endsWith(':') && first.length <= 60) return first.replace(/:$/, '').trim();
        return null;
    }

    _finalize(candidates) {
        this.byName.clear();
        this.bySemantic.clear();
        this.byId.clear();

        const sortRank = (c) => {
            const p = c.sourceGuildId != null && this.priority.has(c.sourceGuildId)
                ? this.priority.get(c.sourceGuildId)
                : Number.MAX_SAFE_INTEGER;
            const sourceRank = c.source === 'channel' ? 0 : 1;
            return [p, sourceRank, c.name || '', c.id || ''];
        };
        const sorted = [...candidates].sort((a, b) => {
            const ra = sortRank(a);
            const rb = sortRank(b);
            for (let i = 0; i < ra.length; i++) {
                if (ra[i] < rb[i]) return -1;
                if (ra[i] > rb[i]) return 1;
            }
            return 0;
        });

        for (const candidate of sorted) {
            if (!candidate.id) continue;
            const live = this._liveById.get(candidate.id);
            if (!live) {
                if (candidate.source === 'catalog' || candidate.source === 'channel') {
                    this.unavailable.push({
                        name: candidate.name,
                        id: candidate.id,
                        sourceGuildId: candidate.sourceGuildId,
                        semanticKey: candidate.key || null,
                        reason: 'not_in_live_guild_emoji_collection',
                    });
                }
                continue;
            }

            const displayName = live.name || candidate.name;
            const entry = {
                key: candidate.key || null,
                name: displayName,
                id: candidate.id,
                animated: Boolean(candidate.animated || live.animated),
                raw: `<${candidate.animated || live.animated ? 'a' : ''}:${displayName}:${candidate.id}>`,
                sourceGuildId: candidate.sourceGuildId || live.guildId,
                category: candidate.category || null,
                source: candidate.source,
            };

            // A renamed emoji keeps its id; keep the catalog/channel name as an
            // alias so older references still resolve.
            if (candidate.name && candidate.name !== displayName && !this.byName.has(candidate.name)) {
                this.byName.set(candidate.name, entry);
            }

            // Name map — deterministic first-wins with an explicit conflict row.
            const existingName = this.byName.get(entry.name);
            if (existingName && existingName.id !== entry.id) {
                this.conflicts.push({
                    name: entry.name,
                    kept: { id: existingName.id, sourceGuildId: existingName.sourceGuildId },
                    rejected: { id: entry.id, sourceGuildId: entry.sourceGuildId },
                });
            } else if (!existingName) {
                this.byName.set(entry.name, entry);
            }

            // Semantic key map. Catalog keys win for their own key; channel
            // labels fill gaps only.
            const semanticKeys = [candidate.key, candidate.semanticName].filter(Boolean);
            for (const key of semanticKeys) {
                const normalized = normalizeKey(key);
                const existing = this.bySemantic.get(normalized);
                if (existing && existing.id !== entry.id) {
                    this.conflicts.push({
                        name: normalized,
                        kept: { id: existing.id, sourceGuildId: existing.sourceGuildId },
                        rejected: { id: entry.id, sourceGuildId: entry.sourceGuildId },
                    });
                } else if (!existing) {
                    this.bySemantic.set(normalized, entry);
                }
            }

            if (!this.byId.has(entry.id)) this.byId.set(entry.id, entry);
        }
    }

    // ── accessors ──────────────────────────────────────────────────────────
    /** Resolve a semantic name to its entry, or null. */
    resolve(name) {
        if (typeof name === 'string' && UNICODE_TO_SEMANTIC[name]) {
            const unicodeKey = resolveKey(UNICODE_TO_SEMANTIC[name]);
            return this.bySemantic.get(unicodeKey) || this.byName.get(unicodeKey) || null;
        }
        const key = resolveKey(name);
        return this.bySemantic.get(key) || this.byName.get(String(name)) ||
            this.byName.get(key) || null;
    }

    has(name) {
        return Boolean(this.resolve(name));
    }

    /**
     * The public accessor. Always returns a renderable string:
     * the custom emoji when validated, otherwise `fallback`, otherwise the
     * catalog's Unicode fallback.
     */
    emoji(name, fallback) {
        const entry = this.resolve(name);
        if (entry) return entry.raw;
        if (fallback !== undefined) return fallback;
        return fallbackFor(name);
    }

    /** Custom emoji only (null when unavailable) — used by renderText. */
    custom(name) {
        const entry = this.resolve(name);
        return entry ? entry.raw : null;
    }

    /** Emoji object for component `emoji` fields, or null. */
    componentEmoji(name) {
        const entry = this.resolve(name);
        if (!entry) return null;
        return { id: entry.id, name: entry.name, animated: entry.animated };
    }

    /**
     * Resolve a name for a component. Returns a custom-emoji object when
     * validated, else the Unicode fallback (which every component accepts).
     */
    forComponent(name, fallback) {
        return this.componentEmoji(name) || fallback || fallbackFor(name);
    }

    /** True when the emoji can be used in `guild` (external-emoji permission). */
    canUseIn(guild) {
        if (!guild || !guild.members || !guild.members.me) return false;
        try {
            const perms = guild.members.me.permissions;
            if (!perms) return false;
            if (typeof perms.has === 'function') return perms.has('UseExternalEmojis');
        } catch (_) { /* fall through */ }
        return false;
    }

    /**
     * Replace Unicode emoji in a string with validated custom emojis.
     * Code spans/fences, URLs and existing custom emoji tokens are preserved.
     */
    renderText(input) {
        if (typeof input !== 'string' || !input) return input;
        return input.split(CODE_SPLIT_RE).map((part, index) => {
            if (index % 2 === 1) return part; // code span / fence
            return this._renderOutsideCode(part);
        }).join('');
    }

    _renderOutsideCode(text) {
        const pieces = [];
        let last = 0;
        let m;
        PROTECTED_RE.lastIndex = 0;
        while ((m = PROTECTED_RE.exec(text))) {
            pieces.push(this._replaceUnicode(text.slice(last, m.index)));
            pieces.push(m[0]);
            last = m.index + m[0].length;
        }
        pieces.push(this._replaceUnicode(text.slice(last)));
        return pieces.join('');
    }

    _replaceUnicode(text) {
        let out = text;
        for (const [unicode, semantic] of this._unicodeEntries) {
            if (!out.includes(unicode)) continue;
            const raw = this.custom(semantic);
            if (!raw || raw === unicode) continue;
            out = out.split(unicode).join(raw);
        }
        return out;
    }

    /**
     * Rewrite a Discord message payload in place-safe fashion: content and
     * embed text get custom emoji; component `emoji` fields are upgraded from
     * Unicode to validated emoji objects (labels are never touched because
     * custom emoji markup does not render inside them).
     */
    transformPayload(payload) {
        if (!payload || typeof payload !== 'object') return payload;
        const out = { ...payload };

        if (typeof out.content === 'string') out.content = this.renderText(out.content);

        if (Array.isArray(out.embeds)) {
            out.embeds = out.embeds.map(embed => this._transformEmbed(embed));
        }

        if (Array.isArray(out.components)) {
            out.components = out.components.map(row => this._transformComponent(row));
        }

        // Interaction callback: { type, data: { content, embeds, components } }
        if (out.data && typeof out.data === 'object') {
            out.data = this.transformPayload(out.data);
        }

        return out;
    }

    _transformEmbed(embed) {
        if (!embed) return embed;
        let data;
        try {
            data = typeof embed.toJSON === 'function' ? embed.toJSON() : embed;
        } catch (_) {
            data = embed;
        }
        if (!data || typeof data !== 'object') return embed;
        const next = { ...data };

        if (typeof next.title === 'string') next.title = this.renderText(next.title);
        if (typeof next.description === 'string') next.description = this.renderText(next.description);
        if (Array.isArray(next.fields)) {
            next.fields = next.fields.map(f => ({
                ...f,
                name: typeof f.name === 'string' ? this.renderText(f.name) : f.name,
                value: typeof f.value === 'string' ? this.renderText(f.value) : f.value,
            }));
        }
        if (next.footer && typeof next.footer.text === 'string') {
            next.footer = { ...next.footer, text: this.renderText(next.footer.text) };
        }
        if (next.author && typeof next.author.name === 'string') {
            next.author = { ...next.author, name: this.renderText(next.author.name) };
        }
        return next;
    }

    _transformComponent(component) {
        if (!component || typeof component !== 'object') return component;
        let data;
        try {
            data = typeof component.toJSON === 'function' ? component.toJSON() : component;
        } catch (_) {
            data = component;
        }
        if (!data || typeof data !== 'object') return component;
        const next = { ...data };

        if (typeof next.emoji === 'string') {
            const entry = this.resolve(next.emoji);
            if (entry) next.emoji = { id: entry.id, name: entry.name, animated: entry.animated };
        } else if (next.emoji && typeof next.emoji === 'object' && !next.emoji.id && next.emoji.name) {
            const entry = this.resolve(next.emoji.name);
            if (entry) next.emoji = { id: entry.id, name: entry.name, animated: entry.animated };
        }
        if (Array.isArray(next.options)) {
            next.options = next.options.map(option => {
                if (!option || typeof option !== 'object') return option;
                const o = { ...option };
                if (typeof o.emoji === 'string') {
                    const entry = this.resolve(o.emoji);
                    if (entry) o.emoji = { id: entry.id, name: entry.name, animated: entry.animated };
                } else if (o.emoji && typeof o.emoji === 'object' && !o.emoji.id && o.emoji.name) {
                    const entry = this.resolve(o.emoji.name);
                    if (entry) o.emoji = { id: entry.id, name: entry.name, animated: entry.animated };
                }
                return o;
            });
        }
        if (Array.isArray(next.components)) {
            next.components = next.components.map(c => this._transformComponent(c));
        }
        return next;
    }

    // ── reporting ──────────────────────────────────────────────────────────
    report() {
        const uniqueCatalogIds = new Set(Object.values(LINIX_EMOJI_CATALOG).map(e => e.id));
        return {
            configuredGuildIds: [...this.guildIds],
            guilds: [...this.guilds.values()],
            catalogEntries: Object.keys(LINIX_EMOJI_CATALOG).length,
            catalogUniqueIds: uniqueCatalogIds.size,
            resolved: this.bySemantic.size,
            resolvedNames: this.byName.size,
            animated: [...this.byId.values()].filter(e => e.animated).length,
            static: [...this.byId.values()].filter(e => !e.animated).length,
            names: [...this.byName.keys()].sort(),
            entries: [...this.byName.values()]
                .map(e => ({
                    name: e.name,
                    id: e.id,
                    animated: e.animated,
                    sourceGuildId: e.sourceGuildId,
                    source: e.source,
                    category: e.category,
                }))
                .sort((a, b) => a.name.localeCompare(b.name)),
            conflicts: (() => {
                const seen = new Set();
                return this.conflicts.filter(c => {
                    const key = `${c.name}|${c.kept && c.kept.id}|${c.rejected && c.rejected.id}`;
                    if (seen.has(key)) return false;
                    seen.add(key);
                    return true;
                });
            })(),
            unavailable: [...this.unavailable],
            lastFetchAt: this.lastFetchAt ? new Date(this.lastFetchAt).toISOString() : null,
            ready: this.ready,
        };
    }

    /** Short multi-line report suitable for a boot log. */
    summary() {
        const r = this.report();
        const perGuild = r.guilds.map(g =>
            `  • ${g.id}: ${g.ok ? `${g.emojiCount} emoji` : 'unavailable'}` +
            `${g.channelFound ? `, emoji list ${g.channelId} (${g.discoveredCount} parsed)` : ''}` +
            `${g.error ? `, error=${g.error}` : ''}`
        ).join('\n');
        return [
            `[EMOJI] guilds=${r.configuredGuildIds.length} catalog=${r.catalogEntries}/${r.catalogUniqueIds} resolved=${r.resolved} (${r.animated} animated, ${r.static} static)`,
            perGuild,
            r.conflicts.length ? `[EMOJI] duplicate names: ${r.conflicts.map(c => c.name).join(', ')}` : '',
            r.unavailable.length ? `[EMOJI] unavailable entries: ${r.unavailable.length}` : '',
        ].filter(Boolean).join('\n');
    }

    // ── legacy list embed (unchanged UI) ──────────────────────────────────
    createEmojiListEmbed(page = 1) {
        const { ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
        const emojisPerPage = 5;
        const emojiEntries = Array.from(this.emojis.entries());
        const totalEmojis = emojiEntries.length;
        const totalPages = Math.max(1, Math.ceil(totalEmojis / emojisPerPage));

        page = Math.max(1, Math.min(page, totalPages));
        const startIndex = (page - 1) * emojisPerPage;
        const endIndex = Math.min(startIndex + emojisPerPage, totalEmojis);
        const pageEmojis = emojiEntries.slice(startIndex, endIndex);

        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle(`${this.emoji('information')} Custom Emoji List`)
            .setDescription(totalEmojis > 0
                ? `Here are custom emojis (Page ${page}/${totalPages}):`
                : 'No custom emojis have been added yet.');

        if (pageEmojis.length > 0) {
            let emojiDisplay = '';
            for (const [name, emoji] of pageEmojis) emojiDisplay += `**${name}**: ${emoji}\n`;
            embed.addFields({
                name: `Showing ${startIndex + 1} to ${endIndex} of ${totalEmojis} emojis`,
                value: emojiDisplay,
            });
        }

        const components = [];
        if (totalPages > 1) {
            const prevButton = new ButtonBuilder()
                .setCustomId('emoji_prev_page')
                .setLabel('Previous')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji(this.forComponent('left'))
                .setDisabled(page === 1);
            const nextButton = new ButtonBuilder()
                .setCustomId('emoji_next_page')
                .setLabel('Next')
                .setStyle(ButtonStyle.Secondary)
                .setEmoji(this.forComponent('right'))
                .setDisabled(page === totalPages);
            components.push(new ActionRowBuilder().addComponents(prevButton, nextButton));
        }

        return {
            embed,
            currentPage: page,
            totalPages,
            components: components.length > 0 ? components : null,
        };
    }
}

// ── module-level helpers (safe to call before `start`) ────────────────────
function getEmojiManager() {
    return globalThis.__primebotEmojiManager || null;
}

/** `emoji('success')` anywhere in the bot. Falls back gracefully. */
function emoji(name, fallback) {
    const manager = getEmojiManager();
    if (manager) return manager.emoji(name, fallback);
    return fallback !== undefined ? fallback : fallbackFor(name);
}

function renderText(text) {
    const manager = getEmojiManager();
    return manager ? manager.renderText(text) : text;
}

module.exports = EmojiManager;
module.exports.EmojiManager = EmojiManager;
module.exports.getEmojiManager = getEmojiManager;
module.exports.emoji = emoji;
module.exports.renderText = renderText;
module.exports.fallbackFor = fallbackFor;
module.exports.resolveKey = resolveKey;
module.exports.sanitizeError = sanitizeError;
module.exports.DEFAULTS = DEFAULTS;
