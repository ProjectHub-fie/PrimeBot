/**
 * Dashboard-side view of the centralized emoji catalog.
 *
 * The bot validates emojis through `utils/emojiManager` (live discord.js guild
 * collections). The dashboard is a separate process, so it performs the same
 * validation over REST: fetch each configured guild's emoji collection with the
 * bot token, keep only emojis that actually exist, and expose the same
 * deterministic guild-priority order. Results are cached so a page render never
 * fans out to Discord repeatedly.
 *
 * No token is ever logged or returned.
 */

const { DEFAULT_EMOJI_GUILDS, LINIX_EMOJI_CATALOG } = require('../shared/emojiCatalog');
const { parseEmojiInput, formatEmoji, normalizeEmojiEntry } = require('../shared/emojiValidation');
const discord = require('./discord');

const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_LIMIT = 500;

let cache = null;
let inflight = null;

function guildIds() {
    const configured = process.env.EMOJI_GUILD_IDS || process.env.EMOJI_GUILD_ID;
    const ids = configured
        ? String(configured).split(',').map(s => s.trim()).filter(Boolean)
        : [...DEFAULT_EMOJI_GUILDS];
    return ids.length ? ids : [...DEFAULT_EMOJI_GUILDS];
}

function sanitizeError(err) {
    return String((err && (err.message || err)) || 'unknown error')
        .replace(/Bot\s+[A-Za-z0-9._-]+/gi, 'Bot <redacted>')
        .replace(/mfa\.[A-Za-z0-9_-]+/g, 'mfa.<redacted>')
        .replace(/\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}\b/g, '<redacted-token>')
        .slice(0, 300);
}

function catalogIndex() {
    const byId = new Map();
    for (const [key, entry] of Object.entries(LINIX_EMOJI_CATALOG)) {
        if (!entry || !entry.id) continue;
        const id = String(entry.id);
        const existing = byId.get(id);
        if (existing) {
            existing.keys.push(key);
        } else {
            byId.set(id, { key, keys: [key], name: entry.name, id, animated: entry.animated === true });
        }
    }
    return byId;
}

async function loadCatalog() {
    const ids = guildIds();
    const priority = new Map(ids.map((id, i) => [id, i]));
    const catalog = catalogIndex();
    const guilds = [];
    const liveById = new Map();
    const conflicts = [];

    const results = await Promise.all(ids.map(async (guildId) => {
        try {
            const list = await discord.getGuildEmojis(guildId);
            return { guildId, emojis: Array.isArray(list) ? list : [] };
        } catch (err) {
            return { guildId, error: sanitizeError(err) };
        }
    }));

    for (const result of results) {
        if (result.error) {
            guilds.push({ id: result.guildId, ok: false, error: result.error });
            continue;
        }
        for (const emoji of result.emojis) {
            if (!emoji || !emoji.id || !emoji.name) continue;
            const id = String(emoji.id);
            if (liveById.has(id)) continue;
            liveById.set(id, {
                id,
                name: emoji.name,
                animated: emoji.animated === true,
                sourceGuildId: result.guildId,
            });
        }
        guilds.push({ id: result.guildId, ok: true, emojiCount: result.emojis.length });
    }

    const byName = new Map();
    const entries = [...liveById.values()].sort((a, b) => {
        const pa = priority.get(a.sourceGuildId) ?? Number.MAX_SAFE_INTEGER;
        const pb = priority.get(b.sourceGuildId) ?? Number.MAX_SAFE_INTEGER;
        if (pa !== pb) return pa - pb;
        return a.name.localeCompare(b.name);
    });

    for (const entry of entries) {
        const meta = catalog.get(entry.id);
        const normalized = normalizeEmojiEntry({
            ...entry,
            semanticKey: meta ? meta.key : null,
            category: meta ? meta.key : null,
        });
        const existing = byName.get(normalized.name);
        if (existing && existing.id !== normalized.id) {
            conflicts.push({
                name: normalized.name,
                kept: { id: existing.id, sourceGuildId: existing.sourceGuildId },
                rejected: { id: normalized.id, sourceGuildId: normalized.sourceGuildId },
            });
            continue;
        }
        if (!existing) byName.set(normalized.name, normalized);
    }

    const unavailable = [];
    for (const [key, entry] of Object.entries(LINIX_EMOJI_CATALOG)) {
        if (!entry || !entry.id) continue;
        if (!liveById.has(String(entry.id))) {
            unavailable.push({
                semanticKey: key,
                name: entry.name,
                id: String(entry.id),
                reason: 'not_in_live_guild_emoji_collection',
            });
        }
    }

    const sorted = [...byName.values()].sort((a, b) => {
        const pa = priority.get(a.sourceGuildId) ?? Number.MAX_SAFE_INTEGER;
        const pb = priority.get(b.sourceGuildId) ?? Number.MAX_SAFE_INTEGER;
        if (pa !== pb) return pa - pb;
        return a.name.localeCompare(b.name);
    });

    return {
        at: Date.now(),
        guilds,
        entries: sorted,
        byId: new Map(sorted.map(e => [e.id, e])),
        byName,
        conflicts,
        unavailable,
    };
}

async function getEmojiCatalog({ force = false } = {}) {
    if (!force && cache && Date.now() - cache.at < CACHE_TTL_MS) return cache;
    if (inflight) return inflight;
    inflight = loadCatalog()
        .then(next => {
            cache = next;
            return next;
        })
        .finally(() => { inflight = null; });
    return inflight;
}

function resolveEmoji(input, catalog = cache) {
    if (!catalog) return null;
    const parsed = parseEmojiInput(input);
    if (!parsed) return null;
    if (parsed.id && catalog.byId.has(parsed.id)) return catalog.byId.get(parsed.id);
    if (parsed.name && catalog.byName.has(parsed.name)) return catalog.byName.get(parsed.name);
    return null;
}

function normalizeConfiguredEmoji(input, catalog = cache) {
    const entry = resolveEmoji(input, catalog);
    if (!entry) return null;
    return { ...entry, raw: formatEmoji(entry) };
}

function listEmojis(catalog, { q = '', limit = MAX_LIMIT } = {}) {
    const query = String(q || '').trim().toLowerCase();
    const capped = Math.max(1, Math.min(MAX_LIMIT, parseInt(limit, 10) || MAX_LIMIT));
    const entries = query
        ? catalog.entries.filter(e =>
            e.name.toLowerCase().includes(query) ||
            (e.semanticKey && e.semanticKey.toLowerCase().includes(query)))
        : catalog.entries;
    return entries.slice(0, capped);
}

function report(catalog) {
    return {
        ready: Boolean(catalog && catalog.guilds.some(g => g.ok)),
        configuredGuildIds: guildIds(),
        guilds: catalog ? catalog.guilds : [],
        emojiCount: catalog ? catalog.entries.length : 0,
        animated: catalog ? catalog.entries.filter(e => e.animated).length : 0,
        static: catalog ? catalog.entries.filter(e => !e.animated).length : 0,
        conflicts: catalog ? catalog.conflicts : [],
        unavailable: catalog ? catalog.unavailable : [],
        fetchedAt: catalog ? new Date(catalog.at).toISOString() : null,
    };
}

module.exports = {
    getEmojiCatalog,
    resolveEmoji,
    normalizeConfiguredEmoji,
    listEmojis,
    report,
    formatEmoji,
    parseEmojiInput,
    CACHE_TTL_MS,
};
