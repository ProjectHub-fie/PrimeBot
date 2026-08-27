/**
 * Discord OAuth2 + REST API helpers for the dashboard.
 *
 * Uses the v10 REST API directly with the bot token for guild lookups and the
 * user's OAuth2 access token for identifying the logged-in admin and their
 * guild list (so we can filter to servers they manage).
 */

const { GUILD_CHANNELS_WITH_COUNTS } = require('./constants');

const API_BASE = 'https://discord.com/api/v10';

async function fetchJson(url, options = {}) {
    const res = await fetch(url, options);
    let body = null;
    const text = await res.text();
    if (text) {
        try { body = JSON.parse(text); } catch { body = text; }
    }
    if (!res.ok) {
        const msg = body && body.message ? body.message : `HTTP ${res.status}`;
        const err = new Error(`Discord API error: ${msg} (${res.status})`);
        err.status = res.status;
        err.body = body;
        throw err;
    }
    return body;
}

function botHeaders() {
    return { Authorization: `Bot ${process.env.DISCORD_TOKEN}` };
}

function bearerHeaders(accessToken) {
    return { Authorization: `Bearer ${accessToken}` };
}

/** Exchange an OAuth2 authorization code for an access token. */
async function exchangeCode(code, redirectUri) {
    const params = new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
    });

    const res = await fetch(`${API_BASE}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
    });
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    if (!res.ok) {
        const msg = body && body.error_description ? body.error_description : `HTTP ${res.status}`;
        throw new Error(`OAuth token exchange failed: ${msg}`);
    }
    return body;
}

/** Refresh an expired access token. */
async function refreshToken(refreshTokenValue) {
    const params = new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: refreshTokenValue,
    });

    const res = await fetch(`${API_BASE}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
    });
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    if (!res.ok) {
        throw new Error(`OAuth token refresh failed: HTTP ${res.status}`);
    }
    return body;
}

/** Get the current user for an OAuth2 access token. */
async function getCurrentUser(accessToken) {
    return fetchJson(`${API_BASE}/users/@me`, { headers: bearerHeaders(accessToken) });
}

/** Get the guilds the user is a member of (raw list). */
async function getUserGuilds(accessToken) {
    const headers = bearerHeaders(accessToken);
    if (GUILD_CHANNELS_WITH_COUNTS) headers['X-Discord-Options'] = 'with_counts=true';
    return fetchJson(`${API_BASE}/users/@me/guilds`, { headers });
}

/** Get a single guild's basic info using the bot token. */
async function getBotGuild(guildId) {
    return fetchJson(`${API_BASE}/guilds/${guildId}`, { headers: botHeaders() });
}

/**
 * Get the bot application's own user via `/users/@me` with the bot token.
 * Used at boot to discover the real bot user ID (which may differ from
 * DISCORD_CLIENT_ID if the env is misconfigured).
 */
async function getBotSelf() {
    return fetchJson(`${API_BASE}/users/@me`, { headers: botHeaders() });
}

// ── Bot guild count (authoritative server count for the stats page) ─────────
//
// `SELECT COUNT(*) FROM server_settings` undercounts because rows are created
// lazily — guilds the bot joined but never configured have no row. The real
// number is "how many guilds is the bot in", which only Discord knows. We fetch
// /users/@me/guilds with the bot token (paginated, 200/page) and count. The
// result is cached for BOT_GUILD_COUNT_TTL_MS so the public /api/stats endpoint
// (hit on every login-screen load) doesn't hammer the API.

const BOT_GUILD_COUNT_TTL_MS = 60_000;
let _botGuildCountCache = { value: null, expiresAt: 0 };

/** Returns the number of guilds the bot is a member of, or null if it can't be
 *  determined (e.g. DISCORD_TOKEN missing/invalid). */
async function getBotGuildCount() {
    const now = Date.now();
    if (_botGuildCountCache.value != null && now < _botGuildCountCache.expiresAt) {
        return _botGuildCountCache.value;
    }
    try {
        let count = 0;
        let after = '0';
        // /users/@me/guilds returns up to 200 guilds per page, ordered by id.
        // Paginate with the `after` cursor (the largest id seen so far) until a
        // page comes back short or empty. Cap the loop to avoid pathological runs.
        for (let i = 0; i < 50; i++) {
            const url = `${API_BASE}/users/@me/guilds?limit=200${after !== '0' ? `&after=${after}` : ''}`;
            const page = await fetchJson(url, { headers: botHeaders() });
            if (!Array.isArray(page) || page.length === 0) break;
            count += page.length;
            if (page.length < 200) break; // last page
            // Cursor = the largest id in this page (ids are snowflake-ordered).
            after = page.reduce((m, g) => (g.id > m ? g.id : m), after);
        }
        _botGuildCountCache = { value: count, expiresAt: now + BOT_GUILD_COUNT_TTL_MS };
        return count;
    } catch (err) {
        // Token issues (401) etc. — leave the cache empty so callers fall back.
        console.warn('[DASHBOARD] getBotGuildCount failed:', err.message);
        return null;
    }
}

const BOT_MEMBER_COUNT_TTL_MS = 60_000;
let _botMemberCountCache = { value: null, expiresAt: 0 };

/** Returns the total member count across all guilds the bot is in, summed
 *  from each guild's approximate_member_count (the REST equivalent of
 *  discord.js `guild.memberCount`). Returns null when it can't be determined
 *  (e.g. DISCORD_TOKEN missing/invalid). Cached like getBotGuildCount. */
async function getBotMemberCount() {
    const now = Date.now();
    if (_botMemberCountCache.value != null && now < _botMemberCountCache.expiresAt) {
        return _botMemberCountCache.value;
    }
    try {
        let total = 0;
        let after = '0';
        // with_counts=true asks Discord to include approximate_member_count on
        // each guild object (same semantics as discord.js guild.memberCount).
        for (let i = 0; i < 50; i++) {
            const url = `${API_BASE}/users/@me/guilds?limit=200&with_counts=true${after !== '0' ? `&after=${after}` : ''}`;
            const page = await fetchJson(url, { headers: botHeaders() });
            if (!Array.isArray(page) || page.length === 0) break;
            total += page.reduce((sum, g) => sum + (Number(g.approximate_member_count) || 0), 0);
            if (page.length < 200) break; // last page
            after = page.reduce((m, g) => (g.id > m ? g.id : m), after);
        }
        _botMemberCountCache = { value: total, expiresAt: now + BOT_MEMBER_COUNT_TTL_MS };
        return total;
    } catch (err) {
        // Token issues (401) etc. — leave the cache empty so callers fall back.
        console.warn('[DASHBOARD] getBotMemberCount failed:', err.message);
        return null;
    }
}

/** Get the bot's member object in a guild (for avatar/nickname display). */
async function getBotMember(guildId, botUserId) {
    const uid = botUserId || process.env.DISCORD_CLIENT_ID;
    return fetchJson(`${API_BASE}/guilds/${guildId}/members/${uid}`, { headers: botHeaders() });
}

/**
 * Get the position of the bot's highest role in a guild. Roles the bot cannot
 * assign (at/above this position, or integration-managed) are hidden from the
 * dashboard's reaction-role / leveling selectors to prevent 50007 "Missing
 * Access" errors when the bot tries to add them.
 */
async function getBotHighestRolePosition(guildId) {
    try {
        const botUserId = process.env.DISCORD_CLIENT_ID;
        const member = await getBotMember(guildId, botUserId);
        const botRoleIds = Array.isArray(member?.roles) ? member.roles : [];
        if (botRoleIds.length === 0) return -1;
        const roles = await getGuildRoles(guildId);
        // The @everyone role is filtered out of getGuildRoles; include it so the
        // lookup never misses a role the bot holds.
        let highest = -1;
        const byId = new Map(roles.map(r => [r.id, r]));
        for (const id of botRoleIds) {
            const r = byId.get(id);
            if (r && r.position > highest) highest = r.position;
        }
        // Fallback: fetch the raw guild roles (includes @everyone) if none matched.
        if (highest < 0) {
            const all = await fetchJson(`${API_BASE}/guilds/${guildId}/roles`, { headers: botHeaders() });
            for (const r of (all || [])) {
                if (botRoleIds.includes(r.id) && r.position > highest) highest = r.position;
            }
        }
        return highest;
    } catch (err) {
        console.warn('[DASHBOARD] getBotHighestRolePosition failed:', err.message);
        return -1;
    }
}

/**
 * Get text channels of a guild for channel selectors.
 */
async function getGuildChannels(guildId) {
    const channels = await fetchJson(`${API_BASE}/guilds/${guildId}/channels`, { headers: botHeaders() });
    return (channels || []).filter(c => c.type === 0); // type 0 = guild text
}

/**
 * Get roles of a guild, optionally excluding roles the bot cannot assign
 * (those at/above the bot's highest role, and integration-managed roles).
 * `excludeUnassignable=true` is used by reaction-role / leveling selectors.
 */
async function getGuildRoles(guildId, { excludeUnassignable = false } = {}) {
    const roles = await fetchJson(`${API_BASE}/guilds/${guildId}/roles`, { headers: botHeaders() });
    let list = (roles || []).filter(r => r.name !== '@everyone');
    if (excludeUnassignable) {
        const highest = await getBotHighestRolePosition(guildId);
        list = list.filter(r =>
            // integration-managed roles (bot/boost) can't be assigned by bots
            !r.managed &&
            r.position < highest
        );
    }
    return list;
}

// ── Message helpers (used by the reaction-role dashboard flows) ─────────────
//
// The dashboard is a separate process from the bot, so for bot-created
// reaction-role menus it posts the embed and adds reactions itself via REST
// (using the bot token), captures the resulting message id, and persists the
// menu row. The bot then picks up the row on its cache reload and starts
// watching the message.

/** Send a message (with embeds) to a channel. Returns the created message. */
async function sendChannelMessage(channelId, payload = {}) {
    return fetchJson(`${API_BASE}/channels/${channelId}/messages`, {
        method: 'POST',
        headers: { ...botHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
}

/** Edit a message's embeds/content. */
async function editChannelMessage(channelId, messageId, payload = {}) {
    return fetchJson(`${API_BASE}/channels/${channelId}/messages/${messageId}`, {
        method: 'PATCH',
        headers: { ...botHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
}

/** Delete a message the bot sent. */
async function deleteChannelMessage(channelId, messageId) {
    const res = await fetch(`${API_BASE}/channels/${channelId}/messages/${messageId}`, {
        method: 'DELETE',
        headers: botHeaders(),
    });
    return res.ok;
}

/** Fetch a single message by id (for attach-to-message validation). */
async function getChannelMessage(channelId, messageId) {
    return fetchJson(`${API_BASE}/channels/${channelId}/messages/${messageId}`, { headers: botHeaders() });
}

/** URL-encode an emoji for the reactions route. Unicode emojis are percent-
 *  encoded; custom emojis use "name:id" (colon is safe unencoded in a path
 *  segment, but we encode to be safe). */
function encodeEmojiForRoute(emoji) {
    if (/^\w+:\d+$/.test(emoji)) return encodeURIComponent(emoji);
    return encodeURIComponent(emoji);
}

/** Add a reaction as the bot to a message. */
async function addMessageReaction(channelId, messageId, emoji) {
    const res = await fetch(
        `${API_BASE}/channels/${channelId}/messages/${messageId}/reactions/${encodeEmojiForRoute(emoji)}/@me`,
        { method: 'PUT', headers: botHeaders() }
    );
    return res.ok;
}

/** Delete all reactions for a specific emoji from a message. */
async function removeAllReactionsForEmoji(channelId, messageId, emoji) {
    const res = await fetch(
        `${API_BASE}/channels/${channelId}/messages/${messageId}/reactions/${encodeEmojiForRoute(emoji)}`,
        { method: 'DELETE', headers: botHeaders() }
    );
    return res.ok;
}

const MANAGE_GUILD_PERMISSION = 0x20;
const ADMINISTRATOR_PERMISSION = 0x8;

/** Does this permissions bitfield include server-admin rights? */
function canManageGuild(permissions) {
    const p = BigInt(permissions || 0);
    return (p & BigInt(ADMINISTRATOR_PERMISSION)) !== 0n ||
           (p & BigInt(MANAGE_GUILD_PERMISSION)) !== 0n;
}

module.exports = {
    API_BASE,
    exchangeCode,
    refreshToken,
    getCurrentUser,
    getUserGuilds,
    getBotGuild,
    getBotGuildCount,
    getBotMemberCount,
    getBotSelf,
    getBotMember,
    getGuildChannels,
    getGuildRoles,
    canManageGuild,
    fetchJson,
    sendChannelMessage,
    editChannelMessage,
    deleteChannelMessage,
    getChannelMessage,
    addMessageReaction,
    removeAllReactionsForEmoji,
    encodeEmojiForRoute,
};
