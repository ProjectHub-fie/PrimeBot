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

/** Get the bot's member object in a guild (for avatar/nickname display). */
async function getBotMember(guildId, botUserId) {
    const uid = botUserId || process.env.DISCORD_CLIENT_ID;
    return fetchJson(`${API_BASE}/guilds/${guildId}/members/${uid}`, { headers: botHeaders() });
}

/** Get text channels of a guild for channel selectors. */
async function getGuildChannels(guildId) {
    const channels = await fetchJson(`${API_BASE}/guilds/${guildId}/channels`, { headers: botHeaders() });
    return (channels || []).filter(c => c.type === 0); // type 0 = guild text
}

/** Get roles of a guild. */
async function getGuildRoles(guildId) {
    const roles = await fetchJson(`${API_BASE}/guilds/${guildId}/roles`, { headers: botHeaders() });
    return (roles || []).filter(r => r.name !== '@everyone');
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
    getBotSelf,
    getBotMember,
    getGuildChannels,
    getGuildRoles,
    canManageGuild,
    fetchJson,
};
