/**
 * Fleet-wide server/member counts.
 *
 * Under active-active sharding every node holds only its OWN shards' guilds, so
 * `client.guilds.cache.size` is a fraction of the bot (17 of 63 in production).
 * Every user-facing count — presence, /about, /stats, the mention card, the help
 * menu, the ready log — must show the fleet total, not the node's share.
 *
 * Sources, in order:
 *   1. `client.guilds.cache` when this process serves every shard (the normal,
 *      unsharded deployment) — exact, no network.
 *   2. Discord REST `GET /users/@me/guilds?with_counts=true` — shard-independent
 *      and authoritative, paginated 200 at a time. Cached for
 *      `FLEET_COUNT_TTL_MS` so a render path never pays for it twice.
 *   3. The last known value, else this node's own cache size, so a REST hiccup
 *      degrades to a lower number instead of throwing.
 *
 * `getFleetGuildCount()` / `getFleetMemberCount()` are SYNCHRONOUS: they return
 * the cached fleet value immediately and refresh it in the background. Async
 * callers that must be exact (the ready log) use `getFleetCounts({ force })`.
 */

const { Routes } = require('discord-api-types/v10');

const FLEET_COUNT_TTL_MS = 60_000;
const FLEET_COUNT_TIMEOUT_MS = 8_000;
const PAGE_LIMIT = 200;
const MAX_PAGES = 50;

const cache = new Map(); // client -> { guilds, members, source, at, pending }

function cacheFor(client) {
    if (!cache.has(client)) cache.set(client, { guilds: null, members: null, source: null, at: 0, pending: null });
    return cache.get(client);
}

/**
 * Does this process hold every shard?
 * `shardCount` > 1 means Discord split the bot; `shards` narrows it further to
 * the ids this process serves.
 */
function servesWholeFleet(client) {
    const total = Number(client?.options?.shardCount) || 1;
    if (total > 1) return false;
    const ids = client?.options?.shards;
    if (Array.isArray(ids) && ids.length > 0 && ids.length < total) return false;
    return true;
}

function localCounts(client) {
    // Callers include pure render helpers that may be invoked without a client
    // (the help catalog is built in tests, for example) — never throw for them.
    const size = client?.guilds?.cache?.size;
    if (!Number.isFinite(size)) return { guilds: null, members: null };
    let members = 0;
    try {
        for (const guild of client.guilds.cache.values()) members += guild.memberCount || 0;
    } catch (_) {
        members = null;
    }
    return { guilds: size, members };
}

async function fetchFromRest(client) {
    const token = client?.token;
    if (!token || typeof client?.rest?.get !== 'function') return null;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FLEET_COUNT_TIMEOUT_MS);
    try {
        let guilds = 0;
        let members = 0;
        let after = '0';
        for (let page = 0; page < MAX_PAGES; page++) {
            const query = new URLSearchParams({ limit: String(PAGE_LIMIT), with_counts: 'true' });
            if (after !== '0') query.set('after', after);
            const rows = await client.rest.get(Routes.userGuilds(), {
                query,
                signal: controller.signal,
                auth: false,
                headers: { Authorization: `Bot ${token}` },
            });
            if (!Array.isArray(rows) || rows.length === 0) break;
            guilds += rows.length;
            for (const row of rows) members += Number(row.approximate_member_count) || 0;
            if (rows.length < PAGE_LIMIT) break;
            after = rows.reduce((max, row) => (row.id > max ? row.id : max), after);
        }
        if (!guilds) return null;
        return { guilds, members };
    } catch (_) {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

async function refresh(client, { force = false } = {}) {
    const entry = cacheFor(client);
    if (entry.pending) return entry.pending;
    if (!force && entry.source && Date.now() - entry.at < FLEET_COUNT_TTL_MS) {
        return { guilds: entry.guilds, members: entry.members, source: entry.source };
    }

    entry.pending = (async () => {
        // Unsharded: the cache IS the fleet, so never spend a REST call on it.
        if (servesWholeFleet(client)) {
            const local = localCounts(client);
            Object.assign(entry, { ...local, source: 'cache', at: Date.now() });
            return { guilds: entry.guilds, members: entry.members, source: entry.source };
        }
        const rest = await fetchFromRest(client);
        if (rest) {
            Object.assign(entry, { ...rest, source: 'rest', at: Date.now() });
        } else {
            // Keep a previously known fleet value; otherwise report this node's
            // share (honest but lower) and let the next call retry.
            if (entry.guilds == null) {
                const local = localCounts(client);
                Object.assign(entry, { ...local, source: 'cache', at: Date.now() });
            }
        }
        return { guilds: entry.guilds, members: entry.members, source: entry.source };
    })().finally(() => { entry.pending = null; });

    return entry.pending;
}

/** Fleet guild count. Never blocks: returns the cache, refreshing in the background. */
function getFleetGuildCount(client) {
    const entry = cacheFor(client);
    if (entry.guilds == null) {
        const local = localCounts(client);
        if (local.guilds == null) return null; // no client, nothing to report
        Object.assign(entry, { ...local, source: 'cache', at: 0 });
        refresh(client).catch(() => {});
    } else if (Date.now() - entry.at > FLEET_COUNT_TTL_MS) {
        refresh(client).catch(() => {});
    }
    return entry.guilds;
}

/** Fleet member total (sum of every guild's memberCount). Same contract as above. */
function getFleetMemberCount(client) {
    const entry = cacheFor(client);
    if (entry.members == null) {
        const local = localCounts(client);
        if (local.guilds == null) return null; // no client, nothing to report
        Object.assign(entry, { members: local.members, at: entry.at || 0 });
        refresh(client).catch(() => {});
    } else if (Date.now() - entry.at > FLEET_COUNT_TTL_MS) {
        refresh(client).catch(() => {});
    }
    return entry.members;
}

/**
 * Exact fleet counts. Use from async paths (ready log, command handlers) where a
 * fresh number matters more than latency.
 * @returns {Promise<{guilds:number, members:number|null, source:'cache'|'rest'}>}
 */
async function getFleetCounts(client, { force = false } = {}) {
    const result = await refresh(client, { force });
    return {
        guilds: result.guilds ?? client?.guilds?.cache?.size ?? 0,
        members: result.members ?? null,
        source: result.source || 'cache',
    };
}

/** Human label: "63" when the fleet is known, "63 (this node: 17)" when sharded. */
function describeFleetSize(client, counts) {
    const total = counts?.guilds ?? getFleetGuildCount(client);
    if (servesWholeFleet(client)) return `${total}`;
    const local = client?.guilds?.cache?.size ?? 0;
    return `${total} (this node: ${local})`;
}

module.exports = {
    getFleetCounts,
    getFleetGuildCount,
    getFleetMemberCount,
    describeFleetSize,
    servesWholeFleet,
    FLEET_COUNT_TTL_MS,
};
