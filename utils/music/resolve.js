/**
 * Provider routing helper.
 *
 * Commands used to `require('../utils/music/providers/registry')` directly, which
 * would bypass the Lavalink engine (its search/resolve must go through the node).
 * This helper resolves through the ACTIVE engine when a music manager is
 * available and falls back to the direct registry otherwise, so a command never
 * silently uses the wrong source resolver.
 *
 * The manager's provider adapter exposes the same surface as the direct registry
 * (resolveQuery / searchQuery / resolveCollection / resolveStream /
 * matchToStreamable), so callers are engine-agnostic.
 */

/** The active provider adapter, or the direct registry as a fallback. */
function providersFor(clientOrManager) {
    const mgr = clientOrManager && clientOrManager.musicManager
        ? clientOrManager.musicManager
        : clientOrManager;
    if (mgr && mgr.providers) return mgr.providers;
    if (mgr && mgr.providerAdapter) return mgr.providerAdapter;
    return require('./providers/registry');
}

/** Resolve a query to a single track through the active engine. */
function resolveQuery(clientOrManager, query, opts) {
    return providersFor(clientOrManager).resolveQuery(query, opts);
}

/** Search candidates through the active engine. */
function searchQuery(clientOrManager, query, limit) {
    return providersFor(clientOrManager).searchQuery(query, limit);
}

/** Resolve a collection (playlist/album) through the active engine. */
function resolveCollection(clientOrManager, url, limit) {
    return providersFor(clientOrManager).resolveCollection(url, limit);
}

module.exports = { providersFor, resolveQuery, searchQuery, resolveCollection };
