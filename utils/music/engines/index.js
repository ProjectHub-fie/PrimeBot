/**
 * Playback-engine resolver.
 *
 * `MUSIC_ENGINE=direct` (default) keeps PrimeBot's original pipeline exactly as
 * it was. `MUSIC_ENGINE=lavalink` switches playback to a Lavalink node.
 *
 * Migration safety:
 *   • `direct` is the default, so an unset/unknown value never changes behaviour.
 *   • Selecting `lavalink` without a valid node configuration falls back to
 *     `direct` with a loud warning instead of leaving music broken — rollback is
 *     therefore a one-line env change (or simply unsetting MUSIC_ENGINE).
 *   • Explicit dependency injection (`deps.voice` / `deps.providers`) always
 *     selects the direct engine, so the existing test doubles keep working.
 */

const { DirectEngine } = require('./direct');

const VALID_ENGINES = ['direct', 'lavalink'];

/** The engine selected by the environment (never throws). */
function resolveEngineName(env = process.env) {
    const raw = String((env.MUSIC_ENGINE || 'direct')).trim().toLowerCase();
    return VALID_ENGINES.includes(raw) ? raw : 'direct';
}

/**
 * Build the playback engine for a client.
 *
 * @param {object} client the discord.js client
 * @param {object} [deps]
 * @param {string} [deps.engineName] override the env selection
 * @param {object} [deps.voice] inject a voice layer (forces direct)
 * @param {object} [deps.providers] inject a provider registry (forces direct)
 * @param {object} [deps.filters] inject a filter catalog
 * @returns {{engine: object, name: string, fallbackReason: string|null}}
 */
function createEngine(client, deps = {}) {
    const injected = !!(deps.voice || deps.providers);
    const requested = deps.engineName ? String(deps.engineName).toLowerCase() : resolveEngineName();

    if (injected || requested === 'direct') {
        return {
            engine: new DirectEngine({ voice: deps.voice, providers: deps.providers, filters: deps.filters }),
            name: 'direct',
            fallbackReason: null,
        };
    }

    // requested === 'lavalink'
    try {
        const { LavalinkEngine } = require('./lavalink');
        const engine = new LavalinkEngine(client, deps);
        return { engine, name: 'lavalink', fallbackReason: null };
    } catch (err) {
        const reason = `Lavalink engine unavailable (${err.message})`;
        console.error(`[MUSIC] ${reason} — falling back to the direct engine.`);
        return {
            engine: new DirectEngine({ voice: deps.voice, providers: deps.providers, filters: deps.filters }),
            name: 'direct',
            fallbackReason: reason,
        };
    }
}

module.exports = { createEngine, resolveEngineName, VALID_ENGINES, DirectEngine };
