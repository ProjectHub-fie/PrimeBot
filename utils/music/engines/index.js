/**
 * Playback-engine resolver.
 *
 * `MUSIC_ENGINE=lavalink` (the PRIMARY engine once a node is configured) routes
 * playback through a Lavalink node. `MUSIC_ENGINE=direct` keeps PrimeBot's
 * original local pipeline (ytdl-core / soundcloud-core / direct HTTP + ffmpeg +
 * @discordjs/voice) and is the rollback switch.
 *
 * Selection rules:
 *   • `MUSIC_ENGINE=direct`            → direct (explicit rollback).
 *   • `MUSIC_ENGINE=lavalink`          → lavalink (falls back to direct if the
 *                                        node config or the libs are unusable).
 *   • unset / unknown / "auto"         → lavalink WHEN a node is configured,
 *                                        otherwise direct. This makes Lavalink
 *                                        the default engine for a real
 *                                        deployment without breaking one that
 *                                        has no node yet.
 *
 * Migration safety:
 *   • An unconfigured deployment never changes behaviour — it stays on direct.
 *   • Selecting `lavalink` without a valid node configuration falls back to
 *     `direct` with a loud warning instead of leaving music broken — rollback is
 *     therefore a one-line env change (or simply `MUSIC_ENGINE=direct`).
 *   • Explicit dependency injection (`deps.voice` / `deps.providers`) always
 *     selects the direct engine, so the existing test doubles keep working.
 */

const { DirectEngine } = require('./direct');
const { hasNodeConfig } = require('../lavalink/nodeConfig');

const VALID_ENGINES = ['direct', 'lavalink'];

/** The engine selected by the environment (never throws). */
function resolveEngineName(env = process.env) {
    const raw = String((env.MUSIC_ENGINE || '')).trim().toLowerCase();
    if (raw === 'direct') return 'direct';
    if (raw === 'lavalink') return 'lavalink';
    // An explicit but unknown value must never surprise-switch the engine.
    if (raw && !VALID_ENGINES.includes(raw)) return 'direct';
    // Unset / "auto": prefer Lavalink, but only when a node is actually
    // configured — otherwise an unconfigured deployment would break every play
    // with "no healthy node available".
    return hasNodeConfig(env) ? 'lavalink' : 'direct';
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

    const direct = (reason = null) => ({
        engine: new DirectEngine({ voice: deps.voice, providers: deps.providers, filters: deps.filters }),
        name: 'direct',
        fallbackReason: reason,
    });

    if (injected || requested === 'direct') return direct();

    // requested === 'lavalink'
    if (!hasNodeConfig()) {
        const reason = 'no Lavalink node configured (set LAVALINK_NODES or LAVALINK_HOST/NODE_URL)';
        console.warn(`[MUSIC] Lavalink requested but ${reason} — falling back to the direct engine.`);
        return direct(reason);
    }
    try {
        const { LavalinkEngine } = require('./lavalink');
        const engine = new LavalinkEngine(client, deps);
        return { engine, name: 'lavalink', fallbackReason: null };
    } catch (err) {
        const reason = `Lavalink engine unavailable (${err.message})`;
        console.error(`[MUSIC] ${reason} — falling back to the direct engine.`);
        return direct(reason);
    }
}

module.exports = { createEngine, resolveEngineName, VALID_ENGINES, DirectEngine };
