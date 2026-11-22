/**
 * Supplies the `client.*` surface the vendored Linix music code expects.
 *
 * Linix's music modules are written against a `MusicBot` client that carries
 * `client.color`, `client.emoji`, `client.embed`, `client.button`,
 * `client.config`, `client.logger`, `client.prefix`, `client.commands`,
 * `client.slashCommands`, `client.manager` and `client.numb`. PrimeBot's client
 * is a plain discord.js Client, so these are attached here instead of replacing
 * it — PrimeBot keeps its own client, shard manager and every unrelated feature.
 */

const Logger = require('./utils/logger');
const button = require('./custom/button');
const makeEmbed = require('./custom/embed');
const installNumFormat = require('./custom/numformat');
const musicConfig = require('./config');

/**
 * Attach the Linix music client surface. Idempotent — safe to call twice (e.g.
 * a reconnect path), and never overwrites a property PrimeBot already uses.
 */
function installMusicClientSurface(client) {
    if (client.__musicSurfaceInstalled) return client;
    client.__musicSurfaceInstalled = true;

    const cfg = musicConfig.getMusicConfig();

    // `client.color` is the numeric embed colour the vendored embeds use.
    if (client.color === undefined) {
        client.color = parseInt(String(cfg.embedColor).replace(/^#/, ''), 16);
    }
    client.embedColor = cfg.embedColor;
    /*
     * `client.emoji` is a live view over the central catalog: each key resolves
     * through utils/emojiManager.js on access (validated custom emoji when
     * available, else the MUSIC_EMOJI_<KEY> override / shared Unicode
     * fallback). Getters keep it correct even if the catalog finishes loading
     * after the music subsystem boots. Linix's own custom-emoji ids are never
     * hardcoded here.
     */
    client.emoji = cfg.emoji;
    try {
        const emojiManagerModule = require('../utils/emojiManager');
        const resolved = {};
        for (const [key, fallback] of Object.entries(cfg.emoji)) {
            Object.defineProperty(resolved, key, {
                enumerable: true,
                configurable: true,
                get() {
                    const manager = emojiManagerModule.getEmojiManager();
                    return manager ? manager.emoji(key, fallback) : fallback;
                },
            });
        }
        client.emoji = resolved;
    } catch (_) { /* manager unavailable — keep the Unicode map */ }
    client.ownerId = cfg.ownerId;
    client.playlistMenu = cfg.playlistMenu;
    client.cardName = cfg.cardName;
    client.embed = makeEmbed(cfg.embedColor);
    client.button = button;
    client.logger = Logger;
    // Linix's `client.prefix` is a single global prefix; PrimeBot resolves the
    // per-guild prefix from server settings. This value is only used in help
    // text, so PrimeBot's default prefix is the correct stand-in.
    if (!client.prefix) client.prefix = require('../config').prefix;
    if (!client.slashCommands) client.slashCommands = new (require('discord.js').Collection)();

    // `client.config` — only the music-relevant keys the vendored code reads
    // (`links.*`). PrimeBot's own config is left untouched.
    client.config = Object.assign({}, client.config || {}, {
        links: cfg.links,
        node_source: cfg.nodeSource,
        nodes: cfg.nodes,
        node_options: cfg.nodeOptions,
    });

    /*
     * Where Linix hardcoded `client.users.fetch('<bot owner id>')` for an
     * avatar and brand link, PrimeBot uses the configured avatar if set, else
     * the sending user's own avatar (passed by the caller — no owner lookup
     * needed, and it avoids a fetch when a private owner id is not configured).
     */
    if (!client.getPlaylistAvatar) {
        client.getPlaylistAvatar = (requester) => {
            const configured = cfg.ownerId && client.users && client.users.cache.get(cfg.ownerId);
            if (configured) return configured.displayAvatarURL();
            if (requester) return requester.displayAvatarURL();
            if (client.user) return client.user.displayAvatarURL();
            return null;
        };
    }

    installNumFormat(client);

    // `client.rest` already exists on discord.js v14 clients and is used by the
    // vendored player events for the voice-status endpoint — nothing to add.

    return client;
}

module.exports = { installMusicClientSurface };
