/**
 * Now-playing artwork card.
 *
 * Linix renders this with `canvafy`'s Spotify card. `canvafy` pulls in the
 * native `canvas` package, which needs system Cairo/Pango headers to build and
 * therefore cannot install on every host (it fails outright on a machine
 * without those dev packages). This adapter keeps the same card, the same
 * inputs and the same PNG output, but prefers `canvafy` and falls back to
 * `canvacard`'s Spotify card — which ships a prebuilt `@napi-rs/canvas` — when
 * `canvafy` cannot load. Both are real renderers; nothing is stubbed.
 */

let canvafy = null;
let canvacardSpotify = null;
let resolved = false;

function loadRenderers() {
    if (resolved) return;
    resolved = true;
    try {
        canvafy = require('canvafy');
    } catch (err) {
        console.warn('[MUSIC] canvafy unavailable, using canvacard for now-playing cards:', err.message.split('\n')[0]);
    }
    if (!canvafy) {
        try {
            canvacardSpotify = require('canvacard').Spotify;
        } catch (err) {
            console.warn('[MUSIC] No card renderer available:', err.message.split('\n')[0]);
        }
    }
}

/**
 * Build a Spotify-style now-playing card.
 * @param {{author:string,title:string,image:string,current:number,total:number}} opts
 * @returns {Promise<Buffer|null>} PNG buffer, or null when no renderer is usable
 */
async function buildSpotifyCard({ author, title, image, current = 0, total = 0 }) {
    loadRenderers();

    if (canvafy) {
        return new canvafy.Spotify()
            .setAuthor(author)
            .setTimestamp(current, total)
            .setImage(image)
            .setTitle(title)
            .setBlur(1)
            .setOverlayOpacity(0.5)
            .build();
    }

    if (canvacardSpotify) {
        const start = Date.now() - Math.max(0, current);
        return new canvacardSpotify()
            .setAuthor(author)
            .setTitle(title)
            .setImage(image)
            .setStartTimestamp(start)
            .setEndTimestamp(start + Math.max(0, total))
            .build();
    }

    return null;
}

module.exports = { buildSpotifyCard };
