/**
 * Now-playing artwork card.
 *
 * Renders a Spotify-style card with `canvacard` (which ships a prebuilt
 * `@napi-rs/canvas`, so it installs cleanly on hosts with no system Cairo/
 * Pango). The original Linix renderer `canvafy` was dropped because it pulls
 * in the native `canvas` package, whose source compile needs `pixman-1` /
 * Cairo headers and breaks cloud builds (Vercel's Node 24 included). The card
 * shape, inputs and PNG output are the same.
 */

let canvacardSpotify = null;
let resolved = false;

function loadRenderer() {
    if (resolved) return;
    resolved = true;
    try {
        canvacardSpotify = require('canvacard').Spotify;
    } catch (err) {
        console.warn('[MUSIC] No card renderer available:', err.message.split('\n')[0]);
    }
}

/**
 * Build a Spotify-style now-playing card.
 * @param {{author:string,title:string,image:string,current:number,total:number}} opts
 * @returns {Promise<Buffer|null>} PNG buffer, or null when no renderer is usable
 */
async function buildSpotifyCard({ author, title, image, current = 0, total = 0 }) {
    loadRenderer();

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
