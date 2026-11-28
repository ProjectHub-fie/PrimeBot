/**
 * Lavalink node `error` event.
 *
 * Records a sanitized reason (so `$stats`, `$music` and the connect diagnostic
 * can explain *why* music is down) and logs it once. The password is never part
 * of the message, and `sanitizeText` redacts it defensively anyway.
 */

const { sanitizeText } = require('../../nodeDiagnostics');
const { getMusicConfig } = require('../../config');

function nodeFor(name) {
    try {
        const nodes = getMusicConfig().nodes || [];
        return nodes.find(n => n.name === name) || nodes[0] || null;
    } catch (_) {
        return null;
    }
}

module.exports = {
  name: "error",
  run: async (client, name, error) => {
    const node = nodeFor(name);
    const msg = sanitizeText(error && error.message ? error.message : error, node);
    if (client.__musicState) {
        client.__musicState.connected = false;
        // Keep the reason: `$stats` / the dashboard show "not connected", and
        // without this the operator cannot tell a wrong password from an
        // unreachable host.
        client.__musicState.lastError = String(msg).slice(0, 200);
        client.__musicState.lastErrorAt = Date.now();
    }
    client.logger.log(`Lavalink "${name}" error: ${String(msg).slice(0, 500)}`, "error");
  },
};
