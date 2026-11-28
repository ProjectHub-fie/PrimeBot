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
  name: "close",
  run: async (client, name, code, reason) => {
    if (client.__musicState) client.__musicState.connected = false;
    // The close reason can echo connection details; redact the password if a
    // library ever embeds it.
    const safeReason = sanitizeText(reason, nodeFor(name)).slice(0, 500);
    client.logger.log(
      `Lavalink ${name}: Closed, Code ${code}, Reason ${safeReason || "No reason"}`,
      "error",
    );
  },
};
