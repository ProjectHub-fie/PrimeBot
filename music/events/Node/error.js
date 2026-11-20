module.exports = {
  name: "error",
  run: async (client, name, error) => {
    if (client.__musicState) client.__musicState.connected = false;
    // Never log the node password. Shoukaku errors carry the host/url, never
    // the auth header, but the message is truncated defensively anyway.
    const msg = error && error.message ? error.message : String(error);
    client.logger.log(`Lavalink "${name}" error: ${String(msg).slice(0, 500)}`, "error");
  },
};
