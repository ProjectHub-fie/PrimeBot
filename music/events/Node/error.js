module.exports = {
  name: "error",
  run: async (client, name, error) => {
    if (client.__musicState) {
        client.__musicState.connected = false;
        // Keep the reason: `$stats` / the dashboard show "not connected", and
        // without this the operator cannot tell a wrong password from an
        // unreachable host. The auth header is never part of `error.message`.
        client.__musicState.lastError = String(error && error.message ? error.message : error).slice(0, 200);
        client.__musicState.lastErrorAt = Date.now();
    }
    // Never log the node password. Shoukaku errors carry the host/url, never
    // the auth header, but the message is truncated defensively anyway.
    const msg = error && error.message ? error.message : String(error);
    client.logger.log(`Lavalink "${name}" error: ${String(msg).slice(0, 500)}`, "error");
  },
};
