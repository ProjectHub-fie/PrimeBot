module.exports = {
  name: "disconnect",
  run: async (client, name, players, moved) => {
    if (!Array.isArray(players)) {
      console.error("Players is not an array.");
      return;
    }
    if (moved) return;
    if (client.__musicState) client.__musicState.connected = false;
    players.map((player) => player.connection.disconnect());
    client.logger.log(`Lavalink ${name}: Disconnected`, "warn");
    // Shoukaku deletes a node from the pool once it gives up reconnecting, so
    // without this the node stays gone until a command happens to self-heal.
    // Bounded backoff lives in the player manager (never a reconnect storm).
    try {
      if (client.manager && typeof client.manager.scheduleNodeReconnect === "function") {
        client.manager.scheduleNodeReconnect(`node "${name}" disconnected`);
      }
    } catch (_) { /* reconnect scheduling must never throw */ }
  },
};
