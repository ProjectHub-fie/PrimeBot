module.exports = {
  name: "close",
  run: async (client, name, code, reason) => {
    if (client.__musicState) client.__musicState.connected = false;
    client.logger.log(
      `Lavalink ${name}: Closed, Code ${code}, Reason ${String(reason || "No reason").slice(0, 500)}`,
      "error",
    );
  },
};
