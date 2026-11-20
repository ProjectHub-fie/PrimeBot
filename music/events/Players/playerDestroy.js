module.exports = {
  name: "playerDestroy",
  run: async (client, player) => {
    const name = client.guilds.cache.get(player.guildId).name;
    const guild = client.guilds.cache.get(player.guildId);
    if (!guild) return;

    const server = client.guilds.cache.get(player.guildId);
      const voice = player.voiceId;
    client.rest
      .put(`/channels/${voice}/voice-status`, { body: { status: `` } })
      .catch(() => null);
    client.logger.log(`Player Destroy in ${name? name : 'idk'} [ ${player.guildId} ]`, "log");
    if (player.data.get("message") && player.data.get("message").deletable)
      player.data
        .get("message")
        .delete()
        .catch(() => null);
    if (player.data.get("autoplay"))
      try {
        player.data.delete("autoplay");
      } catch (err) {
        client.logger.log(err.stack ? err.stack : err, "log");
      }
  },
};
