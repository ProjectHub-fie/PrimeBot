/** @format */

const db = require("../../schema/247");

module.exports = {
  name: "ready",
  run: async (client, name) => {
    // The node connected — THIS is "music ready". Configuration alone never
    // reports ready (see music/index.js and index.js).
    if (client.__musicState) client.__musicState.connected = true;
    client.logger.log(`Lavalink "${name}" connected.`, "ready");
    console.log(`[MUSIC] Linix music system ready — Lavalink node "${name}" connected.`);
    client.logger.log("Auto Reconnect Collecting player 24/7 data", "log");

    const maindata = await db.find();
    client.logger.log(
      `Auto Reconnect found ${
        maindata.length
          ? `${maindata.length} queue${maindata.length > 1 ? "s" : ""}. Resuming all auto reconnect queue`
          : "0 queue"
      }`,
      "ready",
    );

    for (const data of maindata) {
      const guild = client.guilds.cache.get(data.Guild);
      // PrimeBot runs several shard nodes against one database. Only the node
      // that actually holds the guild has its channels cached, so a node that
      // does not own it must leave the row alone — deleting on "not cached"
      // would erase another node's 24/7 sessions on every node restart.
      if (!guild) continue;

      const channel = guild.channels.cache.get(data.TextId);
      const voice = guild.channels.cache.get(data.VoiceId);

      if (!channel || !voice) {
        await data.deleteOne();
        continue;
      }

      await client.manager.createPlayer({
        guildId: data.Guild,
        voiceId: data.VoiceId,
        textId: data.TextId,
        deaf: true,
      });

      await new Promise((resolve) =>
        setTimeout(resolve, Math.floor(Math.random() * (780 - 500 + 1)) + 780),
      );
    }
  },
};
