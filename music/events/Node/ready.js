/** @format */

const db = require("../../schema/247");

module.exports = {
  name: "ready",
  run: async (client, name) => {
    // The node connected — THIS is "music ready". Configuration alone never
    // reports ready (see music/index.js and index.js).
    if (client.__musicState) {
        client.__musicState.connected = true;
        client.__musicState.lastError = null;
        client.__musicState.lastErrorAt = null;
        client.__musicState.connectDiagnostic = null;
    }
    client.__musicConnectDiagDone = true;
    // Endpoint only (host/port/scheme) — never the password.
    let endpoint = "";
    try {
        const { describeNode } = require("../../nodeDiagnostics");
        const { getMusicConfig } = require("../../config");
        endpoint = describeNode((getMusicConfig().nodes || [])[0]).endpoint;
    } catch (_) { /* diagnostics are optional */ }
    client.logger.log(`Lavalink "${name}" connected${endpoint ? ` (${endpoint})` : ""}.`, "ready");
    console.log(`[MUSIC] Linix music system ready — Lavalink node "${name}" connected.`);
    client.logger.log("Auto Reconnect Collecting player 24/7 data", "log");

    // No music database configured (MUSIC_DATABASE_URL, or the shared
    // FALLBACK/DATABASE_URL fallback) → 24/7 sessions cannot be restored.
    // That is a configuration state, not a node failure: the node is connected
    // and playback works, so log it once and continue.
    let maindata = [];
    try {
        maindata = await db.find();
    } catch (err) {
        client.logger.log(
            `Auto Reconnect skipped — no music database configured (${err.message})`,
            "warn",
        );
        return;
    }
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

      // An empty channel cache means the guild is still hydrating (or the bot
      // lost View Channel), so preserve the row and retry on the next ready.
      // A populated cache with missing target channels means the channel was
      // deleted — prune that stale session. The explicit `/247 stop` command
      // remains the only user-facing disable path.
      if (!channel || !voice) {
        if (guild.channels.cache.size > 0) {
          await data.deleteOne();
        } else {
          client.logger.log(
            `Auto Reconnect: skipping guild ${data.Guild} (channel cache not ready)`,
            "warn",
          );
        }
        continue;
      }

      if (client.manager.players.get(data.Guild)) continue;

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
