const { EmbedBuilder } = require("discord.js");

module.exports = {
  name: "skip",
  aliases: ["s"],
  category: "Music",
  cooldown: 3,
  description: "To skip the current playing song.",
  botPrams: ["EMBED_LINKS"],
  player: true,
  inVoiceChannel: true,
  sameVoiceChannel: true,
  execute: async (message, args, client, prefix) => {
    const player = client.manager.players.get(message.guild.id);
    if (
      player.queue.size == 0 &&
      !player.data.get("autoplay") &&
      !player.loop === "track"
    ) {
      return message.reply({
        embeds: [new client.embed().d(`Play a song first!`)],
      });
    }
    await player.skip();

    const thing = new client.embed().d(
      `${client.emoji.tick} | **Skipped** - [${player.queue.current.title}](${client.config.links.support})`,
    );
    return message.reply({ embeds: [thing] });
  },
};
