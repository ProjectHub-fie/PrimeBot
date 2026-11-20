const { EmbedBuilder } = require("discord.js");

module.exports = {
  name: "pause",
  category: "Music",
  cooldown: 3,
  description: "Pause the currently playing music",
  args: false,
  usage: "",
  userPrams: [],
  botPrams: ["EMBED_LINKS"],
  dj: true,
  owner: false,
  player: true,
  inVoiceChannel: true,
  sameVoiceChannel: true,
  execute: async (message, args, client, prefix) => {
    const player = client.manager.players.get(message.guild.id);
    if (!player.queue.current) {
      return message.channel.send({
        embeds: [new client.embed().d(`Play a song first!`)],
      });
    }
    if (player.shoukaku.paused) {
      const thing = new EmbedBuilder()
        .setColor("2f3136")
        .setDescription(
          `${client.emoji.tick} | The player is already **paused**.`,
        );
      return message.reply({ embeds: [thing] });
    }

    await player.pause(true);

    const song = player.queue.current;

    const thing = new EmbedBuilder()
      .setColor("2f3136")
      .setDescription(
        `${client.emoji.tick} | **Paused** - [${song.title}](${client.config.links.support})`,
      );
    return message.reply({ embeds: [thing] });
  },
};
