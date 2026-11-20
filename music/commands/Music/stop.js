const { EmbedBuilder } = require("discord.js");
const Wait = require("util").promisify(setTimeout);

module.exports = {
  name: "stop",
  category: "Music",
  cooldown: 3,
  description: "Stops the music",
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

    player.queue.clear();
    player.data.delete("autoplay");
    player.loop = "none";
    player.playing = false;
    player.paused = false;
    player.autoplay = false;
    await player.skip();
    Wait(500);
    const thing = new EmbedBuilder()
      .setColor("2f3136")
      .setDescription(`${client.emoji.tick} | Stopped the music`);
    message.reply({ embeds: [thing] });
  },
};
