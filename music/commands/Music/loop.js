const { EmbedBuilder } = require("discord.js");

module.exports = {
  name: "loop",
  aliases: ["loop"],
  category: "Music",
  cooldown: 3,
  description: "Toggle music loop",
  botPrams: ["EmbedLinks"],
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

    if (player.setLoop(player.loop === "none" ? "track" : "none") && !args[0]) {
      const sexy = player.loop === "none" ? "Disabled" : "Enabled";
      const thing = new client.embed().d(
        `${client.emoji.loop} | Loop track is now **${sexy}**`,
      );
      return message.reply({ embeds: [thing] });
    }
    if (["q", "queue"].includes(args[0])) {
      await player.setLoop("queue");
      const thing = new EmbedBuilder()
        .setColor("2f3136")
        .setDescription(`${client.emoji.loop} | Loop queue is now **Enabled**`);
      return message.reply({ embeds: [thing] });
    }
  },
};
