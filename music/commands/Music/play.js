const {
  EmbedBuilder,
  MessageFlags,
  PermissionsBitField,
} = require("discord.js");
const { convertTime } = require("../../utils/convert.js");

module.exports = {
  name: "play",
  category: "Music",
  aliases: ["p"],
  cooldown: 3,
  description: "Plays audio from YouTube or Soundcloud",
  args: false,
  usage: "Song URL or Name To Play",
  userPrams: [],
  botPrams: ["EmbedLinks"],
  owner: false,
  inVoiceChannel: true,
  sameVoiceChannel: true,
  execute: async (message, args, client, prefix) => {
    if (!args[0])
      return message.channel.send({
        embeds: [
          new client.embed().setAuthor({
            name: `${prefix}play Song name or Song url`,
            iconURL: message.author.displayAvatarURL(),
            url: client.config.links.support,
          }),
        ],
      });

    const emojiaddsong = message.client.emoji.addsong;
    const emojiplaylist = message.client.emoji.playlist;

    const { channel } = message.member.voice;
    if (
      !message.guild.members.me.permissions.has(
        PermissionsBitField.resolve(["Speak", "Connect"]),
      )
    )
      return message.channel.send({
        embeds: [
          new EmbedBuilder()
            .setColor(client.embedColor)
            .setDescription(
              `I don't have enough permissions to execute this command! Please give me permission to \`CONNECT\` or \`SPEAK\`.`,
            ),
        ],
      });

    const query = args.join(" ");

    const player = await client.manager.createPlayer({
      guildId: message.guild.id,
      voiceId: message.member.voice.channel.id,
      textId: message.channel.id,
      volume: 80,
      deaf: true,
    });

    const result = await player.search(query, { requester: message.author });

    if (!result.tracks.length)
      return message.reply({
        content: `${client.emoji.cross} | No result was found`,
      });

    const tracks = result.tracks;

    const title =
      tracks[0].title.length > 25
        ? tracks[0].title.slice(0, 25) + "....."
        : tracks[0].title + ".....";

    if (result.type === "PLAYLIST")
      for (const track of tracks) player.queue.add(track);
    else player.queue.add(tracks[0]);

    if (!player.playing && !player.paused) player.play();
    return message.reply(
      result.type === "PLAYLIST"
        ? {
            embeds: [
              new client.embed().d(
                `${client.emoji.dot} Queued ${tracks.length} from ${result.playlistName}`,
              ),
            ],
          }
        : {
            embeds: [
              new client.embed().d(
                `${client.emoji.dot} Added [${title}](${client.config.links.support}) By ${message.author.displayName}`,
              ),
              // .setFooter({ text: "Enjoy your music!", iconURL: message.author.displayAvatarURL() })
            ],
          },
    );
  },
};
