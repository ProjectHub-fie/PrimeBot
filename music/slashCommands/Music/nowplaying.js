const {
  EmbedBuilder,
  MessageFlags,
  AttachmentBuilder,
  CommandInteraction,
  Client,
} = require("discord.js");
const { convertTime } = require("../../utils/convert.js");
const { progressbar } = require("../../utils/progressbar.js");
const { buildSpotifyCard } = require("../../utils/spotifyCard");

module.exports = {
  name: "nowplaying",
  description: "Show now playing song",
  userPrams: [],
  botPrams: ["EMBED_LINKS"],
  player: true,
  inVoiceChannel: false,
  sameVoiceChannel: false,
  /**
   *
   * @param {Client} client
   * @param {CommandInteraction} interaction
   */

  run: async (client, interaction) => {
    await interaction.deferReply({
      ephemeral: false,
    });
    const player = client.manager.players.get(interaction.guild.id);
    const song = player.queue.current;

    const emojimusic = client.emoji.music;
    const title =
      song.title.length > 25
        ? song.title.slice(0, 25) + "....."
        : song.title + ".....";
    const req = song.requester;
    const auth = player.queue.current.author;
    const total = song.length;
    const current = player.position;

    const spotify = await buildSpotifyCard({
      author: auth,
      title,
      image: `${song.thumbnail}`,
      current,
      total,
    });
    const cardName = client.cardName || 'primebot-music.png';
    const attachment = new AttachmentBuilder(spotify, { name: cardName });

    const embed = new EmbedBuilder()
      .setThumbnail(interaction.member.displayAvatarURL({ dynamic: true }))
      .setDescription(
        `${client.emoji.playing} **Song** [${title}](${client.config.links.support})\n${client.emoji.dot} **Duration**\n[ \`${convertTime(current)} / ${convertTime(total)}\`]\n${client.emoji.dot} **Requester**\n ${song.requester}`,
      )
      .setImage(`attachment://${cardName}`)
      .setColor(client.color)
      .setAuthor({
        name: `| Now Playing`,
        iconURL: client.user.displayAvatarURL(),
      })
      .setFooter({
        text: `${client.config.links.power}`,
        iconURL: client.user.displayAvatarURL({ dynamic: true }),
      });
    return interaction.editReply({ embeds: [embed], files: [attachment] });
  },
};
