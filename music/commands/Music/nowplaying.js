const { EmbedBuilder, MessageFlags, AttachmentBuilder } = require("discord.js");
const { convertTime } = require("../../utils/convert.js");
const { progressbar } = require("../../utils/progressbar.js");

const { dynamicCard } = require("songcard");

module.exports = {
  name: "nowplaying",
  // Linix also aliases this to "np". PrimeBot already owns `$np` for the
  // developer-only no-prefix administration command (events/messageCreate.js),
  // and its top-level case is matched before the music fallback, so an "np"
  // alias here would be dead code that answers "Access Denied". Use
  // `$nowplaying`, `$music nowplaying` or the slash command instead.
  aliases: [],
  category: "Music",
  description: "Show now playing song",
  args: false,
  usage: "",
  userPrams: [],
  botPrams: ["EmbedLinks"],
  owner: false,
  player: true,
  inVoiceChannel: false,
  sameVoiceChannel: false,
  execute: async (message, args, client, prefix) => {
    const player = client.manager.players.get(message.guild.id);
    const song = player.queue.current;

    if (!player.queue.current) {
      const thing = new client.embed().d(
        `${client.emoji.cross} | No song/s currently playing within this guild.`,
      );

      return message.channel.send({ embeds: [thing] });
    }

    const emojimusic = client.emoji.music;
    const title =
      song.title.length > 25
        ? song.title.slice(0, 25) + "....."
        : song.title + ".....";
    const req = song.requester;
    const auth = player.queue.current.author;
    const total = song.length;
    const current = player.position;
    let playing = "";
    if (
      song.uri.toLowerCase().includes("youtube") ||
      song.uri.toLowerCase().includes("youtu")
    ) {
      playing = "youTube";
    } else if (song.uri.toLowerCase().includes("spotify")) {
      playing = "spotify";
    }

    const buffer = await dynamicCard({
      thumbnailURL: song.thumbnail.replace("hqdefault", "maxresdefault"),
      songTitle: title,
      songArtist: auth,
      streamProvider: playing,
      trackRequester: `@` + req.username,
    });
     
    const cardName = client.cardName || 'primebot-music.png';
    const attachment = new AttachmentBuilder(buffer, { name: cardName });
    const embed = new client.embed().img(`attachment://${cardName}`);
    return message.channel.send({ embeds: [embed], files: [attachment] });
  },
};
