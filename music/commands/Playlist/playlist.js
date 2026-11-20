/** @format */

const { StringSelectMenuBuilder, ActionRowBuilder } = require("discord.js");
const { getMusicConfig } = require("../../config");

module.exports = {
  name: "playlist",
  aliases: ["pl"],
  category: "Playlist",
  cooldown: 3,
  description: "Play the saved Playlist.",
  args: false,
  usage: "playlist name",
  userPrams: [],
  botPrams: ["EMBED_LINKS"],
  voteOnly: true,
  owner: false,
  player: false,
  inVoiceChannel: true,
  sameVoiceChannel: true,
  execute: async (message, args, client, prefix) => {
    const menu = client.playlistMenu || getMusicConfig().playlistMenu;

    const shuffleArray = (array) => {
      for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
      }
      return array;
    };

    if (!menu.enabled || !menu.entries.length) {
      return message.reply({
        embeds: [
          new client.embed()
            .setColor(client.embedColor)
            .setDescription(
              "No quick playlists are configured. Ask the bot owner to set `MUSIC_PLAYLISTS` (JSON) or `MUSIC_PLAYLIST_URL` in the environment.",
            ),
        ],
      });
    }

    const embed = new client.embed().setColor(client.color).setAuthor({
      name: menu.label,
      iconURL: client.getPlaylistAvatar(message.author),
      url: client.config.links.vote,
    });

    const row = new ActionRowBuilder().addComponents(
      new StringSelectMenuBuilder()
        .setCustomId("help_pop")
        .setPlaceholder("Choose a playlist!")
        .addOptions(
          menu.entries.map((entry) => ({ label: entry.label, value: entry.id })),
        ),
    );

    let player = client.manager.players.get(message.guild.id);
    if (!player) {
      player = await client.manager.createPlayer({
        guildId: message.guild.id,
        voiceId: message.member.voice.channel.id,
        textId: message.channel.id,
        deaf: true,
      });
    }

    const msg = await message.channel.send({
      embeds: [embed],
      components: [row],
    });

    const collector = msg.createMessageComponentCollector({
      filter: (i) => {
        if (message.author.id === i.user.id) return true;
        else {
          i.reply({
            content: `${client.emoji.cross} | That's not your session. Run \`${prefix}playlist\` to create your own.`,
            ephemeral: true,
          });
          return false;
        }
      },
      time: 60000,
    });

    const menuEntries = menu.entries;

    const responseAuthor = (label) =>
      new client.embed().setColor(client.color).setAuthor({
        name: label,
        iconURL: message.author.displayAvatarURL(),
        url: client.config.links.support,
      });

    collector.on("collect", async (i) => {
      if (i.isStringSelectMenu()) {
        const selected = i.values[0];
        const entry = menuEntries.find((e) => e.id === selected);
        if (!entry) {
          return i.update({
            embeds: [
              new client.embed()
                .setColor(client.embedColor)
                .setDescription(`No playlist matched \`${selected}\`.`),
            ],
            components: [],
          });
        }

        const query = entry.query;
        const responseEmbed = responseAuthor(`Added ${entry.label}!`);

        const result = await player.search(query, {
          requester: message.author,
        });

        if (!result.tracks.length) {
          return message.reply({
            embeds: [
              new client.embed()
                .setAuthor({
                  name: message.author.username || "Unknown User",
                  iconURL: message.author.displayAvatarURL({ dynamic: true }),
                })

                .d(`No results found for \`${query}\`.`),
            ],
          });
        }

        const tracks = result.tracks;
        if (result.type === "PLAYLIST") {
          shuffleArray(tracks);
          for (const track of tracks) player.queue.add(track);
        } else {
          player.queue.add(tracks[0]);
        }

        if (!player.playing && !player.paused) player.play();
        await player.setLoop("queue");

        return i.update({ embeds: [responseEmbed], components: [] });
      }
    });
  },
};
