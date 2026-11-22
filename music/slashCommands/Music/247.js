const { EmbedBuilder } = require("discord.js");
const db = require("../../schema/247");

const ACTIONS = new Map([
  ["enable", "enable"], ["start", "enable"], ["on", "enable"],
  ["disable", "disable"], ["stop", "disable"], ["off", "disable"],
  ["status", "status"],
]);

function actionOf(value) {
  return ACTIONS.get(String(value || "").toLowerCase()) || "status";
}

function reply(interaction, title) {
  return interaction.editReply({
    embeds: [new EmbedBuilder()
      .setAuthor({ name: `| ${title}`, iconURL: interaction.member.displayAvatarURL() })],
  });
}

module.exports = {
  name: "247",
  description: "Enable, disable, or check the persistent 24/7 voice connection.",
  options: [{
    type: 3,
    name: "action",
    description: "enable/start, disable/stop, or status",
    required: false,
    choices: [
      { name: "enable", value: "enable" },
      { name: "start", value: "start" },
      { name: "disable", value: "disable" },
      { name: "stop", value: "stop" },
      { name: "status", value: "status" },
    ],
  }],
  userPrams: [],
  botPrams: ["EMBED_LINKS"],
  // Stop/status must work with no active player; enable validates inside.
  player: false,
  dj: true,
  inVoiceChannel: false,
  sameVoiceChannel: false,

  run: async (client, interaction) => {
    await interaction.deferReply({ ephemeral: false });
    const action = actionOf(interaction.options.getString("action"));
    const guildId = interaction.guild.id;

    try {
      if (action === "disable") {
        await db.setEnabled(guildId, false);
        return reply(interaction, "247 Mode is Disabled");
      }

      if (action === "enable") {
        const player = client.manager?.players?.get(guildId);
        if (!player || !player.voiceId) {
          return interaction.editReply("Join a voice channel and play a song first, then run `/247 action:enable`.");
        }
        await db.setEnabled(guildId, true, { textId: player.textId, voiceId: player.voiceId });
        return reply(interaction, "247 Mode is Enabled");
      }

      const state = await db.getState(guildId);
      return reply(interaction, state.enabled ? "247 Mode is Enabled" : "247 Mode is Disabled");
    } catch (err) {
      console.error("[247] state update failed:", err.message);
      return interaction.editReply("Could not update 24/7 mode. Please try again.").catch(() => {});
    }
  },
};
