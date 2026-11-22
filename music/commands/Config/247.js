const { EmbedBuilder } = require("discord.js");
const db = require("../../schema/247");

const ACTIONS = new Map([
  ["enable", "enable"], ["start", "enable"], ["on", "enable"],
  ["disable", "disable"], ["stop", "disable"], ["off", "disable"],
  ["status", "status"],
]);

function actionOf(args) {
  const raw = String((args && args[0]) || "").toLowerCase();
  return ACTIONS.get(raw) || "status";
}

function reply(message, title) {
  return message.reply({
    embeds: [new EmbedBuilder()
      .setAuthor({ name: title, iconURL: message.author.displayAvatarURL() })],
  });
}

module.exports = {
  name: "247",
  category: "Config",
  description: "Enable, disable, or check the persistent 24/7 voice connection.",
  args: false,
  usage: "[enable|disable|status]",
  userPrams: [],
  botPrams: ["EMBED_LINKS"],
  owner: false,
  voteonly: false,
  // Stop/status must work even when no player exists, so voice/player checks
  // happen inside `execute` for the enable path only.
  player: false,
  dj: true,
  inVoiceChannel: false,
  sameVoiceChannel: false,
  cooldown: 3,
  execute: async (message, args, client) => {
    const action = actionOf(args);
    const guildId = message.guild.id;

    try {
      if (action === "disable") {
        await db.setEnabled(guildId, false);
        return reply(message, "- 247 Mode is Disabled");
      }

      if (action === "enable") {
        const player = client.manager?.players?.get(guildId);
        if (!player || !player.voiceId) {
          return message.reply("Join a voice channel and play a song first, then run `247 enable`.");
        }
        await db.setEnabled(guildId, true, { textId: player.textId, voiceId: player.voiceId });
        return reply(message, "- 247 Mode is Enabled");
      }

      const state = await db.getState(guildId);
      return reply(message, state.enabled ? "- 247 Mode is Enabled" : "- 247 Mode is Disabled");
    } catch (err) {
      console.error("[247] state update failed:", err.message);
      return message.reply("Could not update 24/7 mode. Please try again.").catch(() => {});
    }
  },
};
