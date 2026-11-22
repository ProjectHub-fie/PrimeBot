const { getMusicConfig } = require("../config");

module.exports = {
  progressbar: function (player) {
    const size = 15;
    const line = "▬";
    // Slider emoji — resolved through the central catalog (custom emoji when
    // validated, otherwise the configured Unicode fallback).
    const configured = getMusicConfig().emoji.dot;
    let slider = configured;
    try {
      const { getEmojiManager } = require("../../utils/emojiManager");
      const manager = getEmojiManager();
      if (manager) slider = manager.emoji("dot", configured);
    } catch (_) { /* keep fallback */ }

    if (!player.queue.current) return `[ ${slider}${line.repeat(size - 1)} ]`;
    const current =
      player.queue.current.length !== 0
        ? player.shoukaku.position
        : player.queue.current.length;
    const total = player.queue.current.length;
    const bar =
      current > total
        ? [line.repeat((size / 2) * 2), (current / total) * 100]
        : [
            line
              .repeat(Math.round((size / 2) * (current / total)))
              .replace(/.$/, slider) +
              line.repeat(size - Math.round(size * (current / total)) + 1),
            current / total,
          ];

    if (!String(bar).includes(slider))
      return `${slider}${line.repeat(size - 1)}`;
    return `${bar[0]}`;
  },
};
