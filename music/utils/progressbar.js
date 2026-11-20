const { getMusicConfig } = require("../config");

module.exports = {
  progressbar: function (player) {
    const size = 15;
    const line = "▬";
    // Env-driven slider emoji — Linix hardcoded a custom emoji from its own
    // emoji server (`<:dot:1201841280577970176>`); defaults to Unicode here.
    const slider = getMusicConfig().emoji.dot;

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
