/**
 * Linix loads its emoji map from `utils/emoji.json` and assigns it to
 * `client.emoji` (`src/structures/MusicClient.js`). The JSON is kept verbatim;
 * this module is the CommonJS entry point the bridge requires.
 */

module.exports = require('./emoji.json');
