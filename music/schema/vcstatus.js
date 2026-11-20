/**
 * Linix `schema/vcstatus.js` — whether the guild mirrors playback into the
 * voice-channel status text.
 */

const { createModel } = require('./_pg');

const VoiceStatus = createModel({
    table: 'music_vcstatus',
    columns: [
        ['id', 'serial PRIMARY KEY'],
        ['guildId', 'varchar(50) NOT NULL'],
    ],
});

module.exports = VoiceStatus;
