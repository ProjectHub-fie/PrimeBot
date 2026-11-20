/**
 * Linix `schema/preset.js` — per-guild now-playing card preset.
 */

const { createModel } = require('./_pg');

const presetSchema = createModel({
    table: 'music_presets',
    columns: [
        ['id', 'serial PRIMARY KEY'],
        ['guildId', 'varchar(50) NOT NULL'],
        ['presetType', 'integer NOT NULL DEFAULT 0'],
    ],
});

module.exports = presetSchema;
