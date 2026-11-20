/**
 * Linix `schema/247.js` — 24/7 auto-reconnect sessions.
 *
 * Same fields and the same model surface as the Linix mongoose schema
 * (`Guild`, `TextId`, `VoiceId`). Storage is PrimeBot's Postgres pool via the
 * mongoose-compatible shim in `_pg.js`, so the vendored Linix code is unchanged.
 */

const { createModel } = require('./_pg');

const autoReconnect = createModel({
    table: 'music_247_sessions',
    columns: [
        ['id', 'serial PRIMARY KEY'],
        ['Guild', 'varchar(50) NOT NULL'],
        ['TextId', 'varchar(50) NOT NULL'],
        ['VoiceId', 'varchar(50) NOT NULL'],
    ],
});

module.exports = autoReconnect;
