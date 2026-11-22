/**
 * Linix `schema/247.js` — 24/7 auto-reconnect sessions.
 *
 * Same fields and the same model surface as the Linix mongoose schema
 * (`Guild`, `TextId`, `VoiceId`). Storage is PrimeBot's Postgres pool via the
 * mongoose-compatible shim in `_pg.js`, so the vendored Linix code is unchanged.
 *
 * State is explicit and guild-isolated: `setEnabled(guildId, true|false)` is
 * idempotent. The old command toggled by presence, which made a second `stop`
 * re-enable the session. Reconnect handlers only ever read rows, so a deleted
 * row is the single authoritative "disabled" signal.
 */

const { createModel, getPool } = require('./_pg');

const autoReconnect = createModel({
    table: 'music_247_sessions',
    columns: [
        ['id', 'serial PRIMARY KEY'],
        ['Guild', 'varchar(50) NOT NULL'],
        ['TextId', 'varchar(50) NOT NULL'],
        ['VoiceId', 'varchar(50) NOT NULL'],
    ],
});

let readyPromise = null;

function ensureReady() {
    if (!readyPromise) {
        readyPromise = (async () => {
            // `findOne` runs the shim's memoized CREATE TABLE step.
            await autoReconnect.findOne({ Guild: '__primebot_ensure__' });
            // Older builds could insert duplicates (the command used find+create).
            await getPool().query(`
                DELETE FROM music_247_sessions a
                 USING music_247_sessions b
                 WHERE a.id > b.id AND a."Guild" = b."Guild";
            `);
            await getPool().query(`
                CREATE UNIQUE INDEX IF NOT EXISTS music_247_sessions_guild_idx
                    ON music_247_sessions ("Guild");
            `);
        })().catch((err) => {
            readyPromise = null;
            throw err;
        });
    }
    return readyPromise;
}

/** True when 24/7 is enabled for this guild. */
autoReconnect.isEnabled = async function isEnabled(guildId) {
    await ensureReady();
    return Boolean(await autoReconnect.findOne({ Guild: String(guildId) }));
};

/**
 * Explicitly enable or disable 24/7 for one guild. Idempotent.
 * @returns {Promise<{enabled:boolean, changed:boolean}>}
 */
autoReconnect.setEnabled = async function setEnabled(guildId, enabled, ids = {}) {
    await ensureReady();
    const guild = String(guildId);
    if (!enabled) {
        const res = await autoReconnect.deleteOne({ Guild: guild });
        return { enabled: false, changed: (res.deletedCount || 0) > 0 };
    }

    const textId = ids.textId ? String(ids.textId) : '';
    const voiceId = ids.voiceId ? String(ids.voiceId) : '';
    const existing = await autoReconnect.findOne({ Guild: guild });
    if (existing) {
        let changed = false;
        if (textId && existing.TextId !== textId) { existing.TextId = textId; changed = true; }
        if (voiceId && existing.VoiceId !== voiceId) { existing.VoiceId = voiceId; changed = true; }
        if (changed) await existing.save();
        return { enabled: true, changed };
    }

    try {
        await autoReconnect.create({ Guild: guild, TextId: textId, VoiceId: voiceId });
    } catch (err) {
        if (String(err.code) === '23505' || /duplicate key/i.test(err.message || '')) {
            await autoReconnect.updateOne({ Guild: guild }, { $set: { TextId: textId, VoiceId: voiceId } });
            return { enabled: true, changed: true };
        }
        throw err;
    }
    return { enabled: true, changed: true };
};

/** Current state, including the stored channel ids when enabled. */
autoReconnect.getState = async function getState(guildId) {
    await ensureReady();
    const row = await autoReconnect.findOne({ Guild: String(guildId) });
    return row
        ? { enabled: true, textId: row.TextId, voiceId: row.VoiceId }
        : { enabled: false, textId: null, voiceId: null };
};

autoReconnect.ensureReady = ensureReady;

module.exports = autoReconnect;
