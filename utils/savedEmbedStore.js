/**
 * Read-only access to the dashboard's saved embeds (EMBED_DATABASE_URL).
 *
 * The Embed Builder lives on the dashboard and owns the `saved_embeds` table
 * (see dashboard/db.js, which writes through `server/embedDb.js`). The bot only
 * READS those rows so `$embed` / `/embed` can post a saved embed into a
 * channel. Both sides resolve the same dedicated pool, so a single
 * EMBED_DATABASE_URL (or the DATABASE_URL fallback) makes it work end-to-end.
 *
 * The table is self-created here too (mirroring the dashboard) so the commands
 * degrade to "no saved embeds" instead of throwing when the dashboard has never
 * run against a fresh database.
 */

const { embedPool } = require('../server/embedDb');

// A misconfigured/unreachable EMBED_DATABASE_URL must never make a chat command
// (or the bot's boot) hang — every lookup is bounded, and a failed boot-time
// check is simply retried on the next command.
const DB_TIMEOUT_MS = 4000;

let tableReady = false;
let tableCheck = null;

function withTimeout(promise, ms) {
    return Promise.race([
        promise,
        new Promise((_, reject) => setTimeout(() => {
            const err = new Error('Embed database timed out');
            err.code = 'EMBED_DB_TIMEOUT';
            reject(err);
        }, ms).unref?.()),
    ]);
}

async function ensureTable() {
    if (tableReady) return;
    // Runs once per process; concurrent first callers share the same attempt so
    // commands don't have to wait for each other.
    if (!tableCheck) {
        tableCheck = (async () => {
            await withTimeout(embedPool.query(`
                CREATE TABLE IF NOT EXISTS saved_embeds (
                    id SERIAL PRIMARY KEY,
                    guild_id VARCHAR(50) NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by VARCHAR(50),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            `), DB_TIMEOUT_MS);
            await withTimeout(embedPool.query(
                'CREATE INDEX IF NOT EXISTS saved_embeds_guild_uniq ON saved_embeds (guild_id, lower(name))'
            ).catch(() => {}), DB_TIMEOUT_MS);
            tableReady = true;
        })().catch((err) => {
            tableCheck = null; // allow a retry on the next attempt
            throw err;
        });
    }
    return tableCheck;
}

function rowToItem(row) {
    let payload = {};
    if (row.payload && typeof row.payload === 'object') payload = row.payload;
    else if (row.payload) {
        try { payload = JSON.parse(row.payload); } catch { payload = {}; }
    }
    return {
        id: Number(row.id),
        guildId: String(row.guild_id),
        name: row.name,
        payload,
    };
}

/** Every saved embed in the guild, ordered by name. */
async function listSavedEmbeds(guildId) {
    await ensureTable();
    const res = await withTimeout(embedPool.query(
        'SELECT id, guild_id, name, payload FROM saved_embeds WHERE guild_id = $1 ORDER BY lower(name) ASC',
        [String(guildId)]
    ), DB_TIMEOUT_MS);
    return (res.rows || []).map(rowToItem);
}

/**
 * Find a saved embed by name (case-insensitive), by numeric id, or by id
 * passed as a string. Returns null when nothing matches.
 */
async function findSavedEmbed(guildId, query) {
    const items = await listSavedEmbeds(guildId);
    const raw = String(query == null ? '' : query).trim();
    if (!raw) return null;

    const byName = items.find((e) => e.name.toLowerCase() === raw.toLowerCase());
    if (byName) return byName;

    if (/^\d+$/.test(raw)) {
        const id = Number(raw);
        return items.find((e) => e.id === id) || null;
    }
    return null;
}

/** Names for slash-command autocomplete. */
async function savedEmbedNames(guildId, prefixQuery = '') {
    try {
        const items = await listSavedEmbeds(guildId);
        const q = String(prefixQuery || '').toLowerCase();
        return items
            .filter((e) => !q || e.name.toLowerCase().includes(q))
            .slice(0, 25)
            .map((e) => ({ name: e.name.slice(0, 100), value: String(e.id) }));
    } catch {
        return [];
    }
}

module.exports = {
    listSavedEmbeds,
    findSavedEmbed,
    savedEmbedNames,
};