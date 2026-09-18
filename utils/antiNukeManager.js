/**
 * AntiNukeManager — per-guild Anti-Nuke configuration storage + cache.
 *
 * Follows the same pattern as the other settings managers: an in-memory Map
 * keyed by guild, write-through to Postgres via the dedicated
 * ANUKE_DATABASE_URL pool (server/anukeDb.js; falls back to
 * FALLBACK_DATABASE_URL then DATABASE_URL), and an AdaptivePoller that re-reads
 * the table so dashboard saves take effect without a bot restart.
 *
 * ── Status ──────────────────────────────────────────────────────────────────
 * The dashboard tab is `upcoming: true`, so this is configuration-only for now:
 * the manager stores and validates settings, and the detection executor is
 * intentionally not attached to Discord audit-log events until the feature ships.
 * That keeps the "Coming Soon" promise honest — nothing silently moderates.
 */

const { anukePool: pool } = require('../server/anukeDb');
const { AdaptivePoller } = require('./adaptivePoller');
const {
    normalizeAntiNukeSettings, defaultAntiNukeSettings,
} = require('./antiNukeRules');

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS antinuke_settings (
        guild_id           VARCHAR(50) PRIMARY KEY,
        enabled            BOOLEAN NOT NULL DEFAULT false,
        alert_channel_id   VARCHAR(50),
        responses          JSONB NOT NULL DEFAULT '[]',
        trusted_user_ids   JSONB NOT NULL DEFAULT '[]',
        trusted_role_ids   JSONB NOT NULL DEFAULT '[]',
        watched            JSONB NOT NULL DEFAULT '{}',
        dry_run            BOOLEAN NOT NULL DEFAULT true,
        updated_at         TIMESTAMP DEFAULT NOW()
    )
`;

class AntiNukeManager {
    constructor(client) {
        this.client = client;
        this._cache = new Map();
        this._tableReady = false;
        this._reloadTimer = null;
        this._init().catch(err =>
            console.error('[ANTINUKE] Init failed:', err.message)
        );
    }

    async _ensureTable() {
        // Run the idempotent DDL directly (not the pool's swallow-errors helper)
        // so a genuine failure propagates and `_tableReady` stays false to retry.
        if (this._tableReady) return;
        await pool.query(CREATE_TABLE_SQL);
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._loadAll();
        this._startReloadInterval();
    }

    _startReloadInterval() {
        if (this._reloadTimer) return;
        this._reloadTimer = new AdaptivePoller({
            name: 'ANTINUKE',
            task: () => this._refreshFromDatabase(),
        });
        this._reloadTimer.start();
    }

    async _loadAll() {
        try {
            const res = await pool.query('SELECT * FROM antinuke_settings');
            for (const row of res.rows) this._cache.set(row.guild_id, rowToSettings(row));
            console.log(`[ANTINUKE] Loaded settings for ${this._cache.size} servers.`);
        } catch (err) {
            console.error('[ANTINUKE] Failed to load settings:', err.message);
        }
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const res = await pool.query('SELECT * FROM antinuke_settings');
        let changed = false;
        for (const row of res.rows) {
            const next = rowToSettings(row);
            const prev = this._cache.get(row.guild_id);
            if (!prev || JSON.stringify(prev) !== JSON.stringify(next)) {
                this._cache.set(row.guild_id, next);
                changed = true;
            }
        }
        return changed;
    }

    getSettings(guildId) {
        if (!this._cache.has(guildId)) this._cache.set(guildId, defaultAntiNukeSettings());
        return this._cache.get(guildId);
    }

    async _saveAsync(guildId) {
        const s = this.getSettings(guildId);
        await this._ensureTable();
        await pool.query(`
            INSERT INTO antinuke_settings (
                guild_id, enabled, alert_channel_id, responses,
                trusted_user_ids, trusted_role_ids, watched, dry_run, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                enabled          = EXCLUDED.enabled,
                alert_channel_id = EXCLUDED.alert_channel_id,
                responses        = EXCLUDED.responses,
                trusted_user_ids = EXCLUDED.trusted_user_ids,
                trusted_role_ids = EXCLUDED.trusted_role_ids,
                watched          = EXCLUDED.watched,
                dry_run          = EXCLUDED.dry_run,
                updated_at       = NOW()
        `, [
            guildId, s.enabled, s.alertChannelId,
            JSON.stringify(s.responses), JSON.stringify(s.trustedUserIds),
            JSON.stringify(s.trustedRoleIds), JSON.stringify(s.watched),
            s.dryRun !== false,
        ]);
    }

    updateSettings(guildId, patch = {}) {
        const current = this.getSettings(guildId);
        const next = normalizeAntiNukeSettings({ ...current, ...patch });
        this._cache.set(guildId, next);
        this._saveAsync(guildId).catch(err =>
            console.error(`[ANTINUKE] Save failed for guild ${guildId}:`, err.message)
        );
        return next;
    }
}

function rowToSettings(row) {
    return normalizeAntiNukeSettings({
        enabled: row.enabled,
        alertChannelId: row.alert_channel_id || null,
        responses: row.responses,
        trustedUserIds: row.trusted_user_ids,
        trustedRoleIds: row.trusted_role_ids,
        watched: row.watched,
        dryRun: row.dry_run !== false,
        updatedAt: row.updated_at || null,
    });
}

module.exports = AntiNukeManager;
module.exports.AntiNukeManager = AntiNukeManager;
module.exports.rowToSettings = rowToSettings;