const { logPool } = require('../server/logDb');
const { DEFAULT_ENABLED_EVENTS, normalizeEvents } = require('./logEvents');

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS logging_settings (
        guild_id              VARCHAR(50) PRIMARY KEY,
        enabled               BOOLEAN NOT NULL DEFAULT false,
        channel_id            VARCHAR(50),
        webhook_url           TEXT,
        webhook_name          VARCHAR(100) DEFAULT 'PrimeBot Logs',
        events                JSONB NOT NULL DEFAULT '[]',
        include_bots          BOOLEAN NOT NULL DEFAULT false,
        color                 VARCHAR(20) DEFAULT '#5865F2',
        updated_at            TIMESTAMP DEFAULT NOW()
    )
`;

const ENSURE_COLUMNS_SQL = `
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS webhook_name  VARCHAR(100) DEFAULT 'PrimeBot Logs';
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS events        JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS include_bots  BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE logging_settings ADD COLUMN IF NOT EXISTS color         VARCHAR(20) DEFAULT '#5865F2';
`;

/**
 * Per-guild logging configuration — backed by PostgreSQL.
 *
 * Mirrors the pattern used by WelcomeSettingsManager: an in-memory Map acts as
 * a read-through cache and writes go straight to DB (fire-and-forget). Because
 * the dashboard is a separate process that writes the same table directly, the
 * cache is re-read on a ~30s interval (SETTINGS_RELOAD_INTERVAL_MS) and again
 * every 5s so dashboard saves take effect without a bot restart.
 */
class LoggingSettingsManager {
    constructor() {
        this._cache = new Map();
        this._tableReady = false;
        this._refreshTimer = null;
        this._init().catch(err =>
            console.error('[LOGGING SETTINGS] Init failed:', err.message)
        );
    }

    async _ensureTable() {
        if (this._tableReady) return;
        await logPool.query(CREATE_TABLE_SQL);
        await logPool.query(ENSURE_COLUMNS_SQL);
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._loadAll();
        this._startReloadInterval();
    }

    /** Re-read the table periodically so dashboard saves reach the bot. */
    _startReloadInterval() {
        const ms = parseInt(process.env.SETTINGS_RELOAD_INTERVAL_MS, 10) || 60000;
        const refreshMs = parseInt(process.env.SETTINGS_REFRESH_INTERVAL_MS, 10) || 15000;
        this._reloadTimer = setInterval(() => {
            this._loadAll().catch(err =>
                console.error('[LOGGING SETTINGS] Background reload failed:', err.message)
            );
        }, ms);
        this._reloadTimer.unref?.();
        this._startRefreshLoop();
    }

    _startRefreshLoop() {
        if (this._refreshTimer) return;
        this._refreshTimer = setInterval(() => {
            this._refreshFromDatabase().catch(err =>
                console.error('[LOGGING SETTINGS] Refresh failed:', err.message)
            );
        }, refreshMs);
        this._refreshTimer.unref?.();
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const res = await logPool.query('SELECT * FROM logging_settings');
        for (const row of res.rows) {
            const next = this._rowToSettings(row);
            const previous = this._cache.get(row.guild_id);
            if (!previous || JSON.stringify(previous) !== JSON.stringify(next)) {
                this._cache.set(row.guild_id, next);
                if (previous) {
                    console.log(`[LOGGING SETTINGS] Applied database update for guild ${row.guild_id}.`);
                }
            }
        }
    }

    async _loadAll() {
        try {
            const res = await logPool.query('SELECT * FROM logging_settings');
            for (const row of res.rows) {
                this._cache.set(row.guild_id, this._rowToSettings(row));
            }
            console.log(`[LOGGING SETTINGS] Loaded settings for ${this._cache.size} servers.`);
        } catch (err) {
            console.error('[LOGGING SETTINGS] Failed to load settings:', err.message);
        }
    }

    _rowToSettings(row) {
        return {
            enabled: row.enabled,
            channelId: row.channel_id || null,
            webhookUrl: row.webhook_url || null,
            webhookName: row.webhook_name || 'PrimeBot Logs',
            events: normalizeEvents(row.events),
            includeBots: row.include_bots,
            color: row.color || '#5865F2',
        };
    }

    _defaults() {
        return {
            enabled: false,
            channelId: null,
            webhookUrl: null,
            webhookName: 'PrimeBot Logs',
            events: [...DEFAULT_ENABLED_EVENTS],
            includeBots: false,
            color: '#5865F2',
        };
    }

    getSettings(guildId) {
        if (!this._cache.has(guildId)) {
            this._cache.set(guildId, this._defaults());
        }
        return this._cache.get(guildId);
    }

    isEnabled(guildId) {
        return this.getSettings(guildId).enabled;
    }

    _save(guildId) {
        this._saveAsync(guildId).catch(err =>
            console.error(`[LOGGING SETTINGS] Save failed for guild ${guildId}:`, err.message)
        );
    }

    async _saveAsync(guildId) {
        const s = this.getSettings(guildId);
        await this._ensureTable();
        await logPool.query(`
            INSERT INTO logging_settings (
                guild_id, enabled, channel_id, webhook_url, webhook_name,
                events, include_bots, color, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                enabled      = EXCLUDED.enabled,
                channel_id   = EXCLUDED.channel_id,
                webhook_url  = EXCLUDED.webhook_url,
                webhook_name = EXCLUDED.webhook_name,
                events       = EXCLUDED.events,
                include_bots = EXCLUDED.include_bots,
                color        = EXCLUDED.color,
                updated_at   = NOW()
        `, [
            guildId,
            s.enabled, s.channelId, s.webhookUrl, s.webhookName,
            JSON.stringify(s.events), s.includeBots, s.color,
        ]);
    }

    _update(guildId, patch) {
        const s = this.getSettings(guildId);
        Object.assign(s, patch);
        this._cache.set(guildId, s);
        this._save(guildId);
    }

    /** Bulk replace settings from the dashboard. Accepts a patch object. */
    updateSettings(guildId, patch = {}) {
        const next = { ...this.getSettings(guildId) };
        if ('enabled' in patch)      next.enabled = Boolean(patch.enabled);
        if ('channelId' in patch)    next.channelId = patch.channelId || null;
        if ('webhookUrl' in patch)   next.webhookUrl = patch.webhookUrl || null;
        if ('webhookName' in patch)  next.webhookName = (patch.webhookName || 'PrimeBot Logs').slice(0, 100);
        if ('events' in patch)       next.events = normalizeEvents(patch.events);
        if ('includeBots' in patch)  next.includeBots = Boolean(patch.includeBots);
        if ('color' in patch)        next.color = patch.color || '#5865F2';
        this._cache.set(guildId, next);
        this._save(guildId);
        return next;
    }
}

module.exports = LoggingSettingsManager;
