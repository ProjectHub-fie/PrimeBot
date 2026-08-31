const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, MessageFlags } = require('discord.js');
const { safeReply } = require('./stabilityUtils');
const { appealPool: pool } = require('../server/appealDb');

/**
 * AppealManager — the ban-DM + appeal subsystem.
 *
 * When a member is banned from a server (via automod, /ban, $ban, or any
 * other ban the bot observes), the bot DMs them an "all available fields" ban
 * embed. If the guild's dashboard Automod tab has "Use appeal" enabled, that
 * DM also carries an **Appeal ban** button, which opens a floating Discord form
 * (a modal) where the member explains why the ban should be lifted. Their
 * submission is recorded in the `appeals` table (dedicated APPEAL_DATABASE_URL
 * pool, falling back to DATABASE_URL) and posted to the configured appeal
 * channel (set from the dashboard's Automod tab → "Appeal channel").
 *
 * Per-guild switches (appeal_settings, driven by the dashboard Automod tab):
 *   dm_user            send the rich ban DM on every ban (default on)
 *   use_appeal         attach the Appeal button to that DM (default off)
 *   appeal_channel_id  where submitted appeals are posted
 *   ban_embed_fields    ordered list of embed field keys to include
 *
 * The manager follows the same caching pattern as the other settings
 * managers: in-memory Map cache, write-through to DB, and a reload
 * interval so dashboard saves take effect without a bot restart.

 */

const CREATE_SETTINGS_SQL = `
    CREATE TABLE IF NOT EXISTS appeal_settings (
        guild_id            VARCHAR(50) PRIMARY KEY,
        dm_user             BOOLEAN NOT NULL DEFAULT true,
        use_appeal          BOOLEAN NOT NULL DEFAULT false,
        appeal_channel_id   VARCHAR(50),
        ban_embed_fields     JSONB NOT NULL DEFAULT '["server","user","moderator","action","reason","rule","cid","time"]',
        updated_at          TIMESTAMP DEFAULT NOW()
    )
`;
const ENSURE_COLUMNS_SQL = `
    ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS dm_user           BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS use_appeal        BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS appeal_channel_id varchar(50);
    ALTER TABLE appeal_settings ADD COLUMN IF NOT EXISTS ban_embed_fields   JSONB NOT NULL DEFAULT '["server","user","moderator","action","reason","rule","cid","time"]';
`;
const CREATE_APPEALS_SQL = `
    CREATE TABLE IF NOT EXISTS appeals (
        id         SERIAL PRIMARY KEY,
        guild_id   VARCHAR(50) NOT NULL,
        user_id    VARCHAR(50) NOT NULL,
        action      VARCHAR(50) NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        cid        INTEGER,
        status      VARCHAR(20) NOT NULL DEFAULT 'pending',
        created_at  TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS appeals_guild_idx ON appeals (guild_id);
    CREATE INDEX IF NOT EXISTS appeals_guild_status_idx ON appeals (guild_id, status);
`;

const DEFAULT_BAN_EMBED_FIELDS = ['server', 'user', 'moderator', 'action', 'reason', 'rule', 'cid', 'time'];

class AppealManager {
    constructor(client) {
        this.client = client;
        this._cache = new Map();
        this._tableReady = false;
        this._recentSent = new Map(); // `${guildId}|${userId}` → ts — dedupes the bot-command send + guildBanAdd event pair
        this._init().catch(err =>
            console.error('[APPEAL] Init failed:', err.message)
        );
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    async _ensureTable() {
        if (this._tableReady) return;
        await pool.query(CREATE_SETTINGS_SQL);
        await pool.query(ENSURE_COLUMNS_SQL);
        await pool.query(CREATE_APPEALS_SQL);
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._loadAll();
        this._startReloadInterval();
    }

    _startReloadInterval() {
        const ms = parseInt(process.env.SETTINGS_RELOAD_INTERVAL_MS, 10) || 60000;
        const refreshMs = parseInt(process.env.SETTINGS_REFRESH_INTERVAL_MS, 10) || 15000;
        setInterval(() => {
            this._loadAll().catch(err =>
                console.error('[APPEAL] Background reload failed:', err.message)
            );
        }, ms).unref?.();
        setInterval(() => {
            this._refreshFromDatabase().catch(err =>
                console.error('[APPEAL] Refresh failed:', err.message)
            );
        }, refreshMs).unref?.();
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const res = await pool.query('SELECT * FROM appeal_settings');
        for (const row of res.rows) {
            const next = this._rowToSettings(row);
            const previous = this._cache.get(row.guild_id);
            if (!previous || JSON.stringify(previous) !== JSON.stringify(next)) {
                this._cache.set(row.guild_id, next);
            }
        }
    }

    async _loadAll() {
        try {
            const res = await pool.query('SELECT * FROM appeal_settings');
            for (const row of res.rows) {
                this._cache.set(row.guild_id, this._rowToSettings(row));
            }
        } catch (err) {
            console.error('[APPEAL] Failed to load settings:', err.message);
        }
    }

    _rowToSettings(row) {
        return {
            dmUser: row.dm_user !== false,
            useAppeal: row.use_appeal === true,
            appealChannelId: row.appeal_channel_id || null,
            banEmbedFields: Array.isArray(row.ban_embed_fields) && row.ban_embed_fields.length
                ? row.ban_embed_fields.filter(k => DEFAULT_BAN_EMBED_FIELDS.includes(k))
                : [...DEFAULT_BAN_EMBED_FIELDS],
        };
    }

    _defaults() {
        return {
            dmUser: true,
            useAppeal: false,
            appealChannelId: null,
            banEmbedFields: [...DEFAULT_BAN_EMBED_FIELDS],
        };
    }

    getSettings(guildId) {
        const automod = this.client?.automodManager?.getSettings?.(guildId);
        const base = this._cache.has(guildId) ? this._cache.get(guildId) : this._defaults();
        // The Automod tab's "DM user" / "Use appeal" switches live on automod_settings
        // (they're part of the automod settings row), so we mirror them here as the
        // authority for whether to send the ban DM and whether to attach the Appeal button.

        if (automod) {
            return {
                ...base,
                dmUser: typeof automod.dmUser === 'undefined' ? (base.dmUser !== false) : automod.dmUser !== false,
                useAppeal: typeof automod.useAppeal === 'undefined' ? (base.useAppeal === true) : automod.useAppeal === true,
                appealChannelId: automod.appealChannelId ?? base.appealChannelId ?? null,
                logChannelId: automod.logChannelId ?? base.logChannelId ?? null,
            };
        }
        return base;
    }

    updateSettings(guildId, patch = {}) {
        const next = { ...this.getSettings(guildId) };
        if ('dmUser' in patch)                next.dmUser = patch.dmUser !== false;
        if ('useAppeal' in patch)           next.useAppeal = patch.useAppeal === true;
        if ('appealChannelId' in patch)      next.appealChannelId = patch.appealChannelId || null;
        if ('banEmbedFields' in patch)      next.banEmbedFields = Array.isArray(patch.banEmbedFields)
            ? patch.banEmbedFields.filter(k => DEFAULT_BAN_EMBED_FIELDS.includes(k))
            : [...DEFAULT_BAN_EMBED_FIELDS];
        this._cache.set(guildId, next);
        this._save(guildId);
        return next;
    }

    _save(guildId) {
        this._saveAsync(guildId).catch(err =>
            console.error(`[APPEAL] Save failed for guild ${guildId}:`, err.message)
        );
    }

    async _saveAsync(guildId) {
        const s = this.getSettings(guildId);
        await this._ensureTable();
        await pool.query(`
            INSERT INTO appeal_settings (
                guild_id, dm_user, use_appeal, appeal_channel_id, ban_embed_fields, updated_at
            ) VALUES ($1,$2,$3,$4,$5,NOW())
            ON CONFLICT (guild_id) DO UPDATE SET
                dm_user           = EXCLUDED.dm_user,
                use_appeal        = EXCLUDED.use_appeal,
                appeal_channel_id = EXCLUDED.appeal_channel_id,
                ban_embed_fields   = EXCLUDED.ban_embed_fields,
                updated_at        = NOW()
        `, [
            guildId, s.dmUser, s.useAppeal, s.appealChannelId,
            JSON.stringify(s.banEmbedFields),
        ]);
    }

    // ─── Ban DM ──────────────────────────────────────────────────────────────

    /**
     * DM the banned member with an "all available fields" ban embed. Returns false
     * when DM is off, the user has no usable DM channel, or the DM couldn't
     * be sent (so callers can fall back to the plain automod DM).
     *
     * A short dedupe window (30s, per guild+user) stops double-sends when
     * a bot-command ban path calls us immediately and the guildBanAdd event fires
     * right after — external bans (other bots/humans via the API) still DM once.

     * @param {Object} opts { guild, user, reason, action, rule, moderator, cid }
     * @returns {Promise<boolean>} whether the DM was sent
     */
    async sendBanDm({ guild, user, reason = '', action = 'ban', rule = null, moderator = null, cid = null }) {
        if (!guild || !user) return false;
        const settings = this.getSettings(guild.id);
        if (settings.dmUser === false) return false;

        const key = `${guild.id}|${user.id}`;
        const prev = this._recentSent.get(key);
        if (prev && Date.now() - prev < 30000) return true; // already sent by a sibling path
        this._recentSent.set(key, Date.now());
        if (this._recentSent.size > 500) this._recentSent.clear();

        const defs = {
            server:      { name: 'Server', value: `${guild.name || 'this server'} — \`${guild.id}\``, inline: false },
            user:        { name: 'User', value: `${user.tag || user.username || 'banned user'} (<@${user.id}>)`, inline: false },
            moderator:   { name: 'Responsible moderator', value: this._moderatorLabel(moderator), inline: false },
            action:      { name: 'Action', value: String(action || 'ban'), inline: true },
            reason:      { name: 'Reason', value: String(reason || '—').slice(0, 1024), inline: false },
            rule:        { name: 'Rule', value: String(rule || '—'), inline: true },
            cid:         { name: 'CID', value: cid ? String(cid) : '—', inline: true },
            time:        { name: 'Time', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: false },
        };

        const fields = [];
        for (const k of settings.banEmbedFields) {
            const d = defs[k];
            if (d) fields.push(d);
        }
        if (fields.length === 0) fields.push(defs.server);

        const embed = new EmbedBuilder()
            .setColor(0xED4245)
            .setTitle(`🔨 Banned from ${guild.name || 'this server'}`)
            .addFields(fields)
            .setFooter({ text: 'PrimeBot Ban DM — failed appeal? Click Appeal button.' })
            .setTimestamp();

        const components = [];
        if (settings.useAppeal) {
            const btn = new ButtonBuilder()
                .setCustomId(`appeal:open:v2:${guild.id}:${action || 'ban'}:${cid || ''}`)
                .setLabel('Appeal ban')
                .setEmoji('📨')
                .setStyle(ButtonStyle.Primary);
            components.push(new ActionRowBuilder().addComponents(btn));
        }

        try {
            if (components.length) {
                await user.send({ embeds: [embed], components });
            } else {
                await user.send({ embeds: [embed] });
            }
            return true;
        } catch (err) {
            console.error('[APPEAL] Ban DM failed:', err.message);
            return false;
        }
    }

    _moderatorLabel(moderator) {
        const user = moderator?.author || moderator?.user || moderator || null;
        if (!user) return 'PrimeBot Automod (automatic)';
        return `${user.tag || user.username || 'unknown'}${user.id ? ` (<@${user.id}>)` : ''}`;
    }

    // ─── Appeal modal + submission ───────────────────────────────────────────

    /**
     * Show the floating appeal form (a Discord modal) when a member clicks the
     * "Appeal ban" button in their ban DM. The custom id carries the guild,
     * the action being appealed, and the automod CID (when available).
     */
    async handleAppealButton(interaction, guildId, action = 'ban', cid = null) {
        const modal = new ModalBuilder()
            .setCustomId(`appeal_modal:${guildId}`)
            .setTitle(`Appeal ban — ${interaction.client.guilds?.cache?.get(guildId)?.name || 'server'}`);

        const actionInput = new TextInputBuilder()
            .setCustomId('appeal-action')
            .setLabel('Action being appealed (read-only)')
            .setStyle(TextInputStyle.Short)
            .setValue(String(action || 'ban').slice(0, 50))
            .setRequired(true)
            .setMaxLength(50);
        const cidInput = new TextInputBuilder()
            .setCustomId('appeal-cid')
            .setLabel('Automod embed number (CID, optional)')
            .setStyle(TextInputStyle.Short)
            .setValue(cid ? String(cid) : '')
            .setRequired(false)
            .setMaxLength(20);
        const reasonInput = new TextInputBuilder()
            .setCustomId('appeal-reason')
            .setLabel('Why should this ban be lifted?')
            .setStyle(TextInputStyle.Paragraph)
            .setPlaceholder('Explain what happened and why you believe the ban was a mistake…')
            .setMaxLength(1000)
            .setRequired(true);

        modal.addComponents(
            new ActionRowBuilder().addComponents(actionInput),
            new ActionRowBuilder().addComponents(cidInput),
            new ActionRowBuilder().addComponents(reasonInput)
        );
        try {
            await interaction.showModal(modal);
        } catch (err) {
            const ackCode = err?.code ?? err?.rawError?.code;
            if (ackCode === 40060) return;
            console.error('[APPEAL] Error showing appeal modal:', err.message || err);
            await safeReply(interaction, {
                content: 'There was an error openingthe appeal form. Please try again.',
                flags: MessageFlags.Ephemeral,
            });
        }
    }

    /** Process the appeal-form submission recorded in `appeals` and post it to the appeal channel. */
    async handleAppealSubmit(interaction, guildId) {
        const reason = String(interaction.fields?.getTextInputValue('appeal-reason') || '').trim().slice(0, 1000);
        const action = String(interaction.fields?.getTextInputValue('appeal-action') || 'ban').trim().slice(0, 50);
        const cidRaw = String(interaction.fields?.getTextInputValue('appeal-cid') || '').trim();
        const cid = /^\d+$/.test(cidRaw) ? parseInt(cidRaw, 10) : null;
        if (!reason) {
            return safeReply(interaction, { content: 'A reason is required to file an appeal.', flags: MessageFlags.Ephemeral });
        }

        // Record the appeal in `automod_appeals` (the table the dashboard Appeals
        // box and /appeal list|approve|deny read), so a ban-DM modal submission shows
        // up immediately instead of vanishing into the legacy `appeals` table.
        // Degrade to the legacy table if the automod manager/DB isn't available.
        let appeal = null;
        const am = this.client?.automodManager;
        if (am?.submitAppeal) {
            appeal = await am.submitAppeal({ guildId, userId: interaction.user.id, action, reason }).catch(err => {
                console.error('[APPEAL] Failed to record appeal in automod_appeals:', err.message);
                return null;
            });
        }
        if (!appeal) {
            appeal = await this.createAppeal({ guildId, userId: interaction.user.id, action, reason, cid }).catch(err => {
                console.error('[APPEAL] Failed to record appeal:', err.message);
                return null;
            });
        }

        // Deliver to the server: prefer the explicit appeal channel, fall back to the
        // automod log channel (so an appeal is never lost just because nobody picked
        // an appeal channel selector).
        const settings = this.getSettings(guildId);
        const channelId = settings.appealChannelId || settings.logChannelId || null;
        let delivered = channelId ? null : false;

        if (channelId) {
            const ch = await interaction.client.channels.fetch(channelId).catch(() => null);
            if (ch?.isTextBased?.() && (!ch.type || ch.type !== 1)) { // 1 = DM — don't post appeals to DMs
                const embed = new EmbedBuilder()
                    .setColor(0xFEE75C)
                    .setTitle(`📨 New ban appeal${cid ? ` (CID ${cid})` : ''}`)
                    .addFields(
                        { name: 'Member', value: `<@${interaction.user.id}>`, inline: false },
                        { name: 'Server', value: `${interaction.client.guilds?.cache?.get(guildId)?.name || 'this server'} — \`${guildId}\``, inline: false },
                        { name: 'Action', value: action, inline: true },
                        { name: 'Reason', value: reason, inline: false },
                    )
                    .setFooter({ text: `Appeal #${appeal?.id || '?'}` })
                    .setTimestamp();
                const sent = await ch.send({ embeds: [embed] }).catch(() => null);
                delivered = Boolean(sent);
            }
        }

        await safeReply(interaction, {
            content: delivered
                ? `📨 Your appeal for **${action}** has been submitted and posted to <#${channelId}>. Moderators will review it.`
                : channelId
                    ? `📨 Your appeal for **${action}** has been recorded, but it could not be posted to <#${channelId}>.`
                    : `📨 Your appeal for **${action}** has been recorded. No appeal channel is configured for this server yet.`,
            flags: MessageFlags.Ephemeral,
        });
    }

    async createAppeal({ guildId, userId, action, reason, cid = null }) {
        await this._ensureTable();
        const res = await pool.query(`
            INSERT INTO appeals (guild_id, user_id, action, reason, cid)
            VALUES ($1,$2,$3,$4,$5)
            RETURNING *
        `, [guildId, userId, String(action || 'ban').slice(0, 50), String(reason || '').slice(0, 1000), cid ? parseInt(cid, 10) : null]);
        return res.rows[0] ? {
            id: res.rows[0].id,
            guildId: res.rows[0].guild_id,
            userId: res.rows[0].user_id,
            action: res.rows[0].action,
            reason: res.rows[0].reason,
            cid: res.rows[0].cid || null,
            status: res.rows[0].status,
            createdAt: res.rows[0].created_at,
        } : null;
    }
}

module.exports = { AppealManager, DEFAULT_BAN_EMBED_FIELDS };