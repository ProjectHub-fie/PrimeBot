const {
    EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder,
    ChannelType, PermissionFlagsBits,
    ModalBuilder, TextInputBuilder, TextInputStyle,
} = require('discord.js');
const { ticketPool } = require('../server/ticketDb');

/**
 * Premium ticket panels — configurable ONLY from the dashboard.
 *
 * A "panel" is a message (embed or plain text) the bot posts to a channel,
 * carrying an "Open Ticket" button. When a member clicks it the bot opens a
 * ticket *instance* (a private channel or thread) and posts a control message
 * holding the Close / Reopen / Claim buttons.
 *
 * Backed by PostgreSQL (TICKET_DATABASE_URL, falling back to DATABASE_URL) in
 * the `ticket_panels` + `ticket_instances` tables. Mirrors the caching pattern
 * of ReactionRoleManager / AutomodManager: in-memory cache, write-through to
 * DB, and a setInterval re-read (~30s + 5s) so dashboard saves take effect
 * without a bot restart.
 *
 * Commands are intentionally disabled from creating/configuring panels — the
 * only way to build a panel is the dashboard's 🎫 Tickets tab. The slash/prefix
 * ticket commands reply with a fixed notice (see commands/ticket.js etc.).
 */

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS ticket_panels (
        id              SERIAL PRIMARY KEY,
        guild_id        VARCHAR(50) NOT NULL,
        name            VARCHAR(100) NOT NULL DEFAULT 'Support Ticket',
        channel_id      VARCHAR(50),
        message_id      VARCHAR(50),
        message_type    VARCHAR(20) NOT NULL DEFAULT 'embed',
        title           VARCHAR(255),
        description     TEXT,
        color           VARCHAR(20) DEFAULT '#5865F2',
        thumbnail_url   TEXT,
        image_url       TEXT,
        footer_text     VARCHAR(255),
        content         TEXT,
        button_label    VARCHAR(80) NOT NULL DEFAULT 'Open Ticket',
        button_style    VARCHAR(20) NOT NULL DEFAULT 'Primary',
        button_emoji    VARCHAR(100),
        category        VARCHAR(50) DEFAULT 'general',
        ticket_name     VARCHAR(100),
        support_role_ids    JSONB NOT NULL DEFAULT '[]',
        ping_role_ids       JSONB NOT NULL DEFAULT '[]',
        ticket_category_id  VARCHAR(50),
        cooldown_seconds        INTEGER NOT NULL DEFAULT 0,
        max_open_per_user      INTEGER NOT NULL DEFAULT 1,
        ask_reason             BOOLEAN NOT NULL DEFAULT false,
        reason_placeholder     VARCHAR(255),
        welcome_message        TEXT,
        close_button_label     VARCHAR(80) DEFAULT 'Close Ticket',
        close_button_emoji     VARCHAR(100),
        claim_button_label     VARCHAR(80),
        claim_button_emoji     VARCHAR(100),
        enabled             BOOLEAN NOT NULL DEFAULT true,
        created_by          VARCHAR(50),
        created_at          TIMESTAMP DEFAULT NOW(),
        updated_at          TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ticket_panels_guild_idx ON ticket_panels (guild_id);
    CREATE UNIQUE INDEX IF NOT EXISTS ticket_panels_guild_name_idx ON ticket_panels (guild_id, name);
    CREATE TABLE IF NOT EXISTS ticket_instances (
        id                  SERIAL PRIMARY KEY,
        panel_id            INTEGER REFERENCES ticket_panels(id) ON DELETE SET NULL,
        guild_id            VARCHAR(50) NOT NULL,
        channel_id          VARCHAR(50) NOT NULL,
        user_id             VARCHAR(50) NOT NULL,
        category            VARCHAR(50) DEFAULT 'general',
        is_thread           BOOLEAN NOT NULL DEFAULT false,
        parent_channel_id   VARCHAR(50),
        control_message_id  VARCHAR(50),
        reason              TEXT,
        status              VARCHAR(20) NOT NULL DEFAULT 'open',
        claimed_by          VARCHAR(50),
        created_at          BIGINT NOT NULL,
        closed_at           BIGINT,
        closed_by           VARCHAR(50),
        reopened_at         BIGINT,
        reopened_by         VARCHAR(50)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ticket_instances_channel_idx ON ticket_instances (channel_id);
    CREATE INDEX IF NOT EXISTS ticket_instances_guild_idx ON ticket_instances (guild_id);
    CREATE INDEX IF NOT EXISTS ticket_instances_panel_idx ON ticket_instances (panel_id);
    CREATE INDEX IF NOT EXISTS ticket_instances_guild_user_idx ON ticket_instances (guild_id, user_id);
`;

const VALID_BUTTON_STYLES = new Set(['Primary', 'Secondary', 'Success', 'Danger']);
const VALID_MESSAGE_TYPES = new Set(['embed', 'plain']);

// Placeholders available in ticket channel name templates.
//   {name}     → panel.ticketName (or the opener's username if unset)
//   {username} → opener's username
//   {id}       → opener's user id
//   {panel}    → panel.name
const NAME_PLACEHOLDERS = ['{name}', '{username}', '{id}', '{panel}'];

const DEFAULT_PANEL = {
    name: 'Support Ticket',
    messageType: 'embed',
    title: '🎫 Support Tickets',
    description: 'Click the button below to open a support ticket.',
    color: '#5865F2',
    content: '',
    buttonLabel: 'Open Ticket',
    buttonStyle: 'Primary',
    buttonEmoji: '🎫',
    category: 'general',
    supportRoleIds: [],
    pingRoleIds: [],
    cooldownSeconds: 0,
    maxOpenPerUser: 1,
    askReason: false,
    reasonPlaceholder: 'Briefly describe your issue',
    welcomeMessage: 'Welcome to your support ticket! Please describe your issue and our staff will assist you shortly.',
    closeButtonLabel: 'Close Ticket',
    closeButtonEmoji: '🔒',
    claimButtonLabel: '',
    claimButtonEmoji: '',
    // Status-based channel name templates. Empty/null → no rename for that state.
    openNameTemplate: '(open) {name}',
    claimedNameTemplate: '(solved) {name}',
    closedNameTemplate: '(closed) {name}',
    enabled: true,
};

class TicketPanelManager {
    constructor(client) {
        this.client = client;
        this._byPanel = new Map();     // panelId -> panel
        this._byMessage = new Map();   // `${guildId}:${channelId}:${messageId}` -> panel
        this._byGuild = new Map();    // guildId -> Set<panelId>
        this._byChannel = new Map();  // channelId -> ticket instance (open tickets)
        this._tableReady = false;
        this._init().catch(err =>
            console.error('[TICKETS] Init failed:', err.message)
        );
    }

    async _ensureTable() {
        if (this._tableReady) return;
        await ticketPool.query(CREATE_TABLE_SQL);
        // Add columns that may have been introduced after the initial ship.
        const adds = [
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS message_type        VARCHAR(20) NOT NULL DEFAULT 'embed'`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS thumbnail_url       TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS image_url           TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS footer_text         VARCHAR(255)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS content             TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS button_emoji        VARCHAR(100)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ticket_name        VARCHAR(100)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ping_role_ids      JSONB NOT NULL DEFAULT '[]'`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ticket_category_id VARCHAR(50)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS cooldown_seconds   INTEGER NOT NULL DEFAULT 0`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS max_open_per_user  INTEGER NOT NULL DEFAULT 1`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS ask_reason         BOOLEAN NOT NULL DEFAULT false`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS reason_placeholder VARCHAR(255)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS welcome_message    TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_button_label VARCHAR(80) DEFAULT 'Close Ticket'`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_button_emoji VARCHAR(100)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_label VARCHAR(80)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_emoji VARCHAR(100)`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS panel_id     INTEGER REFERENCES ticket_panels(id) ON DELETE SET NULL`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS reason       TEXT`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS status       VARCHAR(20) NOT NULL DEFAULT 'open'`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claimed_by   VARCHAR(50)`,
        ];
        for (const sql of adds) {
            await ticketPool.query(sql).catch(() => {});
        }
        this._tableReady = true;
    }

    async _init() {
        await this._ensureTable();
        await this._loadAll();
        this._startReloadInterval();
    }

    _startReloadInterval() {
        const ms = parseInt(process.env.SETTINGS_RELOAD_INTERVAL_MS, 10) || 30000;
        this._reloadTimer = setInterval(() => {
            this._loadAll().catch(err =>
                console.error('[TICKETS] Background reload failed:', err.message)
            );
        }, ms);
        this._reloadTimer.unref?.();
        this._startRefreshLoop();
    }

    _startRefreshLoop() {
        if (this._refreshTimer) return;
        this._refreshTimer = setInterval(() => {
            this._refreshFromDatabase().catch(err =>
                console.error('[TICKETS] Refresh failed:', err.message)
            );
        }, 5000);
        this._refreshTimer.unref?.();
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const panels = await this._fetchAllPanels();
        for (const panel of panels) {
            const key = this._msgKey(panel.guildId, panel.channelId, panel.messageId);
            const previous = this._byMessage.get(key);
            if (!previous || JSON.stringify(previous) !== JSON.stringify(panel)) {
                this._indexPanel(panel);
            }
        }
        const liveIds = new Set(panels.map(p => String(p.id)));
        for (const [id, panel] of this._byPanel) {
            if (!liveIds.has(id)) this._unindexPanel(panel);
        }
        await this._loadInstances();
    }

    async _loadAll() {
        try {
            const panels = await this._fetchAllPanels();
            this._byPanel.clear();
            this._byMessage.clear();
            this._byGuild.clear();
            for (const panel of panels) this._indexPanel(panel);
            await this._loadInstances();
            console.log(`[TICKETS] Loaded ${panels.length} ticket panels.`);
        } catch (err) {
            console.error('[TICKETS] Failed to load panels:', err.message);
        }
    }

    async _loadInstances() {
        try {
            const res = await ticketPool.query(
                `SELECT * FROM ticket_instances WHERE status = 'open' ORDER BY created_at`
            );
            this._byChannel.clear();
            for (const row of res.rows) {
                this._byChannel.set(row.channel_id, this._rowToInstance(row));
            }
        } catch (err) {
            console.error('[TICKETS] Failed to load instances:', err.message);
        }
    }

    async _fetchAllPanels() {
        const res = await ticketPool.query('SELECT * FROM ticket_panels ORDER BY id');
        return res.rows.map(r => this._rowToPanel(r));
    }

    _msgKey(guildId, channelId, messageId) {
        return `${guildId}:${channelId}:${messageId}`;
    }

    _indexPanel(panel) {
        this._byPanel.set(String(panel.id), panel);
        if (panel.channelId && panel.messageId) {
            this._byMessage.set(this._msgKey(panel.guildId, panel.channelId, panel.messageId), panel);
        }
        if (!this._byGuild.has(panel.guildId)) this._byGuild.set(panel.guildId, new Set());
        this._byGuild.get(panel.guildId).add(String(panel.id));
    }

    _unindexPanel(panel) {
        this._byPanel.delete(String(panel.id));
        if (panel.channelId && panel.messageId) {
            this._byMessage.delete(this._msgKey(panel.guildId, panel.channelId, panel.messageId));
        }
        const set = this._byGuild.get(panel.guildId);
        if (set) set.delete(String(panel.id));
    }

    _rowToPanel(row) {
        return {
            id: row.id,
            guildId: row.guild_id,
            name: row.name || 'Support Ticket',
            channelId: row.channel_id || null,
            messageId: row.message_id || null,
            messageType: row.message_type || 'embed',
            title: row.title || null,
            description: row.description || null,
            color: row.color || '#5865F2',
            thumbnailUrl: row.thumbnail_url || null,
            imageUrl: row.image_url || null,
            footerText: row.footer_text || null,
            content: row.content || null,
            buttonLabel: row.button_label || 'Open Ticket',
            buttonStyle: row.button_style || 'Primary',
            buttonEmoji: row.button_emoji || null,
            category: row.category || 'general',
            ticketName: row.ticket_name || null,
            supportRoleIds: Array.isArray(row.support_role_ids) ? row.support_role_ids : [],
            pingRoleIds: Array.isArray(row.ping_role_ids) ? row.ping_role_ids : [],
            ticketCategoryId: row.ticket_category_id || null,
            cooldownSeconds: Number(row.cooldown_seconds) || 0,
            maxOpenPerUser: Number(row.max_open_per_user) || 1,
            askReason: !!row.ask_reason,
            reasonPlaceholder: row.reason_placeholder || 'Briefly describe your issue',
            welcomeMessage: row.welcome_message || null,
            closeButtonLabel: row.close_button_label || 'Close Ticket',
            closeButtonEmoji: row.close_button_emoji || null,
            claimButtonLabel: row.claim_button_label || null,
            claimButtonEmoji: row.claim_button_emoji || null,
            openNameTemplate: row.open_name_template != null ? row.open_name_template : null,
            claimedNameTemplate: row.claimed_name_template != null ? row.claimed_name_template : null,
            closedNameTemplate: row.closed_name_template != null ? row.closed_name_template : null,
            enabled: row.enabled !== false,
            createdBy: row.created_by || null,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
        };
    }

    _rowToInstance(row) {
        return {
            id: row.id,
            panelId: row.panel_id || null,
            guildId: row.guild_id,
            channelId: row.channel_id,
            userId: row.user_id,
            category: row.category || 'general',
            isThread: !!row.is_thread,
            parentChannelId: row.parent_channel_id || null,
            controlMessageId: row.control_message_id || null,
            reason: row.reason || null,
            status: row.status || 'open',
            claimedBy: row.claimed_by || null,
            createdAt: Number(row.created_at),
            closedAt: row.closed_at ? Number(row.closed_at) : null,
            closedBy: row.closed_by || null,
            reopenedAt: row.reopened_at ? Number(row.reopened_at) : null,
            reopenedBy: row.reopened_by || null,
        };
    }

    // ── Public read API ──────────────────────────────────────────────────────

    getPanelForMessage(guildId, channelId, messageId) {
        return this._byMessage.get(this._msgKey(guildId, channelId, messageId)) || null;
    }

    getPanelById(id) {
        return this._byPanel.get(String(id)) || null;
    }

    getGuildPanels(guildId) {
        const ids = this._byGuild.get(guildId);
        if (!ids) return [];
        return [...ids].map(id => this._byPanel.get(id)).filter(Boolean);
    }

    getInstanceByChannel(channelId) {
        return this._byChannel.get(channelId) || null;
    }

    countOpenTickets(guildId, userId) {
        let n = 0;
        for (const t of this._byChannel.values()) {
            if (t.guildId === guildId && t.userId === userId && t.status === 'open') n++;
        }
        return n;
    }

    // ── Persistence (used by the dashboard; the bot reloads via cache) ───────

    async createPanel(guildId, data) {
        await this._ensureTable();
        const panel = this._normalizePanel(data);
        const res = await ticketPool.query(`
            INSERT INTO ticket_panels (
                guild_id, name, channel_id, message_id, message_type, title, description,
                color, thumbnail_url, image_url, footer_text, content, button_label,
                button_style, button_emoji, category, ticket_name, support_role_ids,
                ping_role_ids, ticket_category_id, cooldown_seconds, max_open_per_user,
                ask_reason, reason_placeholder, welcome_message, close_button_label,
                close_button_emoji, claim_button_label, claim_button_emoji,
                open_name_template, claimed_name_template, closed_name_template,
                enabled, created_by, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,NOW(),NOW())
            RETURNING id
        `, [
            guildId, panel.name, panel.channelId || null, panel.messageId || null,
            panel.messageType, panel.title, panel.description,
            panel.color, panel.thumbnailUrl, panel.imageUrl, panel.footerText, panel.content,
            panel.buttonLabel, panel.buttonStyle, panel.buttonEmoji,
            panel.category, panel.ticketName, JSON.stringify(panel.supportRoleIds),
            JSON.stringify(panel.pingRoleIds), panel.ticketCategoryId,
            panel.cooldownSeconds, panel.maxOpenPerUser,
            panel.askReason, panel.reasonPlaceholder, panel.welcomeMessage,
            panel.closeButtonLabel, panel.closeButtonEmoji,
            panel.claimButtonLabel, panel.claimButtonEmoji,
            panel.openNameTemplate, panel.claimedNameTemplate, panel.closedNameTemplate,
            panel.enabled, panel.createdBy || null,
        ]);
        const id = res.rows[0].id;
        const fetched = await this._fetchPanel(id);
        if (fetched) this._indexPanel(fetched);
        return fetched;
    }

    async updatePanel(id, patch) {
        await this._ensureTable();
        const current = await this._fetchPanel(id);
        if (!current) throw new Error('Ticket panel not found.');
        const next = { ...current };
        for (const key of Object.keys(this._panelFields())) {
            if (key in patch) next[key] = patch[key];
        }
        const norm = this._normalizePanel(next, true);
        await ticketPool.query(`
            UPDATE ticket_panels SET
                name = $2, channel_id = $3, message_id = $4, message_type = $5,
                title = $6, description = $7, color = $8, thumbnail_url = $9,
                image_url = $10, footer_text = $11, content = $12, button_label = $13,
                button_style = $14, button_emoji = $15, category = $16, ticket_name = $17,
                support_role_ids = $18, ping_role_ids = $19, ticket_category_id = $20,
                cooldown_seconds = $21, max_open_per_user = $22, ask_reason = $23,
                reason_placeholder = $24, welcome_message = $25, close_button_label = $26,
                close_button_emoji = $27, claim_button_label = $28, claim_button_emoji = $29,
                open_name_template = $30, claimed_name_template = $31, closed_name_template = $32,
                enabled = $33, updated_at = NOW()
            WHERE id = $1
        `, [
            id, norm.name, norm.channelId || null, norm.messageId || null, norm.messageType,
            norm.title, norm.description, norm.color, norm.thumbnailUrl, norm.imageUrl,
            norm.footerText, norm.content, norm.buttonLabel, norm.buttonStyle, norm.buttonEmoji,
            norm.category, norm.ticketName, JSON.stringify(norm.supportRoleIds),
            JSON.stringify(norm.pingRoleIds), norm.ticketCategoryId,
            norm.cooldownSeconds, norm.maxOpenPerUser, norm.askReason,
            norm.reasonPlaceholder, norm.welcomeMessage,
            norm.closeButtonLabel, norm.closeButtonEmoji,
            norm.claimButtonLabel, norm.claimButtonEmoji,
            norm.openNameTemplate, norm.claimedNameTemplate, norm.closedNameTemplate,
            norm.enabled,
        ]);
        const fetched = await this._fetchPanel(id);
        if (fetched) this._indexPanel(fetched);
        return fetched;
    }

    async deletePanel(id) {
        await this._ensureTable();
        const panel = await this._fetchPanel(id);
        await ticketPool.query('DELETE FROM ticket_panels WHERE id = $1', [id]);
        if (panel) this._unindexPanel(panel);
        return !!panel;
    }

    /** Clone an existing panel under a new name (no message/channel binding). */
    async clonePanel(id, newName) {
        await this._ensureTable();
        const src = await this._fetchPanel(id);
        if (!src) throw new Error('Ticket panel not found.');
        const data = { ...src };
        delete data.id;
        data.name = (newName && String(newName).trim()) || `${src.name} (copy)`;
        data.channelId = null;
        data.messageId = null;
        return this.createPanel(src.guildId, data);
    }

    /** Rename a panel (keeps its message binding). */
    async renamePanel(id, newName) {
        const name = newName && String(newName).trim();
        if (!name) throw new Error('A name is required.');
        await this._ensureTable();
        await ticketPool.query('UPDATE ticket_panels SET name = $2, updated_at = NOW() WHERE id = $1', [id, name]);
        const fetched = await this._fetchPanel(id);
        if (fetched) this._indexPanel(fetched);
        return fetched;
    }

    async _fetchPanel(id) {
        const res = await ticketPool.query('SELECT * FROM ticket_panels WHERE id = $1', [id]);
        if (res.rows.length === 0) return null;
        return this._rowToPanel(res.rows[0]);
    }

    _panelFields() {
        return {
            name: 1, channelId: 1, messageId: 1, messageType: 1, title: 1, description: 1,
            color: 1, thumbnailUrl: 1, imageUrl: 1, footerText: 1, content: 1,
            buttonLabel: 1, buttonStyle: 1, buttonEmoji: 1, category: 1, ticketName: 1,
            supportRoleIds: 1, pingRoleIds: 1, ticketCategoryId: 1, cooldownSeconds: 1,
            maxOpenPerUser: 1, askReason: 1, reasonPlaceholder: 1, welcomeMessage: 1,
            closeButtonLabel: 1, closeButtonEmoji: 1, claimButtonLabel: 1,
            claimButtonEmoji: 1, openNameTemplate: 1, claimedNameTemplate: 1,
            closedNameTemplate: 1, enabled: 1, createdBy: 1,
        };
    }

    _normalizePanel(data, keepUndefined = false) {
        const base = keepUndefined ? {} : { ...DEFAULT_PANEL };
        const out = { ...base, ...(data || {}) };
        out.name = (out.name == null ? '' : String(out.name)).trim() || 'Support Ticket';
        out.messageType = VALID_MESSAGE_TYPES.has(out.messageType) ? out.messageType : 'embed';
        out.buttonStyle = VALID_BUTTON_STYLES.has(out.buttonStyle) ? out.buttonStyle : 'Primary';
        out.color = /^#[0-9a-fA-F]{6}$/.test(out.color) ? out.color : '#5865F2';
        out.supportRoleIds = Array.isArray(out.supportRoleIds) ? out.supportRoleIds.map(String) : [];
        out.pingRoleIds = Array.isArray(out.pingRoleIds) ? out.pingRoleIds.map(String) : [];
        out.cooldownSeconds = Math.max(0, parseInt(out.cooldownSeconds, 10) || 0);
        out.maxOpenPerUser = Math.max(0, parseInt(out.maxOpenPerUser, 10) || 1);
        out.askReason = !!out.askReason;
        out.enabled = out.enabled !== false;
        for (const f of ['buttonEmoji', 'closeButtonEmoji', 'claimButtonEmoji', 'thumbnailUrl', 'imageUrl']) {
            if (out[f] != null) out[f] = String(out[f]).trim() || null;
        }
        // Name templates: keepUndefined=false applies DEFAULT_PANEL defaults; trim
        // to null (null = no rename for that state). Only coerce when present.
        for (const f of ['openNameTemplate', 'claimedNameTemplate', 'closedNameTemplate']) {
            if (out[f] != null) out[f] = String(out[f]).trim().slice(0, 100) || null;
        }
        return out;
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    /** Build the panel message payload (embed or plain) + the open button row. */
    buildPanelMessage(panel) {
        const openBtn = new ButtonBuilder()
            .setCustomId(`ticketpanel:open:${panel.id}`)
            .setLabel(panel.buttonLabel || 'Open Ticket')
            .setStyle(ButtonStyle[panel.buttonStyle] || ButtonStyle.Primary);
        if (panel.buttonEmoji) openBtn.setEmoji(panel.buttonEmoji);
        const row = new ActionRowBuilder().addComponents(openBtn);

        if (panel.messageType === 'plain') {
            return {
                content: panel.content || panel.description || 'Click the button below to open a support ticket.',
                components: [row],
            };
        }
        const embed = new EmbedBuilder()
            .setColor(panel.color || '#5865F2')
            .setTitle(panel.title || '🎫 Support Tickets')
            .setDescription(panel.description || 'Click the button below to open a support ticket.');
        if (panel.thumbnailUrl) embed.setThumbnail(panel.thumbnailUrl);
        if (panel.imageUrl) embed.setImage(panel.imageUrl);
        if (panel.footerText) embed.setFooter({ text: panel.footerText });
        embed.setTimestamp();
        return { content: panel.content || null, embeds: [embed], components: [row] };
    }

    /** Build the in-ticket control message (close/claim/rename buttons). */
    buildControlMessage(panel, opener) {
        const closeBtn = new ButtonBuilder()
            .setCustomId('ticketpanel:close')
            .setLabel(panel.closeButtonLabel || 'Close Ticket')
            .setStyle(ButtonStyle.Danger);
        if (panel.closeButtonEmoji) closeBtn.setEmoji(panel.closeButtonEmoji);
        const rows = [new ActionRowBuilder().addComponents(closeBtn)];
        // Claim + Rename go in a second row (or first row if no claim button).
        const extra = [];
        if (panel.claimButtonLabel) {
            const claimBtn = new ButtonBuilder()
                .setCustomId('ticketpanel:claim')
                .setLabel(panel.claimButtonLabel)
                .setStyle(ButtonStyle.Secondary);
            if (panel.claimButtonEmoji) claimBtn.setEmoji(panel.claimButtonEmoji);
            extra.push(claimBtn);
        }
        const renameBtn = new ButtonBuilder()
            .setCustomId('ticketpanel:rename')
            .setLabel('Rename')
            .setStyle(ButtonStyle.Secondary)
            .setEmoji('✏️');
        extra.push(renameBtn);
        if (extra.length) rows.push(new ActionRowBuilder().addComponents(...extra));
        const embed = new EmbedBuilder()
            .setColor(panel.color || '#5865F2')
            .setTitle(`🎫 ${panel.name}`)
            .setDescription(panel.welcomeMessage || `Hello ${opener}, welcome to your support ticket! Please describe your issue and our staff will assist you shortly.`)
            .addFields(
                { name: '📂 Category', value: panel.category || 'general', inline: true },
                { name: '🕐 Opened', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true },
                { name: '👤 Opened by', value: `${opener}`, inline: true },
            )
            .setTimestamp();
        return { embeds: [embed], components: rows };
    }

    // ── Sending / updating panel messages ───────────────────────────────────

    /**
     * Render a ticket channel name from a status template.
     * Placeholders: {name} (panel.ticketName or opener username), {username},
     * {id} (opener id), {panel} (panel.name). Returns null when the template
     * is empty/null (= "don't rename for this state").
     */
    _renderTicketName(template, panel, opener) {
        if (!template) return null;
        const username = opener?.username || opener?.displayName || 'user';
        const nameBase = panel?.ticketName || username;
        let out = String(template)
            .replace(/\{name\}/g, nameBase)
            .replace(/\{username\}/g, username)
            .replace(/\{id\}/g, opener?.id || '')
            .replace(/\{panel\}/g, panel?.name || '');
        // Discord channel names: lowercase, no spaces, max 100 chars.
        out = out.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '').slice(0, 100);
        return out || null;
    }

    /** Apply a status name template to a ticket channel (fire-and-forget). */
    async _setTicketName(channel, template, panel, opener) {
        const name = this._renderTicketName(template, panel, opener);
        if (!name || !channel) return;
        try {
            const current = channel.name;
            if (current === name) return;
            await channel.setName(name);
        } catch (err) {
            console.error('[TICKETS] Failed to rename ticket channel:', err.message);
        }
    }

    /** Post the panel to a channel. */
    async sendPanelToChannel(panelId, channelId) {
        const panel = this.getPanelById(panelId);
        if (!panel) throw new Error('Ticket panel not found.');
        const channel = await this.client.channels.fetch(channelId).catch(() => null);
        if (!channel) throw new Error('Channel not found or not visible to the bot.');
        const payload = this.buildPanelMessage(panel);
        const sent = await channel.send(payload);
        await this.updatePanel(panelId, { channelId, messageId: sent.id });
        return sent;
    }

    /** Re-render an existing panel message by id (the "update" button). */
    async updatePanelMessage(panelId, messageId) {
        const panel = this.getPanelById(panelId);
        if (!panel) throw new Error('Ticket panel not found.');
        const channel = await this.client.channels.fetch(panel.channelId).catch(() => null);
        if (!channel) throw new Error('The panel channel is no longer available.');
        const msg = await channel.messages.fetch(messageId).catch(() => null);
        if (!msg) throw new Error('Could not find that message. Make sure it exists in the panel channel.');
        const payload = this.buildPanelMessage(panel);
        await msg.edit(payload);
        await this.updatePanel(panelId, { channelId: channel.id, messageId });
        return msg;
    }

    // ── Ticket open/close/reopen/claim (button interactions) ──────────────────

    async handleOpen(interaction, panel) {
        const guild = interaction.guild;
        const member = interaction.member;
        const userId = interaction.user.id;
        if (!panel || !panel.enabled) {
            return interaction.reply({ content: 'This ticket panel is currently disabled.', ephemeral: true });
        }
        if (panel.maxOpenPerUser > 0 && this.countOpenTickets(guild.id, userId) >= panel.maxOpenPerUser) {
            return interaction.reply({ content: `You already have ${panel.maxOpenPerUser} open ticket(s). Please close one before opening another.`, ephemeral: true });
        }

        const reason = panel.askReason ? (interaction.options?.getString?.('reason') || null) : null;
        const baseName = panel.ticketName
            ? panel.ticketName
            : `ticket-${interaction.user.username}`.toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 40);
        // Status-based channel name: prefer the panel's open template, falling back
        // to the legacy "🎫 <baseName>" form when no template is configured.
        const openName = this._renderTicketName(panel.openNameTemplate, panel, interaction.user)
            || `🎫 ${baseName}`.slice(0, 100);

        try {
            let ticketChannel;
            // Prefer a private channel under the configured category.
            try {
                ticketChannel = await guild.channels.create({
                    name: openName.slice(0, 100),
                    type: ChannelType.GuildText,
                    parent: panel.ticketCategoryId || undefined,
                    permissionOverwrites: this._channelPerms(guild, member, panel),
                    reason: `Ticket opened via panel "${panel.name}" by ${interaction.user.tag}`,
                });
            } catch (e) {
                // Fallback to a private thread on the interaction channel.
                const parent = interaction.channel;
                ticketChannel = await parent.threads.create({
                    name: openName.slice(0, 100),
                    autoArchiveDuration: 1440,
                    type: ChannelType.PrivateThread,
                    reason: `Ticket opened via panel "${panel.name}" by ${interaction.user.tag}`,
                });
                await ticketChannel.members.add(userId).catch(() => {});
            }

            // For threads, also add support-role members (channels get view via overwrites).
            if (ticketChannel.isThread?.()) {
                const supportMembers = guild.members.cache.filter(m =>
                    panel.supportRoleIds.some(r => m.roles.cache.has(r)) ||
                    m.permissions.has(PermissionFlagsBits.Administrator)
                );
                for (const [, m] of supportMembers) {
                    await ticketChannel.members.add(m.id).catch(() => {});
                }
            }

            const controlPayload = this.buildControlMessage(panel, interaction.user);
            const controlMsg = await ticketChannel.send({
                content: this._ticketPing(panel, interaction.user),
                ...controlPayload,
            });

            const instance = {
                panelId: panel.id,
                guildId: guild.id,
                channelId: ticketChannel.id,
                userId,
                category: panel.category || 'general',
                isThread: !!ticketChannel.isThread?.(),
                parentChannelId: ticketChannel.parentId || null,
                controlMessageId: controlMsg.id,
                reason: reason || null,
                status: 'open',
                claimedBy: null,
                createdAt: Date.now(),
            };
            await this._saveInstance(instance);
            this._byChannel.set(ticketChannel.id, instance);

            return interaction.reply({
                content: `Your ticket has been opened: ${ticketChannel}`,
                ephemeral: true,
            });
        } catch (err) {
            console.error('[TICKETS] Error opening ticket:', err);
            return interaction.reply({ content: 'There was an error opening your ticket. Please try again later.', ephemeral: true });
        }
    }

    _channelPerms(guild, openerMember, panel) {
        const overwrites = [
            { id: guild.id, deny: [PermissionFlagsBits.ViewChannel] },
            { id: openerMember.id, allow: [
                PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages,
                PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles,
                PermissionFlagsBits.EmbedLinks,
            ] },
            { id: guild.members.me.id, allow: [
                PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages,
                PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.ManageChannels,
                PermissionFlagsBits.EmbedLinks,
            ] },
        ];
        for (const roleId of panel.supportRoleIds) {
            overwrites.push({ id: roleId, allow: [
                PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages,
                PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.ManageMessages,
            ] });
        }
        return overwrites;
    }

    _ticketPing(panel, opener) {
        const ping = (panel.pingRoleIds || []).map(id => `<@&${id}>`).join(' ');
        const support = (panel.supportRoleIds || []).map(id => `<@&${id}>`).join(' ');
        return `${opener} ${ping} ${support}`.trim();
    }

    async handleClose(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const isOwner = interaction.user.id === instance.userId;
        const isAdmin = interaction.member?.permissions?.has(PermissionFlagsBits.Administrator);
        const isSupport = await this._isSupportMember(interaction, instance);
        if (!isOwner && !isAdmin && !isSupport) {
            return interaction.reply({ content: 'Only the ticket owner, support staff, or administrators can close this ticket.', ephemeral: true });
        }

        try {
            instance.status = 'closed';
            instance.closedAt = Date.now();
            instance.closedBy = interaction.user.id;
            if (interaction.channel.isThread?.()) {
                await interaction.channel.setArchived(false).catch(() => {});
                await interaction.channel.setLocked(true).catch(() => {});
            }
            const panel = instance.panelId ? this.getPanelById(instance.panelId) : null;
            const reopenBtn = new ButtonBuilder()
                .setCustomId('ticketpanel:reopen')
                .setLabel('Reopen Ticket')
                .setStyle(ButtonStyle.Success)
                .setEmoji('🔓');
            const row = new ActionRowBuilder().addComponents(reopenBtn);
            const embed = new EmbedBuilder()
                .setColor('#ED4245')
                .setTitle('🔒 Ticket Closed')
                .setDescription('This ticket has been closed and archived.\n\nYou or an administrator can reopen it using the button below.')
                .addFields(
                    { name: '👤 Closed by', value: `${interaction.user}`, inline: true },
                    { name: '🕐 Closed at', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true },
                )
                .setTimestamp();
            await interaction.update({ embeds: [embed], components: [row] }).catch(() =>
                interaction.reply({ embeds: [embed], components: [row] })
            );
            this._byChannel.delete(channelId);
            await this._saveInstance(instance);

            // Apply the closed-status channel name template (mainly visible for
            // archived threads; regular channels are deleted shortly after).
            if (panel) {
                const openerMember = await interaction.guild.members.fetch(instance.userId).catch(() => null);
                const opener = openerMember?.user || { id: instance.userId, username: openerMember?.displayName };
                await this._setTicketName(interaction.channel, panel.closedNameTemplate, panel, opener);
            }

            // After a delay, delete channel-type tickets (threads just stay archived).
            if (!interaction.channel.isThread?.()) {
                setTimeout(() => {
                    interaction.channel.delete('Ticket closed').catch(() => {});
                }, 5000);
            }
        } catch (err) {
            console.error('[TICKETS] Error closing ticket:', err);
            return interaction.reply({ content: 'There was an error closing this ticket.', ephemeral: true });
        }
    }

    async handleReopen(interaction) {
        const channelId = interaction.channel.id;
        let instance = this.getInstanceByChannel(channelId);
        if (!instance) {
            const res = await ticketPool.query('SELECT * FROM ticket_instances WHERE channel_id = $1', [channelId]);
            if (res.rows.length === 0) {
                return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
            }
            instance = this._rowToInstance(res.rows[0]);
        }
        const isOwner = interaction.user.id === instance.userId;
        const isAdmin = interaction.member?.permissions?.has(PermissionFlagsBits.Administrator);
        if (!isOwner && !isAdmin) {
            return interaction.reply({ content: 'Only the ticket owner or administrators can reopen this ticket.', ephemeral: true });
        }
        try {
            instance.status = 'open';
            instance.reopenedAt = Date.now();
            instance.reopenedBy = interaction.user.id;
            instance.closedAt = null;
            instance.closedBy = null;
            if (interaction.channel.isThread?.()) {
                await interaction.channel.setArchived(false).catch(() => {});
                await interaction.channel.setLocked(false).catch(() => {});
            }
            const panel = instance.panelId ? this.getPanelById(instance.panelId) : null;
            const closeBtn = new ButtonBuilder()
                .setCustomId('ticketpanel:close')
                .setLabel(panel?.closeButtonLabel || 'Close Ticket')
                .setStyle(ButtonStyle.Danger)
                .setEmoji(panel?.closeButtonEmoji || '🔒');
            const row = new ActionRowBuilder().addComponents(closeBtn);
            const embed = new EmbedBuilder()
                .setColor('#57F287')
                .setTitle('🔓 Ticket Reopened')
                .setDescription('This ticket has been reopened and is now active again.')
                .addFields(
                    { name: '👤 Reopened by', value: `${interaction.user}`, inline: true },
                    { name: '🕐 Reopened at', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true },
                )
                .setTimestamp();
            await interaction.update({ embeds: [embed], components: [row] }).catch(() =>
                interaction.reply({ embeds: [embed], components: [row] })
            );
            this._byChannel.set(channelId, instance);
            await this._saveInstance(instance);
            // Re-apply the open-status channel name template.
            if (panel) {
                const openerMember = await interaction.guild.members.fetch(instance.userId).catch(() => null);
                const opener = openerMember?.user || { id: instance.userId, username: openerMember?.displayName };
                await this._setTicketName(interaction.channel, panel.openNameTemplate, panel, opener);
            }
        } catch (err) {
            console.error('[TICKETS] Error reopening ticket:', err);
            return interaction.reply({ content: 'There was an error reopening this ticket.', ephemeral: true });
        }
    }

    async handleClaim(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const isAdmin = interaction.member?.permissions?.has(PermissionFlagsBits.Administrator);
        const isSupport = await this._isSupportMember(interaction, instance);
        if (!isAdmin && !isSupport) {
            return interaction.reply({ content: 'Only support staff or administrators can claim this ticket.', ephemeral: true });
        }
        try {
            instance.claimedBy = interaction.user.id;
            await this._saveInstance(instance);
            // Apply the claimed-status channel name template.
            const panel = instance.panelId ? this.getPanelById(instance.panelId) : null;
            if (panel) {
                const openerMember = await interaction.guild.members.fetch(instance.userId).catch(() => null);
                const opener = openerMember?.user || { id: instance.userId, username: openerMember?.displayName };
                await this._setTicketName(interaction.channel, panel.claimedNameTemplate, panel, opener);
            }
            const embed = new EmbedBuilder()
                .setColor('#5865F2')
                .setDescription(`This ticket has been claimed by ${interaction.user}.`)
                .setTimestamp();
            await interaction.reply({ embeds: [embed] });
        } catch (err) {
            console.error('[TICKETS] Error claiming ticket:', err);
            return interaction.reply({ content: 'There was an error claiming this ticket.', ephemeral: true });
        }
    }

    /** Show a modal letting staff/owner edit this ticket channel's name. */
    async handleRename(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const isOwner = interaction.user.id === instance.userId;
        const isAdmin = interaction.member?.permissions?.has(PermissionFlagsBits.Administrator);
        const isSupport = await this._isSupportMember(interaction, instance);
        if (!isOwner && !isAdmin && !isSupport) {
            return interaction.reply({ content: 'Only the ticket owner, support staff, or administrators can rename this ticket.', ephemeral: true });
        }
        const modal = new ModalBuilder()
            .setCustomId('ticketpanel:rename')
            .setTitle('Rename Ticket');
        const input = new TextInputBuilder()
            .setCustomId('ticket-name')
            .setLabel('New channel name')
            .setStyle(TextInputStyle.Short)
            .setPlaceholder('e.g. (open) ticket-alice')
            .setValue((interaction.channel.name || '').slice(0, 100))
            .setRequired(true)
            .setMaxLength(100);
        modal.addComponents(new ActionRowBuilder().addComponents(input));
        try {
            await interaction.showModal(modal);
        } catch (err) {
            console.error('[TICKETS] Error showing rename modal:', err);
            return interaction.reply({ content: 'There was an error opening the rename form.', ephemeral: true });
        }
    }

    /** Process the rename modal submission. */
    async handleRenameSubmit(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const isOwner = interaction.user.id === instance.userId;
        const isAdmin = interaction.member?.permissions?.has(PermissionFlagsBits.Administrator);
        const isSupport = await this._isSupportMember(interaction, instance);
        if (!isOwner && !isAdmin && !isSupport) {
            return interaction.reply({ content: 'You are not allowed to rename this ticket.', ephemeral: true });
        }
        let name = interaction.fields?.getTextInputValue('ticket-name');
        if (name == null) name = interaction.fields?.get('ticket-name')?.value;
        name = name && String(name).trim();
        if (!name) {
            return interaction.reply({ content: 'A name is required.', ephemeral: true });
        }
        // Sanitize to Discord channel naming rules.
        name = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '').slice(0, 100);
        if (!name) {
            return interaction.reply({ content: 'That name is not valid for a channel.', ephemeral: true });
        }
        try {
            if (interaction.channel.name !== name) {
                await interaction.channel.setName(name);
            }
            await interaction.reply({ content: `✏️ Ticket renamed to **${name}**.`, ephemeral: true });
        } catch (err) {
            console.error('[TICKETS] Error renaming ticket:', err);
            return interaction.reply({ content: 'There was an error renaming this ticket.', ephemeral: true });
        }
    }

    async _isSupportMember(interaction, instance) {
        const panel = instance.panelId ? this.getPanelById(instance.panelId) : null;
        const roles = panel?.supportRoleIds || [];
        if (roles.length === 0) return false;
        const member = interaction.member || await interaction.guild.members.fetch(interaction.user.id).catch(() => null);
        if (!member) return false;
        return roles.some(r => member.roles.cache.has(r));
    }

    async _fetchInstanceByChannel(channelId) {
        const res = await ticketPool.query('SELECT * FROM ticket_instances WHERE channel_id = $1', [channelId]);
        if (res.rows.length === 0) return null;
        return this._rowToInstance(res.rows[0]);
    }

    async _saveInstance(instance) {
        await ticketPool.query(`
            INSERT INTO ticket_instances (
                panel_id, guild_id, channel_id, user_id, category, is_thread,
                parent_channel_id, control_message_id, reason, status, claimed_by,
                created_at, closed_at, closed_by, reopened_at, reopened_by
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
            ON CONFLICT (channel_id) DO UPDATE SET
                status = EXCLUDED.status,
                claimed_by = EXCLUDED.claimed_by,
                closed_at = EXCLUDED.closed_at,
                closed_by = EXCLUDED.closed_by,
                reopened_at = EXCLUDED.reopened_at,
                reopened_by = EXCLUDED.reopened_by
        `, [
            instance.panelId || null, instance.guildId, instance.channelId, instance.userId,
            instance.category, instance.isThread, instance.parentChannelId,
            instance.controlMessageId, instance.reason, instance.status, instance.claimedBy,
            instance.createdAt, instance.closedAt || null, instance.closedBy || null,
            instance.reopenedAt || null, instance.reopenedBy || null,
        ]);
    }

    getTicketHistory(guildId, userId = null) {
        return Array.from(this._byChannel.values())
            .filter(t => t.guildId === guildId && (userId ? t.userId === userId : true))
            .sort((a, b) => b.createdAt - a.createdAt);
    }

    // ── Startup ──────────────────────────────────────────────────────────────

    async restorePanels() {
        if (!this.client || !this.client.guilds) return;
        const panels = [...this._byPanel.values()].filter(p => p.enabled && p.channelId && p.messageId);
        console.log(`[TICKETS] Restored ${panels.length} ticket panels.`);
    }
}

module.exports = { TicketPanelManager, ticketPool };
