const {
    EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder,
    ChannelType, PermissionFlagsBits,
    ModalBuilder, TextInputBuilder, TextInputStyle,
} = require('discord.js');
const { ticketPool } = require('../server/ticketDb');
const { trolePool, ensureTicketRoleTable } = require('../server/troleDb');
const { tclaimPool, ensureTicketClaimsTable } = require('../server/tclaimDb');
const ticketClaimService = require('./ticketClaimService');
const ticketPerms = require('./ticketPermissions');

/**
 * Premium ticket panels ŌĆö configurable ONLY from the dashboard.
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
 * Commands are intentionally disabled from creating/configuring panels ŌĆö the
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
        close_button_style     VARCHAR(20) DEFAULT 'Danger',
        claim_button_label     VARCHAR(80),
        claim_button_emoji     VARCHAR(100),
        claim_button_style     VARCHAR(20) DEFAULT 'Secondary',
        close_flow             JSONB,
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
        claimed_at          BIGINT,
        claim_history       JSONB,
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
//   {name}     ŌåÆ panel.ticketName (or the opener's username if unset)
//   {username} ŌåÆ opener's username
//   {id}       ŌåÆ opener's user id
//   {panel}    ŌåÆ panel.name
const NAME_PLACEHOLDERS = ['{name}', '{username}', '{id}', '{panel}'];

// Placeholders available in the close embed text (title / description / footer).
//   {time}      ŌåÆ "Mon Aug 17 2026 15:17 +00:00" (human-readable close time)
//   {timestamp} ŌåÆ <t:...:R> Discord relative-time tag
//   {author}    ŌåÆ ticket opener mention
//   {moderator} ŌåÆ the user who closed the ticket (mention)
//   {panel}    ŌåÆ panel.name
//   {reason}   ŌåÆ ticket open reason (or "ŌĆö")
const CLOSE_PLACEHOLDERS = ['{time}', '{timestamp}', '{author}', '{moderator}', '{panel}', '{reason}'];

// Default close-flow config. All sub-objects are optional; missing pieces
// fall back to these values. Stored as the `close_flow` JSONB column.
const DEFAULT_CLOSE_FLOW = {
    confirmYes: { label: 'Yes', emoji: 'Ō£ģ', style: 'Success' },
    confirmNo: { label: 'No', emoji: 'Ō£¢’ĖÅ', style: 'Danger' },
    closeEmbed: {
        enabled: false,
        title: '­¤öÆ Ticket Closed',
        description: 'This ticket was closed by {moderator} at {time}.\nOpened by {author}.',
        color: '#ED4245',
        footer: '{panel} ┬Ę PrimeBot',
    },
    transcript: { enabled: false, channelId: null },
    buttons: {
        transcript: { label: 'Transcript', emoji: '­¤ōØ', style: 'Primary' },
        reopen: { label: 'Reopen', emoji: '­¤öō', style: 'Success' },
        delete: { label: 'Delete', emoji: '­¤Śæ’ĖÅ', style: 'Danger' },
    },
};

const CLOSE_BTN_KEYS = ['transcript', 'reopen', 'delete'];

/** Coerce a value to one of the valid button styles. */
function _coerceStyle(v, fallback = 'Primary') {
    return VALID_BUTTON_STYLES.has(v) ? v : fallback;
}

/** Parse a JSONB value into an array (safe: malformed → []). */
function _safeParseJsonArray(raw) {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    try {
        const arr = JSON.parse(String(raw));
        return Array.isArray(arr) ? arr : [];
    } catch {
        return [];
    }
}

/** Normalize a single button spec { label, emoji, style }. */
function _normalizeBtnSpec(spec, fallback) {
    const s = (spec && typeof spec === 'object') ? spec : {};
    const label = (s.label == null ? '' : String(s.label)).trim();
    const emoji = (s.emoji == null ? '' : String(s.emoji)).trim() || null;
    return {
        label: label || fallback.label,
        emoji: emoji || fallback.emoji,
        style: _coerceStyle(s.style, fallback.style),
    };
}

/**
 * Normalize the close-flow JSONB config. Missing keys inherit defaults so the
 * bot and dashboard always see a complete object. Returns a plain object.
 */
function normalizeCloseFlow(raw) {
    const src = (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
    const out = {
        confirmYes: _normalizeBtnSpec(src.confirmYes, DEFAULT_CLOSE_FLOW.confirmYes),
        confirmNo: _normalizeBtnSpec(src.confirmNo, DEFAULT_CLOSE_FLOW.confirmNo),
        closeEmbed: {
            enabled: src.closeEmbed && src.closeEmbed.enabled === true ? true : false,
            title: (src.closeEmbed && src.closeEmbed.title != null ? String(src.closeEmbed.title) : DEFAULT_CLOSE_FLOW.closeEmbed.title).trim() || DEFAULT_CLOSE_FLOW.closeEmbed.title,
            description: (src.closeEmbed && src.closeEmbed.description != null ? String(src.closeEmbed.description) : DEFAULT_CLOSE_FLOW.closeEmbed.description),
            color: /^#[0-9a-fA-F]{6}$/.test(src.closeEmbed && src.closeEmbed.color) ? src.closeEmbed.color : DEFAULT_CLOSE_FLOW.closeEmbed.color,
            footer: (src.closeEmbed && src.closeEmbed.footer != null ? String(src.closeEmbed.footer) : DEFAULT_CLOSE_FLOW.closeEmbed.footer),
        },
        transcript: {
            enabled: src.transcript && src.transcript.enabled === true ? true : false,
            channelId: (src.transcript && src.transcript.channelId != null ? String(src.transcript.channelId).trim() : null) || null,
        },
        buttons: {},
    };
    for (const k of CLOSE_BTN_KEYS) {
        out.buttons[k] = _normalizeBtnSpec(src.buttons && src.buttons[k], DEFAULT_CLOSE_FLOW.buttons[k]);
    }
    return out;
}

/**
 * Render close-embed placeholders against a context. Used for the title,
 * description, and footer of the (optional) close embed.
 */
function renderCloseText(text, ctx) {
    if (!text) return '';
    const mod = ctx.moderator != null ? String(ctx.moderator) : 'ŌĆö';
    const author = ctx.author != null ? String(ctx.author) : 'ŌĆö';
    const panel = ctx.panel != null ? String(ctx.panel) : '';
    const reason = ctx.reason != null ? String(ctx.reason) : 'ŌĆö';
    const ts = ctx.timestamp != null ? Math.floor(Number(ctx.timestamp) / 1000) : Math.floor(Date.now() / 1000);
    const timeStr = new Date(ts * 1000).toLocaleString();
    return String(text)
        .replace(/\{time\}/g, timeStr)
        .replace(/\{timestamp\}/g, `<t:${ts}:R>`)
        .replace(/\{author\}/g, author)
        .replace(/\{moderator\}/g, mod)
        .replace(/\{panel\}/g, panel)
        .replace(/\{reason\}/g, reason);
}

const DEFAULT_PANEL = {
    name: 'Support Ticket',
    messageType: 'embed',
    title: '🎫 Support Tickets',
    description: 'Click the button below to open a support ticket.',
    color: '#5865F2',
    content: '',
    authorName: '',
    authorUrl: '',
    authorIconUrl: '',
    titleUrl: '',
    footerIconUrl: '',
    timestampEnabled: true,
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
    closeButtonStyle: 'Danger',
    claimButtonLabel: '',
    claimButtonEmoji: '',
    claimButtonStyle: 'Secondary',
    claimEnabled: true,
    panelVersion: 1,
    // Status-based channel name templates. Empty/null → no rename for that state.
    openNameTemplate: '(open) {name}',
    claimedNameTemplate: '(solved) {name}',
    closedNameTemplate: '(closed) {name}',
    closeFlow: null,
    enabled: true,
};

class TicketPanelManager {
    constructor(client) {
        this.client = client;
        this._byPanel = new Map();     // panelId -> panel
        this._byMessage = new Map();   // `${guildId}:${channelId}:${messageId}` -> panel
        this._byGuild = new Map();    // guildId -> Set<panelId>
        this._byChannel = new Map();  // channelId -> ticket instance (open tickets)
        this._roleSettings = new Map();  // panelId -> ticket role add/remove settings (TROLE pool)
        this._components = new Map();     // panelId -> component[] (panel builder)
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
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_button_style VARCHAR(20) DEFAULT 'Danger'`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_label VARCHAR(80)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_emoji VARCHAR(100)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_button_style VARCHAR(20) DEFAULT 'Secondary'`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS open_name_template   VARCHAR(100)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claimed_name_template VARCHAR(100)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS closed_name_template  VARCHAR(100)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS close_flow            JSONB`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS author_name           VARCHAR(255)`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS author_icon_url       TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS claim_enabled          BOOLEAN NOT NULL DEFAULT true`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS panel_version           INTEGER NOT NULL DEFAULT 1`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS author_url             TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS title_url              TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS footer_icon_url       TEXT`,
            `ALTER TABLE ticket_panels ADD COLUMN IF NOT EXISTS timestamp_enabled      BOOLEAN NOT NULL DEFAULT true`,
            `CREATE TABLE IF NOT EXISTS ticket_panel_components (
                id                      SERIAL PRIMARY KEY,
                panel_id                INTEGER NOT NULL REFERENCES ticket_panels(id) ON DELETE CASCADE,
                type                    VARCHAR(20) NOT NULL DEFAULT 'button',
                position                 INTEGER NOT NULL DEFAULT 0,
                label                   VARCHAR(80),
                style                   VARCHAR(20) DEFAULT 'Primary',
                emoji                   VARCHAR(100),
                action                  VARCHAR(20) NOT NULL DEFAULT 'ticket',
                url                     TEXT,
                placeholder              VARCHAR(150),
                min_values               INTEGER,
                max_values               INTEGER,
                claim_enabled            BOOLEAN NOT NULL DEFAULT true,
                ticket_configuration     JSONB,
                created_at              TIMESTAMP DEFAULT NOW(),
                updated_at              TIMESTAMP DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS ticket_panel_components_panel_idx ON ticket_panel_components (panel_id)`,
            `CREATE TABLE IF NOT EXISTS ticket_panel_options (
                id                      SERIAL PRIMARY KEY,
                component_id            INTEGER NOT NULL REFERENCES ticket_panel_components(id) ON DELETE CASCADE,
                label                   VARCHAR(80) NOT NULL,
                value                   VARCHAR(100) NOT NULL,
                description             VARCHAR(150),
                emoji                   VARCHAR(100),
                position                 INTEGER NOT NULL DEFAULT 0,
                ticket_configuration     JSONB,
                created_at              TIMESTAMP DEFAULT NOW(),
                updated_at              TIMESTAMP DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS ticket_panel_options_component_idx ON ticket_panel_options (component_id)`,
            `CREATE TABLE IF NOT EXISTS ticket_panel_messages (
                id                      SERIAL PRIMARY KEY,
                panel_id                INTEGER NOT NULL REFERENCES ticket_panels(id) ON DELETE CASCADE,
                guild_id                VARCHAR(50) NOT NULL,
                channel_id              VARCHAR(50) NOT NULL,
                message_id              VARCHAR(50) NOT NULL,
                panel_version            INTEGER NOT NULL DEFAULT 1,
                created_at              TIMESTAMP DEFAULT NOW(),
                updated_at              TIMESTAMP DEFAULT NOW(),
                UNIQUE (panel_id, channel_id, message_id)
            )`,
            `CREATE INDEX IF NOT EXISTS ticket_panel_messages_panel_idx ON ticket_panel_messages (panel_id)`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS panel_id     INTEGER REFERENCES ticket_panels(id) ON DELETE SET NULL`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS reason       TEXT`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS status       VARCHAR(20) NOT NULL DEFAULT 'open'`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claimed_by   VARCHAR(50)`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claimed_at   BIGINT`,
            `ALTER TABLE ticket_instances ADD COLUMN IF NOT EXISTS claim_history JSONB`,
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
        await this._loadComponents();
        await this._loadInstances();
        await this._loadClaimRows();
    }

    async _loadAll() {
        try {
            const panels = await this._fetchAllPanels();
            this._byPanel.clear();
            this._byMessage.clear();
            this._byGuild.clear();
            for (const panel of panels) this._indexPanel(panel);
            await this._loadRoleSettings();
            await this._loadComponents();
            await this._loadInstances();
            await this._loadClaimRows();
            console.log(`[TICKETS] Loaded ${panels.length} ticket panels.`);
        } catch (err) {
            console.error('[TICKETS] Failed to load panels:', err.message);
        }
    }

    /**
     * Load the per-panel role add/remove settings (TROLE_DATABASE_URL pool).
     * Dashboard saves land here and the manager re-reads on every cache reload,
     * so changes apply to open/close without a bot restart. Failures degrade
     * to an empty map (role mix features simply stay off..
     */
    async _loadRoleSettings() {
        try {
            await ensureTicketRoleTable();
            const res = await trolePool.query('SELECT * FROM ticket_role_settings');
            this._roleSettings.clear();
            for (const row of res.rows) {
                this._roleSettings.set(String(row.panel_id), {
                    open:  { enabled: !!row.open_enabled, channelName: row.open_name || null, showUserName: !!row.open_show_user, showCount: !!row.open_show_count, addRoleId: row.open_add_role || null, removeRoleId: row.open_remove_role || null },
                    close: { enabled: !!row.close_enabled, channelName: row.close_name || null, showUserName: !!row.close_show_user, showCount: !!row.close_show_count, addRoleId: row.close_add_role || null, removeRoleId: row.close_remove_role || null },
                });
            }
        } catch (err) {
            console.error('[TICKETS] Failed to load role settings:', err.message);
            this._roleSettings.clear();
        }
    }

    /**
     * Load the per-panel builder components + dropdown options. Dashboard saves
     * land here and the manager re-reads on every cache reload, so the panel
     * message's buttons/dropdowns pick up edits without a bot restart..
     */
    async _loadComponents() {
        try {
            await this._ensureTable();
            this._components.clear();
            const res = await ticketPool.query(`
                SELECT c.*, JSONB_AGG(
                    JSONB_BUILD_OBJECT(
                        'id', o.id,'label', o.label,'value', o.value,'description', o.description,
                        'emoji', o.emoji,'position', o.position,'ticket_configuration', o.ticket_configuration
                    ) ORDER BY o.position
                ) FILTER (WHERE o.id IS NOT NULL) AS _options
                FROM ticket_panel_components c
                LEFT JOIN ticket_panel_options o ON o.component_id = c.id
                GROUP BY c.id
                ORDER BY c.position, c.id
            `);
            for (const row of res.rows) {
                const opts = [];
                if (Array.isArray(row._options)) {
                    for (const o of row._options) opts.push(this._rowToComponentOption(o));
                }
                const comp = this._rowToComponent(row);
                comp.options = opts;
                if (!this._components.has(String(comp.panelId))) this._components.set(String(comp.panelId), []);
                this._components.get(String(comp.panelId)).push(comp);
            }
        } catch (err) {
            console.error('[TICKETS] Failed to load panel components:', err.message);
            this._components.clear();
        }
    }

    _rowToComponent(row) {
        const type = row.type === 'select' ? 'select' : 'button';
        return {
            id: Number(row.id),
            panelId: Number(row.panel_id),
            type,
            position: Number(row.position) || 0,
            label: row.label != null ? String(row.label) : null,
            style: type === 'button' ? row.style || 'Primary' : undefined,
            emoji: row.emoji || null,
            action: type === 'button' ? String(row.action || 'ticket') : 'ticket',
            url: type === 'button' ? row.url || null : undefined,
            placeholder: type === 'select' ? row.placeholder || null : undefined,
            minValues: type === 'select' ? Math.max(0, Number(row.min_values) || 0) : undefined,
            maxValues: type === 'select' ? Math.min(25, Math.max(1, Number(row.max_values) || 1)) : undefined,
            claimEnabled: row.claim_enabled !== false,
            ticketConfiguration: row.ticket_configuration || null,
            options: [],
        };
    }

    _rowToComponentOption(o) {
        return {
            id: Number(o.id),
            label: String(o.label || '' ),
            value: String(o.value || ''),
            description: o.description != null ? String(o.description) : null,
            emoji: o.emoji || null,
            position: Number(o.position) || 0,
            ticketConfiguration: o.ticket_configuration || null,
        };
    }

    /** All builder components for a panel (sorted by position). */
    getPanelComponents(panelId) {
        const list = this._components.get(String(panelId)) || [];
        return [...list].sort((a, b) => a.position - b.position);
    }

    /** Per-panel ticket role settings (never throws). */
    getRoleSettings(panelId) {
        const s = this._roleSettings.get(String(panelId));
        return s || { open:  { enabled: false, channelName: null, showUserName: false, showCount: false, addRoleId: null, removeRoleId: null }, close: { enabled: false, channelName: null, showUserName: false, showCount: false, addRoleId: null, removeRoleId: null } };
    }

    // Apply the given group's add/remove role to the ticket opener (fire-and-forget).
    async _applyRoleSettings(panel, member, group) {
        if (!panel || !member) return;
        const s = this.getRoleSettings(panel.id);
        const g = s[group];
        if (!g || !g.enabled) return;
        try {
            if (g.removeRoleId && member.roles?.cache?.has(g.removeRoleId)) {
                await member.roles.remove(g.removeRoleId).catch(() => {});
            }
            if (g.addRoleId && g.addRoleId !== g.removeRoleId) {
                await member.roles.add(g.addRoleId).catch(() => {});
            }
        } catch (err) {
            console.error(`[TICKETS] Role ${group} for panel ${panel.id}:`, err.message);
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

    /**
     * Merge claim state from the dedicated TCLAIM_DATABASE_URL pool into the
     * in-memory open instances, seeding a `ticket_claims` row for any
     * legacy instance that predates the claim table (carrying its current
     * claim columns over so pre-migration claims are not lost..
     */
    async _loadClaimRows() {
        try {
            await ensureTicketClaimsTable();
            const res = await tclaimPool.query('SELECT * FROM ticket_claims');
            const claimByChannel = new Map();
            for (const row of res.rows) {
                claimByChannel.set(String(row.channel_id), row);
            }
            for (const [channelId, instance] of this._byChannel) {
                const row = claimByChannel.get(String(channelId));
                if (row) {
                    instance.claimedBy = row.claimed_by || null;
                    instance.claimedAt = row.claimed_at ? Number(row.claimed_at) : null;
                    instance.claimHistory = _safeParseJsonArray(row.claim_history);
                } else {
                    await this._ensureClaimRow(instance).catch(() => {});
                }
            }
        } catch (err) {
            console.error('[TICKETS] Failed to load claim rows:', err.message);
        }
    }

    /**
     * Upsert a ticket's claim row in the TCLAIM pool. Used when opening a
     * ticket and when seeding legacy instances. Only the lifecycle fields
     * (channel/guild/user/status) are written — claim state is never overwritten
     * here (COALESCE keeps the live claim). This is deliberately NOT the
     * claim-state writer; TicketClaimService owns claim mutations.

     */
    async _ensureClaimRow(instance) {
        if (!instance || !instance.channelId) return;
        await ensureTicketClaimsTable();
        await tclaimPool.query(`
            INSERT INTO ticket_claims (channel_id, guild_id, user_id, status, claimed_by, claimed_at, claim_history)
            VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
            ON CONFLICT (channel_id) DO UPDATE SET
                guild_id = EXCLUDED.guild_id,
                user_id = EXCLUDED.user_id,
                status = EXCLUDED.status,
                claimed_by = COALESCE(ticket_claims.claimed_by, EXCLUDED.claimed_by),
                claimed_at = COALESCE(ticket_claims.claimed_at, EXCLUDED.claimed_at),
                claim_history = COALESCE(ticket_claims.claim_history, EXCLUDED.claim_history),
                updated_at = NOW()
        `, [
            String(instance.channelId), String(instance.guildId), String(instance.userId),
            (instance.status || 'open'),
            instance.claimedBy || null,  instance.claimedAt || null,
            JSON.stringify(instance.claimHistory || []),
        ]);
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
            authorName: row.author_name || null,
            authorUrl: row.author_url || null,
            authorIconUrl: row.author_icon_url || null,
            titleUrl: row.title_url || null,
            footerText: row.footer_text || null,
            footerIconUrl: row.footer_icon_url || null,
            timestampEnabled: row.timestamp_enabled !== false,
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
            closeButtonStyle: row.close_button_style || 'Danger',
            claimButtonLabel: row.claim_button_label || null,
            claimButtonEmoji: row.claim_button_emoji || null,
            claimButtonStyle: row.claim_button_style || 'Secondary',
            claimEnabled: row.claim_enabled !== false,
            panelVersion: Number(row.panel_version) || 1,
            openNameTemplate: row.open_name_template != null ? row.open_name_template : null,
            claimedNameTemplate: row.claimed_name_template != null ? row.claimed_name_template : null,
            closedNameTemplate: row.closed_name_template != null ? row.closed_name_template : null,
            closeFlow: row.close_flow != null ? normalizeCloseFlow(row.close_flow) : normalizeCloseFlow({}),
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
            claimedAt: row.claimed_at ? Number(row.claimed_at) : null,
            claimHistory: _safeParseJsonArray(row.claim_history),
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
                close_button_emoji, close_button_style, claim_button_label, claim_button_emoji, claim_button_style,
                claim_enabled, panel_version,
                open_name_template, claimed_name_template, closed_name_template,
                close_flow, enabled, created_by, created_at, updated_at,
                author_url, title_url, footer_icon_url, timestamp_enabled
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,NOW(),NOW(),$40,$41,$42,$43)
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
            panel.closeButtonLabel, panel.closeButtonEmoji, panel.closeButtonStyle,
            panel.claimButtonLabel, panel.claimButtonEmoji, panel.claimButtonStyle,
            panel.claimEnabled, panel.panelVersion,
            panel.openNameTemplate, panel.claimedNameTemplate, panel.closedNameTemplate,
            JSON.stringify(panel.closeFlow || {}),
            panel.enabled, panel.createdBy || null,
            panel.authorUrl, panel.titleUrl, panel.footerIconUrl, panel.timestampEnabled,
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
                close_button_emoji = $27, close_button_style = $28, claim_button_label = $29, claim_button_emoji = $30, claim_button_style = $31,
                claim_enabled = $32, panel_version = $33,
                open_name_template = $34, claimed_name_template = $35, closed_name_template = $36,
                close_flow = $37, enabled = $38, updated_at = NOW(),
                author_url = $39, title_url = $40, footer_icon_url = $41, timestamp_enabled = $42
            WHERE id = $1
        `, [
            id, norm.name, norm.channelId || null, norm.messageId || null, norm.messageType,
            norm.title, norm.description, norm.color, norm.thumbnailUrl, norm.imageUrl,
            norm.footerText, norm.content, norm.buttonLabel, norm.buttonStyle, norm.buttonEmoji,
            norm.category, norm.ticketName, JSON.stringify(norm.supportRoleIds),
            JSON.stringify(norm.pingRoleIds), norm.ticketCategoryId,
            norm.cooldownSeconds, norm.maxOpenPerUser, norm.askReason,
            norm.reasonPlaceholder, norm.welcomeMessage,
            norm.closeButtonLabel, norm.closeButtonEmoji, norm.closeButtonStyle,
            norm.claimButtonLabel, norm.claimButtonEmoji, norm.claimButtonStyle,
            norm.claimEnabled, norm.panelVersion,
            norm.openNameTemplate, norm.claimedNameTemplate, norm.closedNameTemplate,
            JSON.stringify(norm.closeFlow || {}),
            norm.enabled,
            norm.authorUrl, norm.titleUrl, norm.footerIconUrl, norm.timestampEnabled,
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
            color: 1, thumbnailUrl: 1, imageUrl: 1, authorName: 1, authorIconUrl: 1,
            footerText: 1, content: 1,
            buttonLabel: 1, buttonStyle: 1, buttonEmoji: 1, category: 1, ticketName: 1,
            supportRoleIds: 1, pingRoleIds: 1, ticketCategoryId: 1, cooldownSeconds: 1,
            maxOpenPerUser: 1, askReason: 1, reasonPlaceholder: 1, welcomeMessage: 1,
            closeButtonLabel: 1, closeButtonEmoji: 1, closeButtonStyle: 1,
            claimButtonLabel: 1,
            claimButtonEmoji: 1,
            claimButtonStyle: 1,
            claimEnabled: 1,
            panelVersion: 1,
            openNameTemplate: 1, claimedNameTemplate: 1,
            closedNameTemplate: 1, closeFlow: 1, enabled: 1, createdBy: 1,
        };
    }

    _normalizePanel(data, keepUndefined = false) {
        const base = keepUndefined ? {} : { ...DEFAULT_PANEL };
        const out = { ...base, ...(data || {}) };
        out.name = (out.name == null ? '' : String(out.name)).trim() || 'Support Ticket';
        out.messageType = VALID_MESSAGE_TYPES.has(out.messageType) ? out.messageType : 'embed';
        out.buttonStyle = VALID_BUTTON_STYLES.has(out.buttonStyle) ? out.buttonStyle : 'Primary';
        out.closeButtonStyle = VALID_BUTTON_STYLES.has(out.closeButtonStyle) ? out.closeButtonStyle : 'Danger';
        out.claimButtonStyle = VALID_BUTTON_STYLES.has(out.claimButtonStyle) ? out.claimButtonStyle : 'Secondary';
        out.claimEnabled = out.claimEnabled !== false;
        out.panelVersion = Math.max(1, parseInt(out.panelVersion, 10) || 1);
        out.color = /^#[0-9a-fA-F]{6}$/.test(out.color) ? out.color : '#5865F2';
        out.supportRoleIds = Array.isArray(out.supportRoleIds) ? out.supportRoleIds.map(String) : [];
        out.pingRoleIds = Array.isArray(out.pingRoleIds) ? out.pingRoleIds.map(String) : [];
        out.cooldownSeconds = Math.max(0, parseInt(out.cooldownSeconds, 10) || 0);
        out.maxOpenPerUser = Math.max(0, parseInt(out.maxOpenPerUser, 10) || 1);
        out.askReason = !!out.askReason;
        out.enabled = out.enabled !== false;
        out.timestampEnabled = out.timestampEnabled !== false;
        for (const f of ['buttonEmoji', 'closeButtonEmoji', 'claimButtonEmoji', 'thumbnailUrl', 'imageUrl', 'authorName', 'authorIconUrl', 'authorUrl', 'titleUrl', 'footerIconUrl']) {
            if (out[f] != null) out[f] = String(out[f]).trim() || null;
        }
        // Enforce Discord embed limits + URL validity so a crafted/stale panel
        // row can never make the EmbedBuilder below throw on send.
        if (out.title != null) out.title = String(out.title).trim().slice(0, 256) || null;
        if (out.description != null) out.description = String(out.description).trim().slice(0, 4096) || null;
        if (out.footerText != null) out.footerText = String(out.footerText).trim().slice(0, 2048) || null;
        if (out.authorName != null) out.authorName = String(out.authorName).trim().slice(0, 255) || null;
        for (const u of ['thumbnailUrl', 'imageUrl', 'authorIconUrl', 'authorUrl', 'titleUrl', 'footerIconUrl']) {
            if (out[u] == null) continue;
            const v = String(out[u]).trim();
            out[u] = (v && (/^https?:\/\//i.test(v) || /^data:image\//i.test(v))) ? v : null;
        }
        // Button labels: trim to null when empty/whitespace. An empty label
        // means "no label" — claimButtonLabel null => no claim button rendered.
        // Non-empty labels (incl. DEFAULT_PANEL's 'Open Ticket'/'Close Ticket')
        // are preserved; the builders fall back to defaults when null.
        for (const f of ['buttonLabel', 'closeButtonLabel', 'claimButtonLabel']) {
            if (out[f] != null) out[f] = String(out[f]).trim() || null;
        }
        // Name templates: keepUndefined=false applies DEFAULT_PANEL defaults; trim
        // to null (null = no rename for that state). Only coerce when present.
        for (const f of ['openNameTemplate', 'claimedNameTemplate', 'closedNameTemplate']) {
            if (out[f] != null) out[f] = String(out[f]).trim().slice(0, 100) || null;
        }
        out.closeFlow = normalizeCloseFlow(out.closeFlow);
        return out;
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    /** Build the panel message payload (embed or plain) + the open button row(s). */
    buildPanelMessage(panel) {
        const components = this._buildPanelRows(panel);
        if (panel.messageType === 'plain') {
            return {
                content: panel.content || panel.description || 'Click the button below to open a support ticket.',
                components,
            };
        }
        const embed = new EmbedBuilder();
        embed.setColor(panel.color || '#5865F2');
        if (panel.title) embed.setTitle(panel.title);
        if (panel.titleUrl) embed.setURL(panel.titleUrl);
        if (panel.description) embed.setDescription(panel.description);
        if (panel.authorName) {
            const author = { name: panel.authorName };
            if (panel.authorUrl) author.url = panel.authorUrl;
            if (panel.authorIconUrl) author.iconURL = panel.authorIconUrl;

            embed.setAuthor(author);
        }
        if (panel.thumbnailUrl) embed.setThumbnail(panel.thumbnailUrl);
        if (panel.imageUrl) embed.setImage(panel.imageUrl);
        if (panel.footerText || panel.footerIconUrl) {

            const footer = { text: panel.footerText || '' };
            if (panel.footerIconUrl) footer.iconURL = panel.footerIconUrl;

            embed.setFooter(footer);
        }
        if (panel.timestampEnabled !== false) embed.setTimestamp();
        return { content: panel.content || null, embeds: [embed], components };
    }

    /**
     * Build the panel message's action rows from the DB-backed builder components..
     * Falls back to a single legacy open button when no builder components exist,
     * so existing panels keep working unchanged..
     */
    _buildPanelRows(panel) {
        const comps = this.getPanelComponents(panel?.id).filter(c => c.type === 'button' || c.type === 'select');
        if (!panel || !comps.length) {
            const openBtn = new ButtonBuilder()
                .setCustomId(`ticketpanel:open:${panel?.id ?? '0'}`)
                .setLabel(panel?.buttonLabel || 'Open Ticket')
                .setStyle(ButtonStyle[panel?.buttonStyle] || ButtonStyle.Primary);
            if (panel?.buttonEmoji) openBtn.setEmoji(panel.buttonEmoji);
            return [new ActionRowBuilder().addComponents(openBtn)];
        }

        const rows = [];
        let buttonsRow = null;
        const flushButtons = () => {
            if (buttonsRow && buttonsRow.components.length) rows.push(buttonsRow);
            buttonsRow = null;
        };
        for (const c of [...comps].sort((a, b) => a.position - b.position || a.id - b.id)) {
            if (c.type === 'select') {
                flushButtons();
                const sel = this._buildSelect(c);
                if (sel) rows.push(new ActionRowBuilder().addComponents(sel));
                continue;
            }
            const btn = this._buildButton(c);
            if (!btn) continue;
            if (!buttonsRow || buttonsRow.components.length >= 5) {
                flushButtons();
                buttonsRow = new ActionRowBuilder();
            }
            buttonsRow.addComponents(btn);
        }
        flushButtons();
        return rows.slice(0, 5);
    }

    _buildButton(c) {
        try {
            let btn;
            if (c.action === 'link' && c.url) {
                btn = new ButtonBuilder()
                    .setLabel(c.label || 'Open')
                    .setStyle(ButtonStyle.Link)
                    .setURL(c.url);
                if (c.emoji) btn.setEmoji(c.emoji);
            } else {
                btn = new ButtonBuilder()
                    .setCustomId(`ticketpanel:${c.id}:button`)
                    .setLabel(c.label || 'Open Ticket')
                    .setStyle(ButtonStyle[c.style] || ButtonStyle.Primary);
                if (c.emoji) btn.setEmoji(c.emoji);
            }
            return btn;
        } catch (err) {
            console.error('[TICKETS] Error building button component:', err.message);
            return null;
        }
    }

    _buildSelect(c) {
        try {
            const opts = (c.options || []).sort((a, b) => a.position - b.position || a.id - b.id);
            if (!opts.length) return null;
            const sel = new StringSelectMenuBuilder()
                .setCustomId(`ticketpanel:${c.id}:select`)
                .setPlaceholder(c.placeholder || 'Select an option');
            if (c.minValues != null) sel.setMinValues(Math.min(opts.length, Math.max(0, c.minValues)));
            if (c.maxValues != null) sel.setMaxValues(Math.min(opts.length, Math.max(1, c.maxValues)));
            const options = opts.slice(0, 25).map(o => {
                const ob = new StringSelectMenuOptionBuilder()
                    .setLabel(String(o.label || 'Option').slice(0, 100))
                    .setValue(`opt:${o.id}`);
                if (o.description) ob.setDescription(String(o.description).slice(0, 100));
                if (o.emoji) ob.setEmoji(o.emoji);
                return ob;
            });
            sel.addOptions(options);
            return sel;
        } catch (err) {
            console.error('[TICKETS] Error building select component:', err.message);
            return null;
        }
    }

    /** Build the in-ticket control message (close/claim/unclaim/transfer/rename buttons). */
    buildControlMessage(panel, opener, instance = null) {
        const closeBtn = new ButtonBuilder()
            .setCustomId('ticketpanel:close')
            .setLabel(panel.closeButtonLabel || 'Close Ticket')
            .setStyle(ButtonStyle[panel.closeButtonStyle] || ButtonStyle.Danger);
        if (panel.closeButtonEmoji) closeBtn.setEmoji(panel.closeButtonEmoji);
        const rows = [new ActionRowBuilder().addComponents(closeBtn)];
        // Claim management lives in a second row — but only when the panel
        // has a claim button configured (claimButtonLabel non-empty; the dashboard
        // uses a null/empty label to hide the claim feature entirely).
        // Soft-claim: other support staff can still view/reply — these
        // buttons only manage ownership.

        const extra = [];
        // Claim method toggle: the panel's claim tab switch (claimEnabled, default
        // on) gates whether the claim control-row is available at all — independent
        // of the claim button label (which hides just the claim button when blank)..
        const claimGate = panel && panel.claimEnabled !== false;
        const claimEnabled = claimGate && !!(panel && panel.claimButtonLabel);
        const claimedBy = claimEnabled && instance && instance.claimedBy ? String(instance.claimedBy) : null;
        if (claimEnabled) {
            if (claimedBy) {
                extra.push(new ButtonBuilder()
                    .setCustomId('ticketpanel:unclaim')
                    .setLabel('Unclaim')
                    .setStyle(ButtonStyle.Secondary)
                    .setEmoji('✋'));
                extra.push(new ButtonBuilder()
                    .setCustomId('ticketpanel:transfer')
                    .setLabel('Transfer')
                    .setStyle(ButtonStyle.Secondary)
                    .setEmoji('🔄'));
            } else {
                const claimBtn = new ButtonBuilder()
                    .setCustomId('ticketpanel:claim')
                    .setLabel(panel.claimButtonLabel || 'Claim Ticket')
                    .setStyle(ButtonStyle[panel.claimButtonStyle] || ButtonStyle.Secondary);
                if (panel.claimButtonEmoji) claimBtn.setEmoji(panel.claimButtonEmoji);
                extra.push(claimBtn);
            }
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
            );

        // Claim status block — unclaimed shows "⚪ Unclaimed / Nobody"; a
        // claimed ticket shows the claimant (mention) + claimed-at timestamp.

        const claimedBy2 = instance && instance.claimedBy ? String(instance.claimedBy) : null;
        if (claimedBy2) {
            const claimedAtSec = instance && instance.claimedAt ? Math.floor(Number(instance.claimedAt) / 1000) : null;
            embed.addFields(
                { name: '🔵 Claim Status', value: 'Claimed', inline: true },
                { name: '👤 Claimed By', value: `<@${claimedBy2}>`, inline: true },
            );
            if (claimedAtSec) embed.addFields({ name: '🕐 Claimed At', value: `<t:${claimedAtSec}:R>`, inline: true });
        } else {
            embed.addFields(
                { name: '⚪ Claim Status', value: 'Unclaimed', inline: true },
                { name: '👤 Claimed By', value: 'Nobody', inline: true },
            );
        }

        embed.setTimestamp();
        return { embeds: [embed], components: rows };
    }

    /**
     * Build the Yes/No confirmation row shown when "Close" is pressed.
     * Replaces the control message's components so the user must confirm
     * before the ticket is actually closed.
     */
    buildCloseConfirmComponents(panel) {
        const cf = panel.closeFlow || normalizeCloseFlow({});
        const yes = new ButtonBuilder()
            .setCustomId('ticketpanel:closeconfirm:yes')
            .setLabel(cf.confirmYes.label)
            .setStyle(ButtonStyle[cf.confirmYes.style] || ButtonStyle.Success);
        if (cf.confirmYes.emoji) yes.setEmoji(cf.confirmYes.emoji);
        const no = new ButtonBuilder()
            .setCustomId('ticketpanel:closeconfirm:no')
            .setLabel(cf.confirmNo.label)
            .setStyle(ButtonStyle[cf.confirmNo.style] || ButtonStyle.Danger);
        if (cf.confirmNo.emoji) no.setEmoji(cf.confirmNo.emoji);
        return [new ActionRowBuilder().addComponents(yes, no)];
    }

    /**
     * Build the closed-ticket control message: the (optional, red) close
     * embed + the 3 post-close action buttons (Transcript / Reopen / Delete).
     * All button labels, emojis, and colours come from the panel's closeFlow.
     */
    buildClosedControlMessage(panel, ctx = {}) {
        const cf = panel.closeFlow || normalizeCloseFlow({});
        const buttons = cf.buttons || normalizeCloseFlow({}).buttons;
        const mk = (key, customId) => {
            const b = buttons[key];
            const btn = new ButtonBuilder()
                .setCustomId(customId)
                .setLabel(b.label)
                .setStyle(ButtonStyle[b.style] || ButtonStyle.Secondary);
            if (b.emoji) btn.setEmoji(b.emoji);
            return btn;
        };
        const row = new ActionRowBuilder().addComponents(
            mk('transcript', 'ticketpanel:transcript'),
            mk('reopen', 'ticketpanel:reopen'),
            mk('delete', 'ticketpanel:delete'),
        );
        const embed = new EmbedBuilder()
            .setColor(cf.closeEmbed.color || '#ED4245')
            .setTitle(renderCloseText(cf.closeEmbed.title, ctx) || 'Ticket Closed')
            .setDescription(renderCloseText(cf.closeEmbed.description, ctx))
            .setTimestamp();
        const footerText = renderCloseText(cf.closeEmbed.footer, ctx);
        if (footerText) embed.setFooter({ text: footerText });
        return { embeds: [embed], components: [row] };
    }

    /** Resolve a panel for an instance (with fallback for missing panel). */
    _panelForInstance(instance) {
        return instance && instance.panelId ? this.getPanelById(instance.panelId) : null;
    }

    // ── Sending / updating panel messages ───────────────────────────────────

    /**
     * Render a ticket channel name from a status template.
     * Placeholders: {name} (panel.ticketName or opener username), {username},
     * {id} (opener id), {panel} (panel.name). Returns null when the template
     * is empty/null (= "don't rename for this state").
     */
    _renderTicketName(template, panel, opener, opts = {}) {
        if (!template) return null;
        const showUser = opts.showUserName !== false;
        const showCount = opts.showCount !== false;
        const username = showUser ? (opener?.username || opener?.displayName || 'user') : '';
        const nameBase = panel?.ticketName || (showUser ? username : '');
        const count = showCount ? Number(opts.count) || 0 : '';
        let out = String(template)
            .replace(/\{name\}/g, nameBase)
            .replace(/\{username\}/g, username)
            .replace(/\{id\}/g, showUser ? (opener?.id || '') : '')
            .replace(/\{panel\}/g, panel?.name || '')
            .replace(/\{count\}/g, String(count));
        // Discord channel names: lowercase, no spaces, max 100 chars.
        out = out.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '').slice(0, 100);
        return out || null;
    }

    /** Apply a status name template to a ticket channel (fire-and-forget). */
    async _setTicketName(channel, template, panel, opener, opts = {}) {
        const name = this._renderTicketName(template, panel, opener, opts);
        if (!name || !channel) return;
        try {
            const current = channel.name;
            if (current === name) return;
            await channel.setName(name);
        } catch (err) {
            console.error('[TICKETS] Failed to rename ticket channel:', err.message);
        }
    }

    /**
     * Resolve the effective channel-name template + attribute opts for a state.
     * Prefers the panel's Ticket-tab role settings (TROLE pool) when that state's
     * toggle is on; otherwise falls back to the legacy per-state template.

    _troleNameState(panel, state, fallbackTemplate) {
        const s = this.getRoleSettings(panel?.id);
        const g = s?.[state];
        if (g && g.enabled) {
            return {
                template: g.channelName || null,
                showUserName: g.showUserName !== false,
                showCount: g.showCount !== false,
            };
        }
        return { template: fallbackTemplate || null, showUserName: false, showCount: false };
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

    async handleOpen(interaction, panel, component = null, option = null) {
        const guild = interaction.guild;
        const member = interaction.member;
        const userId = interaction.user.id;
        if (!panel || !panel.enabled) {
            return interaction.reply({ content: 'This ticket panel is currently disabled.', ephemeral: true });
        }
        if (panel.maxOpenPerUser > 0 && this.countOpenTickets(guild.id, userId) >= panel.maxOpenPerUser) {


            return interaction.reply({ content: `You already have ${panel.maxOpenPerUser} open ticket(s. Please close one before opening another.`, ephemeral: true });
        }

        // Ask-for-reason flow: show a modal asking the member why they are opening a ticket..
        // (the ticket itself is created on submit when the panel requests it)..
        // Button interactions carry no interaction.options., so the old
        // `interaction.options?.getString?.('reason')` path silently never ran..
        const cfg = this._ticketConfigFor(panel, (component && component.ticketConfiguration) || (option && option.ticketConfiguration));
        const ref = component ? { componentId: component.id, optionId: option ? option.id : null } : null;
        if (panel.askReason) {
            return this._showOpenReasonModal(interaction, panel, cfg, ref);
        }

        return this._openTicket(interaction, panel, guild, member, userId, null, cfg);
    }

    /**
     * Open a ticket from a specific panel component (button or select option)..
     * The component is resolved from the DB-backed cache by its stable id —
     * never from the interaction's customId payload — and cross-guild usage is
     * rejected by checking the component's panel belongs to the interaction guild..
     * Supported customId forms:
     *   button ticketpanel:<componentId>:button
     *   select ticketpanel:<componentId>:select   (value "opt:<optionId>")
     */
    async handleComponentOpen(interaction, componentId, optionId = null) {
        const comp = this.findComponentById(componentId);
        if (!comp) {
            return interaction.reply({ content: 'This ticket input could not be found. It may have been deleted.', ephemeral: true });
        }
        const panel = this.getPanelById(comp.panelId);
        const guildOk = !panel || panel.guildId == null || String(panel.guildId) === String(interaction.guild?.id);
        if (!panel || !guildOk) {
            return interaction.reply({ content: 'This ticket panel could not be found. It may have been deleted.', ephemeral: true });
        }
        let option = null;
        if (optionId) {
            option = (comp.options || []).find(o => String(o.id) === String(optionId)) || null;
            if (!option) {
                return interaction.reply({ content: 'This ticket option could not be found. It may have been deleted.', ephemeral: true });
            }
        }
        return this.handleOpen(interaction, panel, comp, option);
    }

    /** Find a builder component by id across the cache (never throws). */
    findComponentById(componentId) {
        const target = String(componentId);
        for (const list of this._components.values()) {
            const hit = list.find(c => String(c.id) === target);
            if (hit) return hit;
        }
        return null;
    }

    /**
     * Resolve the component (and option) from the manager's DB-backed cache..
     * Returns null when the panel/component/option doesn't belong to this guild..
     */
    _resolveInput(panel, componentId, optionId = null) {
        if (!panel || !componentId) return null;
        const comp = this.getPanelComponents(panel.id).find(c => String(c.id) === String(componentId));
        if (!comp) return null;
        if (optionId) {
            const opt = (comp.options || []).find(o => String(o.id) === String(optionId));
            if (!opt) return null;
            return { component: comp, option: opt };
        }
        return { component: comp, option: null };
    }

    /**
     * Resolve a per-input (button/option) ticket configuration into a panel
     * patch. Components/options may carry an embedded config object — it is
     * applied over the panel's own settings for that ticket only (panel+config..
     * The panel (and its configs) always come from the DB,, never the customId..
     */
    _ticketConfigFor(panel, src) {
        const c = (src && typeof src === 'object' && !Array.isArray(src)) ? src : null;
        if (!c) return null;
        const out = {};
        const remap = {
            category: 'category',
            ticketName: 'ticketName',
            ticketCategoryId: 'ticketCategoryId',
            supportRoleIds: 'supportRoleIds',
            pingRoleIds: 'pingRoleIds',
            cooldown_seconds: 'cooldownSeconds',
            cooldownSeconds: 'cooldownSeconds',
            max_open_per_user: 'maxOpenPerUser',
            maxOpenPerUser: 'maxOpenPerUser',
            ask_reason: 'askReason',
            askReason: 'askReason',
            reason_placeholder: 'reasonPlaceholder',
            reasonPlaceholder: 'reasonPlaceholder',
            welcome_message: 'welcomeMessage',
            welcomeMessage: 'welcomeMessage',
            channel_name_template: 'openNameTemplate',
            openNameTemplate: 'openNameTemplate',
            claimedNameTemplate: 'claimedNameTemplate',
            closedNameTemplate: 'closedNameTemplate',
        };
        for (const k of Object.keys(c)) {
            const key = remap[k] || k;
            out[key] = c[k];
        }
        const merged = { ...panel, ...out };
        for (const f of ['supportRoleIds', 'pingRoleIds']) {
            if (Array.isArray(merged[f])) merged[f] = merged[f].map(String);
        }
        if (merged.ticketCategoryId == null) delete merged.ticketCategoryId;
        if (merged.askReason == null) merged.askReason = false;
        merged.enabled = panel.enabled !== false;
        return this._normalizePanel(merged, true);
    }

    /** Show a modal asking for the ticket reason (used when panel.askReason)). */
    async _showOpenReasonModal(interaction, panel, cfg = null, ref = null) {
        const refSuffix = ref && ref.componentId ? `:${ref.componentId}${ref.optionId ? `:${ref.optionId}` : ''}` : '';
        const modal = new ModalBuilder()
            .setCustomId('ticketpanel:reason:' + String(panel.id) + refSuffix)
            .setTitle('Open ' + (panel.name ? String(panel.name).slice(0, 42) : 'Ticket'));
        const input = new TextInputBuilder()
            .setCustomId('ticket-reason')
            .setLabel('Reason for opening this ticket')
            .setStyle(TextInputStyle.Paragraph)
            .setRequired(true)
            .setMaxLength(500)
            .setPlaceholder(panel.reasonPlaceholder || 'Briefly describe your issue');
        modal.addComponents(new ActionRowBuilder().addComponents(input));
        try {
            return await interaction.showModal(modal);
        } catch (err) {
            console.error('[TICKETS] Error showing ticket reason modal:', err);
            return interaction.reply({ content: 'There was an error opening the ticket form. Please try again.', ephemeral: true });
        }
    }

    /** Handle the reason modal submit, then open the ticket. */
    async handleOpenReasonSubmit(interaction) {
        const m = /^ticketpanel:reason:(\d+)(?::(\d+))?(?::(\d+))?$/.exec(interaction.customId);
        const panel = m ? this.getPanelById(m[1]) : null;
        if (!panel) {
            return interaction.reply({ content: 'This ticket panel could not be found. It may have been deleted.', ephemeral: true });
        }
        let reason = interaction.fields?.getTextInputValue('ticket-reason');
        if (reason == null) reason = interaction.fields?.get('ticket-reason')?.value;
        reason = reason && String(reason.trim());
        if (!reason) {
            return interaction.reply({ content: 'A reason is required to open this ticket.', ephemeral: true });
        }

        // Re-check disabled + the per-user open limit: state may have changed while the modal was open.
        if (!panel.enabled) {
            return interaction.reply({ content: 'This ticket panel is currently disabled.', ephemeral: true });
        }
        const guild = interaction.guild;
        const userId = interaction.user.id;
        if (panel.maxOpenPerUser > 0 && this.countOpenTickets(guild.id, userId) >= panel.maxOpenPerUser) {
            return interaction.reply({ content: `You already have ${panel.maxOpenPerUser} open ticket(s. Please close one before opening another.`, ephemeral: true });
        }

        // Re-resolve the input from the DB (never from the custom id) and load its
        // per-input ticket configuration.so the resulting ticket honors the builder config..
        const ref = m && (m[2] || m[3]) ? this._resolveInput(panel, m[2], m[3]) : null;
        const cfg = this._ticketConfigFor(panel, (ref && (ref.component?.ticketConfiguration || ref.option?.ticketConfiguration)) || null);
        return this._openTicket(interaction, panel, guild, interaction.member, userId, reason, cfg);
    }

    /** Open the ticket (shared by handleOpen and handleOpenReasonSubmit)). */
    async _openTicket(interaction, panel, guild, member, userId, reason, cfg = null) {
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
                claimedAt: null,
                claimHistory: [],
                createdAt: Date.now(),
            };
            await this._saveInstance(instance);
            await this._ensureClaimRow(instance).catch(() => {});
            this._byChannel.set(ticketChannel.id, instance);

            // Apply the panel's "on open" role add/remove to the ticket author.

            await this._applyRoleSettings(panel, member, 'open');

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

    /**
     * Close button: instead of closing immediately, swap the control
     * message for a Yes/No confirmation row. The actual close happens in
     * handleCloseConfirm (yes). 'No' restores the open control message.
     */
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
        const panel = this._panelForInstance(instance);
        try {
            const components = this.buildCloseConfirmComponents(panel || {});
            const embed = new EmbedBuilder()
                .setColor('#ED4245')
                .setTitle('Close this ticket?')
                .setDescription('Are you sure you want to close this ticket? Choose an option below.')
                .setTimestamp();
            await interaction.update({ embeds: [embed], components }).catch(() =>
                interaction.reply({ embeds: [embed], components })
            );
        } catch (err) {
            console.error('[TICKETS] Error prompting close confirm:', err);
            return interaction.reply({ content: 'There was an error. Please try again.', ephemeral: true });
        }
    }

    /** Build the open-state control payload for restore-after-cancel/reopen. */
    _openControlPayload(panel, opener, instance = null) {
        const base = this.buildControlMessage(panel || {}, opener, instance);
        return base;
    }

    async _resolveOpener(interaction, instance) {
        const openerMember = await interaction.guild.members.fetch(instance.userId).catch(() => null);
        return openerMember?.user || { id: instance.userId, username: openerMember?.displayName || 'user' };
    }

    /** Yes → actually close: mark closed, show the (optional) close embed + 3 buttons. */
    async handleCloseConfirm(interaction, choice) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const panel = this._panelForInstance(instance);
        // 'No' → restore the open control message and stop.
        if (choice !== 'yes') {
            try {
                const opener = await this._resolveOpener(interaction, instance);
                const payload = this._openControlPayload(panel, opener);
                await interaction.update(payload).catch(() =>
                    interaction.reply(payload)
                );
            } catch (err) {
                console.error('[TICKETS] Error restoring open control message:', err);
                return interaction.reply({ content: 'There was an error. Please try again.', ephemeral: true });
            }
            return;
        }
        // 'Yes' → close the ticket.
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
            const opener = await this._resolveOpener(interaction, instance);
            const ctx = {
                moderator: interaction.user.toString(),
                author: opener.toString(),
                panel: panel ? panel.name : '',
                reason: instance.reason || '—',
                timestamp: instance.closedAt,
            };
            const closedPayload = this.buildClosedControlMessage(panel || {}, ctx);
            await interaction.update(closedPayload).catch(() =>
                interaction.reply(closedPayload)
            );
            this._byChannel.delete(channelId);
            await this._saveInstance(instance);
            await this._ensureClaimRow(instance).catch(() => {});
            // Apply the closed-status channel name template.
            if (panel) {
                await this._setTicketName(interaction.channel, panel.closedNameTemplate, panel, opener);
                // Apply the panel's "on close" role add/remove to the ticket author.

                const openerMember = await interaction.guild.members.fetch(instance.userId).catch(() => null);
                await this._applyRoleSettings(panel, openerMember, 'close');
            }
        } catch (err) {
            console.error('[TICKETS] Error closing ticket:', err);
            return interaction.reply({ content: 'There was an error closing this ticket.', ephemeral: true });
        }
    }

    /** Generate a text transcript of the ticket channel's messages and post it
     *  to the panel's configured transcript channel (dashboard-only). */
    async handleTranscript(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const isAdmin = interaction.member?.permissions?.has(PermissionFlagsBits.Administrator);
        const isSupport = await this._isSupportMember(interaction, instance);
        const isOwner = interaction.user.id === instance.userId;
        if (!isOwner && !isAdmin && !isSupport) {
            return interaction.reply({ content: 'You do not have permission to create a transcript.', ephemeral: true });
        }
        const panel = this._panelForInstance(instance);
        const cf = (panel && panel.closeFlow) || normalizeCloseFlow({});
        const transcriptChannelId = cf.transcript && cf.transcript.enabled ? cf.transcript.channelId : null;
        if (!transcriptChannelId) {
            return interaction.reply({ content: 'No transcript channel is configured for this panel. Set one in the dashboard (Tickets tab → Transcript settings).', ephemeral: true });
        }
        await interaction.deferReply({ ephemeral: true }).catch(() => {});
        try {
            const channel = interaction.channel;
            // Fetch up to ~1000 most recent messages (paginate 100 at a time).
            let all = [];
            let before = undefined;
            for (let i = 0; i < 10; i++) {
                const batch = await channel.messages.fetch({ limit: 100, ...(before ? { before } : {}) }).catch(() => null);
                if (!batch || batch.size === 0) break;
                all = all.concat([...batch.values()]);
                before = batch.last().id;
                if (batch.size < 100) break;
            }
            // Oldest first.
            all.reverse();
            const opener = await this._resolveOpener(interaction, instance);
            const header = [
                `── Ticket Transcript ──`,
                `Panel: ${panel ? panel.name : 'Unknown'}`,
                `Ticket author: ${opener} (${instance.userId})`,
                `Opened: <t:${Math.floor(Number(instance.createdAt) / 1000)}:F>`,
                instance.closedAt ? `Closed: <t:${Math.floor(Number(instance.closedAt) / 1000)}:F>` : null,
                instance.closedBy ? `Closed by: <@${instance.closedBy}>` : null,
                `Messages: ${all.length}`,
                `────────`,
            ].filter(Boolean).join('\n');
            const lines = all.map(m => {
                const ts = new Date(m.createdTimestamp).toISOString();
                const author = m.author ? `${m.author.tag} (${m.author.id})` : 'Unknown';
                const body = m.content || (m.attachments && m.attachments.size ? `[${m.attachments.size} attachment(s)]` : '');
                return `[${ts}] ${author}: ${body}`;
            });
            const fullText = `${header}\n\n${lines.join('\n')}`.slice(0, 1800);
            const targetChannel = await this.client.channels.fetch(transcriptChannelId).catch(() => null);
            if (!targetChannel) {
                return interaction.editReply({ content: 'The configured transcript channel is no longer available.' });
            }
            const tEmbed = new EmbedBuilder()
                .setColor(cf.closeEmbed.color || '#5865F2')
                .setTitle(`📝 Transcript: ${panel ? panel.name : 'Ticket'}`)
                .setDescription(`Ticket author: ${opener}\nChannel: ${channel}\nMessages: ${all.length}\nClosed by: ${instance.closedBy ? `<@${instance.closedBy}>` : '—'}`)
                .setTimestamp();
            await targetChannel.send({ embeds: [tEmbed] }).catch(() => {});
            // Post the transcript text in chunks (Discord 2000-char limit).
            const chunkSize = 1900;
            for (let i = 0; i < fullText.length; i += chunkSize) {
                await targetChannel.send({ content: '\u0060\u0060\u0060' + fullText.slice(i, i + chunkSize) + '\u0060\u0060\u0060' }).catch(() => {});
            }
            return interaction.editReply({ content: `✅ Transcript posted to <#${transcriptChannelId}> (${all.length} messages).` });
        } catch (err) {
            console.error('[TICKETS] Error generating transcript:', err);
            return interaction.editReply({ content: 'There was an error generating the transcript: ' + (err.message || err) });
        }
    }

    /** Delete the ticket channel immediately (after confirmation prompt). */
    async handleDelete(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const isAdmin = interaction.member?.permissions?.has(PermissionFlagsBits.Administrator);
        const isSupport = await this._isSupportMember(interaction, instance);
        if (!isAdmin && !isSupport) {
            return interaction.reply({ content: 'Only support staff or administrators can delete this ticket.', ephemeral: true });
        }
        try {
            await interaction.reply({ content: '🗑️ Deleting this ticket channel…', ephemeral: true }).catch(() => {});
            await this._saveInstance({ ...instance, status: 'deleted' });
            await this._ensureClaimRow({ ...instance, status: 'deleted' }).catch(() => {});
            this._byChannel.delete(channelId);
            await interaction.channel.delete('Ticket deleted via panel button').catch(() => {});
        } catch (err) {
            console.error('[TICKETS] Error deleting ticket:', err);
            return interaction.reply({ content: 'There was an error deleting this ticket.', ephemeral: true }).catch(() => {});
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
            const panel = this._panelForInstance(instance);
            const opener = await this._resolveOpener(interaction, instance);
            // Restore the full open-state control message (close + claim + rename).
            const payload = this._openControlPayload(panel, opener);
            await interaction.update(payload).catch(() =>
                interaction.reply(payload)
            );
            this._byChannel.set(channelId, instance);
            await this._saveInstance(instance);
            await this._ensureClaimRow(instance).catch(() => {});
            // Re-apply the open-status channel name template.
            if (panel) {
                await this._setTicketName(interaction.channel, panel.openNameTemplate, panel, opener);
            }
        } catch (err) {
            console.error('[TICKETS] Error reopening ticket:', err);
            return interaction.reply({ content: 'There was an error reopening this ticket.', ephemeral: true });
        }
    }

    /** Claim the ticket for the invoking staff member (atomic + permission-checked). */
    async handleClaim(interaction) {
        const channelId = interaction.channel.id;

        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const panel = this._panelForInstance(instance);
        // Claim-method toggle:: tickets created from a panel with claimEnabled = false
        // (the dashboard Claim tab switch) are not claimable via the button route..
        if (panel && panel.claimEnabled === false) {
            return interaction.reply({ content: 'Claiming is disabled for this ticket panel.', ephemeral: true });
        }
        const allowed = await ticketPerms.canClaimTicket(interaction.guild, interaction.member, panel, instance);
        if (!allowed) {
            return interaction.reply({ content: 'You do not have permission to claim tickets.', ephemeral: true });
        }
        await interaction.deferReply({ ephemeral: true });
        try {
            const claim = await ticketClaimService.claimTicket(channelId, interaction.user.id, { performedBy: interaction.user.id });
            if (!claim) {
                const fresh = await ticketClaimService.getTicketClaim(channelId);
                if (fresh && fresh.claimedBy && String(fresh.claimedBy) !== String(interaction.user.id)) {

                    return interaction.editReply({ content: `This ticket is already claimed by <@${fresh.claimedBy}>.` });
                }
                return interaction.editReply({ content: 'The ticket could not be claimed. Please try again.', ephemeral: true });
            }
            // Reflect the new claim state in the in-memory instance.
            instance.claimedBy = claim.claimedBy;
            instance.claimedAt = claim.claimedAt;
            instance.claimHistory = claim.claimHistory;
            this._byChannel.set(channelId, instance);
            // Apply the claimed-status channel name template..
            if (panel) {
                const openerMember = await interaction.guild.members.fetch(instance.userId).catch(() => null);
                const opener = openerMember?.user || { id: instance.userId, username: openerMember?.displayName };
                await this._setTicketName(interaction.channel, panel.claimedNameTemplate, panel, opener);
            }
            // Update the control message in place (claim state + buttons swap)..
            const payload = this._openControlPayload(panel, await this._resolveOpener(interaction, instance), instance);
            await interaction.channel?.messages?.fetch(instance.controlMessageId).then(m => m.edit(payload).catch(() => {}));
            const embed = new EmbedBuilder()
                .setColor('#5865F2')
                .setDescription(`🎫 Ticket Claimed

This ticket has been claimed by ${interaction.user}.
The claimed moderator is now the primary staff member responsible for handling this ticket.`)
                .setTimestamp();
            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error('[TICKETS] Error claiming ticket:', err);
            return interaction.editReply({ content: 'There was an error claiming this ticket. Please try again.', ephemeral: true });
        }
    }

    /** Unclaim a claimed ticket (claimant always; admin/ticket managers force). */
    async handleUnclaim(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const panel = this._panelForInstance(instance);
        if (panel && panel.claimEnabled === false) {
            return interaction.reply({ content: 'Claiming is disabled for this ticket panel.', ephemeral: true });
        }
        const perm = await ticketPerms.canUnclaimTicket(interaction.guild, interaction.member, panel, instance);
        if (!perm.allowed) {
            const text = perm.reason === 'ticket_closed' ? 'This ticket is already closed.' : perm.reason === 'claim_other' ? 'You can only unclaim tickets assigned to you.' : 'You do not have permission to unclaim this ticket.';
            return interaction.reply({ content: text, ephemeral: true });
        }
        await interaction.deferReply({ ephemeral: true });
        try {
            const claimerId = perm.force ? null : instance.claimedBy;
            const res = await ticketClaimService.unclaimTicket(channelId, claimerId, { performedBy: interaction.user.id, force: !!perm.force });
            if (!res) {
                const fresh = await ticketClaimService.getTicketClaim(channelId)
                if (!fresh || fresh.status !== 'open') return interaction.editReply({ content: 'This ticket is already closed.', ephemeral: true });
                if (fresh.claimedBy) return interaction.editReply({ content: `This ticket is already claimed by <@${fresh.claimedBy}>.` });
                return interaction.editReply({ content: 'The ticket could not be updated. Please try again.', ephemeral: true });
            }
            instance.claimedBy = null;
            instance.claimedAt = null;
            instance.claimHistory = res.claimHistory;
            this._byChannel.set(channelId, instance);
            const opener = await this._resolveOpener(interaction, instance);
            const payload = this._openControlPayload(panel, opener, instance);
            await interaction.channel?.messages?.fetch(instance.controlMessageId).then(m => m.edit(payload).catch(() => {}));
            const embed = new EmbedBuilder()
                .setColor('#ED4245')
                .setDescription(`🎫 Ticket Unclaimed

This ticket is now available for another staff member to handle.`)
                .setTimestamp();
            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error('[TICKETS] Error unclaiming ticket:', err);
            return interaction.editReply({ content: 'There was an error unclaiming this ticket. Please try again.', ephemeral: true });
        }
    }

    /** Transfer/resassign a claim via a short modal (current claimer or force). */
    async handleTransferPrompt(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const panel = this._panelForInstance(instance);
        if (panel && panel.claimEnabled === false) {
            return interaction.reply({ content: 'Claiming is disabled for this ticket panel.', ephemeral: true });
        }
        const perm = await ticketPerms.canTransferTicketClaim(interaction.guild, interaction.member, panel, instance);
        if (!perm.allowed) {
            return interaction.reply({ content: perm.reason === 'claim_other' ? 'Only the current claimer or administrators can transfer this ticket.' : 'You do not have permission to transfer this ticket.', ephemeral: true });
        }
        const modal = new ModalBuilder()
            .setCustomId('ticketpanel:transfer')
            .setTitle('Transfer Claim');
        const input = new TextInputBuilder()
            .setCustomId('transfer-target')
            .setLabel('New staff member ID / mention')
            .setStyle(TextInputStyle.Short)
            .setPlaceholder('Paste the Discord user ID of the new staff member');
        modal.addComponents(new ActionRowBuilder().addComponents(input));
        try {
            await interaction.showModal(modal);
        } catch (err) {
            console.error('[TICKETS] Error showing transfer modal:', err);
            return interaction.reply({ content: 'There was an error openingthe transfer form.', ephemeral: true });
        }
    }

    /** Process the transfer modal submission (atomic + perm-checked). */
    async handleTransferSubmit(interaction) {
        const channelId = interaction.channel.id;
        const instance = this.getInstanceByChannel(channelId) || await this._fetchInstanceByChannel(channelId);
        if (!instance) {
            return interaction.reply({ content: 'This is not a valid ticket channel.', ephemeral: true });
        }
        const panel = this._panelForInstance(instance);
        if (panel && panel.claimEnabled === false) {
            return interaction.reply({ content: 'Claiming is disabled for this ticket panel.', ephemeral: true });
        }
        const perm = await ticketPerms.canTransferTicketClaim(interaction.guild, interaction.member, panel, instance);
        if (!perm.allowed) {
            return interaction.reply({ content: perm.reason === 'claim_other' ? 'Only the current claimer or administrators can transfer this ticket.' : 'You do not have permission to transfer this ticket.', ephemeral: true });
        }
        let raw = interaction.fields?.getTextInputValue('transfer-target');
        if (raw == null) raw = interaction.fields?.get('transfer-target')?.value;
        const match = String(raw || '').trim().match(/(\d{6,25})/);
        const toStaffId = match ? match[1] : null;
        if (!toStaffId) {
            return interaction.reply({ content: 'Please provide a valid Discord user ID or mention.', ephemeral: true });
        }
        if (instance.claimedBy && String(instance.claimedBy) === toStaffId) {
            return interaction.reply({ content: 'That user already owns the claim on this ticket.', ephemeral: true });
        }
        // The target must be a support-capable member (same panel role config).
        try {
            const targetMember = await interaction.guild.members.fetch(toStaffId).catch(() => null);
            if (targetMember) {
                const targetPerm = await ticketPerms.canManageTicket(interaction.guild, targetMember, panel);
                if (!targetPerm) {
                    return interaction.reply({ content: 'The selected user is not authorized to handle tickets.', ephemeral: true });
                }
            }
        } catch (err) {
            // Ignore resolution errors — fall through to the atomic transfer (it
            // re-checks state and only succeeds when the claim is still owned by
            // which we expect); the timestamp + history still record properly.

        }
        await interaction.deferReply({ ephemeral: true });
        try {
            const prevClaimer = instance.claimedBy || null;
            const res = await ticketClaimService.transferTicketClaim(channelId, prevClaimer, toStaffId, { performedBy: interaction.user.id, force: !!perm.force });
            if (!res) {
                const fresh = await ticketClaimService.getTicketClaim(channelId)
                if (!fresh || fresh.status !== 'open') return interaction.editReply({ content: 'This ticket is already closed.', ephemeral: true });
                if (!fresh.claimedBy) return interaction.editReply({ content: 'This ticket is unclaimed — claim it first before transferring.', ephemeral: true });
                return interaction.editReply({ content: `This ticket is now claimed by <@${fresh.claimedBy}>.`, ephemeral: true });
            }
            instance.claimedBy = res.claimedBy;
            instance.claimedAt = res.claimedAt;
            instance.claimHistory = res.claimHistory;

            this._byChannel.set(channelId, instance);
            const opener = await this._resolveOpener(interaction, instance);
            const payload = this._openControlPayload(panel, opener, instance);
            await interaction.channel?.messages?.fetch(instance.controlMessageId).then(m => m.edit(payload).catch(() => {}));
            const embed = new EmbedBuilder()
                .setColor('#5865F2')
                .setDescription(`🎫 Ticket Reassigned

Previous Staff: ${prevClaimer ? `<@${prevClaimer}>` : 'Nobody'}
New Staff: <@${toStaffId}>`)
                .setTimestamp();
            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error('[TICKETS] Error transferring ticket claim:', err);
            return interaction.editReply({ content: 'There was an error transferring this ticket. Please try again.', ephemeral: true });
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
            await interaction.reply({ content: `Ō£Å’ĖÅ Ticket renamed to **${name}**.`, ephemeral: true });
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
                claimed_at, claim_history,
                created_at, closed_at, closed_by, reopened_at, reopened_by
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
            ON CONFLICT (channel_id) DO UPDATE SET
                status = EXCLUDED.status,
                claimed_by = EXCLUDED.claimed_by,
                claimed_at = EXCLUDED.claimed_at,
                claim_history = EXCLUDED.claim_history,
                closed_at = EXCLUDED.closed_at,
                closed_by = EXCLUDED.closed_by,
                reopened_at = EXCLUDED.reopened_at,
                reopened_by = EXCLUDED.reopened_by
        `, [
            instance.panelId || null, instance.guildId, instance.channelId, instance.userId,
            instance.category, instance.isThread, instance.parentChannelId,
            instance.controlMessageId, instance.reason, instance.status, instance.claimedBy,
            instance.claimedAt || null, instance.claimHistory ? JSON.stringify(instance.claimHistory) : null,
            instance.createdAt, instance.closedAt || null, instance.closedBy || null,
            instance.reopenedAt || null, instance.reopenedBy || null,
        ]);
    }

    getTicketHistory(guildId, userId = null) {
        return Array.from(this._byChannel.values())
            .filter(t => t.guildId === guildId && (userId ? t.userId === userId : true))
            .sort((a, b) => b.createdAt - a.createdAt);
    }

    // ── Startup ──────────────────────────────────────────────

    /**
     * Re-bind live panel messages + open tickets after a bot restart.
     * Crucially, a panel whose Discord message can no longer be fetched
     * (deleted by a moderator, channel removed) is NOT deleted: its config
     * is preserved so the dashboard can Resend it. We only log + leave it.
     */
    async restorePanels() {
        if (!this.client || !this.client.guilds) return;
        try {
            // Ensure the in-memory maps reflect the DB (panels + open tickets).
            await this._refreshFromDatabase();
        } catch (err) {
            console.error('[TICKETS] restorePanels refresh failed:', err.message);
        }
        const panels = [...this._byPanel.values()].filter(p => p.enabled && p.channelId && p.messageId);
        let missing = 0;
        for (const panel of panels) {
            try {
                const guild = this.client.guilds.cache.get(panel.guildId)
                    || await this.client.guilds.fetch(panel.guildId).catch(() => null);
                if (!guild) continue;
                const channel = guild.channels.cache.get(panel.channelId)
                    || await guild.channels.fetch(panel.channelId).catch(() => null);
                if (!channel) { missing++; continue; }
                // Verify the panel message still exists. If not, keep the config
                // (do NOT delete) so the dashboard can Resend.
                await channel.messages.fetch(panel.messageId).catch(() => { missing++; });
            } catch {
                missing++;
            }
        }
        console.log(`[TICKETS] Restored ${panels.length} ticket panels${missing ? ` (${missing} message(s) missing — configs preserved)` : ''}.`);
    }
}

module.exports = { TicketPanelManager, ticketPool, normalizeCloseFlow, renderCloseText, DEFAULT_CLOSE_FLOW };