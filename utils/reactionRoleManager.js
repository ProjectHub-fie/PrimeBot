const { reactionPool } = require('../server/reactionDb');
const { EmbedBuilder } = require('discord.js');

/**
 * Reaction-role menus — backed by PostgreSQL (REACTION_DATABASE_URL, falling
 * back to DATABASE_URL).
 *
 * A "menu" is a message the bot watches for reactions that grant roles. Menus
 * support two creation paths:
 *   1. Bot-created: the bot posts a role embed to a channel and watches its
 *      own message. The embed is rebuilt from stored title/description/color.
 *   2. Attach-to-message: the bot attaches emoji→role mappings to ANY existing
 *      message (referenced by channelId + messageId) without rewriting it.
 *
 * Premium behavior modes (all free — PrimeBot's motto is premium features free):
 *   normal  — toggle (react adds, unreact removes)
 *   sticky  — react adds role, bot removes the reaction but keeps the role
 *   verify  — react grants once; unreact does not remove (rules-gate style)
 *   unique  — only one role from the menu at a time (swap on new reaction)
 *
 * Plus per-menu options: persistent (re-apply on startup), includeBots,
 * requiredRoleId (gate), exclusiveRoleId (cross-menu mutually exclusive).
 *
 * Mirrors the caching pattern of WelcomeSettingsManager / LoggingSettingsManager:
 * in-memory cache, write-through to DB, and a setInterval re-read (~30s + 5s)
 * so dashboard saves take effect without a bot restart.
 */

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS reaction_roles (
        id                   SERIAL PRIMARY KEY,
        guild_id             VARCHAR(50) NOT NULL,
        channel_id           VARCHAR(50) NOT NULL,
        message_id           VARCHAR(50) NOT NULL,
        title                VARCHAR(255),
        description          TEXT,
        color                VARCHAR(20) DEFAULT '#5865F2',
        mode                 VARCHAR(20) DEFAULT 'normal',
        persistent           BOOLEAN DEFAULT true,
        include_bots         BOOLEAN DEFAULT false,
        required_role_id     VARCHAR(50),
        exclusive_role_id    VARCHAR(50),
        created_by           VARCHAR(50),
        enabled              BOOLEAN DEFAULT true,
        created_at           TIMESTAMP DEFAULT NOW(),
        updated_at           TIMESTAMP DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS reaction_roles_message_idx
        ON reaction_roles (guild_id, channel_id, message_id);
    CREATE INDEX IF NOT EXISTS reaction_roles_guild_idx
        ON reaction_roles (guild_id);
    CREATE TABLE IF NOT EXISTS reaction_role_mappings (
        id         SERIAL PRIMARY KEY,
        menu_id    INTEGER NOT NULL REFERENCES reaction_roles(id) ON DELETE CASCADE,
        emoji      VARCHAR(100) NOT NULL,
        role_id    VARCHAR(50) NOT NULL,
        label      VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS reaction_role_mappings_menu_idx
        ON reaction_role_mappings (menu_id);
    CREATE UNIQUE INDEX IF NOT EXISTS reaction_role_mappings_menu_emoji_idx
        ON reaction_role_mappings (menu_id, emoji);
`;

const VALID_MODES = new Set(['normal', 'sticky', 'verify', 'unique']);

class ReactionRoleManager {
    constructor(client) {
        this.client = client;
        this._byMessage = new Map();   // `${guildId}:${channelId}:${messageId}` -> menu
        this._byGuild = new Map();     // guildId -> Set<menuId>
        this._byId = new Map();        // menuId -> menu
        this._tableReady = false;
        this._init().catch(err =>
            console.error('[REACTION ROLES] Init failed:', err.message)
        );
    }

    async _ensureTable() {
        if (this._tableReady) return;
        await reactionPool.query(CREATE_TABLE_SQL);
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
                console.error('[REACTION ROLES] Background reload failed:', err.message)
            );
        }, ms);
        this._reloadTimer.unref?.();
        this._startRefreshLoop();
    }

    _startRefreshLoop() {
        if (this._refreshTimer) return;
        this._refreshTimer = setInterval(() => {
            this._refreshFromDatabase().catch(err =>
                console.error('[REACTION ROLES] Refresh failed:', err.message)
            );
        }, 5000);
        this._refreshTimer.unref?.();
    }

    async _refreshFromDatabase() {
        await this._ensureTable();
        const menus = await this._fetchAllMenus();
        for (const menu of menus) {
            const key = this._key(menu.guildId, menu.channelId, menu.messageId);
            const previous = this._byMessage.get(key);
            if (!previous || JSON.stringify(previous) !== JSON.stringify(menu)) {
                this._indexMenu(menu);
                if (previous) {
                    console.log(`[REACTION ROLES] Applied database update for menu ${menu.id} (guild ${menu.guildId}).`);
                }
            }
        }
        // Drop menus that no longer exist in the DB.
        const liveIds = new Set(menus.map(m => String(m.id)));
        for (const [id, menu] of this._byId) {
            if (!liveIds.has(id)) this._unindexMenu(menu);
        }
    }

    async _loadAll() {
        try {
            const menus = await this._fetchAllMenus();
            this._byMessage.clear();
            this._byGuild.clear();
            this._byId.clear();
            for (const menu of menus) this._indexMenu(menu);
            console.log(`[REACTION ROLES] Loaded ${menus.length} reaction-role menus.`);
        } catch (err) {
            console.error('[REACTION ROLES] Failed to load menus:', err.message);
        }
    }

    async _fetchAllMenus() {
        const menusRes = await reactionPool.query('SELECT * FROM reaction_roles ORDER BY id');
        if (menusRes.rows.length === 0) return [];
        const ids = menusRes.rows.map(r => r.id);
        const mapsRes = await reactionPool.query(
            'SELECT * FROM reaction_role_mappings WHERE menu_id = ANY($1::int[]) ORDER BY id',
            [ids]
        );
        const mapsByMenu = new Map();
        for (const r of mapsRes.rows) {
            if (!mapsByMenu.has(r.menu_id)) mapsByMenu.set(r.menu_id, []);
            mapsByMenu.get(r.menu_id).push(this._rowToMapping(r));
        }
        return menusRes.rows.map(r => this._rowToMenu(r, mapsByMenu.get(r.id) || []));
    }

    _key(guildId, channelId, messageId) {
        return `${guildId}:${channelId}:${messageId}`;
    }

    _indexMenu(menu) {
        const key = this._key(menu.guildId, menu.channelId, menu.messageId);
        this._byMessage.set(key, menu);
        this._byId.set(String(menu.id), menu);
        if (!this._byGuild.has(menu.guildId)) this._byGuild.set(menu.guildId, new Set());
        this._byGuild.get(menu.guildId).add(String(menu.id));
    }

    _unindexMenu(menu) {
        const key = this._key(menu.guildId, menu.channelId, menu.messageId);
        this._byMessage.delete(key);
        this._byId.delete(String(menu.id));
        const set = this._byGuild.get(menu.guildId);
        if (set) set.delete(String(menu.id));
    }

    _rowToMenu(row, mappings) {
        return {
            id: row.id,
            guildId: row.guild_id,
            channelId: row.channel_id,
            messageId: row.message_id,
            title: row.title || null,
            description: row.description || null,
            color: row.color || '#5865F2',
            mode: row.mode || 'normal',
            persistent: row.persistent,
            includeBots: row.include_bots,
            requiredRoleId: row.required_role_id || null,
            exclusiveRoleId: row.exclusive_role_id || null,
            createdBy: row.created_by || null,
            enabled: row.enabled,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            mappings,
        };
    }

    _rowToMapping(row) {
        return {
            id: row.id,
            menuId: row.menu_id,
            emoji: row.emoji,
            roleId: row.role_id,
            label: row.label || null,
        };
    }

    // ── Public read API ──────────────────────────────────────────────────────

    /** Find a menu by the message a reaction happened on (or null). */
    getMenuForMessage(guildId, channelId, messageId) {
        return this._byMessage.get(this._key(guildId, channelId, messageId)) || null;
    }

    getMenuById(id) {
        return this._byId.get(String(id)) || null;
    }

    getGuildMenus(guildId) {
        const ids = this._byGuild.get(guildId);
        if (!ids) return [];
        return [...ids].map(id => this._byId.get(id)).filter(Boolean);
    }

    // ── Emoji helpers ────────────────────────────────────────────────────────
    //
    // Discord identifies reactions by an "emoji identifier". For unicode
    // emojis it's the raw codepoint string (e.g. "🎉"); for custom guild
    // emojis it's "name:id" (e.g. "rolemoji:1234567890"). We normalize both
    // sides of the comparison to this form so a stored mapping matches the
    // incoming reaction regardless of how the emoji was supplied.

    normalizeEmoji(emoji) {
        if (!emoji) return null;
        // Custom emoji: discord.js gives { id, name } — we want "name:id".
        if (emoji.id) return `${emoji.name}:${emoji.id}`;
        // Unicode emoji.
        return emoji.name || String(emoji);
    }

    /** Resolve a user-supplied emoji string (from the dashboard/command) into
     *  the canonical identifier we store and compare against. Accepts either
     *  a unicode emoji or a custom-emoji reference like "<:name:id>". */
    static parseEmojiString(input) {
        if (!input) return null;
        const s = String(input).trim();
        if (!s) return null;
        // Custom emoji mention form: <:name:id> or <a:name:id>
        const m = s.match(/^<a?:(\w+):(\d+)>$/);
        if (m) return `${m[1]}:${m[2]}`;
        // Already in name:id form without brackets.
        if (/^\w+:\d+$/.test(s)) return s;
        // Otherwise treat as a unicode emoji (take the first grapheme).
        return s;
    }

    _findMapping(menu, emojiIdentifier) {
        return (menu.mappings || []).find(m => m.emoji === emojiIdentifier) || null;
    }

    // ── Reaction handling ────────────────────────────────────────────────────

    /** Called by the messageReactionAdd event. Returns true if handled. */
    async handleReactionAdd(reaction, user) {
        const message = reaction.message;
        if (!message || !message.guild) return false;
        const menu = this.getMenuForMessage(message.guild.id, message.channel.id, message.id);
        if (!menu || !menu.enabled) return false;
        if (user.bot && !menu.includeBots) return false;

        const emojiId = this.normalizeEmoji(reaction.emoji);
        const mapping = this._findMapping(menu, emojiId);
        if (!mapping) return false;

        const guild = message.guild;
        const member = await guild.members.fetch(user.id).catch(() => null);
        if (!member) return false;

        // Premium gate: required role.
        if (menu.requiredRoleId && !member.roles.cache.has(menu.requiredRoleId)) {
            await reaction.users.remove(user.id).catch(() => {});
            try {
                await user.send(`You need <@&${menu.requiredRoleId}> to use this reaction-role menu.`);
            } catch (_) {}
            return true;
        }

        const role = guild.roles.cache.get(mapping.roleId);
        if (!role) {
            console.warn(`[REACTION ROLES] Role ${mapping.roleId} no longer exists in guild ${guild.id}.`);
            return false;
        }

        // Safety: don't try to assign a role at/above the bot's highest role.
        const me = guild.members.me;
        if (me && role.position >= me.roles.highest.position) {
            console.warn(`[REACTION ROLES] Cannot assign role "${role.name}" — it is at/above the bot's highest role in guild ${guild.id}. Move the bot role above it.`);
            // Warn the user so they know why nothing happened.
            try {
                const { EmbedBuilder } = require('discord.js');
                const warn = new EmbedBuilder()
                    .setColor(0xED4245)
                    .setTitle('⚠️ Cannot grant this role')
                    .setDescription(`The role **${role.name}** is at or above PrimeBot's highest role, so I can't assign it. Ask a server admin to move PrimeBot's role above it.`)
                    .setTimestamp();
                await user.send({ embeds: [warn] }).catch(() => {});
            } catch (_) {}
            await reaction.users.remove(user.id).catch(() => {});
            return false;
        }

        // Premium "unique" mode: remove all other roles from this menu first.
        if (menu.mode === 'unique') {
            for (const m of menu.mappings) {
                if (m.roleId !== mapping.roleId && member.roles.cache.has(m.roleId)) {
                    await member.roles.remove(m.roleId, 'Reaction-role unique mode swap').catch(() => {});
                }
            }
        }

        // Premium "exclusive" cross-menu role: remove it if set.
        if (menu.exclusiveRoleId && member.roles.cache.has(menu.exclusiveRoleId)) {
            await member.roles.remove(menu.exclusiveRoleId, 'Reaction-role exclusive role').catch(() => {});
        }

        if (!member.roles.cache.has(mapping.roleId)) {
            try {
                await member.roles.add(mapping.roleId, `Reaction role by ${user.tag}`);
            } catch (err) {
                console.error(`[REACTION ROLES] Failed to add role ${role.name} to ${user.tag} in guild ${guild.id}:`, err.message);
                return false;
            }
        }

        // Premium "sticky"/"verify" modes: remove the user's reaction but keep
        // the role (one-click assign; no toggle-off).
        if (menu.mode === 'sticky' || menu.mode === 'verify') {
            await reaction.users.remove(user.id).catch(() => {});
        }

        return true;
    }

    /** Called by the messageReactionRemove event. Returns true if handled. */
    async handleReactionRemove(reaction, user) {
        const message = reaction.message;
        if (!message || !message.guild) return false;
        const menu = this.getMenuForMessage(message.guild.id, message.channel.id, message.id);
        if (!menu || !menu.enabled) return false;
        if (user.bot && !menu.includeBots) return false;

        // sticky/verify modes don't toggle off — the role stays.
        if (menu.mode === 'sticky' || menu.mode === 'verify') return true;

        const emojiId = this.normalizeEmoji(reaction.emoji);
        const mapping = this._findMapping(menu, emojiId);
        if (!mapping) return false;

        const guild = message.guild;
        const member = await guild.members.fetch(user.id).catch(() => null);
        if (!member) return false;

        const role = guild.roles.cache.get(mapping.roleId);
        if (!role) {
            console.warn(`[REACTION ROLES] Role ${mapping.roleId} no longer exists in guild ${guild.id}.`);
            return false;
        }
        const me = guild.members.me;
        if (me && role.position >= me.roles.highest.position) {
            console.warn(`[REACTION ROLES] Cannot remove role "${role.name}" — it is at/above the bot's highest role in guild ${guild.id}.`);
            return false;
        }

        if (member.roles.cache.has(mapping.roleId)) {
            try {
                await member.roles.remove(mapping.roleId, `Reaction role removed by ${user.tag}`);
            } catch (err) {
                console.error(`[REACTION ROLES] Failed to remove role ${role.name} from ${user.tag} in guild ${guild.id}:`, err.message);
                return false;
            }
        }
        return true;
    }

    // ── Persistence (write API used by the slash command + dashboard) ─────────

    /**
     * Create a menu and (for bot-created menus) post the embed. Returns the
     * stored menu. For attach-to-message menus pass { attach: true, channelId,
     * messageId } and the bot will NOT post a new message.
     */
    async createMenu({
        guildId, channelId, title, description, color, mode,
        persistent, includeBots, requiredRoleId, exclusiveRoleId, createdBy,
        mappings, attach, messageId,
    }) {
        await this._ensureTable();
        const safeMode = VALID_MODES.has(mode) ? mode : 'normal';
        const safeColor = /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#5865F2';
        const cleanMappings = this._normalizeMappings(mappings);

        let finalMessageId = messageId || null;

        // Bot-created menu: post the embed now so we capture the real message id.
        if (!attach) {
            const channel = await this.client.channels.fetch(channelId).catch(() => null);
            if (!channel) throw new Error('Channel not found or not visible to the bot.');
            const embed = this._buildEmbed({ title, description, color: safeColor, mappings: cleanMappings });
            const sent = await channel.send({ embeds: [embed] });
            finalMessageId = sent.id;
            for (const m of cleanMappings) {
                await sent.react(this._emojiToReactString(m.emoji)).catch(() => {});
            }
        } else {
            if (!finalMessageId) throw new Error('messageId is required when attaching to an existing message.');
            // Add the reactions to the existing message.
            const channel = await this.client.channels.fetch(channelId).catch(() => null);
            if (channel) {
                try {
                    const msg = await channel.messages.fetch(finalMessageId);
                    for (const m of cleanMappings) {
                        await msg.react(this._emojiToReactString(m.emoji)).catch(() => {});
                    }
                } catch (_) { /* message may be uncached; reactions still stored */ }
            }
        }

        const res = await reactionPool.query(`
            INSERT INTO reaction_roles (
                guild_id, channel_id, message_id, title, description, color, mode,
                persistent, include_bots, required_role_id, exclusive_role_id,
                created_by, enabled, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true,NOW(),NOW())
            RETURNING id
        `, [
            guildId, channelId, finalMessageId, title || null, attach ? null : (description || null),
            safeColor, safeMode,
            persistent !== false, includeBots === true,
            requiredRoleId || null, exclusiveRoleId || null, createdBy || null,
        ]);

        const menuId = res.rows[0].id;
        await this._replaceMappings(menuId, cleanMappings);

        const menu = await this._fetchMenu(menuId);
        if (menu) this._indexMenu(menu);
        return menu;
    }

    /** Patch an existing menu's settings and/or mappings. */
    async updateMenu(id, patch = {}) {
        await this._ensureTable();
        const existing = await this._fetchMenu(id);
        if (!existing) throw new Error('Reaction-role menu not found.');

        const next = {
            title: patch.title !== undefined ? patch.title : existing.title,
            description: patch.description !== undefined ? patch.description : existing.description,
            color: patch.color !== undefined ? patch.color : existing.color,
            mode: patch.mode !== undefined ? patch.mode : existing.mode,
            persistent: patch.persistent !== undefined ? patch.persistent : existing.persistent,
            includeBots: patch.includeBots !== undefined ? patch.includeBots : existing.includeBots,
            requiredRoleId: patch.requiredRoleId !== undefined ? patch.requiredRoleId : existing.requiredRoleId,
            exclusiveRoleId: patch.exclusiveRoleId !== undefined ? patch.exclusiveRoleId : existing.exclusiveRoleId,
            enabled: patch.enabled !== undefined ? patch.enabled : existing.enabled,
        };
        if (next.mode && !VALID_MODES.has(next.mode)) next.mode = 'normal';
        if (next.color && !/^#[0-9a-fA-F]{6}$/.test(next.color)) next.color = '#5865F2';

        await reactionPool.query(`
            UPDATE reaction_roles SET
                title = $2, description = $3, color = $4, mode = $5,
                persistent = $6, include_bots = $7, required_role_id = $8,
                exclusive_role_id = $9, enabled = $10, updated_at = NOW()
            WHERE id = $1
        `, [
            id, next.title, next.description, next.color, next.mode,
            next.persistent, next.includeBots, next.requiredRoleId || null,
            next.exclusiveRoleId || null, next.enabled,
        ]);

        if (Array.isArray(patch.mappings)) {
            const cleanMappings = this._normalizeMappings(patch.mappings);
            await this._replaceMappings(id, cleanMappings);
            next.mappings = cleanMappings;
        }

        const menu = await this._fetchMenu(id);
        if (menu) this._indexMenu(menu);
        return menu;
    }

    async deleteMenu(id) {
        await this._ensureTable();
        const menu = await this._fetchMenu(id);
        await reactionPool.query('DELETE FROM reaction_roles WHERE id = $1', [id]);
        if (menu) this._unindexMenu(menu);
        return !!menu;
    }

    async _fetchMenu(id) {
        const res = await reactionPool.query('SELECT * FROM reaction_roles WHERE id = $1', [id]);
        if (res.rows.length === 0) return null;
        const mapsRes = await reactionPool.query(
            'SELECT * FROM reaction_role_mappings WHERE menu_id = $1 ORDER BY id',
            [id]
        );
        return this._rowToMenu(res.rows[0], mapsRes.rows.map(r => this._rowToMapping(r)));
    }

    async _replaceMappings(menuId, mappings) {
        await reactionPool.query('DELETE FROM reaction_role_mappings WHERE menu_id = $1', [menuId]);
        for (const m of mappings) {
            await reactionPool.query(`
                INSERT INTO reaction_role_mappings (menu_id, emoji, role_id, label, created_at)
                VALUES ($1,$2,$3,$4,NOW())
                ON CONFLICT (menu_id, emoji) DO UPDATE SET role_id = EXCLUDED.role_id, label = EXCLUDED.label
            `, [menuId, m.emoji, m.roleId, m.label || null]);
        }
    }

    _normalizeMappings(mappings) {
        if (!Array.isArray(mappings)) return [];
        const seen = new Set();
        const out = [];
        for (const m of mappings) {
            if (!m || !m.emoji || !m.roleId) continue;
            const emoji = ReactionRoleManager.parseEmojiString(m.emoji);
            if (!emoji || seen.has(emoji)) continue;
            seen.add(emoji);
            out.push({ emoji, roleId: String(m.roleId), label: m.label || null });
        }
        return out;
    }

    /** Convert a stored emoji identifier into the string discord.js' react()
     *  expects. Unicode emojis pass through; "name:id" becomes a custom emoji
     *  reference. */
    _emojiToReactString(emoji) {
        if (/^\w+:\d+$/.test(emoji)) return emoji; // discord.js accepts "name:id" for custom
        return emoji;
    }

    // ── Embed building (for bot-created menus) ───────────────────────────────

    _buildEmbed({ title, description, color, mappings }) {
        const embed = new EmbedBuilder()
            .setColor(color || '#5865F2')
            .setTitle(title || 'Reaction Roles')
            .setDescription(description || 'React to get a role!');
        if (Array.isArray(mappings) && mappings.length) {
            const lines = mappings.map(m => {
                const e = this._emojiDisplay(m.emoji);
                return `${e} → <@&${m.roleId}>${m.label ? ` — ${m.label}` : ''}`;
            });
            embed.addFields({ name: 'Roles', value: lines.join('\n') });
        }
        embed.setFooter({ text: 'PrimeBot · Reaction Roles' });
        return embed;
    }

    /** Pretty-print an emoji identifier for an embed (custom emojis get the
     *  mention form so Discord renders them). */
    _emojiDisplay(emoji) {
        if (/^\w+:\d+$/.test(emoji)) return `<:${emoji}>`;
        return emoji;
    }

    // ── Startup persistence ──────────────────────────────────────────────────
    //
    // For persistent menus the bot re-applies roles by reading the watched
    // message's current reactions and granting the matching roles to everyone
    // who reacted. This survives bot restarts and Discord's reaction cache
    // evictions. Called from the ready event.

    async restorePersistentMenus() {
        if (!this.client || !this.client.guilds) return;
        const menus = [...this._byId.values()].filter(m => m.persistent && m.enabled);
        for (const menu of menus) {
            try {
                const channel = await this.client.channels.fetch(menu.channelId).catch(() => null);
                if (!channel) continue;
                const msg = await channel.messages.fetch(menu.messageId).catch(() => null);
                if (!msg) continue;
                for (const mapping of menu.mappings) {
                    const react = msg.reactions.cache.find(r => this.normalizeEmoji(r.emoji) === mapping.emoji);
                    if (!react) continue;
                    const users = await react.users.fetch().catch(() => null);
                    if (!users) continue;
                    const guild = this.client.guilds.cache.get(menu.guildId) || await this.client.guilds.fetch(menu.guildId).catch(() => null);
                    if (!guild) continue;
                    for (const user of users.values()) {
                        if (user.bot && !menu.includeBots) continue;
                        const member = await guild.members.fetch(user.id).catch(() => null);
                        if (!member) continue;
                        if (menu.requiredRoleId && !member.roles.cache.has(menu.requiredRoleId)) continue;
                        const role = guild.roles.cache.get(mapping.roleId);
                        if (!role) continue;
                        const me = guild.members.me;
                        if (me && role.position >= me.roles.highest.position) continue;
                        if (!member.roles.cache.has(mapping.roleId)) {
                            await member.roles.add(mapping.roleId, 'Reaction-role restore on startup').catch(() => {});
                        }
                    }
                }
            } catch (err) {
                console.error(`[REACTION ROLES] Restore failed for menu ${menu.id}:`, err.message);
            }
        }
        console.log(`[REACTION ROLES] Restored ${menus.length} persistent menus.`);
    }
}

module.exports = ReactionRoleManager;
