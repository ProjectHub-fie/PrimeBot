const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const config = require('../config');
const { livePool } = require('../server/liveDb');

/**
 * LiveGiveawayManager — cross-server giveaways (the giveaway counterpart to
 * LivePollManager). Created with `$lgiveway` / `/lgiveway`, shared via a
 * giveaway ID + pass code, joinable from any server via `$lgiveway join <key>`
 * or the Join button on a join interface. Backed by the dedicated
 * LIVE_DATABASE_URL pool (server/liveDb.js, falls back to DATABASE_URL) using
 * raw SQL — so it works in a database separate from the bot's main schema
 * without dragging in drizzle.
 *
 * Caching pattern: in-memory map keyed by giveawayId, write-through to DB, plus
 * a `checkExpiredGiveaways()` sweep (called from events/ready.js) that ends
 * giveaways whose `ends_at` has passed and edits the original message.
 */

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS live_giveaways (
        id              SERIAL PRIMARY KEY,
        giveaway_id     VARCHAR(100) NOT NULL UNIQUE,
        pass_code       VARCHAR(20) NOT NULL,
        prize           TEXT NOT NULL,
        description     TEXT,
        creator_id      VARCHAR(50) NOT NULL,
        winner_count    INTEGER NOT NULL DEFAULT 1,
        is_active       BOOLEAN NOT NULL DEFAULT true,
        ended           BOOLEAN NOT NULL DEFAULT false,
        created_at      TIMESTAMP DEFAULT NOW(),
        ends_at         TIMESTAMP,
        message_id      VARCHAR(50),
        channel_id      VARCHAR(50)
    );
    CREATE INDEX IF NOT EXISTS live_giveaways_creator_idx ON live_giveaways (creator_id);
    CREATE TABLE IF NOT EXISTS live_giveaway_participants (
        id          SERIAL PRIMARY KEY,
        giveaway_id VARCHAR(100) NOT NULL,
        user_id     VARCHAR(50) NOT NULL,
        joined_at   TIMESTAMP DEFAULT NOW(),
        UNIQUE (giveaway_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS live_giveaway_participants_giveaway_idx ON live_giveaway_participants (giveaway_id);
    CREATE TABLE IF NOT EXISTS live_giveaway_winners (
        id          SERIAL PRIMARY KEY,
        giveaway_id VARCHAR(100) NOT NULL,
        user_id     VARCHAR(50) NOT NULL,
        selected_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS live_giveaway_winners_giveaway_idx ON live_giveaway_winners (giveaway_id);
`;

class LiveGiveawayManager {
    constructor(client = null) {
        this.client = client;
        this.giveaways = new Map(); // giveawayId -> giveaway (+ participants Set)
        this.dbReady = false;
        this._initPromise = this.initialize();
    }

    waitForReady() {
        return this._initPromise;
    }

    async initialize() {
        try {
            await livePool.query(CREATE_TABLE_SQL);
            this.dbReady = true;
            await this.loadAll();
            console.log('✅ LiveGiveawayManager database connection established');
        } catch (error) {
            this.dbReady = false;
            console.error('❌ LiveGiveawayManager database initialization failed:', error.message);
            console.log('⚠️ Live giveaways will use fallback mode (memory only)');
        }
    }

    async loadAll() {
        if (!this.dbReady) return;
        const { rows } = await livePool.query(
            `SELECT * FROM live_giveaways WHERE is_active = true ORDER BY created_at DESC`
        );
        for (const row of rows) {
            const pRes = await livePool.query(
                `SELECT user_id FROM live_giveaway_participants WHERE giveaway_id = $1`,
                [row.giveaway_id]
            );
            this.giveaways.set(row.giveaway_id, this._rowToGiveaway(row, new Set(pRes.rows.map(r => r.user_id))));
        }
    }

    _rowToGiveaway(row, participants = new Set()) {
        return {
            giveawayId: row.giveaway_id,
            passCode: row.pass_code,
            prize: row.prize,
            description: row.description || null,
            creatorId: row.creator_id,
            winnerCount: Number(row.winner_count) || 1,
            isActive: row.is_active !== false,
            ended: row.ended === true,
            createdAt: row.created_at ? new Date(row.created_at) : new Date(),
            endsAt: row.ends_at ? new Date(row.ends_at) : null,
            messageId: row.message_id || null,
            channelId: row.channel_id || null,
            participants,
        };
    }

    generateGiveawayId() {
        return 'lg' + Math.random().toString(36).substring(2, 12) + Math.random().toString(36).substring(2, 8);
    }

    generatePassCode() {
        return Math.random().toString(36).substring(2, 8).toUpperCase();
    }

    async createGiveaway({ prize, description = null, creatorId, winnerCount = 1, duration = null }) {
        await this._initPromise;
        const giveawayId = this.generateGiveawayId();
        const passCode = this.generatePassCode();
        const endsAt = duration ? new Date(Date.now() + duration) : null;
        const giveaway = {
            giveawayId, passCode, prize, description, creatorId,
            winnerCount: Math.max(1, parseInt(winnerCount, 10) || 1),
            isActive: true, ended: false,
            createdAt: new Date(), endsAt,
            messageId: null, channelId: null,
            participants: new Set(),
        };
        if (this.dbReady) {
            await livePool.query(
                `INSERT INTO live_giveaways (giveaway_id, pass_code, prize, description, creator_id, winner_count, is_active, ended, ends_at)
                 VALUES ($1,$2,$3,$4,$5,$6,true,false,$7)`,
                [giveawayId, passCode, prize, description, creatorId, giveaway.winnerCount, endsAt]
            );
        }
        this.giveaways.set(giveawayId, giveaway);
        return { giveawayId, passCode, giveaway };
    }

    async updateGiveawayMessage(giveawayId, messageId, channelId) {
        const g = this.giveaways.get(giveawayId);
        if (g) { g.messageId = messageId; g.channelId = channelId; }
        if (this.dbReady) {
            await livePool.query(
                `UPDATE live_giveaways SET message_id = $2, channel_id = $3 WHERE giveaway_id = $1`,
                [giveawayId, messageId, channelId]
            ).catch(err => console.error('[LIVE GIVEAWAY] updateGiveawayMessage:', err.message));
        }
    }

    async getGiveaway(identifier) {
        // Try cache by giveaway id, then by pass code.
        let g = this.giveaways.get(identifier);
        if (!g) {
            for (const gv of this.giveaways.values()) {
                if (gv.passCode === identifier) { g = gv; break; }
            }
        }
        if (g) return g;
        if (!this.dbReady) return null;
        const res = await livePool.query(
            `SELECT * FROM live_giveaways WHERE giveaway_id = $1 OR pass_code = $1 LIMIT 1`, [identifier]
        );
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        const pRes = await livePool.query(
            `SELECT user_id FROM live_giveaway_participants WHERE giveaway_id = $1`, [row.giveaway_id]
        );
        const giveaway = this._rowToGiveaway(row, new Set(pRes.rows.map(r => r.user_id)));
        this.giveaways.set(row.giveaway_id, giveaway);
        return giveaway;
    }

    async joinGiveaway(identifier, userId) {
        const giveaway = await this.getGiveaway(identifier);
        if (!giveaway) return { success: false, message: 'Giveaway not found' };
        const resolvedId = giveaway.giveawayId;
        if (!giveaway.isActive || giveaway.ended) return { success: false, message: 'This giveaway has ended.' };
        if (giveaway.endsAt && new Date() > giveaway.endsAt) return { success: false, message: 'This giveaway has ended.' };
        if (giveaway.participants.has(userId)) return { success: false, message: 'You have already joined this giveaway.' };

        giveaway.participants.add(userId);
        if (this.dbReady) {
            try {
                await livePool.query(
                    `INSERT INTO live_giveaway_participants (giveaway_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                    [resolvedId, userId]
                );
            } catch (err) {
                giveaway.participants.delete(userId);
                return { success: false, message: 'Error joining giveaway' };
            }
        }
        return { success: true, message: 'You joined the giveaway! Good luck!' };
    }

    async getGiveawayResults(identifier) {
        const giveaway = await this.getGiveaway(identifier);
        if (!giveaway) return null;
        let winners = [];
        if (this.dbReady) {
            const wRes = await livePool.query(
                `SELECT user_id FROM live_giveaway_winners WHERE giveaway_id = $1`, [giveaway.giveawayId]
            );
            winners = wRes.rows.map(r => r.user_id);
        }
        return { giveaway, participants: Array.from(giveaway.participants), winners };
    }

    async endGiveaway(identifier, userId) {
        const giveaway = await this.getGiveaway(identifier);
        if (!giveaway) return { success: false, message: 'Giveaway not found' };
        const resolvedId = giveaway.giveawayId;
        if (giveaway.creatorId !== userId) return { success: false, message: 'Only the giveaway creator can end this giveaway' };

        const participants = Array.from(giveaway.participants);
        const winners = this.selectWinners(participants, giveaway.winnerCount);

        giveaway.ended = true;
        giveaway.isActive = false;
        if (this.dbReady) {
            await livePool.query(
                `UPDATE live_giveaways SET is_active = false, ended = true WHERE giveaway_id = $1`, [resolvedId]
            );
            for (const w of winners) {
                await livePool.query(
                    `INSERT INTO live_giveaway_winners (giveaway_id, user_id) VALUES ($1,$2)`, [resolvedId, w]
                ).catch(() => {});
            }
        }

        // Edit the original message to show ended state.
        try {
            if (giveaway.messageId && giveaway.channelId && this.client) {
                const channel = await this.client.channels.fetch(giveaway.channelId).catch(() => null);
                if (channel) {
                    const message = await channel.messages.fetch(giveaway.messageId).catch(() => null);
                    if (message) {
                        await message.edit({ embeds: [this.createGiveawayEmbed(giveaway, participants.length, winners, true)], components: [] });
                    }
                }
            }
        } catch (err) {
            console.error('[LIVE GIVEAWAY] Could not update Discord message for ended giveaway:', err.message);
        }

        this.giveaways.delete(resolvedId);
        return { success: true, message: 'Giveaway ended', winners, participants, giveaway };
    }

    selectWinners(participants, count) {
        if (participants.length === 0) return [];
        if (participants.length <= count) return [...participants];
        const winners = [];
        const copy = [...participants];
        for (let i = 0; i < count; i++) {
            if (copy.length === 0) break;
            const idx = Math.floor(Math.random() * copy.length);
            winners.push(copy[idx]);
            copy.splice(idx, 1);
        }
        return winners;
    }

    async getUserGiveaways(userId, limit = 10) {
        if (!this.dbReady) {
            return Array.from(this.giveaways.values()).filter(g => g.creatorId === userId).slice(0, limit);
        }
        const { rows } = await livePool.query(
            `SELECT * FROM live_giveaways WHERE creator_id = $1 ORDER BY created_at DESC LIMIT $2`, [userId, limit]
        );
        return rows.map(r => this._rowToGiveaway(r));
    }

    async getAllActive() {
        if (this.dbReady) {
            const { rows } = await livePool.query(`SELECT * FROM live_giveaways WHERE is_active = true ORDER BY created_at DESC`);
            return rows.map(r => this._rowToGiveaway(r));
        }
        return Array.from(this.giveaways.values()).filter(g => g.isActive);
    }

    async getAllEnded(limit = 50) {
        if (!this.dbReady) return [];
        const { rows } = await livePool.query(
            `SELECT g.*, COALESCE(json_agg(w.user_id) FILTER (WHERE w.user_id IS NOT NULL), '[]') AS winners
             FROM live_giveaways g
             LEFT JOIN live_giveaway_winners w ON w.giveaway_id = g.giveaway_id
             WHERE g.ended = true
             GROUP BY g.id
             ORDER BY g.created_at DESC LIMIT $1`, [limit]
        );
        return rows.map(r => ({
            ...this._rowToGiveaway(r),
            winners: Array.isArray(r.winners) ? r.winners : [],
        }));
    }

    createGiveawayEmbed(giveaway, participantCount = 0, winners = [], isEnded = false) {
        if (isEnded) {
            const winnersText = winners.length > 0
                ? winners.map(id => `<@${id}>`).join(', ')
                : 'No one joined — no winners.';
            return new EmbedBuilder()
                .setColor(config.colors.success)
                .setTitle('🎉 LIVE GIVEAWAY ENDED 🎉')
                .setDescription(`**Prize**: ${giveaway.prize}`)
                .addFields(
                    { name: '🏆 Winner(s)', value: winnersText, inline: false },
                    { name: '📊 Entries', value: `${participantCount}`, inline: true },
                    { name: '🆔 ID', value: `\`${giveaway.giveawayId}\``, inline: true },
                )
                .setFooter({ text: 'Thanks for participating! • Powered by ProjectHub' })
                .setTimestamp();
        }
        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('🎉 LIVE GIVEAWAY 🎉')
            .setDescription(`**Prize**: ${giveaway.prize}`)
            .addFields(
                { name: '🏆 Winners', value: `${giveaway.winnerCount}`, inline: true },
                { name: '🆔 Giveaway ID', value: `\`${giveaway.giveawayId}\``, inline: true },
                { name: '🔑 Pass Code', value: `\`${giveaway.passCode}\``, inline: true },
                { name: '👥 Entries', value: `${participantCount}`, inline: true },
            );
        if (giveaway.description) {
            embed.addFields({ name: '📋 Description', value: giveaway.description });
        }
        if (giveaway.endsAt) {
            embed.addFields({ name: '⏱️ Ends', value: `<t:${Math.floor(new Date(giveaway.endsAt).getTime() / 1000)}:R>`, inline: true });
        } else {
            embed.addFields({ name: '⏱️ Ends', value: 'Permanent (until manually ended)', inline: true });
        }
        embed.addFields(
            { name: '\u200B', value: '\u200B' },
            { name: '📝 How to Enter', value: `Use \`${config.prefix}lgiveway join ${giveaway.passCode}\` or click a **Join** button!` }
        );
        embed.setFooter({ text: 'Good luck! • Powered by ProjectHub' }).setTimestamp();
        return embed;
    }

    createJoinButton(giveawayId) {
        return new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId(`lgive_${giveawayId}`)
                .setLabel('Join Giveaway')
                .setStyle(ButtonStyle.Success)
                .setEmoji('🎉')
        );
    }

    async checkExpiredGiveaways() {
        if (!this.dbReady) return;
        const { rows } = await livePool.query(
            `SELECT * FROM live_giveaways WHERE is_active = true AND ends_at IS NOT NULL AND ends_at <= NOW()`
        ).catch(() => ({ rows: [] }));
        for (const row of rows) {
            const giveaway = this._rowToGiveaway(row, this.giveaways.get(row.giveaway_id)?.participants || new Set());
            if (this.giveaways.has(row.giveaway_id)) {
                const cached = this.giveaways.get(row.giveaway_id);
                cached.participants.forEach(u => giveaway.participants.add(u));
            }
            try {
                const participants = Array.from(giveaway.participants);
                const winners = this.selectWinners(participants, giveaway.winnerCount);
                await livePool.query(
                    `UPDATE live_giveaways SET is_active = false, ended = true WHERE giveaway_id = $1`, [giveaway.giveawayId]
                );
                for (const w of winners) {
                    await livePool.query(
                        `INSERT INTO live_giveaway_winners (giveaway_id, user_id) VALUES ($1,$2)`, [giveaway.giveawayId, w]
                    ).catch(() => {});
                }
                if (giveaway.messageId && giveaway.channelId && this.client) {
                    const channel = await this.client.channels.fetch(giveaway.channelId).catch(() => null);
                    if (channel) {
                        const message = await channel.messages.fetch(giveaway.messageId).catch(() => null);
                        if (message) {
                            await message.edit({ embeds: [this.createGiveawayEmbed(giveaway, participants.length, winners, true)], components: [] });
                        }
                        if (winners.length > 0) {
                            await channel.send(`🎉 **Live Giveaway Ended!** 🎉\nCongratulations ${winners.map(id => `<@${id}>`).join(', ')}! You won **${giveaway.prize}**!`).catch(() => {});
                        } else {
                            await channel.send(`🎉 **Live Giveaway Ended!** 🎉\nThe giveaway for **${giveaway.prize}** ended, but no one entered!`).catch(() => {});
                        }
                    }
                }
                this.giveaways.delete(giveaway.giveawayId);
                console.log(`[LIVE GIVEAWAY] Auto-ended expired giveaway ${giveaway.giveawayId}`);
            } catch (err) {
                console.error(`[LIVE GIVEAWAY] Failed to auto-end ${giveaway.giveawayId}:`, err.message);
            }
        }
    }
}

module.exports = LiveGiveawayManager;
