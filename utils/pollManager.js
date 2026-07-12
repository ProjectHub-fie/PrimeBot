const { EmbedBuilder } = require('discord.js');
const config = require('../config');
const ms = require('ms');
const { pool } = require('../server/db');

class PollManager {
    constructor(client) {
        this.client = client;
        this.polls = new Map(); // messageId → poll object (active polls only)

        this._init().catch(err =>
            console.error('[POLLS] Initialisation failed:', err.message)
        );
    }

    // ─── Internal ─────────────────────────────────────────────────────────────

    async _ensureTables() {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS polls (
                message_id  VARCHAR(50) PRIMARY KEY,
                channel_id  VARCHAR(50) NOT NULL,
                guild_id    VARCHAR(50) NOT NULL,
                question    TEXT NOT NULL,
                creator_id  VARCHAR(50),
                is_active   BOOLEAN NOT NULL DEFAULT true,
                created_at  TIMESTAMP DEFAULT NOW(),
                expires_at  TIMESTAMP,
                ended       BOOLEAN NOT NULL DEFAULT false
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS poll_options (
                id           SERIAL PRIMARY KEY,
                message_id   VARCHAR(50) NOT NULL,
                option_text  TEXT NOT NULL,
                option_index INTEGER NOT NULL,
                emoji        VARCHAR(10) NOT NULL,
                vote_count   INTEGER NOT NULL DEFAULT 0
            )
        `);
    }

    async _init() {
        await this._ensureTables();
        await this._migrateFromJson();
        await this.loadPolls();
        setTimeout(() => this.startCheckingPolls(), 5000);
    }

    /** One-time import of existing polls.json data. */
    async _migrateFromJson() {
        const fs = require('fs');
        const path = require('path');
        const jsonPath = path.join(__dirname, '../data/polls.json');
        const donePath = jsonPath + '.migrated';
        if (!fs.existsSync(jsonPath) || fs.existsSync(donePath)) return;

        try {
            const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            let count = 0;
            for (const [messageId, poll] of Object.entries(data)) {
                try {
                    const expiresAt = poll.endTime ? new Date(poll.endTime) : null;
                    await pool.query(`
                        INSERT INTO polls (message_id, channel_id, guild_id, question, creator_id, is_active, expires_at, ended)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        ON CONFLICT (message_id) DO NOTHING
                    `, [messageId, poll.channelId, poll.guildId || 'unknown', poll.question,
                        poll.createdBy || null, !poll.ended, expiresAt, poll.ended || false]);

                    if (poll.options && Array.isArray(poll.options)) {
                        for (let i = 0; i < poll.options.length; i++) {
                            await pool.query(`
                                INSERT INTO poll_options (message_id, option_text, option_index, emoji, vote_count)
                                VALUES ($1, $2, $3, $4, 0)
                                ON CONFLICT DO NOTHING
                            `, [messageId, poll.options[i], i, this.getOptionEmoji(i)]);
                        }
                    }
                    count++;
                } catch (e) {
                    console.error(`[POLLS] Migration: failed on poll ${messageId}:`, e.message);
                }
            }
            fs.renameSync(jsonPath, donePath);
            console.log(`[POLLS] Migrated ${count} polls from JSON → DB.`);
        } catch (err) {
            console.error('[POLLS] JSON migration failed:', err.message);
        }
    }

    async loadPolls() {
        try {
            // Load all active (not ended) polls
            const pollsRes = await pool.query(`
                SELECT message_id, channel_id, guild_id, question, creator_id,
                       EXTRACT(EPOCH FROM expires_at) * 1000 AS end_time_ms, ended
                FROM polls
                WHERE ended = false
            `);

            for (const row of pollsRes.rows) {
                const optsRes = await pool.query(
                    `SELECT option_text FROM poll_options WHERE message_id = $1 ORDER BY option_index`,
                    [row.message_id]
                );
                this.polls.set(row.message_id, {
                    messageId: row.message_id,
                    channelId: row.channel_id,
                    guildId: row.guild_id,
                    question: row.question,
                    options: optsRes.rows.map(r => r.option_text),
                    endTime: row.end_time_ms ? Number(row.end_time_ms) : null,
                    createdBy: row.creator_id,
                    ended: row.ended,
                });
            }
            console.log(`[POLLS] Loaded ${this.polls.size} active polls from database.`);
        } catch (error) {
            console.error('[POLLS] Error loading polls:', error);
        }
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    startCheckingPolls() {
        setInterval(() => this.checkPolls(), 10000);
        console.log('[POLLS] Poll checking system started.');
    }

    async checkPolls() {
        const now = Date.now();
        const endedPolls = [];

        for (const [messageId, poll] of this.polls.entries()) {
            if (!poll.ended && poll.endTime !== null && poll.endTime <= now) {
                endedPolls.push(messageId);
            }
        }

        for (const messageId of endedPolls) {
            try {
                await this.endPoll(messageId);
            } catch (error) {
                console.error(`[POLLS] Error ending poll ${messageId}:`, error);
            }
        }
    }

    async createPoll({ channelId, question, options, duration, userId }) {
        if (!options || options.length < 2 || options.length > 10) {
            throw new Error('A poll must have between 2 and 10 options.');
        }

        const channel = await this.client.channels.fetch(channelId);
        if (!channel) throw new Error('Channel not found.');

        const durationMs = ms(duration);
        if (!durationMs) throw new Error('Invalid duration. Please use a valid format like 1m, 1h, 1d.');

        const endTime = Date.now() + durationMs;
        const guildId = channel.guildId || channel.guild?.id || 'unknown';

        const optionsWithEmojis = options.map((opt, i) => `${this.getOptionEmoji(i)} ${opt}`);

        const embed = new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle(`📊 Poll: ${question}`)
            .setDescription(optionsWithEmojis.join('\n\n'))
            .addFields({ name: 'Poll Duration', value: `Ends <t:${Math.floor(endTime / 1000)}:R>` })
            .setFooter({
                text: `Poll created by ${userId ? (channel.guild?.members.cache.get(userId)?.displayName || 'Unknown') : 'Unknown'}`,
                iconURL: userId ? (channel.guild?.members.cache.get(userId)?.user.displayAvatarURL({ dynamic: true }) || null) : null,
            })
            .setTimestamp();

        const message = await channel.send({ embeds: [embed] });

        for (let i = 0; i < options.length; i++) {
            await message.react(this.getOptionEmoji(i));
        }

        // Save to DB
        await pool.query(`
            INSERT INTO polls (message_id, channel_id, guild_id, question, creator_id, is_active, expires_at, ended)
            VALUES ($1, $2, $3, $4, $5, true, to_timestamp($6 / 1000.0), false)
            ON CONFLICT (message_id) DO NOTHING
        `, [message.id, channelId, guildId, question, userId || null, endTime]);

        for (let i = 0; i < options.length; i++) {
            await pool.query(`
                INSERT INTO poll_options (message_id, option_text, option_index, emoji, vote_count)
                VALUES ($1, $2, $3, $4, 0)
            `, [message.id, options[i], i, this.getOptionEmoji(i)]);
        }

        const pollData = {
            messageId: message.id,
            channelId,
            guildId,
            question,
            options,
            endTime,
            createdBy: userId,
            ended: false,
        };
        this.polls.set(message.id, pollData);

        return message;
    }

    async endPoll(messageId) {
        const poll = this.polls.get(messageId);
        if (!poll || poll.ended) return false;

        try {
            const channel = await this.client.channels.fetch(poll.channelId);
            if (!channel) {
                await this._markPollEnded(messageId);
                return false;
            }

            const message = await channel.messages.fetch(messageId).catch(() => null);
            if (!message) {
                await this._markPollEnded(messageId);
                return false;
            }

            // Fetch all reactions
            try { await message.reactions.fetch(); } catch (_) {}

            const results = [];
            const botId = this.client.user.id;

            for (let i = 0; i < poll.options.length; i++) {
                const emoji = this.getOptionEmoji(i);
                const reaction = message.reactions.cache.get(emoji);
                let votes = 0;
                if (reaction) {
                    try {
                        const users = await this.fetchAllReactionUsers(reaction);
                        votes = users.filter(u => u.id !== botId).size;
                    } catch (_) {
                        votes = reaction.count > 0 ? reaction.count - 1 : 0;
                    }
                }
                results.push({ option: poll.options[i], emoji, votes });
            }

            results.sort((a, b) => b.votes - a.votes);
            const totalVotes = results.reduce((sum, r) => sum + r.votes, 0);
            const highestVotes = results[0]?.votes || 0;
            const winners = results.filter(r => r.votes === highestVotes && r.votes > 0).map(r => r.option);

            const resultLines = results.map(r => {
                const pct = totalVotes > 0 ? Math.round((r.votes / totalVotes) * 100) : 0;
                const bar = this.getProgressBar(pct);
                const isWinner = r.votes === highestVotes && r.votes > 0;
                return isWinner
                    ? `👑 ${r.emoji} **${r.option}** 👑\n${bar} **${r.votes} votes (${pct}%)**`
                    : `${r.emoji} **${r.option}**\n${bar} ${r.votes} votes (${pct}%)`;
            });

            let winnerField;
            if (totalVotes === 0) {
                winnerField = { name: 'No Votes', value: 'No votes were cast in this poll.' };
            } else if (winners.length === 1) {
                winnerField = { name: '🏆 Winner', value: `**${winners[0]}** with ${highestVotes} vote${highestVotes !== 1 ? 's' : ''}!` };
            } else {
                winnerField = { name: '🏆 Tied Winners', value: `**${winners.join('** and **')}** with ${highestVotes} vote${highestVotes !== 1 ? 's' : ''} each!` };
            }

            const embedColor = winners.length > 0 ? (config.colors.Gold || '#FFD700') : config.colors.primary;
            const resultsEmbed = new EmbedBuilder()
                .setColor(embedColor)
                .setTitle(`📊 Poll Results: ${poll.question}`)
                .setDescription(resultLines.join('\n\n'))
                .addFields(winnerField, { name: '📊 Total Votes', value: `${totalVotes} vote${totalVotes !== 1 ? 's' : ''}` })
                .setFooter({ text: 'Poll ended • Results are final' })
                .setTimestamp();

            await channel.send({ embeds: [resultsEmbed] });
            await this._markPollEnded(messageId);
            return true;
        } catch (error) {
            console.error('[POLLS] Error ending poll:', error);
            return false;
        }
    }

    async _markPollEnded(messageId) {
        await pool.query(
            `UPDATE polls SET ended = true, is_active = false WHERE message_id = $1`,
            [messageId]
        ).catch(err => console.error('[POLLS] DB update failed:', err.message));
        this.polls.delete(messageId);
    }

    async forceEndPoll(messageId) {
        const poll = this.polls.get(messageId);
        if (!poll || poll.ended) return false;
        return this.endPoll(messageId);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    getOptionEmoji(index) {
        const emojis = ['1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣', '🔟'];
        return emojis[index] || '❓';
    }

    getProgressBar(percentage) {
        const filled = Math.round(percentage / 10);
        return '█'.repeat(filled) + '░'.repeat(10 - filled);
    }

    async fetchAllReactionUsers(reaction) {
        try {
            let allUsers = reaction.users.cache.clone();
            let lastId = null;
            let hasMore = true;
            let fetchCount = 0;
            while (hasMore && fetchCount < 10) {
                fetchCount++;
                const opts = { limit: 100 };
                if (lastId) opts.after = lastId;
                const newUsers = await reaction.users.fetch(opts);
                if (newUsers.size === 0) { hasMore = false; break; }
                allUsers = allUsers.concat(newUsers);
                lastId = newUsers.last().id;
                if (newUsers.size < 100) hasMore = false;
            }
            return allUsers;
        } catch (error) {
            console.error('[POLLS] Error fetching reaction users:', error);
            return reaction.users.cache;
        }
    }
}

module.exports = PollManager;
