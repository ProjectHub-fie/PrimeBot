const { EmbedBuilder, ButtonBuilder, ButtonStyle, ActionRowBuilder } = require('discord.js');
const config = require('../config');
const { pool } = require('../server/db');

class CountingManager {
    constructor(client) {
        this.client = client;
        this.counting = new Map();

        this.loadCounting().catch(err =>
            console.error('[COUNTING] Failed to load counting games:', err.message)
        );
    }

    async loadCounting() {
        try {
            this.counting.clear();
            const res = await pool.query(
                'SELECT channel_id, start_number, current_number, goal_number, last_user_id, highest_number, fail_count, participants FROM counting_games'
            );
            for (const row of res.rows) {
                let participants = {};
                try { participants = row.participants ? JSON.parse(row.participants) : {}; } catch (_) {}
                this.counting.set(row.channel_id, {
                    currentNumber: row.current_number,
                    goalNumber: row.goal_number,
                    startNumber: row.start_number,
                    lastUserId: row.last_user_id,
                    highestNumber: row.highest_number,
                    failCount: row.fail_count,
                    participants,
                });
            }
            console.log(`[COUNTING] Loaded ${this.counting.size} counting games from database.`);
        } catch (error) {
            console.error('[COUNTING] Error loading counting games:', error);
        }
    }

    async saveCounting(channelId) {
        const game = this.counting.get(channelId);
        if (!game) return;
        try {
            await pool.query(`
                INSERT INTO counting_games (channel_id, start_number, current_number, goal_number, last_user_id, highest_number, fail_count, participants, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
                ON CONFLICT (channel_id) DO UPDATE SET
                    start_number   = EXCLUDED.start_number,
                    current_number = EXCLUDED.current_number,
                    goal_number    = EXCLUDED.goal_number,
                    last_user_id   = EXCLUDED.last_user_id,
                    highest_number = EXCLUDED.highest_number,
                    fail_count     = EXCLUDED.fail_count,
                    participants   = EXCLUDED.participants,
                    updated_at     = NOW()
            `, [
                channelId,
                game.startNumber,
                game.currentNumber,
                game.goalNumber,
                game.lastUserId,
                game.highestNumber,
                game.failCount,
                JSON.stringify(game.participants),
            ]);
        } catch (error) {
            console.error(`[COUNTING] Error saving game for channel ${channelId}:`, error);
        }
    }

    async processCountingMessage(message) {
        const channelId = message.channel.id;
        const game = this.counting.get(channelId);
        if (!game) return;

        const content = message.content.trim();
        const number = parseInt(content, 10);

        if (isNaN(number) || number.toString() !== content) {
            return;
        }

        const expectedNumber = game.currentNumber + 1;

        if (number !== expectedNumber) {
            game.failCount++;
            await message.react('❌');
            const embed = new EmbedBuilder()
                .setColor('#FF0000')
                .setTitle('❌ Wrong Number!')
                .setDescription(`The next number was **${expectedNumber}**, not **${number}**.\nCount resets to **${game.startNumber}**!`)
                .addFields(
                    { name: '💀 Ruined by', value: `${message.author}`, inline: true },
                    { name: '📊 Fail Count', value: `${game.failCount}`, inline: true }
                )
                .setTimestamp();
            await message.channel.send({ embeds: [embed] });
            game.currentNumber = game.startNumber - 1;
            game.lastUserId = null;
            this.counting.set(channelId, game);
            await this.saveCounting(channelId);
            return;
        }

        if (game.lastUserId === message.author.id) {
            game.failCount++;
            await message.react('❌');
            const embed = new EmbedBuilder()
                .setColor('#FFA500')
                .setTitle('⚠️ No Consecutive Counting!')
                .setDescription(`You can't count twice in a row! Count resets to **${game.startNumber}**!`)
                .setTimestamp();
            await message.channel.send({ embeds: [embed] });
            game.currentNumber = game.startNumber - 1;
            game.lastUserId = null;
            this.counting.set(channelId, game);
            await this.saveCounting(channelId);
            return;
        }

        game.currentNumber = number;
        game.lastUserId = message.author.id;
        if (!game.participants[message.author.id]) game.participants[message.author.id] = 0;
        game.participants[message.author.id]++;
        if (number > game.highestNumber) game.highestNumber = number;

        await message.react('✅');
        this.counting.set(channelId, game);
        await this.saveCounting(channelId);

        if (number >= game.goalNumber) {
            await this.handleGameWin(message, game, channelId);
        }
    }

    async handleGameWin(message, game, channelId) {
        const sortedParticipants = Object.entries(game.participants)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 5);

        const leaderboard = sortedParticipants.map(([uid, count], i) =>
            `${['🥇', '🥈', '🥉', '4️⃣', '5️⃣'][i]} <@${uid}>: **${count}** numbers`
        ).join('\n') || 'No participants';

        const embed = new EmbedBuilder()
            .setColor('#FFD700')
            .setTitle('🎉 Counting Goal Reached!')
            .setDescription(`Amazing! You reached **${game.goalNumber}**! 🎊\n\nNew goal: **${game.goalNumber * 2}**`)
            .addFields(
                { name: '🏆 Top Counters', value: leaderboard },
                { name: '📈 New Goal', value: `${game.goalNumber * 2}`, inline: true },
                { name: '💀 Total Fails', value: `${game.failCount}`, inline: true }
            )
            .setTimestamp();

        await message.channel.send({ embeds: [embed] });

        game.goalNumber *= 2;
        game.currentNumber = 0;
        game.startNumber = 1;
        game.lastUserId = null;
        game.participants = {};
        this.counting.set(channelId, game);
        await this.saveCounting(channelId);
    }

    /**
     * Start a counting game.
     * Accepts either positional args (channelId, startNumber, goalNumber)
     * or a single options object { channelId, startNumber, goalNumber }.
     */
    async startCountingGame(channelIdOrOpts, startNumber = 1, goalNumber = 100) {
        let channelId;
        if (channelIdOrOpts && typeof channelIdOrOpts === 'object') {
            channelId   = channelIdOrOpts.channelId;
            startNumber = channelIdOrOpts.startNumber ?? startNumber;
            goalNumber  = channelIdOrOpts.goalNumber  ?? goalNumber;
        } else {
            channelId = channelIdOrOpts;
        }

        const game = {
            currentNumber: startNumber - 1,
            goalNumber,
            startNumber,
            lastUserId: null,
            highestNumber: 0,
            failCount: 0,
            participants: {},
        };
        this.counting.set(channelId, game);
        await this.saveCounting(channelId);
        return game;
    }

    /**
     * End a counting game.
     * Returns true if a game existed and was ended, false if there was nothing to end.
     */
    async endCountingGame(channelId) {
        if (!this.counting.has(channelId)) return false;
        this.counting.delete(channelId);
        await pool.query('DELETE FROM counting_games WHERE channel_id = $1', [channelId]).catch(err =>
            console.error(`[COUNTING] Error deleting game for ${channelId}:`, err.message)
        );
        return true;
    }

    /** Get the active game for a channel (null if none). */
    getCountingGame(channelId) {
        return this.counting.get(channelId) || null;
    }

    /** Alias used by both prefix and slash commands. */
    getCountingStatus(channelId) {
        return this.getCountingGame(channelId);
    }

    isCountingChannel(channelId) {
        return this.counting.has(channelId);
    }

    /** Build a status embed for a game object. */
    createCountingEmbed(game) {
        const progress = game.goalNumber > 0
            ? Math.floor((game.currentNumber / game.goalNumber) * 100)
            : 0;
        return new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('🔢 Counting Game')
            .addFields(
                { name: 'Current Number', value: `${game.currentNumber}`,          inline: true },
                { name: 'Next Number',    value: `${game.currentNumber + 1}`,      inline: true },
                { name: 'Goal',           value: `${game.goalNumber}`,             inline: true },
                { name: 'Progress',       value: `${progress}%`,                   inline: true },
                { name: 'Highest Reached',value: `${game.highestNumber}`,          inline: true },
                { name: 'Fail Count',     value: `${game.failCount}`,              inline: true }
            )
            .setFooter({ text: `Version: ${config.version}` })
            .setTimestamp();
    }

    /** Build the help embed. */
    createHelpEmbed() {
        return new EmbedBuilder()
            .setColor(config.colors.primary)
            .setTitle('🔢 Counting Game — Help')
            .setDescription('Count up together as a server! Each member must count the next number in sequence.')
            .addFields(
                { name: '`$cstart [start] [goal]`',  value: 'Start a game (default: 1 → 100)', inline: false },
                { name: '`$cstatus`',                value: 'Show current game progress',       inline: false },
                { name: '`$cend`',                   value: 'End the current game (Admin)',     inline: false },
                { name: '`$chelp`',                  value: 'Show this help message',           inline: false },
                { name: '📋 Rules',                  value: '• Type only the next number\n• You cannot count twice in a row\n• Wrong number resets the count', inline: false }
            )
            .setFooter({ text: `Version: ${config.version}` });
    }
}

module.exports = CountingManager;
